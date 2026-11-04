import { useEffect, useMemo, useRef, useState } from "react";
import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import type { CockpitSnapshot, Subagent, Worker } from "./model";
import type { SourceDeliveryOutcome, SourceThread } from "./source";
import { attentionGroups, formatReason, shortIdentity } from "./model";
import { DEFAULT_TOPOLOGY_SETTINGS, type TopologySettings } from "./SettingsPage";

interface TopologyGraphProps {
  snapshot: CockpitSnapshot;
  workers: Worker[];
  selectedSlot: string | null;
  filter: "all" | "dispatch" | "callbacks";
  settings?: TopologySettings;
  onSelect: (worker: Worker) => void;
  sourceThreads?: SourceThread[];
  onSelectSource: (thread: SourceThread) => void;
  selectedSourceId?: string | null;
  sourceActivity?: { sequence: number; threadId: string; outcome: SourceDeliveryOutcome } | null;
}

interface SceneNode {
  id: string;
  label: string;
  meta: string;
  kind: "source" | "proxy" | "worker" | "subagent";
  lifecycle: "persistent" | "disposable" | "available" | "unavailable";
  position: THREE.Vector3;
  worker: Worker | null;
  sourceThread: SourceThread | null;
  lane: LaneId | null;
  pool: PoolId | null;
  routeSourceId: string | null;
  subagentState: Subagent["state"] | null;
}

export interface RouteLayers {
  dispatch: THREE.Object3D[];
  callbacks: THREE.Object3D[];
}

export interface RouteVisibility {
  showDispatch: boolean;
  showCallbacks: boolean;
}

export interface GraphSettingsTarget {
  controls: { autoRotate: boolean; autoRotateSpeed: number };
  depthField: { visible: boolean };
  distanceFog: THREE.Fog;
  halos: Array<{ visible: boolean }>;
  reducedMotion: boolean;
  scene: { fog: THREE.Fog | THREE.FogExp2 | null };
}

interface GraphRuntime extends GraphSettingsTarget {
  controls: OrbitControls;
  depthField: THREE.Points;
  halos: THREE.Mesh[];
  scene: THREE.Scene;
}

interface SharedGeometries {
  workerGeometry: THREE.BoxGeometry;
  proxyGeometry: THREE.CylinderGeometry;
  sourceGeometry: THREE.TetrahedronGeometry;
  subagentGeometry: THREE.BoxGeometry;
  haloGeometry: THREE.BoxGeometry;
}

export interface PhysicsBody {
  id: string;
  position: THREE.Vector3;
  target: THREE.Vector3;
  velocity: THREE.Vector3;
  radius: number;
  dragging: boolean;
  pool?: string;
}

const COLLISION_PADDING = .12;
const SETTLED_SPEED_SQ = .0004;
const FRAME_INTERVAL_MS = 1000 / 60;
const LABEL_INTERVAL_MS = 1000 / 30;
const PHYSICS_WAKE_MS = 8000;

export interface PhysicsLink {
  from: string;
  to: string;
  idealDistance?: number;
}

export interface GalaxyPhysicsSettings {
  idealDistance: number;
  cohesion: number;
  repulsion: number;
  gravity: number;
  damping: number;
}

const DEFAULT_GALAXY_PHYSICS: GalaxyPhysicsSettings = {
  idealDistance: 2.8,
  cohesion: .45,
  repulsion: 1.1,
  gravity: .12,
  damping: 3.2,
};

function fallbackCollisionNormal(first: string, second: string): THREE.Vector3 {
  let hash = 2166136261;
  for (const character of `${first}:${second}`) hash = Math.imul(hash ^ character.charCodeAt(0), 16777619);
  const axis = Math.abs(hash) % 3;
  return new THREE.Vector3(axis === 0 ? 1 : 0, axis === 1 ? 1 : 0, axis === 2 ? 1 : 0);
}

export function stepGraphPhysics(
  bodies: PhysicsBody[],
  elapsed: number,
  links: PhysicsLink[] = [],
  settings: GalaxyPhysicsSettings = DEFAULT_GALAXY_PHYSICS,
): boolean {
  const delta = Math.min(Math.max(elapsed, 1 / 240), .05);
  const damping = Math.exp(-settings.damping * delta);
  if (links.length === 0 && bodies.every((body) => !body.pool)) {
    const spring = new THREE.Vector3();
    let anchoredMoving = false;
    for (const body of bodies) {
      if (body.dragging) { anchoredMoving = true; continue; }
      spring.copy(body.target).sub(body.position);
      body.velocity.addScaledVector(spring, 5.4 * delta);
      body.velocity.multiplyScalar(damping);
      body.position.addScaledVector(body.velocity, delta);
    }
    for (let firstIndex = 0; firstIndex < bodies.length; firstIndex += 1) {
      const first = bodies[firstIndex];
      for (let secondIndex = firstIndex + 1; secondIndex < bodies.length; secondIndex += 1) {
        const second = bodies[secondIndex];
        const offset = second.position.clone().sub(first.position);
        const minimum = first.radius + second.radius + COLLISION_PADDING;
        const distance = offset.length();
        if (distance >= minimum) continue;
        const normal = distance > 1e-6 ? offset.multiplyScalar(1 / distance) : fallbackCollisionNormal(first.id, second.id);
        const overlap = minimum - distance;
        const firstShare = first.dragging ? 0 : second.dragging ? 1 : .5;
        const secondShare = second.dragging ? 0 : first.dragging ? 1 : .5;
        if (firstShare > 0) first.position.addScaledVector(normal, -overlap * firstShare);
        if (secondShare > 0) second.position.addScaledVector(normal, overlap * secondShare);
        const approach = second.velocity.clone().sub(first.velocity).dot(normal);
        if (approach < 0) {
          if (!first.dragging) first.velocity.addScaledVector(normal, approach * .35);
          if (!second.dragging) second.velocity.addScaledVector(normal, -approach * .35);
        }
        anchoredMoving = true;
      }
    }
    for (const body of bodies) {
      if (body.dragging || body.velocity.lengthSq() > SETTLED_SPEED_SQ || body.position.distanceToSquared(body.target) > .0009) anchoredMoving = true;
      else { body.velocity.set(0, 0, 0); body.position.copy(body.target); }
    }
    return anchoredMoving;
  }
  const forces = new Map(bodies.map((body) => [body.id, new THREE.Vector3()]));
  const byId = new Map(bodies.map((body) => [body.id, body]));
  const poolSums = new Map<string, { sum: THREE.Vector3; count: number }>();
  for (const body of bodies) {
    if (!body.pool) continue;
    const aggregate = poolSums.get(body.pool) ?? { sum: new THREE.Vector3(), count: 0 };
    aggregate.sum.add(body.position);
    aggregate.count += 1;
    poolSums.set(body.pool, aggregate);
  }
  let moving = false;
  for (const body of bodies) {
    if (body.dragging) { moving = true; continue; }
    const force = forces.get(body.id)!;
    if (body.pool) {
      const aggregate = poolSums.get(body.pool);
      if (aggregate && aggregate.count > 1) {
        force.addScaledVector(
          aggregate.sum.clone().multiplyScalar(1 / aggregate.count).sub(body.position),
          settings.cohesion,
        );
      }
      force.addScaledVector(body.position, -settings.gravity);
    } else {
      force.addScaledVector(body.target.clone().sub(body.position), 5.4);
    }
  }
  for (let firstIndex = 0; firstIndex < bodies.length; firstIndex += 1) {
    const first = bodies[firstIndex];
    for (let secondIndex = firstIndex + 1; secondIndex < bodies.length; secondIndex += 1) {
      const second = bodies[secondIndex];
      const offset = second.position.clone().sub(first.position);
      const minimum = first.radius + second.radius + COLLISION_PADDING;
      const distance = Math.max(offset.length(), 1e-6);
      const normal = distance > 1e-6 ? offset.clone().multiplyScalar(1 / distance) : fallbackCollisionNormal(first.id, second.id);
      const repulsion = (first.pool && second.pool && first.pool !== second.pool ? settings.repulsion : settings.repulsion * .12)
        / Math.max(distance * distance, .18);
      if (!first.dragging) forces.get(first.id)!.addScaledVector(normal, -repulsion);
      if (!second.dragging) forces.get(second.id)!.addScaledVector(normal, repulsion);
      if (distance >= minimum) continue;
      const overlap = minimum - distance;
      const firstShare = first.dragging ? 0 : second.dragging ? 1 : .5;
      const secondShare = second.dragging ? 0 : first.dragging ? 1 : .5;
      if (firstShare > 0) first.position.addScaledVector(normal, -overlap * firstShare);
      if (secondShare > 0) second.position.addScaledVector(normal, overlap * secondShare);
      const approach = second.velocity.clone().sub(first.velocity).dot(normal);
      if (approach < 0) {
        if (!first.dragging) first.velocity.addScaledVector(normal, approach * .35);
        if (!second.dragging) second.velocity.addScaledVector(normal, -approach * .35);
      }
      moving = true;
    }
  }
  for (const link of links) {
    const first = byId.get(link.from);
    const second = byId.get(link.to);
    if (!first || !second) continue;
    const offset = second.position.clone().sub(first.position);
    const distance = Math.max(offset.length(), 1e-6);
    const normal = distance > 1e-6 ? offset.multiplyScalar(1 / distance) : fallbackCollisionNormal(first.id, second.id);
    const displacement = distance - (link.idealDistance ?? settings.idealDistance);
    const spring = displacement * .9;
    if (!first.dragging) forces.get(first.id)!.addScaledVector(normal, spring);
    if (!second.dragging) forces.get(second.id)!.addScaledVector(normal, -spring);
  }
  for (const body of bodies) {
    if (body.dragging) continue;
    body.velocity.addScaledVector(forces.get(body.id)!, delta);
    body.velocity.multiplyScalar(damping).clampLength(0, 8);
    body.position.addScaledVector(body.velocity, delta);
    if (body.velocity.lengthSq() > SETTLED_SPEED_SQ) moving = true;
    else body.velocity.set(0, 0, 0);
  }
  return moving;
}

export function applyRouteFilter(layers: RouteLayers, filter: TopologyGraphProps["filter"], invalidate?: () => void, visibility: RouteVisibility = { showDispatch: true, showCallbacks: true }): void {
  layers.dispatch.forEach((route) => {
    const supportsCallback = route.userData.supportsCallback === true;
    route.visible = filter === "dispatch"
      ? visibility.showDispatch
      : filter === "callbacks"
        ? visibility.showCallbacks && supportsCallback
        : visibility.showDispatch || (visibility.showCallbacks && supportsCallback);
  });
  layers.callbacks.forEach((route) => { route.visible = visibility.showCallbacks && filter !== "dispatch"; });
  invalidate?.();
}

export function applyGraphSettings(runtime: GraphSettingsTarget, settings: TopologySettings, invalidate?: () => void): void {
  runtime.controls.autoRotate = settings.autoRotate && !runtime.reducedMotion;
  runtime.controls.autoRotateSpeed = settings.rotationSpeed;
  runtime.depthField.visible = settings.showDepthField;
  runtime.halos.forEach((halo) => { halo.visible = settings.showHalos; });
  runtime.scene.fog = settings.useFog ? runtime.distanceFog : null;
  invalidate?.();
}

function workerLifecycle(worker: Worker): SceneNode["lifecycle"] {
  if (worker.slot_state !== "assigned") return worker.slot_state === "clear" ? "available" : "unavailable";
  return worker.agent_lifecycle ?? "unavailable";
}

export type AgentVisualState = "intervention" | "recovery" | "active" | "handoff" | "recent" | "idle";

export const HANDOFF_TRANSPORT_STATES: ReadonlySet<string> = new Set(["reserved", "prepared", "sending"]);

export const AGENT_STATE_COLOURS: Record<AgentVisualState, number> = {
  intervention: 0xd94f4f,
  recovery: 0xe88a1e,
  active: 0x3fb96c,
  handoff: 0x6fb7e6,
  recent: 0xffffff,
  idle: 0x756d60,
};

export function isHandedOffTransport(state: unknown): boolean {
  return typeof state === "string" && HANDOFF_TRANSPORT_STATES.has(state);
}

export function isAssignedHandedOffWorker(worker: Worker): boolean {
  if (worker.slot_state !== "assigned") return false;
  const transportState = (worker as { transport?: { state?: unknown } }).transport?.state;
  return isHandedOffTransport(transportState);
}

function snapshotRecentItems(snapshot: CockpitSnapshot): unknown[] | null {
  const recent = (snapshot as unknown as { recent_turns?: { status?: unknown; items?: unknown } }).recent_turns;
  if (!recent || recent.status !== "available") return null;
  if (!Array.isArray(recent.items) || recent.items.length === 0) return null;
  return recent.items as unknown[];
}

export function isRecentWorker(worker: Worker): boolean {
  if (worker.slot_state === "assigned") return false;
  return worker.recent_turns.status === "available" && worker.recent_turns.items.length > 0;
}

export function hasHandedOffWorker(workers: Worker[]): boolean {
  return workers.some(isAssignedHandedOffWorker);
}

export function agentVisualState(worker: Worker, snapshot: CockpitSnapshot): AgentVisualState {
  const attention = attentionGroups(snapshot);
  const matches = (item: { work_id?: string | null; target_id?: string | null }) =>
    (worker.work_id !== null && item.work_id === worker.work_id)
    || (worker.recovery.target_id !== null && item.target_id === worker.recovery.target_id);
  if (attention.operator.items.some(matches)) return "intervention";
  const durableRecovery = worker.recovery.status === "available"
    && worker.recovery.target_id !== null
    && !["active", "completed"].includes(worker.recovery.phase);
  if (attention.automatic.items.some(matches) || durableRecovery) return "recovery";
  if (worker.slot_state === "assigned") {
    if (isAssignedHandedOffWorker(worker)) return "handoff";
    return "active";
  }
  if (isRecentWorker(worker)) return "recent";
  return "idle";
}

export function infraVisualState(kind: "source" | "controller", snapshot: CockpitSnapshot, workers: Worker[]): AgentVisualState {
  const attention = attentionGroups(snapshot);
  const matchesWorker = (item: { work_id?: string | null; target_id?: string | null }) =>
    workers.some((worker) =>
      (worker.work_id !== null && item.work_id === worker.work_id)
      || (worker.recovery.target_id !== null && item.target_id === worker.recovery.target_id));
  if (kind === "source") {
    if (attention.delivery.items.length > 0) return "recovery";
    if (snapshot.availability.status !== "unavailable") return "active";
    if (hasHandedOffWorker(workers)) return "handoff";
    if (snapshotRecentItems(snapshot) !== null) return "recent";
    return "idle";
  }
  if (attention.operator.items.some((item) => item.scope === "controller")) return "intervention";
  if (snapshot.availability.status === "unavailable") return "intervention";
  if (snapshot.availability.status === "degraded" || attention.automatic.items.some((item) => !matchesWorker(item))) return "recovery";
  if (snapshot.availability.status === "available") return "active";
  if (hasHandedOffWorker(workers)) return "handoff";
  if (snapshotRecentItems(snapshot) !== null) return "recent";
  return "idle";
}

export type LaneId = "tensorhost" | "homelab" | "personal" | "control" | "hands-off";

interface LaneInfo {
  id: LaneId;
  title: string;
  center: THREE.Vector3;
}

const LANE_ORDER: LaneInfo[] = [
  { id: "tensorhost", title: "TENSORHOST", center: new THREE.Vector3(2.9, 2.35, -1.85) },
  { id: "homelab", title: "HOME LAB", center: new THREE.Vector3(2.9, 2.35, 1.85) },
  { id: "personal", title: "PERSONAL", center: new THREE.Vector3(3.1, 0, 0) },
  { id: "control", title: "CONTROL", center: new THREE.Vector3(2.9, -2.35, -1.85) },
  { id: "hands-off", title: "HANDS-OFF", center: new THREE.Vector3(2.9, -2.35, 1.85) },
];
const SOURCE_POOL = { id: "codex" as const, title: "CODEX", center: new THREE.Vector3(-5.6, 0, 0) };
type PoolId = LaneId | typeof SOURCE_POOL.id;
const POOL_ORDER = [SOURCE_POOL, ...LANE_ORDER] as const;

export function poolRadiusForCount(count: number): number {
  if (!Number.isFinite(count) || count <= 0) return 0;
  if (count === 1) return .74;
  return Math.min(2.55, .74 + Math.cbrt(count - 1) * .55);
}

export type PoolFieldFit = {
  center: THREE.Vector3;
  scale: THREE.Vector3;
};

export function fitPoolFieldToMembers(members: readonly PhysicsBody[]): PoolFieldFit | null {
  if (members.length === 0) return null;
  const POOL_FIELD_PADDING = 0.35;
  const POOL_FIELD_MIN = 0.74;
  const POOL_FIELD_MAX = 12;
  const clampExtent = (extent: number): number => {
    return Math.min(POOL_FIELD_MAX, Math.max(POOL_FIELD_MIN, extent + POOL_FIELD_PADDING));
  };
  if (members.length === 1) {
    const center = members[0].position.clone();
    const extent = clampExtent(members[0].radius);
    return { center, scale: new THREE.Vector3(extent, extent, extent) };
  }
  const points = members.map((member) => member.position);
  const center = new THREE.Vector3(0, 0, 0);
  for (const point of points) center.add(point);
  center.divideScalar(points.length);
  let extentX = 0;
  let extentY = 0;
  let extentZ = 0;
  for (let i = 0; i < points.length; i += 1) {
    const radius = members[i].radius;
    extentX = Math.max(extentX, Math.abs(points[i].x - center.x) + radius);
    extentY = Math.max(extentY, Math.abs(points[i].y - center.y) + radius);
    extentZ = Math.max(extentZ, Math.abs(points[i].z - center.z) + radius);
  }
  return {
    center,
    scale: new THREE.Vector3(clampExtent(extentX), clampExtent(extentY), clampExtent(extentZ)),
  };
}
function hashString(value: string): number {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function laneForWorker(worker: Worker): LaneId {
  return worker.lane as LaneId;
}

export function exactVisibleSourceRouteId(worker: Worker, visibleSourceIds: ReadonlySet<string>): string | null {
  const sourceId = worker.source_id ?? null;
  return sourceId !== null && visibleSourceIds.has(sourceId) ? sourceId : null;
}

function sceneNodes(workers: Worker[], sourceThreads: SourceThread[], snapshot: CockpitSnapshot): SceneNode[] {
  const result: SceneNode[] = [];
  sourceThreads.slice(0, 24).forEach((thread, index) => {
    const hash = hashString(thread.id);
    const angle = index * 2.399963229728653 + ((hash % 360) * Math.PI / 180);
    const radius = index === 0 ? 0 : .58 + Math.min(1.2, Math.sqrt(index) * .24);
    result.push({
      id: `source:${thread.id}`,
      label: thread.name?.trim() || `CODEX ${index + 1}`,
      meta: `${thread.runtimeStatus.toUpperCase()} · ${thread.source}`,
      kind: "source",
      lifecycle: thread.runtimeStatus === "system_error" ? "unavailable" : "available",
      position: new THREE.Vector3(
        SOURCE_POOL.center.x + (((hash >> 4) % 100) / 100 - .5) * .55,
        SOURCE_POOL.center.y + Math.cos(angle) * radius,
        SOURCE_POOL.center.z + Math.sin(angle) * radius,
      ),
      worker: null,
      sourceThread: thread,
      lane: null,
      pool: "codex",
      routeSourceId: null,
      subagentState: null,
    });
  });
  const grouped = new Map<LaneId, Worker[]>();
  for (const lane of LANE_ORDER) grouped.set(lane.id, []);
  for (const worker of workers) {
    const lane = laneForWorker(worker);
    grouped.get(lane)?.push(worker);
  }
  for (const lane of LANE_ORDER) {
    const group = (grouped.get(lane.id) ?? []).slice().sort((a, b) => a.slot_id.localeCompare(b.slot_id));
    group.forEach((worker, index) => {
      const hash = hashString(worker.slot_id);
      const golden = 2.399963229728653;
      const angle = ((hash % 1000) / 1000) * Math.PI * 2 + index * golden;
      const ring = Math.floor(index / 5);
      const rawRadius = index === 0 ? 0 : 0.58 + ring * 0.42 + ((hash >> 7) % 100) / 100 * 0.16;
      const radius = Math.min(rawRadius, 1.25);
      const jitterX = (((hash >> 3) % 100) / 100 - 0.5) * 0.55;
      const parity = index % 2 === 0 ? 0.06 : -0.06;
      const x = lane.center.x + jitterX + parity;
      const y = lane.center.y + Math.cos(angle) * radius;
      const z = lane.center.z + Math.sin(angle) * radius;
      result.push({
        id: worker.slot_id,
        label: worker.slot_id.toUpperCase(),
        meta: `${workerLifecycle(worker).toUpperCase()} · ${worker.slot_state === "assigned" ? shortIdentity(worker.work_id) : formatReason(worker.transport.state)}`,
        kind: "worker",
        lifecycle: workerLifecycle(worker),
        position: new THREE.Vector3(x, y, z),
        worker,
        sourceThread: null,
        lane: lane.id,
        pool: lane.id,
        routeSourceId: null,
        subagentState: null,
      });
    });
  }
  for (const [index, subagent] of (snapshot.worker_graph.subagents ?? []).entries()) {
    const parent = result.find((node) => node.kind === "worker" && node.id === subagent.parent_slot_id);
    if (!parent?.worker) continue;
    const hash = hashString(subagent.id);
    const angle = index * 2.399963229728653 + ((hash % 360) * Math.PI / 180);
    result.push({
      id: `subagent:${subagent.id}`,
      label: `CHILD ${index + 1}`,
      meta: `${subagent.state.toUpperCase()} · ${shortIdentity(subagent.id)}`,
      kind: "subagent",
      lifecycle: "disposable",
      position: parent.position.clone().add(new THREE.Vector3(.35, Math.cos(angle) * .72, Math.sin(angle) * .72)),
      worker: parent.worker,
      sourceThread: null,
      lane: parent.lane,
      pool: parent.pool,
      routeSourceId: null,
      subagentState: subagent.state,
    });
  }
  const sourceById = new Map(result.filter((node) => node.kind === "source").map((node) => [node.sourceThread!.id, node]));
  const visibleSourceIds = new Set(sourceById.keys());
  for (const workerNode of result.filter((node) => node.kind === "worker" && node.worker?.slot_state === "assigned")) {
    const worker = workerNode.worker!;
    const routedSourceId = exactVisibleSourceRouteId(worker, visibleSourceIds);
    const sourceNode = routedSourceId ? sourceById.get(routedSourceId) ?? null : null;
    const sourcePosition = sourceNode?.position ?? SOURCE_POOL.center;
    result.push({
      id: `fugue-proxy:${worker.slot_id}`,
      label: "FUGUE",
      meta: "ROUTE",
      kind: "proxy",
      lifecycle: workerLifecycle(worker),
      position: sourcePosition.clone().lerp(workerNode.position, .5),
      worker,
      sourceThread: null,
      lane: workerNode.lane,
      pool: workerNode.pool,
      routeSourceId: sourceNode?.id ?? null,
      subagentState: null,
    });
  }
  return result;
}

export function nodeColour(node: SceneNode, snapshot: CockpitSnapshot, workers: Worker[]): number {
  if (node.kind === "subagent") {
    if (node.subagentState === "terminal") return AGENT_STATE_COLOURS.idle;
    if (node.worker) {
      const status = agentVisualState(node.worker, snapshot);
      if (status === "intervention" || status === "recovery") return AGENT_STATE_COLOURS[status];
    }
    return node.subagentState === "waiting" ? AGENT_STATE_COLOURS.active : AGENT_STATE_COLOURS.idle;
  }
  if (node.kind === "source" && node.sourceThread) {
    if (node.sourceThread.runtimeStatus === "system_error") return AGENT_STATE_COLOURS.intervention;
    return AGENT_STATE_COLOURS.recent;
  }
  if (node.kind === "source") {
    const status = infraVisualState("source", snapshot, workers);
    return AGENT_STATE_COLOURS[status];
  }
  if (node.worker) {
    const status = agentVisualState(node.worker, snapshot);
    if (node.kind === "worker" && status === "idle") return AGENT_STATE_COLOURS.recent;
    return AGENT_STATE_COLOURS[status];
  }
  if (node.lifecycle === "persistent") return 0xf3aa19;
  if (node.lifecycle === "disposable") return 0xe8e2d7;
  return 0x756d60;
}

function line(scene: THREE.Scene, start: THREE.Vector3, end: THREE.Vector3, colour: number, opacity: number, curve = .4): THREE.Line {
  const middle = start.clone().lerp(end, .5);
  middle.z += curve;
  const points = new THREE.QuadraticBezierCurve3(start, middle, end).getPoints(28);
  const geometry = new THREE.BufferGeometry().setFromPoints(points);
  const material = new THREE.LineBasicMaterial({ color: colour, transparent: true, opacity });
  const route = new THREE.Line(geometry, material);
  route.userData.baseOpacity = opacity;
  scene.add(route);
  return route;
}

function restoreEdgeOpacity(layers: RouteLayers): void {
  for (const routes of [layers.dispatch, layers.callbacks]) {
    for (const route of routes) {
      const base = typeof (route.userData as { baseOpacity?: unknown }).baseOpacity === "number"
        ? (route.userData as { baseOpacity: number }).baseOpacity
        : null;
      if (base === null) continue;
      const material = (route as THREE.Line).material as THREE.LineBasicMaterial;
      material.opacity = base;
    }
  }
}

export default function TopologyGraph({ snapshot, workers, selectedSlot, filter, settings = DEFAULT_TOPOLOGY_SETTINGS, onSelect, sourceThreads = [], onSelectSource, selectedSourceId = null, sourceActivity = null }: TopologyGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const labelRefs = useRef(new Map<string, HTMLButtonElement>());
  const laneLabelRefs = useRef(new Map<string, HTMLDivElement>());
  const routeLayersRef = useRef<RouteLayers>({ dispatch: [], callbacks: [] });
  const runtimeRef = useRef<GraphRuntime | null>(null);
  const renderRef = useRef<(() => void) | null>(null);
  const startAnimationRef = useRef<(() => void) | null>(null);
  const edgePulseRef = useRef(0);
  const edgePulseKeyRef = useRef<string | null>(null);
  const lastEventSequenceRef = useRef<number | null>(null);
  const meshByIdRef = useRef(new Map<string, THREE.Mesh>());
  const haloByIdRef = useRef(new Map<string, THREE.Mesh>());
  const workerByMeshRef = useRef(new Map<THREE.Object3D, Worker>());
  const nodeByIdRef = useRef(new Map<string, SceneNode>());
  const sharedGeometriesRef = useRef<SharedGeometries | null>(null);
  const poolMeshesRef = useRef(new Map<PoolId, THREE.Mesh>());
  const outerPoolMeshRef = useRef<THREE.Mesh | null>(null);
  const laneAnchorsRef = useRef(new Map<string, THREE.Vector3>());
  const physicsBodiesRef = useRef(new Map<string, PhysicsBody>());
  const onSelectRef = useRef(onSelect);
  const onSelectSourceRef = useRef(onSelectSource);
  const filterRef = useRef(filter);
  const settingsRef = useRef(settings);
  const selectedSlotRef = useRef(selectedSlot);
  const selectedSourceIdRef = useRef(selectedSourceId);
  const selectedGraphNodeIdRef = useRef<string | null>(null);
  onSelectRef.current = onSelect;
  onSelectSourceRef.current = onSelectSource;
  filterRef.current = filter;
  settingsRef.current = settings;
  selectedSlotRef.current = selectedSlot;
  selectedSourceIdRef.current = selectedSourceId;
  const [webglUnavailable, setWebglUnavailable] = useState(false);
  const [selectedGraphNodeId, setSelectedGraphNodeId] = useState<string | null>(null);
  const nodes = useMemo(() => sceneNodes(workers, sourceThreads, snapshot), [snapshot, sourceThreads, workers]);
  selectedGraphNodeIdRef.current = selectedGraphNodeId;
  const selectSceneNode = (node: SceneNode) => {
    setSelectedGraphNodeId(node.id);
    if (node.worker) onSelectRef.current(node.worker);
    else if (node.sourceThread) onSelectSourceRef.current(node.sourceThread);
  };
  useEffect(() => {
    setSelectedGraphNodeId((current) => {
      const currentNode = current ? nodes.find((node) => node.id === current) : null;
      if (selectedSourceId) {
        return currentNode?.sourceThread?.id === selectedSourceId ? current : `source:${selectedSourceId}`;
      }
      if (selectedSlot) {
        return currentNode?.worker?.slot_id === selectedSlot ? current : selectedSlot;
      }
      return null;
    });
  }, [nodes, selectedSlot, selectedSourceId]);
  const laneCounts = useMemo(() => {
    const counts = new Map<PoolId, number>();
    for (const lane of POOL_ORDER) counts.set(lane.id, 0);
    counts.set("codex", Math.min(sourceThreads.length, 24));
    for (const worker of workers) {
      const lane = laneForWorker(worker);
      counts.set(lane, (counts.get(lane) ?? 0) + 1);
    }
    return counts;
  }, [sourceThreads.length, workers]);
  const eventSequence = snapshot.snapshot_version.event_sequence ?? null;
  useEffect(() => {
    if (typeof eventSequence !== "number") return;
    if (lastEventSequenceRef.current === null) {
      lastEventSequenceRef.current = eventSequence;
      return;
    }
    if (eventSequence > lastEventSequenceRef.current) {
      lastEventSequenceRef.current = eventSequence;
      edgePulseRef.current = 1;
      const activity = snapshot.recent_activity?.items.find((item) => item.sequence === eventSequence);
      if (activity?.origin.startsWith("source:") && workers.some((worker) => worker.slot_id === activity.destination)) {
        edgePulseKeyRef.current = `dispatch:${activity.origin}->fugue-proxy:${activity.destination}`;
      } else if (activity?.destination.startsWith("source:") && workers.some((worker) => worker.slot_id === activity.origin)) {
        edgePulseKeyRef.current = `dispatch:fugue-proxy:${activity.origin}->${activity.origin}`;
      } else {
        edgePulseKeyRef.current = null;
      }
      renderRef.current?.();
    } else if (eventSequence !== lastEventSequenceRef.current) {
      lastEventSequenceRef.current = eventSequence;
    }
  }, [eventSequence, snapshot, workers]);
  useEffect(() => {
    if (!sourceActivity) return;
    const worker = workers.find((item) => item.source_id === sourceActivity.threadId) ?? null;
    edgePulseKeyRef.current = worker
      ? `dispatch:source:${sourceActivity.threadId}->fugue-proxy:${worker.slot_id}`
      : null;
    edgePulseRef.current = 1;
    startAnimationRef.current?.();
    renderRef.current?.();
  }, [sourceActivity?.sequence, workers]);
  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container || !("WebGLRenderingContext" in window)) {
      setWebglUnavailable(true);
      return;
    }
    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true, powerPreference: "high-performance" });
    } catch {
      setWebglUnavailable(true);
      return;
    }
    setWebglUnavailable(false);
    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    const scene = new THREE.Scene();
    const distanceFog = new THREE.Fog(0x070706, 13, 31);
    scene.fog = distanceFog;
    const camera = new THREE.PerspectiveCamera(42, 1, .1, 100);
    camera.position.set(10.5, 6.2, 13.5);
    const controls = new OrbitControls(camera, renderer.domElement);
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    controls.target.set(-.2, 0, 0);
    controls.enableDamping = !reducedMotion;
    controls.dampingFactor = .055;
    controls.enablePan = true;
    controls.enableRotate = true;
    controls.enableZoom = true;
    controls.zoomToCursor = true;
    controls.minDistance = 5;
    controls.maxDistance = 32;
    controls.mouseButtons = { LEFT: THREE.MOUSE.ROTATE, MIDDLE: THREE.MOUSE.DOLLY, RIGHT: THREE.MOUSE.PAN };
    controls.touches = { ONE: THREE.TOUCH.ROTATE, TWO: THREE.TOUCH.DOLLY_PAN };
    controls.autoRotate = DEFAULT_TOPOLOGY_SETTINGS.autoRotate && !reducedMotion;
    controls.autoRotateSpeed = DEFAULT_TOPOLOGY_SETTINGS.rotationSpeed;
    controls.saveState();
    controls.update();
    const hemisphere = new THREE.HemisphereLight(0xf5f1e7, 0x050504, 2.15);
    const keyLight = new THREE.DirectionalLight(0xffffff, 2.8);
    keyLight.position.set(7, 9, 10);
    const amberRim = new THREE.DirectionalLight(0xf3aa19, 1.7);
    amberRim.position.set(-8, 2, -7);
    scene.add(hemisphere, keyLight, amberRim);
    const depthPositions = new Float32Array(90 * 3);
    let depthSeed = 0x5f3759df;
    const nextDepth = () => {
      depthSeed = (Math.imul(depthSeed, 1664525) + 1013904223) >>> 0;
      return depthSeed / 0x100000000;
    };
    for (let index = 0; index < 90; index += 1) {
      depthPositions[index * 3] = nextDepth() * 22 - 11;
      depthPositions[index * 3 + 1] = nextDepth() * 13 - 6.5;
      depthPositions[index * 3 + 2] = nextDepth() * 20 - 10;
    }
    const depthGeometry = new THREE.BufferGeometry();
    depthGeometry.setAttribute("position", new THREE.BufferAttribute(depthPositions, 3));
    const depthMaterial = new THREE.PointsMaterial({ color: 0x6b4a18, size: .03, transparent: true, opacity: .24, depthWrite: false, sizeAttenuation: true });
    const depthField = new THREE.Points(depthGeometry, depthMaterial);
    scene.add(depthField);
    const poolGeometry = new THREE.SphereGeometry(1, 30, 20);
    const poolMeshes = new Map<PoolId, THREE.Mesh>();
    const laneAnchors = new Map<string, THREE.Vector3>();
    for (const lane of POOL_ORDER) {
      const material = new THREE.MeshBasicMaterial({
        color: lane.id === "codex" ? 0xf5f1e7 : 0xf3aa19,
        transparent: true,
        opacity: lane.id === "codex" ? .032 : .045,
        depthWrite: false,
        side: THREE.BackSide,
        blending: THREE.AdditiveBlending,
      });
      const mesh = new THREE.Mesh(poolGeometry, material);
      mesh.renderOrder = -2;
      mesh.visible = false;
      scene.add(mesh);
      poolMeshes.set(lane.id, mesh);
    }
    const outerPool = new THREE.Mesh(poolGeometry, new THREE.MeshBasicMaterial({
      color: 0xf3aa19,
      transparent: true,
      opacity: .018,
      depthWrite: false,
      side: THREE.BackSide,
      blending: THREE.AdditiveBlending,
    }));
    outerPool.renderOrder = -3;
    outerPool.visible = false;
    scene.add(outerPool);
    poolMeshesRef.current = poolMeshes;
    outerPoolMeshRef.current = outerPool;
    laneAnchorsRef.current = laneAnchors;
    const workerGeometry = new THREE.BoxGeometry(.46, .46, .46);
    const proxyGeometry = new THREE.CylinderGeometry(.13, .13, .34, 12, 1, false);
    const sourceGeometry = new THREE.TetrahedronGeometry(.52, 0);
    const subagentGeometry = new THREE.BoxGeometry(.28, .28, .28);
    const haloGeometry = new THREE.BoxGeometry(.67, .67, .67);
    sharedGeometriesRef.current = { workerGeometry, proxyGeometry, sourceGeometry, subagentGeometry, haloGeometry };
    meshByIdRef.current.clear();
    haloByIdRef.current.clear();
    workerByMeshRef.current.clear();
    nodeByIdRef.current.clear();
    routeLayersRef.current = { dispatch: [], callbacks: [] };
    const halos: THREE.Mesh[] = [];
    const runtime: GraphRuntime = { controls, depthField, distanceFog, halos, reducedMotion, scene };
    runtimeRef.current = runtime;
    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();
    const dragPlane = new THREE.Plane();
    const dragOffset = new THREE.Vector3();
    const planeHit = new THREE.Vector3();
    const cameraDir = new THREE.Vector3();
    let pendingNodeId: string | null = null;
    let pendingPointerId: number | null = null;
    let downX = 0;
    let downY = 0;
    let nodeDragging = false;
    let lastDragPosition = new THREE.Vector3();
    let lastDragTime = 0;
    const setPointerFromEvent = (event: PointerEvent) => {
      const bounds = renderer.domElement.getBoundingClientRect();
      pointer.set(((event.clientX - bounds.left) / bounds.width) * 2 - 1, -((event.clientY - bounds.top) / bounds.height) * 2 + 1);
      raycaster.setFromCamera(pointer, camera);
    };
    const updateRoutesForNode = (nodeId: string) => {
      const layers = routeLayersRef.current;
      for (const layerName of ["dispatch", "callbacks"] as const) {
        for (const route of layers[layerName]) {
          const edgeKey = (route.userData as { edgeKey?: unknown }).edgeKey;
          if (typeof edgeKey !== "string") continue;
          const arrow = edgeKey.slice(edgeKey.indexOf(":") + 1).split("->");
          if (arrow.length !== 2) continue;
          const startId = arrow[0];
          const endId = arrow[1];
          if (startId !== nodeId && endId !== nodeId) continue;
          const startMesh = meshByIdRef.current.get(startId);
          const endMesh = meshByIdRef.current.get(endId);
          if (!startMesh || !endMesh) continue;
          const userData = route.userData as { curve?: number; sx?: number; sy?: number; sz?: number; ex?: number; ey?: number; ez?: number };
          const curve = typeof userData.curve === "number" ? userData.curve : .4;
          const start = startMesh.position;
          const end = endMesh.position;
          const middle = start.clone().lerp(end, .5);
          middle.z += curve;
          const points = new THREE.QuadraticBezierCurve3(start, middle, end).getPoints(28);
          (route as THREE.Line).geometry.setFromPoints(points);
          userData.sx = start.x;
          userData.sy = start.y;
          userData.sz = start.z;
          userData.ex = end.x;
          userData.ey = end.y;
          userData.ez = end.z;
        }
      }
    };
    const pointerDownCapture = (event: PointerEvent) => {
      if (event.button !== 0) return;
      setPointerFromEvent(event);
      const hit = raycaster.intersectObjects([...meshByIdRef.current.values()], false)[0];
      if (!hit) return;
      const nodeId = (hit.object.userData as { nodeId?: unknown }).nodeId;
      if (typeof nodeId !== "string") return;
      event.stopImmediatePropagation();
      event.preventDefault();
      pendingNodeId = nodeId;
      pendingPointerId = event.pointerId;
      downX = event.clientX;
      downY = event.clientY;
      nodeDragging = false;
      camera.getWorldDirection(cameraDir);
      dragPlane.setFromNormalAndCoplanarPoint(cameraDir, hit.point);
      const mesh = meshByIdRef.current.get(nodeId);
      if (mesh) dragOffset.copy(mesh.position).sub(hit.point);
      else dragOffset.set(0, 0, 0);
      const body = physicsBodiesRef.current.get(nodeId);
      if (body) {
        body.dragging = true;
        body.velocity.set(0, 0, 0);
        lastDragPosition.copy(body.position);
        lastDragTime = performance.now();
      }
      controls.enabled = false;
      renderer.domElement.style.cursor = "grabbing";
      try { renderer.domElement.setPointerCapture(event.pointerId); } catch { /* noop */ }
    };
    const pointerMove = (event: PointerEvent) => {
      if (pendingNodeId !== null && (pendingPointerId === null || event.pointerId === pendingPointerId)) {
        const dist = Math.hypot(event.clientX - downX, event.clientY - downY);
        if (!nodeDragging && dist > 5) nodeDragging = true;
        if (nodeDragging) {
          setPointerFromEvent(event);
          const mesh = meshByIdRef.current.get(pendingNodeId);
          const halo = haloByIdRef.current.get(pendingNodeId);
          if (mesh && raycaster.ray.intersectPlane(dragPlane, planeHit)) {
            planeHit.add(dragOffset);
            mesh.position.copy(planeHit);
            const body = physicsBodiesRef.current.get(pendingNodeId);
            if (body) {
              const now = performance.now();
              const elapsed = Math.max((now - lastDragTime) / 1000, 1 / 240);
              body.velocity.copy(planeHit).sub(lastDragPosition).multiplyScalar(1 / elapsed).clampLength(0, 8);
              body.position.copy(planeHit);
              body.dragging = true;
              lastDragPosition.copy(planeHit);
              lastDragTime = now;
            }
            if (halo) {
              halo.position.copy(planeHit);
              halo.rotation.copy(mesh.rotation);
            }
            updateRoutesForNode(pendingNodeId);
            renderRef.current?.();
          }
        }
        return;
      }
      if (event.buttons === 0 && event.pointerType === "mouse" && event.target === renderer.domElement) {
        setPointerFromEvent(event);
        const hit = raycaster.intersectObjects([...meshByIdRef.current.values()], false)[0];
        renderer.domElement.style.cursor = hit ? "grab" : "";
      }
    };
    const pointerUp = (event: PointerEvent) => {
      if (pendingNodeId !== null && (pendingPointerId === null || event.pointerId === pendingPointerId)) {
        const wasDragging = nodeDragging;
        const nodeId = pendingNodeId;
        const body = physicsBodiesRef.current.get(nodeId);
        if (body) body.dragging = false;
        pendingNodeId = null;
        pendingPointerId = null;
        nodeDragging = false;
        controls.enabled = true;
        controls.mouseButtons.LEFT = THREE.MOUSE.ROTATE;
        renderer.domElement.style.cursor = "";
        try { if (renderer.domElement.hasPointerCapture(event.pointerId)) renderer.domElement.releasePointerCapture(event.pointerId); } catch { /* noop */ }
        if (!wasDragging) {
          const node = nodeByIdRef.current.get(nodeId);
          if (node) selectSceneNode(node);
        } else {
          startAnimationRef.current?.();
        }
        return;
      }
      if (controls.mouseButtons.LEFT !== THREE.MOUSE.ROTATE) controls.mouseButtons.LEFT = THREE.MOUSE.ROTATE;
    };
    const pointerCancel = (event: PointerEvent) => {
      if (pendingNodeId !== null) {
        const body = physicsBodiesRef.current.get(pendingNodeId);
        if (body) { body.dragging = false; body.velocity.set(0, 0, 0); }
        pendingNodeId = null;
        pendingPointerId = null;
        nodeDragging = false;
        controls.enabled = true;
        controls.mouseButtons.LEFT = THREE.MOUSE.ROTATE;
        renderer.domElement.style.cursor = "";
        try { if (renderer.domElement.hasPointerCapture(event.pointerId)) renderer.domElement.releasePointerCapture(event.pointerId); } catch { /* noop */ }
        renderRef.current?.();
      } else if (controls.mouseButtons.LEFT !== THREE.MOUSE.ROTATE) {
        controls.mouseButtons.LEFT = THREE.MOUSE.ROTATE;
      }
    };
    renderer.domElement.addEventListener("pointerdown", pointerDownCapture, true);
    window.addEventListener("pointermove", pointerMove);
    window.addEventListener("pointerup", pointerUp);
    window.addEventListener("pointercancel", pointerCancel);
    const projected = new THREE.Vector3();
    let lastLabelPaint = 0;
    const getSelectedNodeId = (): string | null => selectedGraphNodeIdRef.current
      ?? (selectedSourceIdRef.current ? `source:${selectedSourceIdRef.current}` : selectedSlotRef.current);
    const draw = (delta = 0) => {
      if (!reducedMotion) controls.update(delta);
      let physicsMoving = false;
      const bodies = [...physicsBodiesRef.current.values()];
      if (reducedMotion) {
        for (const body of bodies) if (!body.dragging) { body.position.copy(body.target); body.velocity.set(0, 0, 0); }
      } else if (delta > 0) {
        const links: PhysicsLink[] = [];
        for (const routes of [routeLayersRef.current.dispatch, routeLayersRef.current.callbacks]) {
          for (const route of routes) {
            const edgeKey = (route.userData as { edgeKey?: unknown }).edgeKey;
            if (typeof edgeKey !== "string") continue;
            const arrow = edgeKey.slice(edgeKey.indexOf(":") + 1).split("->");
            if (arrow.length === 2) links.push({ from: arrow[0], to: arrow[1] });
          }
        }
        const current = settingsRef.current;
        physicsMoving = stepGraphPhysics(bodies, delta, links, {
          idealDistance: current.galaxyIdealDistance,
          cohesion: current.galaxyCohesion,
          repulsion: current.galaxyRepulsion,
          gravity: current.galaxyGravity,
          damping: current.galaxyDamping,
        });
      }
      for (const body of bodies) {
        const mesh = meshByIdRef.current.get(body.id);
        if (!mesh || mesh.position.equals(body.position)) continue;
        mesh.position.copy(body.position);
        const halo = haloByIdRef.current.get(body.id);
        if (halo) halo.position.copy(body.position);
        updateRoutesForNode(body.id);
      }
      const membersByPool = new Map<PoolId, PhysicsBody[]>();
      for (const body of bodies) {
        if (!body.pool) continue;
        const members = membersByPool.get(body.pool as PoolId) ?? [];
        members.push(body);
        membersByPool.set(body.pool as PoolId, members);
      }
      for (const lane of POOL_ORDER) {
        const mesh = poolMeshesRef.current.get(lane.id);
        const fit = fitPoolFieldToMembers(membersByPool.get(lane.id) ?? []);
        if (mesh && fit) {
          mesh.position.copy(fit.center);
          mesh.scale.copy(fit.scale);
          mesh.visible = true;
          laneAnchorsRef.current.set(
            lane.id,
            fit.center.clone().add(new THREE.Vector3(0, fit.scale.y + .24, 0)),
          );
        } else {
          if (mesh) mesh.visible = false;
          laneAnchorsRef.current.delete(lane.id);
        }
      }
      const opencodeBodies = bodies.filter((body) => body.pool && body.pool !== "codex");
      const opencodeFit = fitPoolFieldToMembers(opencodeBodies);
      if (outerPoolMeshRef.current && opencodeFit) {
        outerPoolMeshRef.current.position.copy(opencodeFit.center);
        outerPoolMeshRef.current.scale.copy(opencodeFit.scale).addScalar(.65);
        outerPoolMeshRef.current.visible = true;
        laneAnchorsRef.current.set("opencode", opencodeFit.center.clone().add(new THREE.Vector3(0, opencodeFit.scale.y + 1.01, 0)));
      } else {
        if (outerPoolMeshRef.current) outerPoolMeshRef.current.visible = false;
        laneAnchorsRef.current.delete("opencode");
      }
      const layers = routeLayersRef.current;
      const pulse = edgePulseRef.current;
      if (pulse > 0) {
        if (reducedMotion) {
          for (const routes of [layers.dispatch, layers.callbacks]) {
            for (const route of routes) {
              if (edgePulseKeyRef.current && route.userData.edgeKey !== edgePulseKeyRef.current) continue;
              const base = typeof (route.userData as { baseOpacity?: unknown }).baseOpacity === "number"
                ? (route.userData as { baseOpacity: number }).baseOpacity
                : null;
              if (base === null) continue;
              const material = (route as THREE.Line).material as THREE.LineBasicMaterial;
              material.opacity = Math.min(1, base + .18);
            }
          }
          edgePulseRef.current = 0;
          edgePulseKeyRef.current = null;
        } else {
          for (const routes of [layers.dispatch, layers.callbacks]) {
            for (const route of routes) {
              if (edgePulseKeyRef.current && route.userData.edgeKey !== edgePulseKeyRef.current) continue;
              const base = typeof (route.userData as { baseOpacity?: unknown }).baseOpacity === "number"
                ? (route.userData as { baseOpacity: number }).baseOpacity
                : null;
              if (base === null) continue;
              const material = (route as THREE.Line).material as THREE.LineBasicMaterial;
              material.opacity = Math.min(1, base + pulse * .65);
            }
          }
          const decay = Math.pow(.06, Math.max(delta, 1 / 120));
          const next = pulse * decay;
          if (next < .03) {
            edgePulseRef.current = 0;
            edgePulseKeyRef.current = null;
            restoreEdgeOpacity(layers);
          } else {
            edgePulseRef.current = next;
          }
        }
      }
      const paintTime = performance.now();
      if (reducedMotion || paintTime - lastLabelPaint >= LABEL_INTERVAL_MS) {
        lastLabelPaint = paintTime;
        const selectedNodeId = getSelectedNodeId();
        const outerField = outerPoolMeshRef.current;
        const opencodeDistance = outerField?.visible ? camera.position.distanceTo(outerField.position) : Number.POSITIVE_INFINITY;
        const subpoolOpacity = 1 - THREE.MathUtils.smoothstep(opencodeDistance, 12, 18);
        const outerPoolOpacity = THREE.MathUtils.smoothstep(opencodeDistance, 11, 17);
        for (const node of nodeByIdRef.current.values()) {
          const label = labelRefs.current.get(node.id);
          const mesh = meshByIdRef.current.get(node.id);
          if (!label || !mesh) continue;
          projected.copy(mesh.position).project(camera);
          const visible = projected.z > -1 && projected.z < 1
            && Math.abs(projected.x) < 1.08 && Math.abs(projected.y) < 1.08;
          label.style.left = `${(projected.x * .5 + .5) * container.clientWidth}px`;
          label.style.top = `${(-projected.y * .5 + .5) * container.clientHeight}px`;
          label.style.opacity = visible ? "1" : "0";
          label.style.visibility = visible ? "visible" : "hidden";
          label.style.pointerEvents = visible ? "auto" : "none";
          const isSelected = selectedNodeId !== null && node.id === selectedNodeId;
          label.style.zIndex = isSelected ? "3000" : String(Math.round((1 - projected.z) * 1000));
        }
        for (const lane of POOL_ORDER) {
          const element = laneLabelRefs.current.get(lane.id);
          const anchor = laneAnchorsRef.current.get(lane.id);
          if (!element || !anchor) continue;
          projected.copy(anchor).project(camera);
          const visible = projected.z > -1 && projected.z < 1
            && Math.abs(projected.x) < 1.08 && Math.abs(projected.y) < 1.08;
          const opacity = lane.id === "codex" ? 1 : subpoolOpacity;
          const displayed = visible && opacity > .02;
          element.style.left = `${(projected.x * .5 + .5) * container.clientWidth}px`;
          element.style.top = `${(-projected.y * .5 + .5) * container.clientHeight}px`;
          element.style.opacity = displayed ? String(opacity) : "0";
          element.style.visibility = displayed ? "visible" : "hidden";
          element.style.zIndex = String(Math.round((1 - projected.z) * 900));
        }
        const outerLabel = laneLabelRefs.current.get("opencode");
        const outerAnchor = laneAnchorsRef.current.get("opencode");
        if (outerLabel && outerAnchor) {
          projected.copy(outerAnchor).project(camera);
          const visible = projected.z > -1 && projected.z < 1
            && Math.abs(projected.x) < 1.08 && Math.abs(projected.y) < 1.08;
          const displayed = visible && outerPoolOpacity > .02;
          outerLabel.style.left = `${(projected.x * .5 + .5) * container.clientWidth}px`;
          outerLabel.style.top = `${(-projected.y * .5 + .5) * container.clientHeight}px`;
          outerLabel.style.opacity = displayed ? String(outerPoolOpacity) : "0";
          outerLabel.style.visibility = displayed ? "visible" : "hidden";
          outerLabel.style.zIndex = String(Math.round((1 - projected.z) * 880));
        }
      }
      renderer.render(scene, camera);
      return physicsMoving;
    };
    renderRef.current = () => { if (!document.hidden) draw(); };
    const resize = () => {
      const { width, height } = container.getBoundingClientRect();
      renderer.setSize(Math.max(width, 1), Math.max(height, 1), false);
      camera.aspect = Math.max(width, 1) / Math.max(height, 1);
      camera.updateProjectionMatrix();
      if (reducedMotion && !document.hidden) draw();
    };
    const observer = new ResizeObserver(resize);
    observer.observe(container);
    resize();
    let frame = 0;
    let animating = false;
    let previous = performance.now();
    let lastFrame = 0;
    let physicsWakeUntil = previous + PHYSICS_WAKE_MS;
    const animate = (now: number) => {
      if (!animating) return;
      if (now - lastFrame < FRAME_INTERVAL_MS) {
        frame = requestAnimationFrame(animate);
        return;
      }
      const delta = Math.min((now - previous) / 1000, .1);
      previous = now;
      lastFrame = now;
      const physicsMoving = draw(delta);
      const physicsAwake = physicsMoving && now < physicsWakeUntil;
      if (physicsMoving && !physicsAwake) {
        physicsBodiesRef.current.forEach((body) => body.velocity.set(0, 0, 0));
      }
      if (edgePulseRef.current > 0 || physicsAwake) {
        frame = requestAnimationFrame(animate);
        return;
      }
      if (controls.autoRotate) {
        frame = requestAnimationFrame(animate);
        return;
      }
      animating = false;
    };
    const ensureAnimation = () => {
      if (animating || reducedMotion || document.hidden || !document.hasFocus()) return;
      animating = true;
      previous = performance.now();
      lastFrame = 0;
      frame = requestAnimationFrame(animate);
    };
    const startAnimation = () => {
      physicsWakeUntil = performance.now() + PHYSICS_WAKE_MS;
      ensureAnimation();
    };
    startAnimationRef.current = startAnimation;
    const stopAnimation = () => {
      animating = false;
      cancelAnimationFrame(frame);
    };
    const renderOnControlsChange = () => {
      if (reducedMotion) {
        if (!document.hidden) draw();
      } else {
        // OrbitControls emits `change` from controls.update() while damping.
        // Keep rendering the camera movement without extending the physics
        // budget on every frame, otherwise a non-converging galaxy can never
        // reach the bounded idle state.
        ensureAnimation();
      }
    };
    const visibilityChanged = () => {
      if (document.hidden) stopAnimation();
      else if (reducedMotion || !document.hasFocus()) draw();
      else ensureAnimation();
    };
    const focusChanged = () => {
      if (document.hasFocus()) ensureAnimation();
      else stopAnimation();
    };
    controls.addEventListener("change", renderOnControlsChange);
    document.addEventListener("visibilitychange", visibilityChanged);
    window.addEventListener("focus", focusChanged);
    window.addEventListener("blur", focusChanged);
    if (reducedMotion) draw(); else startAnimation();
    return () => {
      stopAnimation();
      observer.disconnect();
      document.removeEventListener("visibilitychange", visibilityChanged);
      window.removeEventListener("focus", focusChanged);
      window.removeEventListener("blur", focusChanged);
      controls.removeEventListener("change", renderOnControlsChange);
      renderer.domElement.removeEventListener("pointerdown", pointerDownCapture, true);
      window.removeEventListener("pointermove", pointerMove);
      window.removeEventListener("pointerup", pointerUp);
      window.removeEventListener("pointercancel", pointerCancel);
      controls.enabled = true;
      controls.mouseButtons.LEFT = THREE.MOUSE.ROTATE;
      renderer.domElement.style.cursor = "";
      controls.dispose();
      scene.traverse((object) => {
        if (object instanceof THREE.Mesh || object instanceof THREE.Line || object instanceof THREE.Points) {
          object.geometry.dispose();
          const materials = Array.isArray(object.material) ? object.material : [object.material];
          materials.forEach((material) => material.dispose());
        }
      });
      renderer.dispose();
      meshByIdRef.current.clear();
      haloByIdRef.current.clear();
      workerByMeshRef.current.clear();
      nodeByIdRef.current.clear();
      poolMeshesRef.current.clear();
      outerPoolMeshRef.current = null;
      laneAnchorsRef.current.clear();
      sharedGeometriesRef.current = null;
      if (runtimeRef.current === runtime) runtimeRef.current = null;
      routeLayersRef.current = { dispatch: [], callbacks: [] };
      renderRef.current = null;
      startAnimationRef.current = null;
      physicsBodiesRef.current.clear();
    };
  }, []);

  useEffect(() => {
    const runtime = runtimeRef.current;
    const shared = sharedGeometriesRef.current;
    const scene = runtime?.scene;
    if (!runtime || !scene || !shared) return;
    for (const physicsId of Array.from(physicsBodiesRef.current.keys())) if (!nodes.some((node) => node.id === physicsId)) physicsBodiesRef.current.delete(physicsId);
    const desiredById = new Map<string, SceneNode>();
    for (const node of nodes) {
      let body = physicsBodiesRef.current.get(node.id);
      if (!body) {
        body = {
          id: node.id,
          position: node.position.clone(),
          target: node.position.clone(),
          velocity: new THREE.Vector3(),
          radius: node.kind === "worker" ? .34 : node.kind === "subagent" ? .22 : node.kind === "proxy" ? .16 : .46,
          dragging: false,
          pool: node.pool ?? undefined,
        };
        physicsBodiesRef.current.set(node.id, body);
      } else {
        body.target.copy(node.position);
        body.pool = node.pool ?? undefined;
      }
      desiredById.set(node.id, node);
    }
    nodeByIdRef.current = desiredById;
    const workersForColour: Worker[] = [];
    for (const node of nodes) {
      if (node.worker) workersForColour.push(node.worker);
    }
    for (const node of nodes) {
      const colour = nodeColour(node, snapshot, workersForColour);
      let mesh = meshByIdRef.current.get(node.id);
      if (!mesh) {
        const geometry = node.kind === "proxy" ? shared.proxyGeometry : node.kind === "source" ? shared.sourceGeometry : node.kind === "subagent" ? shared.subagentGeometry : shared.workerGeometry;
        const material = new THREE.MeshStandardMaterial({
          color: colour,
          emissive: colour,
          emissiveIntensity: node.kind === "proxy" ? .22 : .05,
          metalness: .1,
          roughness: .54,
        });
        mesh = new THREE.Mesh(geometry, material);
        mesh.position.copy(node.position);
        mesh.rotation.set(node.kind === "proxy" ? 0 : .4, node.kind === "proxy" ? 0 : .6, node.kind === "proxy" ? 0 : .14);
        mesh.userData.nodeId = node.id;
        scene.add(mesh);
        meshByIdRef.current.set(node.id, mesh);
      } else {
        mesh.position.copy(physicsBodiesRef.current.get(node.id)?.position ?? node.position);
        const material = mesh.material as THREE.MeshStandardMaterial;
        material.color.setHex(colour);
        material.emissive.setHex(colour);
        material.emissiveIntensity = node.kind === "proxy" ? .22 : .05;
      }
      if (node.kind === "worker" && node.worker) {
        workerByMeshRef.current.set(mesh, node.worker);
      } else {
        workerByMeshRef.current.delete(mesh);
      }
      if (node.kind === "worker") {
        let halo = haloByIdRef.current.get(node.id);
        if (!halo) {
          const haloMaterial = new THREE.MeshBasicMaterial({ color: colour, transparent: true, opacity: .2, wireframe: true });
          halo = new THREE.Mesh(shared.haloGeometry, haloMaterial);
          halo.position.copy(mesh.position);
          halo.rotation.copy(mesh.rotation);
          scene.add(halo);
          haloByIdRef.current.set(node.id, halo);
          runtime.halos.push(halo);
        } else {
          halo.position.copy(mesh.position);
          halo.rotation.copy(mesh.rotation);
          (halo.material as THREE.MeshBasicMaterial).color.setHex(colour);
        }
        halo.visible = settingsRef.current.showHalos;
      }
    }
    for (const [id, mesh] of Array.from(meshByIdRef.current.entries())) {
      if (desiredById.has(id)) continue;
      scene.remove(mesh);
      workerByMeshRef.current.delete(mesh);
      const materials = Array.isArray(mesh.material) ? mesh.material : [mesh.material];
      materials.forEach((material) => material.dispose());
      meshByIdRef.current.delete(id);
      const halo = haloByIdRef.current.get(id);
      if (halo) {
        scene.remove(halo);
        (halo.material as THREE.Material).dispose();
        haloByIdRef.current.delete(id);
        const haloIndex = runtime.halos.indexOf(halo);
        if (haloIndex >= 0) runtime.halos.splice(haloIndex, 1);
      }
    }
    for (const [id, halo] of Array.from(haloByIdRef.current.entries())) {
      const node = desiredById.get(id);
      if (!node || node.kind !== "worker") {
        scene.remove(halo);
        (halo.material as THREE.Material).dispose();
        haloByIdRef.current.delete(id);
        const haloIndex = runtime.halos.indexOf(halo);
        if (haloIndex >= 0) runtime.halos.splice(haloIndex, 1);
      }
    }
    {
      interface DesiredEdge {
        key: string;
        layer: "dispatch" | "callbacks";
        start: THREE.Vector3;
        end: THREE.Vector3;
        colour: number;
        opacity: number;
        curve: number;
        supportsCallback: boolean;
      }
      const currentPosition = (node: SceneNode) => physicsBodiesRef.current.get(node.id)?.position ?? node.position;
      const desiredEdges: DesiredEdge[] = [];
      for (const node of nodes) {
        if (node.kind !== "worker") continue;
        const proxy = desiredById.get(`fugue-proxy:${node.id}`);
        if (!proxy) continue;
        const sourceNode = proxy.routeSourceId ? desiredById.get(proxy.routeSourceId) : undefined;
        const worker = node.worker;
        const hasCallback = Boolean(worker && (worker.completion.id !== null || !["not-applicable", "unavailable", "disabled", "idle"].includes(worker.completion.callback_state)));
        if (sourceNode) {
          desiredEdges.push({
            key: `dispatch:${sourceNode.id}->${proxy.id}`,
            layer: "dispatch",
            start: currentPosition(sourceNode),
            end: currentPosition(proxy),
            colour: 0xf3aa19,
            opacity: .58,
            curve: .18,
            supportsCallback: hasCallback,
          });
        }
        desiredEdges.push({
          key: `dispatch:${proxy.id}->${node.id}`,
          layer: "dispatch",
          start: currentPosition(proxy),
          end: currentPosition(node),
          colour: 0x8a641f,
          opacity: node.worker?.slot_state === "assigned" ? .88 : .28,
          curve: .28,
          supportsCallback: hasCallback,
        });
      }
      for (const node of nodes) {
        if (node.kind !== "subagent" || !node.worker) continue;
        const parent = desiredById.get(node.worker.slot_id);
        if (!parent) continue;
        desiredEdges.push({
          key: `dispatch:${parent.id}->${node.id}`,
          layer: "dispatch",
          start: currentPosition(parent),
          end: currentPosition(node),
          colour: 0xffffff,
          opacity: node.subagentState === "waiting" ? .82 : .42,
          curve: .16,
          supportsCallback: false,
        });
      }
      const layers = routeLayersRef.current;
      const existingByKey = new Map<string, { route: THREE.Line; layerName: "dispatch" | "callbacks" }>();
      ((["dispatch", "callbacks"] as const)).forEach((layerName) => {
        for (const route of layers[layerName]) {
          const edgeKey = (route.userData as { edgeKey?: unknown }).edgeKey;
          if (typeof edgeKey === "string") existingByKey.set(edgeKey, { route: route as THREE.Line, layerName });
        }
      });
      const desiredKeys = new Set(desiredEdges.map((edge) => edge.key));
      for (const [key, entry] of Array.from(existingByKey.entries())) {
        if (desiredKeys.has(key)) continue;
        const list = layers[entry.layerName];
        const index = list.indexOf(entry.route);
        if (index >= 0) list.splice(index, 1);
        scene.remove(entry.route);
        entry.route.geometry.dispose();
        const routeMaterials = Array.isArray(entry.route.material) ? entry.route.material : [entry.route.material];
        routeMaterials.forEach((material) => (material as THREE.Material).dispose());
        existingByKey.delete(key);
      }
      for (const edge of desiredEdges) {
        const found = existingByKey.get(edge.key);
        if (found) {
          if (found.layerName !== edge.layer) {
            const from = layers[found.layerName];
            const index = from.indexOf(found.route);
            if (index >= 0) from.splice(index, 1);
            layers[edge.layer].push(found.route);
            found.layerName = edge.layer;
          }
          const userData = found.route.userData as { sx?: number; sy?: number; sz?: number; ex?: number; ey?: number; ez?: number; curve?: number; colour?: number; baseOpacity?: number; supportsCallback?: boolean };
          const moved = userData.sx !== edge.start.x || userData.sy !== edge.start.y || userData.sz !== edge.start.z
            || userData.ex !== edge.end.x || userData.ey !== edge.end.y || userData.ez !== edge.end.z
            || userData.curve !== edge.curve;
          if (moved) {
            const middle = edge.start.clone().lerp(edge.end, .5);
            middle.z += edge.curve;
            const points = new THREE.QuadraticBezierCurve3(edge.start, middle, edge.end).getPoints(28);
            found.route.geometry.setFromPoints(points);
            userData.sx = edge.start.x;
            userData.sy = edge.start.y;
            userData.sz = edge.start.z;
            userData.ex = edge.end.x;
            userData.ey = edge.end.y;
            userData.ez = edge.end.z;
            userData.curve = edge.curve;
          }
          const material = found.route.material as THREE.LineBasicMaterial;
          if (userData.colour !== edge.colour) {
            material.color.setHex(edge.colour);
            userData.colour = edge.colour;
          }
          if (userData.baseOpacity !== edge.opacity) {
            const previousBase = typeof userData.baseOpacity === "number" ? userData.baseOpacity : material.opacity;
            const boost = material.opacity - previousBase;
            userData.baseOpacity = edge.opacity;
            material.opacity = edgePulseRef.current > 0 ? Math.min(1, edge.opacity + Math.max(0, boost)) : edge.opacity;
          }
          userData.supportsCallback = edge.supportsCallback;
        } else {
          const route = line(scene, edge.start, edge.end, edge.colour, edge.opacity, edge.curve);
          route.userData.edgeKey = edge.key;
          route.userData.sx = edge.start.x;
          route.userData.sy = edge.start.y;
          route.userData.sz = edge.start.z;
          route.userData.ex = edge.end.x;
          route.userData.ey = edge.end.y;
          route.userData.ez = edge.end.z;
          route.userData.curve = edge.curve;
          route.userData.colour = edge.colour;
          route.userData.supportsCallback = edge.supportsCallback;
          layers[edge.layer].push(route);
          existingByKey.set(edge.key, { route, layerName: edge.layer });
        }
      }
      applyRouteFilter(layers, filterRef.current, undefined, { showDispatch: settingsRef.current.showDispatch, showCallbacks: settingsRef.current.showCallbacks });
    }
    startAnimationRef.current?.();
    renderRef.current?.();
  }, [laneCounts, nodes, snapshot]);

  useEffect(() => {
    applyRouteFilter(routeLayersRef.current, filter, () => renderRef.current?.(), settings);
  }, [filter, settings.showCallbacks, settings.showDispatch]);

  useEffect(() => { renderRef.current?.(); }, [selectedSlot, selectedSourceId]);

  useEffect(() => {
    const runtime = runtimeRef.current;
    if (!runtime) return;
    applyGraphSettings(runtime, settings, () => {
      startAnimationRef.current?.();
      renderRef.current?.();
    });
  }, [settings.autoRotate, settings.rotationSpeed, settings.showDepthField, settings.showHalos, settings.showLabels, settings.useFog, settings.galaxyIdealDistance, settings.galaxyCohesion, settings.galaxyRepulsion, settings.galaxyGravity, settings.galaxyDamping]);

  return (
    <div className="topology-frame topology-3d" ref={containerRef}>
      <canvas ref={canvasRef} aria-label={`Interactive 3D Fugue agent graph at event ${snapshot.snapshot_version.event_sequence ?? "unknown"}`} />
      {!webglUnavailable && settings.showLabels && <div className="graph-label-layer">
        {nodes.filter((node) => node.kind !== "proxy").map((node) => (
          <button
            className={`graph-label label-${node.kind} label-${node.lifecycle} ${node.id === selectedGraphNodeId ? "label-selected" : ""}`}
            key={node.id}
            ref={(element) => { if (element) labelRefs.current.set(node.id, element); else labelRefs.current.delete(node.id); }}
            type="button"
            onPointerDown={(event) => event.stopPropagation()}
            onClick={() => selectSceneNode(node)}
          >
            <strong>{node.label}</strong><span>{node.meta}</span>
          </button>
        ))}
      </div>}
      {!webglUnavailable && settings.showLabels && <div className="lane-pool-layer" aria-hidden="true" style={{ position: "absolute", inset: 0, overflow: "hidden", pointerEvents: "none" }}>
        <div ref={(element) => { if (element) laneLabelRefs.current.set("opencode", element); else laneLabelRefs.current.delete("opencode"); }} className="lane-pool-label lane-opencode" style={{ position: "absolute", left: 0, top: 0, visibility: "hidden", transform: "translate(-50%,-135%)", pointerEvents: "none", whiteSpace: "nowrap", textAlign: "center", background: "rgba(7,7,6,0.55)", border: "none", borderRadius: 6, padding: "3px 8px", color: "#f3aa19", fontSize: 10, letterSpacing: "0.12em", lineHeight: 1.3 }}><strong style={{ display: "block", fontSize: 10, letterSpacing: "0.14em" }}>OPENCODE</strong><span style={{ display: "block", fontSize: 9, opacity: .72 }}>{nodes.filter((node) => node.pool !== "codex").length} NODES · {LANE_ORDER.filter((lane) => (laneCounts.get(lane.id) ?? 0) > 0).length} SUBPOOLS</span></div>
        {POOL_ORDER.filter((lane) => (laneCounts.get(lane.id) ?? 0) > 0).map((lane) => (
          <div
            key={lane.id}
            ref={(element) => { if (element) laneLabelRefs.current.set(lane.id, element); else laneLabelRefs.current.delete(lane.id); }}
            className={`lane-pool-label lane-${lane.id}`}
            style={{ position: "absolute", left: 0, top: 0, transform: "translate(-50%,-135%)", pointerEvents: "none", whiteSpace: "nowrap", textAlign: "center", background: "rgba(7,7,6,0.55)", border: "none", borderRadius: 6, padding: "3px 8px", color: "#e8e2d7", fontSize: 10, letterSpacing: "0.12em", lineHeight: 1.3 }}
          >
            <strong style={{ display: "block", fontSize: 10, letterSpacing: "0.14em" }}>{lane.title}</strong><span style={{ display: "block", fontSize: 9, opacity: .72 }}>{laneCounts.get(lane.id) ?? 0} NODES</span>
          </div>
        ))}
      </div>}
      <div className="graph-help">DRAG BACKGROUND TO ROTATE · RIGHT-DRAG PAN · SCROLL / PINCH ZOOM · DRAG NODE TO MOVE · CLICK NODE TO SELECT</div>
      {webglUnavailable && <div className="webgl-fallback" role="status"><p>3D GRAPH UNAVAILABLE · WORKER METADATA REMAINS AVAILABLE</p><div>{nodes.filter((node) => node.worker || node.sourceThread).map((node) => <button type="button" key={node.id} onClick={() => node.worker ? onSelect(node.worker) : node.sourceThread ? onSelectSource(node.sourceThread) : undefined}><strong>{node.label}</strong><span>{node.meta}</span></button>)}</div></div>}
    </div>
  );
}
