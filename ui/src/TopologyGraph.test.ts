import * as THREE from "three";
import { AGENT_STATE_COLOURS, agentVisualState, applyGraphSettings, applyRouteFilter, exactVisibleSourceRouteId, fitPoolFieldToMembers, infraVisualState, nodeColour, poolRadiusForCount, stepGraphPhysics, type PhysicsBody } from "./TopologyGraph";
import { DEFAULT_TOPOLOGY_SETTINGS } from "./SettingsPage";
import { snapshotFixture } from "./test/fixture";

describe("3D route filtering", () => {
  const body = (id: string, position: THREE.Vector3, target = position.clone(), dragging = false): PhysicsBody => ({
    id,
    position,
    target,
    velocity: new THREE.Vector3(),
    radius: .3,
    dragging,
  });

  it("returns displaced nodes toward their pool anchors with damped momentum", () => {
    const displaced = body("worker-1", new THREE.Vector3(3, 0, 0), new THREE.Vector3(0, 0, 0));

    for (let frame = 0; frame < 180; frame += 1) stepGraphPhysics([displaced], 1 / 60);

    expect(displaced.position.length()).toBeLessThan(.08);
    expect(displaced.velocity.length()).toBeLessThan(.08);
  });

  it("separates overlapping nodes without moving a node being dragged", () => {
    const dragged = body("worker-a", new THREE.Vector3(0, 0, 0), undefined, true);
    const neighbour = body("worker-b", new THREE.Vector3(.1, 0, 0));

    stepGraphPhysics([dragged, neighbour], 1 / 60);

    expect(dragged.position.toArray()).toEqual([0, 0, 0]);
    expect(neighbour.position.distanceTo(dragged.position)).toBeGreaterThanOrEqual(.72 - 1e-6);
  });

  it("uses relationships and pool forces instead of returning pooled nodes to fixed homes", () => {
    const first = { ...body("worker-a", new THREE.Vector3(-3, 0, 0), new THREE.Vector3(-9, 0, 0)), pool: "control" };
    const second = { ...body("worker-b", new THREE.Vector3(3, 0, 0), new THREE.Vector3(9, 0, 0)), pool: "control" };
    const initialDistance = first.position.distanceTo(second.position);

    for (let frame = 0; frame < 120; frame += 1) {
      stepGraphPhysics([first, second], 1 / 60, [{ from: first.id, to: second.id, idealDistance: 2.8 }], {
        idealDistance: 2.8,
        cohesion: .45,
        repulsion: 0,
        gravity: 0,
        damping: 3.2,
      });
    }

    expect(first.position.distanceTo(second.position)).toBeLessThan(initialDistance);
    expect(first.position.x).toBeGreaterThan(-9);
    expect(second.position.x).toBeLessThan(9);
  });

  it("repels different pools while weak world gravity keeps the galaxy bounded", () => {
    const first = { ...body("source", new THREE.Vector3(-.2, 0, 0)), pool: "codex" };
    const second = { ...body("worker", new THREE.Vector3(.2, 0, 0)), pool: "control" };
    const initialDistance = first.position.distanceTo(second.position);

    for (let frame = 0; frame < 30; frame += 1) {
      stepGraphPhysics([first, second], 1 / 60, [], {
        idealDistance: 2.8,
        cohesion: .45,
        repulsion: 1.1,
        gravity: .12,
        damping: 3.2,
      });
    }

    expect(first.position.distanceTo(second.position)).toBeGreaterThan(initialDistance);
    expect(Math.max(first.position.length(), second.position.length())).toBeLessThan(4);
  });

  it("scales spatial pool gradients with occupancy and caps extreme input", () => {
    expect(poolRadiusForCount(0)).toBe(0);
    expect(poolRadiusForCount(1)).toBe(.74);
    expect(poolRadiusForCount(3)).toBeGreaterThan(poolRadiusForCount(1));
    expect(poolRadiusForCount(10_000)).toBe(2.55);
  });

  it("fits one bounded ellipsoid to live pool members without mutating them", () => {
    const first = body("first", new THREE.Vector3(-2, 1, 0));
    const second = body("second", new THREE.Vector3(1, -1, .5));
    const before = [first.position.clone(), second.position.clone()];

    expect(fitPoolFieldToMembers([])).toBeNull();
    const single = fitPoolFieldToMembers([first]);
    expect(single?.center.toArray()).toEqual(first.position.toArray());
    expect(single?.scale.toArray()).toEqual([.74, .74, .74]);

    const fit = fitPoolFieldToMembers([first, second]);
    expect(fit?.center.toArray()).toEqual([-.5, 0, .25]);
    expect(fit?.scale.x).toBeCloseTo(2.15);
    expect(fit?.scale.y).toBeCloseTo(1.65);
    expect(fit?.scale.z).toBeCloseTo(.9);
    expect(first.position.toArray()).toEqual(before[0].toArray());
    expect(second.position.toArray()).toEqual(before[1].toArray());
  });

  it("draws source routing only for the exact visible bound thread", () => {
    const worker = snapshotFixture().worker_graph.workers[0];
    worker.source_id = "thread-visible";
    expect(exactVisibleSourceRouteId(worker, new Set(["thread-visible", "thread-other"]))).toBe("thread-visible");
    expect(exactVisibleSourceRouteId(worker, new Set(["thread-other"]))).toBeNull();
    worker.source_id = null;
    expect(exactVisibleSourceRouteId(worker, new Set(["thread-visible"]))).toBeNull();
  });

  it("uses parent attention for waiting children and keeps terminal children grey", () => {
    const snapshot = snapshotFixture();
    const worker = snapshot.worker_graph.workers[0];
    const child = {
      id: "subagent:child-1", label: "CHILD 1", meta: "WAITING", kind: "subagent",
      lifecycle: "disposable", position: new THREE.Vector3(), worker,
      sourceThread: null, lane: "tensorhost", pool: "tensorhost",
      routeSourceId: null, subagentState: "waiting",
    } as Parameters<typeof nodeColour>[0];

    expect(nodeColour(child, snapshot, [worker])).toBe(AGENT_STATE_COLOURS.active);
    worker.recovery.target_id = "recovery-target";
    expect(nodeColour(child, snapshot, [worker])).toBe(AGENT_STATE_COLOURS.recovery);
    snapshot.attention.operator_required.items.push({
      kind: "backend_attention", id: "attention-child", work_id: worker.work_id ?? undefined,
      generation: 1, state: "attention", reason: "operator_required",
    });
    expect(nodeColour(child, snapshot, [worker])).toBe(AGENT_STATE_COLOURS.intervention);
    child.subagentState = "terminal";
    expect(nodeColour(child, snapshot, [worker])).toBe(AGENT_STATE_COLOURS.idle);
  });

  it("invalidates the canvas after changing visibility for reduced-motion rendering", () => {
    const dispatch = new THREE.Object3D();
    const callback = new THREE.Object3D();
    const invalidate = vi.fn();

    applyRouteFilter({ dispatch: [dispatch], callbacks: [callback] }, "callbacks", invalidate);

    expect(dispatch.visible).toBe(false);
    expect(callback.visible).toBe(true);
    expect(invalidate).toHaveBeenCalledOnce();
  });

  it("combines toolbar filters with settings layer visibility", () => {
    const dispatch = new THREE.Object3D();
    const callback = new THREE.Object3D();

    applyRouteFilter(
      { dispatch: [dispatch], callbacks: [callback] },
      "all",
      undefined,
      { showDispatch: false, showCallbacks: true },
    );

    expect(dispatch.visible).toBe(false);
    expect(callback.visible).toBe(true);
  });

  it("reuses one physical edge for dispatch and callback filtering", () => {
    const shared = new THREE.Object3D();
    shared.userData.supportsCallback = true;
    const layers = { dispatch: [shared], callbacks: [] };

    applyRouteFilter(layers, "callbacks");
    expect(shared.visible).toBe(true);

    applyRouteFilter(layers, "dispatch");
    expect(shared.visible).toBe(true);

    applyRouteFilter(layers, "all", undefined, { showDispatch: false, showCallbacks: false });
    expect(shared.visible).toBe(false);
  });

  it("applies visual settings without rebuilding the scene", () => {
    const fog = new THREE.Fog(0x070706, 13, 31);
    const runtime = {
      controls: { autoRotate: true, autoRotateSpeed: .55 },
      depthField: { visible: true },
      distanceFog: fog,
      halos: [{ visible: true }, { visible: true }],
      reducedMotion: false,
      scene: { fog },
    };
    const invalidate = vi.fn();

    applyGraphSettings(runtime, { ...DEFAULT_TOPOLOGY_SETTINGS, autoRotate: false, rotationSpeed: 1.1, showDepthField: false, showHalos: false, useFog: false }, invalidate);

    expect(runtime.controls).toEqual({ autoRotate: false, autoRotateSpeed: 1.1 });
    expect(runtime.depthField.visible).toBe(false);
    expect(runtime.halos.every((halo) => !halo.visible)).toBe(true);
    expect(runtime.scene.fog).toBeNull();
    expect(invalidate).toHaveBeenCalledOnce();
  });

  it("uses only authoritative state with red then orange then green precedence", () => {
    const snapshot = snapshotFixture();
    const worker = snapshot.worker_graph.workers[0];
    expect(agentVisualState(worker, snapshot)).toBe("handoff");

    worker.recovery.target_id = "recovery-target";
    expect(agentVisualState(worker, snapshot)).toBe("recovery");

    worker.recovery.phase = "active";
    worker.transport.state = "accepted";
    expect(agentVisualState(worker, snapshot)).toBe("active");
    worker.recovery.phase = "corpse";

    snapshot.attention.operator_required.items.push({
      kind: "backend_attention",
      id: "attention-2",
      work_id: worker.work_id ?? undefined,
      generation: 1,
      state: "attention",
      reason: "operator_required",
    });
    expect(agentVisualState(worker, snapshot)).toBe("intervention");
  });

  it("separates source delivery recovery from controller operator attention", () => {
    const snapshot = snapshotFixture();
    expect(infraVisualState("source", snapshot, snapshot.worker_graph.workers)).toBe("recovery");
    expect(infraVisualState("controller", snapshot, snapshot.worker_graph.workers)).toBe("intervention");

    snapshot.attention.operator_required.items = [];
    snapshot.attention.operator_required.total = 0;
    expect(infraVisualState("source", snapshot, snapshot.worker_graph.workers)).toBe("active");
    expect(infraVisualState("controller", snapshot, snapshot.worker_graph.workers)).toBe("active");

    snapshot.availability.status = "degraded";
    expect(infraVisualState("controller", snapshot, snapshot.worker_graph.workers)).toBe("recovery");
    snapshot.availability.status = "unavailable";
    expect(infraVisualState("controller", snapshot, snapshot.worker_graph.workers)).toBe("intervention");
    expect(infraVisualState("source", snapshot, snapshot.worker_graph.workers)).toBe("handoff");
  });

  it("marks only a worker with its own bounded recent turns as recent", () => {
    const snapshot = snapshotFixture();
    const recent = snapshot.worker_graph.workers[1];
    recent.recent_turns.status = "available";
    recent.recent_turns.reason = null;
    recent.recent_turns.items = [{ turn_id: "turn-1", ordinal: 1, state: "completed", occurred_at: "2026-09-06T00:00:00Z", token_count: 12 }];

    expect(agentVisualState(recent, snapshot)).toBe("recent");
    expect(agentVisualState(snapshot.worker_graph.workers[2], snapshot)).toBe("idle");
  });
});
