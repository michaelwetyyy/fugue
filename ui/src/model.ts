export type AvailabilityStatus = "available" | "degraded" | "unavailable";
export type SlotState = "clear" | "assigned" | "unavailable";
export type ComponentStatus = "available" | "unavailable" | "disabled";
export type TotalStatus = "exact" | "capped" | "unknown";

export interface SnapshotVersion {
  event_sequence: number | null;
  migration_version: string;
  digest?: string;
}

export interface Availability {
  status: AvailabilityStatus;
  errors: string[];
}

export interface Topology {
  lanes: string[];
  expected_slots: number;
  observed_slots: number | null;
  observed_status: TotalStatus;
}

export interface CockpitLane {
  id: string;
  label: string;
  symbol: string;
  slots: Array<{
    slot_id: string;
    position: number;
    state: SlotState;
    display_name: string;
  }>;
}

export interface Slot {
  slot_id: string;
  lane: string;
  position: number;
  state: SlotState;
  assignment_id: string | null;
  work_id: string | null;
}

export interface ReferenceComponent {
  status: ComponentStatus;
  ref: string | null;
}

export interface TransportComponent {
  status: ComponentStatus;
  reason: string | null;
  id: string | null;
  state: string;
  generation: number | null;
  acknowledgement_id: string | null;
  error_code: string | null;
  adapter: {
    status: ComponentStatus;
    kind: string | null;
    reason: string | null;
  };
}

export interface CompletionComponent {
  status: ComponentStatus;
  reason: string | null;
  id: string | null;
  registration_state: string;
  route_state: string;
  callback_state: string;
  callback_adapter: {
    status: ComponentStatus;
    reason: string | null;
  };
}

export interface RecoveryComponent {
  status: ComponentStatus;
  reason: string | null;
  target_id: string | null;
  phase: string;
  circuit_state: string;
  episode_state: string;
  timer_state: string;
}

export interface RecentTurn {
  turn_id: string;
  ordinal: number;
  state: string;
  occurred_at: string;
  token_count: number;
}

export interface RecentTurns {
  status: "available" | "unavailable";
  reason: string | null;
  limit: 2;
  items: RecentTurn[];
  content_included: false;
}

export interface Worker {
  slot_id: string;
  lane: string;
  position: number;
  slot_state: SlotState;
  display_name: string;
  session: ReferenceComponent;
  pane: ReferenceComponent;
  work_id: string | null;
  /** Exact source-thread return route when this assignment has one. */
  source_id?: string | null;
  /** Absent only while a newly installed GUI is paired with the prior controller release. */
  agent_lifecycle?: "disposable" | "persistent" | null;
  owner_id: string | null;
  assignment_id: string | null;
  attempt: number | null;
  transport: TransportComponent;
  completion: CompletionComponent;
  recovery: RecoveryComponent;
  recent_turns: RecentTurns;
}

export interface GraphEdge {
  from: string;
  to: string;
  kind: string;
}

export interface Subagent {
  id: string;
  parent_session_id: string;
  parent_slot_id: string;
  parent_work_id: string;
  state: "waiting" | "terminal";
  updated_at: string;
}

export interface ActivityAgent {
  agent_id: string;
  last_sequence: number;
  last_occurred_at: string;
}

export interface ActivityItem {
  sequence: number;
  event_type: string;
  origin: string;
  destination: string;
  occurred_at: string;
}

export interface RecentActivity {
  status: "available" | "unavailable";
  window_events: 200;
  agents: ActivityAgent[];
  items: ActivityItem[];
  content_included: false;
}

export interface QueueItem {
  work_id: string;
  sequence: number;
  queue_order: number;
  lane: string;
  state: string;
  policy: string;
  attempt: number;
  enqueued_at: string;
}

export interface AttentionItem {
  kind: string;
  id: string;
  target_id?: string;
  work_id?: string | null;
  scope?: "controller";
  generation?: number;
  state: string;
  reason: string | null;
  attempts?: number;
}

export interface Collection<T> {
  status: "available" | "unavailable";
  items: T[];
  total: number | null;
  total_status: TotalStatus;
  lower_bound: number;
  truncated: boolean;
}

export type Metric =
  | { status: "available"; source: "durable_samples"; value: number }
  | { status: "unavailable"; reason: string };

export interface SourceInboxItem {
  id: string;
  kind: "completion_nudge" | "message" | "tool_output";
  origin: string;
  work_id: string | null;
  state: "queued" | "delivering" | "accepted" | "committed" | "attention";
  queued_at: string;
  reason: string | null;
}

export interface SourceInbox {
  status: "available" | "unavailable";
  source_id: string;
  runtime_status: "active" | "idle" | "unavailable";
  active_turn_id: string | null;
  items: SourceInboxItem[];
  total: number | null;
  total_status: TotalStatus;
  lower_bound: number;
  truncated: boolean;
}

export type TranscriptRole = "user" | "agent" | "tool";
export type TranscriptKind = "text" | "tool_call" | "tool_output" | "steer";
export type TranscriptState = "committed" | "inflight" | "uncertain";

export interface TranscriptTurn {
  seq: number;
  role: TranscriptRole;
  kind: TranscriptKind;
  preview: string;
  state: TranscriptState;
}

export interface WorkerTranscriptTarget {
  slot_id: string;
  work_id: string;
  generation: number;
}

export interface TranscriptBundle {
  thread_id: string;
  slot_id: string;
  work_id: string;
  generation: number;
  fetched_at: string;
  expires_at: string;
  turns: TranscriptTurn[];
  redacted: string[];
  anchor_item_id?: string;
}

export interface TranscriptArchiveItem {
  archive_id: string;
  slot_id: string;
  work_id: string;
  generation: number;
  outcome: "succeeded" | "failed" | "cancelled";
  captured_at_us: number;
  turn_count: number;
  redaction_count: number;
}

export interface TranscriptArchive extends Collection<TranscriptArchiveItem> {
  content_included: false;
}

export interface ArchivedTranscriptTarget {
  archive_id: string;
  slot_id: string;
  work_id: string;
  generation: number;
}

export interface ArchivedTranscriptBundle {
  archive_id: string;
  thread_id: string;
  slot_id: string;
  work_id: string;
  generation: number;
  captured_at: string;
  outcome: "succeeded" | "failed" | "cancelled";
  turns: TranscriptTurn[];
  redacted: string[];
  read_only: true;
}

export type ComposerDeliveryState =
  | "queued"
  | "accepted"
  | "committed"
  | "uncertain"
  | "failed"
  | "rejected"
  | "expired";

export interface ComposerSubmit {
  thread_id: string;
  slot_id: string;
  work_id: string;
  generation: number;
  idempotency_key: string;
  text: string;
  anchor_item_id?: string;
}

export interface ComposerReceipt {
  thread_id: string;
  slot_id: string;
  work_id: string;
  generation: number;
  item_id: string;
  state: ComposerDeliveryState;
  queued_at: string;
  reason: string | null;
}

export interface CockpitSnapshot {
  projection_version: 1;
  snapshot_version: SnapshotVersion;
  availability: Availability;
  /** Normalized controller responses carry lanes; projection fixtures may carry topology. */
  lanes?: CockpitLane[];
  topology?: Topology;
  slots?: Slot[];
  worker_graph: { workers: Worker[]; subagents?: Subagent[]; edges: GraphEdge[] };
  queue: Collection<QueueItem>;
  attention: {
    automatic_recovery: Collection<AttentionItem>;
    operator_required: Collection<AttentionItem>;
    delivery_attention?: Collection<AttentionItem>;
  };
  metrics: {
    token_total: Metric;
    token_rate_5m: Metric;
  };
  recent_turns: RecentTurns;
  recent_activity?: RecentActivity;
  transcript_archive?: TranscriptArchive;
  source_inbox?: SourceInbox;
  refresh: { mode: "explicit"; polling: "disabled" };
}

export const LANE_META = [
  { id: "tensorhost", label: "TensorHost", symbol: "TH", capacity: 3 },
  { id: "homelab", label: "Home Lab", symbol: "HL", capacity: 3 },
  { id: "personal", label: "Personal", symbol: "PE", capacity: 3 },
  { id: "control", label: "Control", symbol: "CT", capacity: 3 },
  { id: "hands-off", label: "Hands-off", symbol: "HO", capacity: 1 },
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOwn(value: object, key: PropertyKey): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

const MAX_TEXT = 160;
const MAX_COLLECTION_ITEMS = 64;
const FORBIDDEN_TURN_FIELDS = new Set([
  "content", "text", "message", "messages", "prompt", "output", "transcript",
]);
const QUEUE_LANES = LANE_META.map((lane) => lane.id);
const OPERATOR_ATTENTION_KINDS = [
  "backend_attention", "callback_attention", "provisional_session_attention",
  "persistent_session_attention", "recovery_attention", "transport_attention",
  "transport_release_attention",
] as const;

function invalid(): never {
  throw new Error("The controller returned an unsupported cockpit snapshot.");
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!isRecord(value)) invalid();
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) invalid();
  return value;
}

function oneOf<T extends string>(value: unknown, values: readonly T[]): T {
  if (typeof value !== "string" || !values.includes(value as T)) invalid();
  return value as T;
}

function text(value: unknown, nullable = false): string | null {
  if (nullable && value === null) return null;
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_TEXT) invalid();
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (
      code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x00ad ||
      code === 0x2028 || code === 0x2029 || code === 0xfeff ||
      code === 0x061c || code === 0x200e || code === 0x200f ||
      (code >= 0x200b && code <= 0x200d) || code === 0x2060 ||
      (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069)
    ) invalid();
  }
  return value;
}

function boundedBoundaryText(
  value: unknown,
  maximum: number,
  { multiline = false, nullable = false }: { multiline?: boolean; nullable?: boolean } = {},
): string | null {
  if (nullable && value === null) return null;
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) invalid();
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    const allowedWhitespace = multiline && (code === 0x09 || code === 0x0a);
    if (
      (code < 0x20 && !allowedWhitespace) || (code >= 0x7f && code <= 0x9f) ||
      code === 0x00ad || code === 0x2028 || code === 0x2029 || code === 0xfeff ||
      code === 0x061c || code === 0x200e || code === 0x200f ||
      (code >= 0x200b && code <= 0x200d) || code === 0x2060 ||
      (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069)
    ) invalid();
  }
  return value;
}

function boundaryIdentifier(value: unknown, maximum = 128): string {
  const parsed = boundedBoundaryText(value, maximum) as string;
  if (!/^[A-Za-z0-9:_-]+$/.test(parsed)) invalid();
  return parsed;
}

function utcTimestamp(value: unknown): string {
  const parsed = boundedBoundaryText(value, 32) as string;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(parsed)) invalid();
  if (!Number.isFinite(Date.parse(parsed))) invalid();
  return parsed;
}

function cloneBoundary(value: unknown): unknown {
  try {
    return structuredClone(value);
  } catch {
    invalid();
  }
}

function integer(value: unknown, nullable = false): number | null {
  if (nullable && value === null) return null;
  if (!Number.isSafeInteger(value) || (value as number) < 0) invalid();
  return value as number;
}

function boolean(value: unknown): boolean {
  if (typeof value !== "boolean") invalid();
  return value;
}

function array(value: unknown, maximum: number): unknown[] {
  if (!Array.isArray(value) || value.length > maximum) invalid();
  return value;
}

function reference(value: unknown): void {
  const item = exactRecord(value, ["status", "ref"]);
  oneOf(item.status, ["available", "unavailable", "disabled"]);
  text(item.ref, true);
}

function recentTurns(value: unknown): void {
  const turns = exactRecord(value, ["status", "reason", "limit", "items", "content_included"]);
  oneOf(turns.status, ["available", "unavailable"]);
  text(turns.reason, true);
  if (turns.limit !== 2 || turns.content_included !== false) invalid();
  for (const raw of array(turns.items, 2)) {
    if (!isRecord(raw) || Object.keys(raw).some((key) => FORBIDDEN_TURN_FIELDS.has(key))) invalid();
    const turn = exactRecord(raw, ["turn_id", "ordinal", "state", "occurred_at", "token_count"]);
    text(turn.turn_id); integer(turn.ordinal); text(turn.state); text(turn.occurred_at); integer(turn.token_count);
  }
}

function worker(value: unknown): Worker {
  const baseKeys = [
    "slot_id", "lane", "position", "slot_state", "display_name", "session", "pane",
    "work_id", "owner_id", "assignment_id", "attempt", "transport", "completion",
    "recovery", "recent_turns",
  ] as const;
  const hasLifecycle = isRecord(value) && hasOwn(value, "agent_lifecycle");
  const hasSourceId = isRecord(value) && hasOwn(value, "source_id");
  const item = exactRecord(value, [
    ...baseKeys,
    ...(hasLifecycle ? ["agent_lifecycle"] : []),
    ...(hasSourceId ? ["source_id"] : []),
  ]);
  text(item.slot_id); text(item.lane); integer(item.position);
  oneOf(item.slot_state, ["clear", "assigned", "unavailable"]); text(item.display_name);
  reference(item.session); reference(item.pane);
  text(item.work_id, true);
  if (hasSourceId) text(item.source_id, true);
  if (hasLifecycle) {
    if (item.agent_lifecycle !== null) oneOf(item.agent_lifecycle, ["disposable", "persistent"]);
    if (item.slot_state !== "assigned" && item.agent_lifecycle !== null) invalid();
  }
  text(item.owner_id, true); text(item.assignment_id, true); integer(item.attempt, true);

  const transport = exactRecord(item.transport, [
    "status", "reason", "id", "state", "generation", "acknowledgement_id", "error_code", "adapter",
  ]);
  oneOf(transport.status, ["available", "unavailable", "disabled"]);
  text(transport.reason, true); text(transport.id, true); text(transport.state);
  integer(transport.generation, true); text(transport.acknowledgement_id, true); text(transport.error_code, true);
  const adapter = exactRecord(transport.adapter, ["status", "kind", "reason"]);
  oneOf(adapter.status, ["available", "unavailable", "disabled"]); text(adapter.kind, true); text(adapter.reason, true);

  const completion = exactRecord(item.completion, [
    "status", "reason", "id", "registration_state", "route_state", "callback_state", "callback_adapter",
  ]);
  oneOf(completion.status, ["available", "unavailable", "disabled"]);
  text(completion.reason, true); text(completion.id, true); text(completion.registration_state);
  text(completion.route_state); text(completion.callback_state);
  const callback = exactRecord(completion.callback_adapter, ["status", "reason"]);
  oneOf(callback.status, ["available", "unavailable", "disabled"]); text(callback.reason, true);

  const recovery = exactRecord(item.recovery, [
    "status", "reason", "target_id", "phase", "circuit_state", "episode_state", "timer_state",
  ]);
  oneOf(recovery.status, ["available", "unavailable", "disabled"]);
  text(recovery.reason, true); text(recovery.target_id, true); text(recovery.phase);
  text(recovery.circuit_state); text(recovery.episode_state); text(recovery.timer_state);
  recentTurns(item.recent_turns);
  return item as unknown as Worker;
}

function collection(value: unknown, kind: "queue" | "automatic" | "operator"): void {
  const section = exactRecord(value, ["status", "items", "total", "total_status", "lower_bound", "truncated"]);
  oneOf(section.status, ["available", "unavailable"]);
  const totalStatus = oneOf(section.total_status, ["exact", "capped", "unknown"]);
  if (totalStatus === "exact") integer(section.total); else if (section.total !== null) invalid();
  integer(section.lower_bound); boolean(section.truncated);
  for (const raw of array(section.items, MAX_COLLECTION_ITEMS)) {
    if (kind === "queue") {
      const item = exactRecord(raw, ["work_id", "sequence", "queue_order", "lane", "state", "policy", "attempt", "enqueued_at"]);
      text(item.work_id); integer(item.sequence); integer(item.queue_order); oneOf(item.lane, QUEUE_LANES);
      oneOf(item.state, ["queued"]); oneOf(item.policy, ["pending", "allowed", "rejected"]); integer(item.attempt); text(item.enqueued_at);
    } else if (kind === "automatic") {
      const item = exactRecord(raw, ["kind", "id", "target_id", "work_id", "generation", "state", "reason", "attempts"]);
      oneOf(item.kind, ["recovery_episode"]); text(item.id); text(item.target_id); text(item.work_id); integer(item.generation);
      oneOf(item.state, ["open"]); text(item.reason, true); integer(item.attempts);
    } else {
      if (!isRecord(raw)) invalid();
      const keys = hasOwn(raw, "scope")
        ? ["kind", "id", "scope", "state", "reason"]
        : ["kind", "id", "work_id", "generation", "state", "reason"];
      const item = exactRecord(raw, keys);
      const kindValue = oneOf(item.kind, OPERATOR_ATTENTION_KINDS); text(item.id); text(item.state); text(item.reason, true);
      if (hasOwn(item, "scope")) {
        if (kindValue !== "backend_attention") invalid();
        oneOf(item.scope, ["controller"]);
      } else if (kindValue === "persistent_session_attention") {
        if (item.work_id !== null || item.generation !== 0) invalid();
      } else { text(item.work_id); integer(item.generation); }
    }
  }
}

function metric(value: unknown): void {
  if (!isRecord(value)) invalid();
  if (value.status === "available") {
    const item = exactRecord(value, ["status", "source", "value"]);
    if (item.source !== "durable_samples" || typeof item.value !== "number" || !Number.isFinite(item.value) || item.value < 0) invalid();
  } else {
    const item = exactRecord(value, ["status", "reason"]);
    if (item.status !== "unavailable") invalid();
    text(item.reason);
  }
}

function validateSnapshot(value: unknown): asserts value is CockpitSnapshot {
  if (!isRecord(value)) invalid();
  const hasSourceInbox = hasOwn(value, "source_inbox");
  const hasRecentActivity = hasOwn(value, "recent_activity");
  const hasTranscriptArchive = hasOwn(value, "transcript_archive");
  const snapshot = exactRecord(value, [
    "projection_version", "snapshot_version", "availability", "topology", "slots",
    "worker_graph", "queue", "attention", "metrics", "recent_turns", "refresh",
    ...(hasSourceInbox ? ["source_inbox"] : []),
    ...(hasRecentActivity ? ["recent_activity"] : []),
    ...(hasTranscriptArchive ? ["transcript_archive"] : []),
  ]);
  if (snapshot.projection_version !== 1) invalid();

  const version = exactRecord(snapshot.snapshot_version, ["event_sequence", "migration_version", "digest"]);
  integer(version.event_sequence, true); text(version.migration_version); text(version.digest);
  const availability = exactRecord(snapshot.availability, ["status", "errors"]);
  oneOf(availability.status, ["available", "degraded", "unavailable"]);
  for (const error of array(availability.errors, 64)) text(error);

  const topology = exactRecord(snapshot.topology, ["lanes", "expected_slots", "observed_slots", "observed_status"]);
  const topologyLanes = array(topology.lanes, LANE_META.length);
  if (
    topologyLanes.length !== LANE_META.length
    || (topology.expected_slots !== 11 && topology.expected_slots !== 13)
  ) invalid();
  const slotCount = topology.expected_slots as 11 | 13;
  const expectedSlots = new Set(LANE_META.flatMap((lane) => {
    const capacity = slotCount === 11 && lane.id === "control" ? 1 : lane.capacity;
    return Array.from({ length: capacity }, (_, index) => `${lane.id}-${index + 1}`);
  }));
  topologyLanes.forEach((lane, index) => { if (lane !== LANE_META[index].id) invalid(); });
  integer(topology.observed_slots, true); oneOf(topology.observed_status, ["exact", "capped", "unknown"]);
  const slots = array(snapshot.slots, 13);
  if (slots.length !== slotCount) invalid();
  const seen = new Set<string>();
  for (const raw of slots) {
    const slot = exactRecord(raw, ["slot_id", "lane", "position", "state", "assignment_id", "work_id"]);
    const slotId = text(slot.slot_id) as string;
    if (!expectedSlots.has(slotId) || seen.has(slotId)) invalid();
    const separator = slotId.lastIndexOf("-");
    const expectedLane = slotId.slice(0, separator);
    const expectedPosition = Number(slotId.slice(separator + 1));
    if (slot.lane !== expectedLane || slot.position !== expectedPosition) invalid();
    seen.add(slotId); oneOf(slot.lane, QUEUE_LANES); integer(slot.position);
    oneOf(slot.state, ["clear", "assigned", "unavailable"]); text(slot.assignment_id, true); text(slot.work_id, true);
  }

  const hasSubagents = isRecord(snapshot.worker_graph) && hasOwn(snapshot.worker_graph, "subagents");
  const graph = exactRecord(snapshot.worker_graph, ["workers", "edges", ...(hasSubagents ? ["subagents"] : [])]);
  const workers = array(graph.workers, 13);
  if (workers.length !== slotCount) invalid();
  const parsedWorkers = workers.map((raw) => worker(raw));
  for (const item of parsedWorkers) {
    const separator = item.slot_id.lastIndexOf("-");
    const expectedLane = item.slot_id.slice(0, separator);
    const expectedPosition = Number(item.slot_id.slice(separator + 1));
    if (item.lane !== expectedLane || item.position !== expectedPosition) invalid();
  }
  const workerIds = new Set(parsedWorkers.map((item) => item.slot_id));
  if (workerIds.size !== slotCount || [...workerIds].some((id) => !expectedSlots.has(id))) invalid();
  const subagentIds = new Set<string>();
  if (hasSubagents) {
    for (const raw of array(graph.subagents, 48)) {
      const item = exactRecord(raw, [
        "id", "parent_session_id", "parent_slot_id", "parent_work_id", "state", "updated_at",
      ]);
      const id = boundaryIdentifier(item.id);
      const parentSlotId = text(item.parent_slot_id) as string;
      if (subagentIds.has(id) || !workerIds.has(parentSlotId)) invalid();
      subagentIds.add(id);
      boundaryIdentifier(item.parent_session_id);
      boundaryIdentifier(item.parent_work_id);
      oneOf(item.state, ["waiting", "terminal"]);
      text(item.updated_at);
    }
  }
  const expectedEdges = new Set<string>();
  for (const item of parsedWorkers) {
    const relationships = [
      [item.work_id, "runs"],
      [item.transport.id, "transport"],
      [item.completion.id, "completion"],
      [item.recovery.target_id, "recovery"],
    ] as const;
    for (const [target, kind] of relationships) {
      if (target !== null) expectedEdges.add(`${item.slot_id}\u0000${kind}\u0000${target}`);
    }
  }
  if (hasSubagents) {
    for (const item of graph.subagents as unknown as Subagent[]) {
      expectedEdges.add(`${item.parent_slot_id}\u0000delegates\u0000${item.id}`);
    }
  }
  const observedEdges = new Set<string>();
  for (const raw of array(graph.edges, 64)) {
    const edge = exactRecord(raw, ["from", "to", "kind"]);
    const from = text(edge.from) as string;
    const to = text(edge.to) as string;
    const kind = oneOf(edge.kind, ["runs", "transport", "completion", "recovery", "delegates"]);
    const key = `${from}\u0000${kind}\u0000${to}`;
    if (!expectedEdges.has(key) || observedEdges.has(key)) invalid();
    observedEdges.add(key);
  }
  if (observedEdges.size !== expectedEdges.size) invalid();
  collection(snapshot.queue, "queue");
  const hasDeliveryAttention = isRecord(snapshot.attention) && hasOwn(snapshot.attention, "delivery_attention");
  const attention = exactRecord(
    snapshot.attention,
    hasDeliveryAttention
      ? ["automatic_recovery", "delivery_attention", "operator_required"]
      : ["automatic_recovery", "operator_required"],
  );
  collection(attention.automatic_recovery, "automatic");
  if (hasDeliveryAttention) collection(attention.delivery_attention, "operator");
  collection(attention.operator_required, "operator");
  const metrics = exactRecord(snapshot.metrics, ["token_total", "token_rate_5m"]);
  metric(metrics.token_total); metric(metrics.token_rate_5m);
  recentTurns(snapshot.recent_turns);
  if (hasRecentActivity) {
    const activity = exactRecord(snapshot.recent_activity, [
      "status", "window_events", "agents", "items", "content_included",
    ]);
    oneOf(activity.status, ["available", "unavailable"]);
    if (activity.window_events !== 200 || activity.content_included !== false) invalid();
    const seenAgents = new Set<string>();
    for (const raw of array(activity.agents, 64)) {
      const agent = exactRecord(raw, ["agent_id", "last_sequence", "last_occurred_at"]);
      const agentId = boundaryIdentifier(agent.agent_id);
      if (seenAgents.has(agentId)) invalid();
      seenAgents.add(agentId);
      integer(agent.last_sequence);
      utcTimestamp(agent.last_occurred_at);
    }
    let priorSequence = -1;
    for (const raw of array(activity.items, 12)) {
      const item = exactRecord(raw, ["sequence", "event_type", "origin", "destination", "occurred_at"]);
      const sequence = integer(item.sequence) as number;
      if (sequence <= priorSequence) invalid();
      priorSequence = sequence;
      text(item.event_type);
      boundaryIdentifier(item.origin);
      boundaryIdentifier(item.destination);
      utcTimestamp(item.occurred_at);
    }
  }
  if (hasTranscriptArchive) {
    const archive = exactRecord(snapshot.transcript_archive, [
      "status", "items", "total", "total_status", "lower_bound", "truncated", "content_included",
    ]);
    oneOf(archive.status, ["available", "unavailable"]);
    if (archive.content_included !== false) invalid();
    const totalStatus = oneOf(archive.total_status, ["exact", "capped", "unknown"]);
    const lowerBound = integer(archive.lower_bound) as number;
    if (totalStatus === "exact") {
      const total = integer(archive.total) as number;
      if (total !== lowerBound) invalid();
    } else if (archive.total !== null) invalid();
    boolean(archive.truncated);
    const archiveIds = new Set<string>();
    let priorCapturedAt = Number.MAX_SAFE_INTEGER;
    for (const raw of array(archive.items, 12)) {
      const item = exactRecord(raw, [
        "archive_id", "slot_id", "work_id", "generation", "outcome",
        "captured_at_us", "turn_count", "redaction_count",
      ]);
      const archiveId = boundaryIdentifier(item.archive_id);
      const slotId = boundaryIdentifier(item.slot_id);
      if (archiveIds.has(archiveId) || !workerIds.has(slotId)) invalid();
      archiveIds.add(archiveId);
      boundaryIdentifier(item.work_id);
      const generation = integer(item.generation) as number;
      if (generation < 1) invalid();
      oneOf(item.outcome, ["succeeded", "failed", "cancelled"]);
      const capturedAt = integer(item.captured_at_us) as number;
      if (capturedAt > priorCapturedAt) invalid();
      priorCapturedAt = capturedAt;
      const turnCount = integer(item.turn_count) as number;
      const redactionCount = integer(item.redaction_count) as number;
      if (turnCount > 16 || redactionCount > 64) invalid();
    }
  }
  if (hasSourceInbox) {
    const inbox = exactRecord(snapshot.source_inbox, [
      "status", "source_id", "runtime_status", "active_turn_id", "items",
      "total", "total_status", "lower_bound", "truncated",
    ]);
    oneOf(inbox.status, ["available", "unavailable"]);
    text(inbox.source_id);
    oneOf(inbox.runtime_status, ["active", "idle", "unavailable"]);
    text(inbox.active_turn_id, true);
    const totalStatus = oneOf(inbox.total_status, ["exact", "capped", "unknown"]);
    if (totalStatus === "exact") integer(inbox.total); else if (inbox.total !== null) invalid();
    integer(inbox.lower_bound); boolean(inbox.truncated);
    for (const raw of array(inbox.items, MAX_COLLECTION_ITEMS)) {
      const item = exactRecord(raw, ["id", "kind", "origin", "work_id", "state", "queued_at", "reason"]);
      text(item.id); oneOf(item.kind, ["completion_nudge", "message", "tool_output"]);
      text(item.origin); text(item.work_id, true);
      oneOf(item.state, ["queued", "delivering", "accepted", "committed", "attention"]);
      text(item.queued_at); text(item.reason, true);
    }
  }
  const refresh = exactRecord(snapshot.refresh, ["mode", "polling"]);
  if (refresh.mode !== "explicit" || refresh.polling !== "disabled") invalid();
}

const COMPOSER_DELIVERY_STATES = [
  "queued", "accepted", "committed", "uncertain", "failed", "rejected", "expired",
] as const;

/** Validate an ephemeral, explicitly fetched transcript for one selected thread. */
export function parseTranscriptBundle(
  value: unknown,
  expected: WorkerTranscriptTarget,
): TranscriptBundle {
  const cloned = cloneBoundary(value);
  const hasAnchor = isRecord(cloned) && hasOwn(cloned, "anchor_item_id");
  const bundle = exactRecord(cloned, [
    "thread_id", "slot_id", "work_id", "generation", "fetched_at", "expires_at", "turns", "redacted",
    ...(hasAnchor ? ["anchor_item_id"] : []),
  ]);
  boundaryIdentifier(bundle.thread_id);
  if (
    boundaryIdentifier(bundle.slot_id) !== boundaryIdentifier(expected.slot_id)
    || boundaryIdentifier(bundle.work_id) !== boundaryIdentifier(expected.work_id)
    || integer(bundle.generation) !== integer(expected.generation)
  ) invalid();
  const fetchedAt = utcTimestamp(bundle.fetched_at);
  const expiresAt = utcTimestamp(bundle.expires_at);
  if (Date.parse(expiresAt) <= Date.parse(fetchedAt)) invalid();
  if (hasAnchor) boundaryIdentifier(bundle.anchor_item_id, 64);

  let transcriptBytes = 0;
  let previousSequence = -1;
  for (const raw of array(bundle.turns, 25)) {
    const turn = exactRecord(raw, ["seq", "role", "kind", "preview", "state"]);
    const sequence = integer(turn.seq) as number;
    if (sequence <= previousSequence) invalid();
    previousSequence = sequence;
    oneOf(turn.role, ["user", "agent", "tool"]);
    oneOf(turn.kind, ["text", "tool_call", "tool_output", "steer"]);
    const preview = boundedBoundaryText(turn.preview, 2000, { multiline: true }) as string;
    transcriptBytes += new TextEncoder().encode(preview).byteLength;
    if (transcriptBytes > 32768) invalid();
    oneOf(turn.state, ["committed", "inflight", "uncertain"]);
  }

  const redactions = new Set<string>();
  for (const raw of array(bundle.redacted, 64)) {
    const path = boundedBoundaryText(raw, 256) as string;
    if (redactions.has(path)) invalid();
    redactions.add(path);
  }
  return bundle as unknown as TranscriptBundle;
}

/** Validate one immutable sanitized transcript captured at completion. */
export function parseArchivedTranscriptBundle(
  value: unknown,
  expected: ArchivedTranscriptTarget,
): ArchivedTranscriptBundle {
  const cloned = cloneBoundary(value);
  const bundle = exactRecord(cloned, [
    "archive_id", "thread_id", "slot_id", "work_id", "generation", "captured_at",
    "outcome", "turns", "redacted", "read_only",
  ]);
  if (
    boundaryIdentifier(bundle.archive_id) !== boundaryIdentifier(expected.archive_id)
    || boundaryIdentifier(bundle.slot_id) !== boundaryIdentifier(expected.slot_id)
    || boundaryIdentifier(bundle.work_id) !== boundaryIdentifier(expected.work_id)
    || integer(bundle.generation) !== integer(expected.generation)
  ) invalid();
  boundaryIdentifier(bundle.thread_id);
  utcTimestamp(bundle.captured_at);
  oneOf(bundle.outcome, ["succeeded", "failed", "cancelled"]);
  if (bundle.read_only !== true) invalid();

  let transcriptBytes = 0;
  const turns = array(bundle.turns, 16);
  turns.forEach((raw, index) => {
    const turn = exactRecord(raw, ["seq", "role", "kind", "preview", "state"]);
    if (integer(turn.seq) !== index) invalid();
    oneOf(turn.role, ["user", "agent"]);
    if (turn.kind !== "text") invalid();
    const preview = boundedBoundaryText(turn.preview, 2000, { multiline: true }) as string;
    if (!preview) invalid();
    transcriptBytes += new TextEncoder().encode(preview).byteLength;
    if (transcriptBytes > 32768) invalid();
    oneOf(turn.state, ["committed", "inflight"]);
  });
  const redactions = new Set<string>();
  for (const raw of array(bundle.redacted, 64)) {
    const path = boundedBoundaryText(raw, 256) as string;
    if (!path || redactions.has(path)) invalid();
    redactions.add(path);
  }
  return bundle as unknown as ArchivedTranscriptBundle;
}

/** Normalize and bind a composer request to the currently selected destination. */
export function parseComposerSubmit(
  value: unknown,
  expected: Pick<TranscriptBundle, "thread_id" | "slot_id" | "work_id" | "generation">,
): ComposerSubmit {
  const cloned = cloneBoundary(value);
  const hasAnchor = isRecord(cloned) && hasOwn(cloned, "anchor_item_id");
  const submit = exactRecord(cloned, [
    "thread_id", "slot_id", "work_id", "generation", "idempotency_key", "text", ...(hasAnchor ? ["anchor_item_id"] : []),
  ]);
  if (
    boundaryIdentifier(submit.thread_id) !== boundaryIdentifier(expected.thread_id)
    || boundaryIdentifier(submit.slot_id) !== boundaryIdentifier(expected.slot_id)
    || boundaryIdentifier(submit.work_id) !== boundaryIdentifier(expected.work_id)
    || integer(submit.generation) !== integer(expected.generation)
  ) invalid();
  if (
    typeof submit.idempotency_key !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(submit.idempotency_key)
  ) invalid();
  const normalized = (boundedBoundaryText(submit.text, 2000, { multiline: true }) as string).normalize("NFC");
  if (!normalized.trim() || normalized.split("\n").length - 1 > 20) invalid();
  if (/:\/\/[^/\s:@]+:[^/\s@]+@/u.test(normalized)) invalid();
  submit.text = normalized;
  if (hasAnchor) boundaryIdentifier(submit.anchor_item_id, 64);
  return submit as unknown as ComposerSubmit;
}

/** Validate one authoritative delivery receipt without treating acceptance as commit. */
export function parseComposerReceipt(
  value: unknown,
  expected: Pick<TranscriptBundle, "thread_id" | "slot_id" | "work_id" | "generation">,
): ComposerReceipt {
  const cloned = cloneBoundary(value);
  const receipt = exactRecord(cloned, [
    "thread_id", "slot_id", "work_id", "generation", "item_id", "state", "queued_at", "reason",
  ]);
  if (
    boundaryIdentifier(receipt.thread_id) !== boundaryIdentifier(expected.thread_id)
    || boundaryIdentifier(receipt.slot_id) !== boundaryIdentifier(expected.slot_id)
    || boundaryIdentifier(receipt.work_id) !== boundaryIdentifier(expected.work_id)
    || integer(receipt.generation) !== integer(expected.generation)
  ) invalid();
  boundaryIdentifier(receipt.item_id, 64);
  oneOf(receipt.state, COMPOSER_DELIVERY_STATES);
  utcTimestamp(receipt.queued_at);
  boundedBoundaryText(receipt.reason, 280, { nullable: true });
  return receipt as unknown as ComposerReceipt;
}

/** Reject an unknown command payload before it reaches the view. */
export function parseCockpitSnapshot(value: unknown): CockpitSnapshot {
  let snapshot: unknown;
  try {
    snapshot = structuredClone(value);
  } catch {
    invalid();
  }
  validateSnapshot(snapshot);
  return snapshot;
}

export function collectionCount<T>(collection: Collection<T>): string {
  if (collection.total_status === "exact" && collection.total !== null) {
    return String(collection.total);
  }
  if (collection.total_status === "capped") return `\u2265${collection.lower_bound}`;
  return "\u2014";
}

export function formatReason(reason: string | null | undefined): string {
  if (!reason) return "No reason recorded";
  return reason.replaceAll("_", " ");
}

export function shortIdentity(value: string | null | undefined): string {
  if (!value) return "Unassigned";
  if (value.length <= 22) return value;
  return `${value.slice(0, 9)}\u2026${value.slice(-7)}`;
}

export function attentionGroups(snapshot: CockpitSnapshot): {
  automatic: Collection<AttentionItem>;
  delivery: Collection<AttentionItem>;
  operator: Collection<AttentionItem>;
} {
  if (snapshot.attention.delivery_attention) {
    return {
      automatic: snapshot.attention.automatic_recovery,
      delivery: snapshot.attention.delivery_attention,
      operator: snapshot.attention.operator_required,
    };
  }

  const source = snapshot.attention.operator_required;
  const deliveryItems = source.items.filter((item) => item.kind === "callback_attention");
  const operatorItems = source.items.filter((item) => item.kind !== "callback_attention");
  const split = (items: AttentionItem[]): Collection<AttentionItem> => ({
    status: source.status,
    items,
    total: source.total_status === "exact" ? items.length : null,
    total_status: source.total_status,
    lower_bound: items.length,
    truncated: source.truncated,
  });
  return {
    automatic: snapshot.attention.automatic_recovery,
    delivery: split(deliveryItems),
    operator: split(operatorItems),
  };
}
