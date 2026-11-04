import { LANE_META, type CockpitSnapshot, type Worker } from "../model";

function worker(slotId: string, lane: string, position: number): Worker {
  return {
    slot_id: slotId,
    lane,
    position,
    slot_state: "clear",
    display_name: `session-${slotId} · ${slotId}`,
    session: { status: "available", ref: `session-${slotId}` },
    pane: { status: "unavailable", ref: null },
    work_id: null,
    agent_lifecycle: null,
    owner_id: null,
    assignment_id: null,
    attempt: null,
    transport: {
      status: "available",
      reason: null,
      id: null,
      state: "idle",
      generation: null,
      acknowledgement_id: null,
      error_code: null,
      adapter: { status: "available", kind: "opencode-http-sse-v1", reason: null },
    },
    completion: {
      status: "available",
      reason: null,
      id: null,
      registration_state: "not-applicable",
      route_state: "not-applicable",
      callback_state: "not-applicable",
      callback_adapter: { status: "available", reason: null },
    },
    recovery: {
      status: "available",
      reason: null,
      target_id: null,
      phase: "not-applicable",
      circuit_state: "not-applicable",
      episode_state: "not-applicable",
      timer_state: "not-applicable",
    },
    recent_turns: {
      status: "unavailable",
      reason: "privacy_safe_turn_metadata_not_recorded",
      limit: 2,
      items: [],
      content_included: false,
    },
  };
}

export function snapshotFixture(): CockpitSnapshot {
  const workers = LANE_META.flatMap((lane) =>
    Array.from({ length: lane.capacity }, (_, index) => worker(`${lane.id}-${index + 1}`, lane.id, index + 1)),
  );
  workers[0] = {
    ...workers[0],
    slot_state: "assigned",
    work_id: "work-42",
    agent_lifecycle: "persistent",
    assignment_id: "assignment-42",
    attempt: 1,
    transport: { ...workers[0].transport, id: "transport-42", state: "reserved", generation: 1 },
  };
  const slots = workers.map((item) => ({
    slot_id: item.slot_id,
    lane: item.lane,
    position: item.position,
    state: item.slot_state,
    assignment_id: item.assignment_id,
    work_id: item.work_id,
  }));
  return {
    projection_version: 1,
    snapshot_version: {
      event_sequence: 27,
      migration_version: "014_durable_completion_results.sql",
      digest: "a".repeat(64),
    },
    availability: { status: "available", errors: [] },
    topology: {
      lanes: LANE_META.map((lane) => lane.id),
      expected_slots: 13,
      observed_slots: 13,
      observed_status: "exact",
    },
    slots,
    worker_graph: {
      workers,
      edges: [
        { from: "tensorhost-1", to: "work-42", kind: "runs" },
        { from: "tensorhost-1", to: "transport-42", kind: "transport" },
      ],
    },
    queue: {
      status: "available",
      items: [{
        work_id: "work-next",
        sequence: 28,
        queue_order: 1,
        lane: "homelab",
        state: "queued",
        policy: "allowed",
        attempt: 0,
        enqueued_at: "2026-09-03T10:00:00Z",
      }],
      total: 1,
      total_status: "exact",
      lower_bound: 1,
      truncated: false,
    },
    attention: {
      automatic_recovery: {
        status: "available",
        items: [],
        total: 0,
        total_status: "exact",
        lower_bound: 0,
        truncated: false,
      },
      operator_required: {
        status: "available",
        items: [
          { kind: "callback_attention", id: "callback-1", work_id: "work-42", generation: 1, state: "attention", reason: "codex_nonzero_exit" },
          { kind: "backend_attention", id: "backend-1", scope: "controller", state: "attention", reason: "backend_degraded" },
        ],
        total: 2,
        total_status: "exact",
        lower_bound: 2,
        truncated: false,
      },
    },
    metrics: {
      token_total: { status: "unavailable", reason: "no_durable_token_samples" },
      token_rate_5m: { status: "unavailable", reason: "no_durable_token_samples" },
    },
    recent_turns: {
      status: "unavailable",
      reason: "privacy_safe_turn_metadata_not_recorded",
      limit: 2,
      items: [],
      content_included: false,
    },
    source_inbox: {
      status: "available",
      source_id: "codex",
      runtime_status: "active",
      active_turn_id: "turn-active-1",
      items: [
        {
          id: "source-message-1",
          kind: "completion_nudge",
          origin: "control-1",
          work_id: "work-42",
          state: "queued",
          queued_at: "2026-09-06T00:00:00Z",
          reason: null,
        },
      ],
      total: 1,
      total_status: "exact",
      lower_bound: 1,
      truncated: false,
    },
    refresh: { mode: "explicit", polling: "disabled" },
  };
}
