import {
  attentionGroups,
  collectionCount,
  parseArchivedTranscriptBundle,
  parseCockpitSnapshot,
  parseComposerReceipt,
  parseComposerSubmit,
  parseTranscriptBundle,
} from "./model";
import { snapshotFixture } from "./test/fixture";

describe("cockpit model", () => {
  it("accepts projection version one and rejects unsupported payloads", () => {
    const snapshot = snapshotFixture();
    const parsed = parseCockpitSnapshot(snapshot);
    expect(parsed).not.toBe(snapshot);
    expect(parsed.worker_graph).not.toBe(snapshot.worker_graph);
    snapshot.availability.status = "unavailable";
    expect(parsed.availability.status).toBe("available");
    const legacyWorker = snapshotFixture() as unknown as { worker_graph: { workers: Array<Record<string, unknown>> } };
    delete legacyWorker.worker_graph.workers[0].agent_lifecycle;
    expect(() => parseCockpitSnapshot(legacyWorker)).not.toThrow();
    expect(() => parseCockpitSnapshot({ projection_version: 2 })).toThrow(/unsupported/i);
  });

  it("accepts the staged 11-slot controller and the current 13-slot controller", () => {
    const current = snapshotFixture();
    expect(current.topology!.expected_slots).toBe(13);
    expect(() => parseCockpitSnapshot(current)).not.toThrow();

    const staged = snapshotFixture();
    staged.topology!.expected_slots = 11;
    staged.topology!.observed_slots = 11;
    staged.slots = staged.slots!.filter((slot) => !["control-2", "control-3"].includes(slot.slot_id));
    staged.worker_graph.workers = staged.worker_graph.workers.filter(
      (worker) => !["control-2", "control-3"].includes(worker.slot_id),
    );
    expect(() => parseCockpitSnapshot(staged)).not.toThrow();

    staged.topology!.expected_slots = 12;
    expect(() => parseCockpitSnapshot(staged)).toThrow(/unsupported/i);
  });

  it("rejects malformed nested and privacy-unsafe controller data", () => {
    const fixture = snapshotFixture();
    const malformed = {
      ...fixture,
      worker_graph: { workers: [], edges: [] },
    };
    expect(() => parseCockpitSnapshot(malformed)).toThrow(/unsupported/i);

    const transcript = snapshotFixture() as unknown as Record<string, unknown>;
    const turns = transcript.recent_turns as Record<string, unknown>;
    turns.content_included = true;
    expect(() => parseCockpitSnapshot(transcript)).toThrow(/unsupported/i);

    const unknown = snapshotFixture() as unknown as Record<string, unknown>;
    (unknown.availability as Record<string, unknown>).detail = "not in schema";
    expect(() => parseCockpitSnapshot(unknown)).toThrow(/unsupported/i);

    const wrongLane = snapshotFixture();
    wrongLane.worker_graph.workers[0].lane = "personal";
    expect(() => parseCockpitSnapshot(wrongLane)).toThrow(/unsupported/i);

    const oversized = snapshotFixture() as unknown as Record<string, unknown>;
    (oversized.snapshot_version as Record<string, unknown>).migration_version = "x".repeat(161);
    expect(() => parseCockpitSnapshot(oversized)).toThrow(/unsupported/i);

    const missingLifecycle = snapshotFixture();
    missingLifecycle.worker_graph.workers[0].agent_lifecycle = null;
    expect(() => parseCockpitSnapshot(missingLifecycle)).not.toThrow();

    const staleLifecycle = snapshotFixture();
    staleLifecycle.worker_graph.workers[1].agent_lifecycle = "persistent";
    expect(() => parseCockpitSnapshot(staleLifecycle)).toThrow(/unsupported/i);

    const wrongPosition = snapshotFixture();
    wrongPosition.worker_graph.workers[0].position = 999;
    expect(() => parseCockpitSnapshot(wrongPosition)).toThrow(/unsupported/i);

    const spoofedEdge = snapshotFixture();
    spoofedEdge.worker_graph.edges[0].to = "pretend-work";
    expect(() => parseCockpitSnapshot(spoofedEdge)).toThrow(/unsupported/i);

    const spoofedQueue = snapshotFixture();
    spoofedQueue.queue.items[0].lane = "not-a-lane";
    expect(() => parseCockpitSnapshot(spoofedQueue)).toThrow(/unsupported/i);

    const invisibleText = snapshotFixture();
    invisibleText.source_inbox!.items[0].origin = "control\u200b-1";
    expect(() => parseCockpitSnapshot(invisibleText)).toThrow(/unsupported/i);
  });

  it("separates callback delivery attention from operator attention", () => {
    const snapshot = snapshotFixture();
    expect(() => parseCockpitSnapshot(snapshot)).not.toThrow();
    const groups = attentionGroups(snapshot);
    expect(groups.delivery.items.map((item) => item.kind)).toEqual(["callback_attention"]);
    expect(groups.operator.items.map((item) => item.kind)).toEqual(["backend_attention"]);
    expect(collectionCount(groups.delivery)).toBe("1");

    delete snapshot.attention.delivery_attention;
    expect(() => parseCockpitSnapshot(snapshot)).not.toThrow();
  });

  it("accepts opaque persistent-session attention without private authority", () => {
    const snapshot = snapshotFixture();
    const item = {
      kind: "persistent_session_attention",
      id: "persistent-7",
      work_id: null,
      generation: 0,
      state: "attention",
      reason: "persistent_delete_uncertain",
    };
    snapshot.attention.operator_required.items.push(item);
    snapshot.attention.operator_required.total = 3;
    snapshot.attention.operator_required.lower_bound = 3;
    const parsed = parseCockpitSnapshot(snapshot);
    expect(attentionGroups(parsed).operator.items).toContainEqual(item);

    const leaked = snapshotFixture() as unknown as { attention: { operator_required: { items: Array<Record<string, unknown>>; total: number; lower_bound: number } } };
    leaked.attention.operator_required.items.push({ ...item, scope_hash: "9".repeat(64) });
    leaked.attention.operator_required.total = 3;
    leaked.attention.operator_required.lower_bound = 3;
    expect(() => parseCockpitSnapshot(leaked)).toThrow(/unsupported/i);

    const rebound = snapshotFixture() as unknown as { attention: { operator_required: { items: Array<Record<string, unknown>>; total: number; lower_bound: number } } };
    rebound.attention.operator_required.items.push({ ...item, work_id: "private-work" });
    rebound.attention.operator_required.total = 3;
    rebound.attention.operator_required.lower_bound = 3;
    expect(() => parseCockpitSnapshot(rebound)).toThrow(/unsupported/i);
  });

  it("accepts only bounded metadata in the optional source inbox", () => {
    const snapshot = snapshotFixture();
    expect(() => parseCockpitSnapshot(snapshot)).not.toThrow();

    const contentBearing = snapshotFixture() as unknown as Record<string, unknown>;
    const inbox = contentBearing.source_inbox as { items: Array<Record<string, unknown>> };
    inbox.items[0].content = "message text must never enter the projection";
    expect(() => parseCockpitSnapshot(contentBearing)).toThrow(/unsupported/i);

    const accepted = snapshotFixture();
    accepted.source_inbox!.items[0].state = "accepted";
    expect(() => parseCockpitSnapshot(accepted)).not.toThrow();

    const legacyCapped = snapshotFixture();
    legacyCapped.source_inbox!.total = null;
    legacyCapped.source_inbox!.total_status = "capped";
    legacyCapped.source_inbox!.lower_bound = 2;
    legacyCapped.source_inbox!.truncated = true;
    expect(() => parseCockpitSnapshot(legacyCapped)).not.toThrow();

    const legacyExactSubset = snapshotFixture();
    legacyExactSubset.source_inbox!.total = 5;
    legacyExactSubset.source_inbox!.lower_bound = 5;
    legacyExactSubset.source_inbox!.truncated = true;
    expect(() => parseCockpitSnapshot(legacyExactSubset)).not.toThrow();

    const legacy = snapshotFixture() as unknown as Record<string, unknown>;
    delete legacy.source_inbox;
    expect(() => parseCockpitSnapshot(legacy)).not.toThrow();
  });

  it("accepts only exact child topology and metadata-only activity recency", () => {
    const snapshot = snapshotFixture();
    snapshot.worker_graph.workers[0].source_id = "codex-thread-1";
    snapshot.worker_graph.subagents = [{
      id: "child-session-1",
      parent_session_id: "root-session-1",
      parent_slot_id: snapshot.worker_graph.workers[0].slot_id,
      parent_work_id: snapshot.worker_graph.workers[0].work_id!,
      state: "terminal",
      updated_at: "2026-09-06T18:00:00Z",
    }];
    snapshot.worker_graph.edges.push({
      from: snapshot.worker_graph.workers[0].slot_id,
      to: "child-session-1",
      kind: "delegates",
    });
    snapshot.recent_activity = {
      status: "available",
      window_events: 200,
      agents: [{
        agent_id: snapshot.worker_graph.workers[0].slot_id,
        last_sequence: 27,
        last_occurred_at: "2026-09-06T18:00:00Z",
      }],
      items: [{
        sequence: 27,
        event_type: "callback.delivered",
        origin: snapshot.worker_graph.workers[0].slot_id,
        destination: "source:codex-thread-1",
        occurred_at: "2026-09-06T18:00:00Z",
      }],
      content_included: false,
    };

    expect(() => parseCockpitSnapshot(snapshot)).not.toThrow();

    const contentBearing = structuredClone(snapshot);
    contentBearing.recent_activity!.content_included = true as false;
    expect(() => parseCockpitSnapshot(contentBearing)).toThrow(/unsupported/i);

    const wrongParent = structuredClone(snapshot);
    wrongParent.worker_graph.subagents![0].parent_slot_id = "unknown-1";
    expect(() => parseCockpitSnapshot(wrongParent)).toThrow(/unsupported/i);
  });

  it("validates metadata-only completion transcript archives", () => {
    const snapshot = snapshotFixture();
    snapshot.transcript_archive = {
      status: "available",
      items: [{
        archive_id: "completion-result-1",
        slot_id: "tensorhost-1",
        work_id: "work-archived-1",
        generation: 1,
        outcome: "succeeded",
        captured_at_us: 1_787_000_000_000_000,
        turn_count: 2,
        redaction_count: 1,
      }],
      total: 1,
      total_status: "exact",
      lower_bound: 1,
      truncated: false,
      content_included: false,
    };
    expect(() => parseCockpitSnapshot(snapshot)).not.toThrow();
    const contentBearing = structuredClone(snapshot);
    contentBearing.transcript_archive!.content_included = true as false;
    expect(() => parseCockpitSnapshot(contentBearing)).toThrow(/unsupported/i);
    const wrongSlot = structuredClone(snapshot);
    wrongSlot.transcript_archive!.items[0].slot_id = "unknown-1";
    expect(() => parseCockpitSnapshot(wrongSlot)).toThrow(/unsupported/i);
  });

  it("validates exact read-only archived transcript bundles", () => {
    const target = {
      archive_id: "completion-result-1",
      slot_id: "tensorhost-1",
      work_id: "work-archived-1",
      generation: 1,
    };
    const bundle = {
      ...target,
      thread_id: "session-archived-1",
      captured_at: "2026-09-09T14:00:00Z",
      outcome: "succeeded",
      turns: [{ seq: 0, role: "agent", kind: "text", preview: "sanitized result", state: "committed" }],
      redacted: ["messages[0].parts[1]"],
      read_only: true,
    };
    const parsed = parseArchivedTranscriptBundle(bundle, target);
    expect(parsed.read_only).toBe(true);
    expect(parsed.turns[0].preview).toBe("sanitized result");
    expect(() => parseArchivedTranscriptBundle({ ...bundle, read_only: false }, target)).toThrow(/unsupported/i);
    expect(() => parseArchivedTranscriptBundle({ ...bundle, work_id: "other-work" }, target)).toThrow(/unsupported/i);
    expect(() => parseArchivedTranscriptBundle({ ...bundle, turns: [{ ...bundle.turns[0], seq: 2 }] }, target)).toThrow(/unsupported/i);
  });

  it("validates ephemeral transcripts and exact-destination composer payloads", () => {
    const bundle = {
      thread_id: "thread-1",
      slot_id: "homelab-1",
      work_id: "work-1",
      generation: 2,
      fetched_at: "2026-09-06T11:00:00Z",
      expires_at: "2026-09-06T11:05:00Z",
      turns: [
        { seq: 1, role: "agent", kind: "text", preview: "bounded result", state: "committed" },
      ],
      redacted: ["turns[0].tool.input"],
    };
    const target = { slot_id: "homelab-1", work_id: "work-1", generation: 2 };
    const parsed = parseTranscriptBundle(bundle, target);
    expect(parsed).not.toBe(bundle);
    expect(parsed.turns[0].preview).toBe("bounded result");
    expect(() => parseTranscriptBundle({ ...bundle, work_id: "work-2" }, target)).toThrow(/unsupported/i);
    expect(() => parseTranscriptBundle({ ...bundle, turns: [{ ...bundle.turns[0], preview: "x".repeat(2001) }] }, target)).toThrow(/unsupported/i);
    expect(() => parseTranscriptBundle({ ...bundle, turns: Array.from({ length: 17 }, (_, index) => ({ ...bundle.turns[0], seq: index, preview: "x".repeat(2000) })) }, target)).toThrow(/unsupported/i);

    const submit = parseComposerSubmit({
      thread_id: "thread-1",
      slot_id: "homelab-1",
      work_id: "work-1",
      generation: 2,
      idempotency_key: "123e4567-e89b-42d3-a456-426614174000",
      text: "Cafe\u0301",
    }, bundle);
    expect(submit.text).toBe("Café");
    expect(() => parseComposerSubmit({ ...submit, thread_id: "thread-2" }, bundle)).toThrow(/unsupported/i);
    expect(() => parseComposerSubmit({ ...submit, text: "https://user:pass@example.com" }, bundle)).toThrow(/unsupported/i);

    const receipt = parseComposerReceipt({
      thread_id: "thread-1",
      slot_id: "homelab-1",
      work_id: "work-1",
      generation: 2,
      item_id: "message-1",
      state: "accepted",
      queued_at: "2026-09-06T11:00:01Z",
      reason: null,
    }, bundle);
    expect(receipt.state).toBe("accepted");
    expect(receipt.state).not.toBe("committed");
  });
});
