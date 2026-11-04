import { invoke } from "@tauri-apps/api/core";
import { fetchSourceInbox, parseSourceChange, parseSourceDelivery, parseSourceInbox, parseSourceInspection, parseSourceThreads, SourceInboxUnsupportedError, watchSourceChanges } from "./source";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

describe("Codex source bridge", () => {
  it("accepts only closed metadata change notifications", () => {
    expect(parseSourceChange({ method: "turn/started" })).toEqual({ method: "turn/started" });
    expect(parseSourceChange({ method: "turn/completed" })).toEqual({ method: "turn/completed" });
    expect(parseSourceChange({ method: "thread/status/changed" })).toEqual({ method: "thread/status/changed" });
    expect(() => parseSourceChange({ method: "item/agentMessage/delta" })).toThrow(/source_protocol_invalid/);
    expect(() => parseSourceChange({ method: "turn/started", params: { text: "must not cross" } })).toThrow(/source_protocol_invalid/);
  });

  it("shares one native source wait across overlapping watchers and re-arms after settlement", async () => {
    vi.mocked(invoke).mockReset();
    let resolveFirst!: (value: unknown) => void;
    const firstNative = new Promise<unknown>((resolve) => { resolveFirst = resolve; });
    vi.mocked(invoke)
      .mockImplementationOnce(() => firstNative)
      .mockResolvedValueOnce({ method: "turn/completed" });

    const first = watchSourceChanges();
    const second = watchSourceChanges();
    expect(first).toBe(second);
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith("source_watch");

    resolveFirst({ method: "turn/started" });
    await expect(first).resolves.toEqual({ method: "turn/started" });
    await expect(second).resolves.toEqual({ method: "turn/started" });

    await expect(watchSourceChanges()).resolves.toEqual({ method: "turn/completed" });
    expect(invoke).toHaveBeenCalledTimes(2);
  });

  it("projects only bounded thread metadata", () => {
    expect(parseSourceThreads({ data: [{
      id: "thread-1", name: "Example", cwd: "/repo", source: "appServer",
      created_at: 1, updated_at: 2, status: { type: "active", active_flags: ["waiting"] },
    }], next_cursor: null, backwards_cursor: null })).toEqual([expect.objectContaining({
      id: "thread-1", runtimeStatus: "active", activeFlags: ["waiting"],
    })]);
  });

  it("validates an exact metadata-only per-thread inbox and preserves accepted", () => {
    const inbox = {
      status: "available", source_id: "thread-1", runtime_status: "active", active_turn_id: null,
      items: [{
        id: "callback-1", kind: "completion_nudge", origin: "control-1", work_id: "work-1",
        state: "accepted", queued_at: "2026-09-10T20:00:00.123456Z", reason: null,
      }],
      total: 1, total_status: "exact", lower_bound: 1, truncated: false,
    };
    expect(parseSourceInbox(inbox, "thread-1").items[0].state).toBe("accepted");
    expect(() => parseSourceInbox({ ...inbox, source_id: "thread-2" }, "thread-1")).toThrow(/source_binding_changed/);
    expect(() => parseSourceInbox({ ...inbox, items: [{ ...inbox.items[0], content: "must not cross" }] }, "thread-1")).toThrow(/source_protocol_invalid/);
    expect(() => parseSourceInbox({ ...inbox, items: [{ ...inbox.items[0], state: "committed" }] }, "thread-1")).toThrow(/source_protocol_invalid/);
    expect(() => parseSourceInbox({ ...inbox, items: [{ ...inbox.items[0], state: "attention", reason: null }] }, "thread-1")).toThrow(/source_protocol_invalid/);
    expect(() => parseSourceInbox({
      ...inbox, items: [], total: null, total_status: "capped", lower_bound: 13, truncated: true,
    }, "thread-1")).toThrow(/source_protocol_invalid/);
  });

  it("uses legacy fallback signalling only for an exact unsupported-operation error", async () => {
    vi.mocked(invoke).mockReset();
    vi.mocked(invoke).mockRejectedValueOnce({ code: "unsupported_operation", message: "newer controller required" });
    await expect(fetchSourceInbox("thread-1")).rejects.toBeInstanceOf(SourceInboxUnsupportedError);

    const failure = { code: "source_inbox_protocol", message: "invalid response" };
    vi.mocked(invoke).mockRejectedValueOnce(failure);
    await expect(fetchSourceInbox("thread-1")).rejects.toBe(failure);
  });

  it("keeps explicit transcript content in the inspection value", () => {
    const result = parseSourceInspection({
      thread_id: "thread-1", active_turn_id: "turn-1",
      thread: { id: "thread-1", turns: [{ id: "turn-1", status: "inProgress", items: [
        { type: "userMessage", content: [{ type: "text", text: "hello" }] },
        { type: "reasoning", text: "private" },
        { type: "agentMessage", text: "hi" },
      ] }] },
    }, "thread-1");
    expect(result.turns[0].lines).toEqual([{ role: "user", text: "hello" }, { role: "agent", text: "hi" }]);
    expect(JSON.stringify(result)).not.toContain("private");
  });

  it("requires exact delivery correlation and preserves unknown", () => {
    const id = "123e4567-e89b-42d3-a456-426614174000";
    expect(parseSourceDelivery({
      endpoint: "turn/steer",
      thread_id: "thread-1",
      transitions: [{ message_id: id, state: "accepted", reason: "request_written" }, { message_id: id, state: "unknown", reason: "outcome_uncertain" }],
      receipt: { message_id: id, route_id: null, state: "unknown", turn_id: null, reason: "outcome_uncertain" },
    }, "thread-1", id).state).toBe("unknown");
  });
});
