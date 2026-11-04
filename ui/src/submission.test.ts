import { invoke } from "@tauri-apps/api/core";
import { closePersistentTask, fetchTaskResult, parseScope, submitTask, validateSubmission, type TaskSubmission } from "./submission";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

const input: TaskSubmission = {
  submission_id: "123e4567-e89b-12d3-a456-426614174000",
  lane: "homelab",
  repository: "/Users/example/project",
  scope: ["src/main.ts"],
  objective: "Review the boundary",
  agent_lifecycle: "disposable",
  reservation_attempt: 1,
};

describe("task submission boundary", () => {
  it("parses one relative scope per line", () => {
    expect(parseScope(" src/main.ts\n\ntests/main.test.ts ")).toEqual(["src/main.ts", "tests/main.test.ts"]);
  });

  it("rejects traversal and duplicate scope before invoking native code", () => {
    expect(validateSubmission({ ...input, scope: ["../escape"] })).toMatch(/invalid/i);
    expect(validateSubmission({ ...input, scope: ["src/main.ts", "SRC/main.ts"] })).toMatch(/duplicate/i);
  });

  it("invokes only the fixed task command and validates its result", async () => {
    vi.mocked(invoke).mockResolvedValue({
      submission_id: input.submission_id,
      work_id: "work-1",
      lane: "homelab",
      state: "accepted",
      agent_lifecycle: "disposable",
      child_agents: "allowed",
      reservation_attempt: 1,
    });
    await expect(submitTask(input)).resolves.toMatchObject({ work_id: "work-1" });
    expect(invoke).toHaveBeenCalledWith("task_submit", { input });
  });

  it("reads only the matching bounded durable result", async () => {
    vi.mocked(invoke).mockResolvedValue({
      submission_id: input.submission_id,
      reservation_attempt: 1,
      state: "completed",
      outcome: "succeeded",
      result_ref: "completion-result-one",
      text: "Bounded result",
      persistent_session_state: null,
    });
    await expect(fetchTaskResult(input.submission_id, 1)).resolves.toMatchObject({
      state: "completed",
      text: "Bounded result",
    });
    expect(invoke).toHaveBeenCalledWith("task_result", {
      input: { submission_id: input.submission_id, reservation_attempt: 1 },
    });
  });

  it("closes only the exact persistent task identity and validates terminal state", async () => {
    vi.mocked(invoke).mockResolvedValue({
      submission_id: input.submission_id,
      reservation_attempt: 1,
      state: "closed",
      reason: null,
    });
    await expect(closePersistentTask(input.submission_id, 1)).resolves.toEqual({
      submission_id: input.submission_id,
      reservation_attempt: 1,
      state: "closed",
      reason: null,
    });
    expect(invoke).toHaveBeenCalledWith("task_close", {
      input: { submission_id: input.submission_id, reservation_attempt: 1 },
    });
  });
});
