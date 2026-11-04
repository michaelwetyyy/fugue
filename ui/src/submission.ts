import { invoke } from "@tauri-apps/api/core";

export type AgentLifecycle = "disposable" | "persistent";
export type SubmissionState = "accepted" | "busy" | "rejected";
export type PersistentSessionState = "active" | "closed" | "attention" | "unavailable";

export interface TaskSubmission {
  submission_id: string;
  lane: string;
  repository: string;
  scope: string[];
  objective: string;
  agent_lifecycle: AgentLifecycle;
  reservation_attempt: number;
}

export interface TaskSubmissionResult {
  submission_id: string;
  work_id: string;
  lane: string;
  state: SubmissionState;
  agent_lifecycle: AgentLifecycle;
  child_agents: "allowed";
  reservation_attempt: number;
}

export interface TaskResult {
  submission_id: string;
  reservation_attempt: number;
  state: "waiting" | "completed" | "not_started";
  outcome: "succeeded" | "failed" | "cancelled" | null;
  result_ref: string | null;
  text: string | null;
  persistent_session_state: PersistentSessionState | null;
}

export interface TaskSessionCloseResult {
  submission_id: string;
  reservation_attempt: number;
  state: "closed" | "attention";
  reason: "persistent_session_attention" | null;
}

const LANES = new Set(["tensorhost", "homelab", "personal", "control", "hands-off"]);
const SAFE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasUnsafeText(value: string): boolean {
  return [...value].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code === 0 || code === 0x7f || code === 0x061c || code === 0x200e || code === 0x200f ||
      (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069);
  });
}

export function parseScope(value: string): string[] {
  return value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
}

export function validateSubmission(input: TaskSubmission): string | null {
  if (!SAFE_ID.test(input.submission_id)) return "The submission identity is invalid.";
  if (!Number.isInteger(input.reservation_attempt) || input.reservation_attempt < 1 || input.reservation_attempt > 32) return "The retry generation is invalid.";
  if (!LANES.has(input.lane)) return "Choose a lane.";
  if (!input.repository.startsWith("/") || input.repository.length > 4096 || hasUnsafeText(input.repository)) {
    return "Enter an absolute repository path.";
  }
  if (!input.objective.trim() || new TextEncoder().encode(input.objective).length > 4096 || hasUnsafeText(input.objective)) {
    return "Describe one objective in 4,096 bytes or fewer.";
  }
  if (!input.scope.length || input.scope.length > 32) return "Add between 1 and 32 scoped paths.";
  const seen = new Set<string>();
  for (const path of input.scope) {
    const parts = path.split("/");
    if (!path || path.startsWith("/") || path.includes("\\") || path.length > 1024 || hasUnsafeText(path) ||
      parts.some((part) => !part || part === "." || part === ".." || part.toLowerCase() === ".git")) {
      return `Scope path “${path || "empty"}” is invalid.`;
    }
    const key = path.normalize("NFKC").toLowerCase();
    if (seen.has(key)) return "Remove duplicate scope paths.";
    seen.add(key);
  }
  return null;
}

export function parseSubmissionResult(value: unknown): TaskSubmissionResult {
  if (!isRecord(value)) throw new Error("Fugue returned an invalid task result.");
  const expected = ["agent_lifecycle", "child_agents", "lane", "reservation_attempt", "state", "submission_id", "work_id"];
  const attempt = value.reservation_attempt;
  if (Object.keys(value).sort().join("|") !== expected.sort().join("|") ||
    typeof value.submission_id !== "string" || !SAFE_ID.test(value.submission_id) ||
    typeof value.work_id !== "string" || value.work_id.length > 256 ||
    typeof value.lane !== "string" || !LANES.has(value.lane) ||
    !["accepted", "busy", "rejected"].includes(String(value.state)) ||
    !["disposable", "persistent"].includes(String(value.agent_lifecycle)) ||
    value.child_agents !== "allowed" || typeof attempt !== "number" ||
    !Number.isInteger(attempt) || attempt < 1 || attempt > 32) {
    throw new Error("Fugue returned an invalid task result.");
  }
  return value as unknown as TaskSubmissionResult;
}

export async function submitTask(input: TaskSubmission): Promise<TaskSubmissionResult> {
  const issue = validateSubmission(input);
  if (issue) throw new Error(issue);
  return parseSubmissionResult(await invoke<unknown>("task_submit", { input }));
}

export async function fetchTaskResult(
  submissionId: string,
  reservationAttempt: number,
): Promise<TaskResult> {
  if (!SAFE_ID.test(submissionId) || !Number.isInteger(reservationAttempt) || reservationAttempt < 1 || reservationAttempt > 32) {
    throw new Error("The task identity is invalid.");
  }
  const value = await invoke<unknown>("task_result", {
    input: { submission_id: submissionId, reservation_attempt: reservationAttempt },
  });
  if (!isRecord(value)) throw new Error("Fugue returned an invalid task result.");
  const expected = ["outcome", "persistent_session_state", "reservation_attempt", "result_ref", "state", "submission_id", "text"];
  const state = String(value.state);
  const outcome = value.outcome;
  const attempt = value.reservation_attempt;
  if (Object.keys(value).sort().join("|") !== expected.sort().join("|") ||
    value.submission_id !== submissionId || typeof attempt !== "number" || !Number.isInteger(attempt) || attempt !== reservationAttempt ||
    !["waiting", "completed", "not_started"].includes(state) ||
    !(outcome === null || ["succeeded", "failed", "cancelled"].includes(String(outcome))) ||
    !(value.result_ref === null || (typeof value.result_ref === "string" && value.result_ref.length <= 256)) ||
    !(value.text === null || (typeof value.text === "string" && new TextEncoder().encode(value.text).length <= 49_152)) ||
    !(value.persistent_session_state === null || ["active", "closed", "attention", "unavailable"].includes(String(value.persistent_session_state))) ||
    (state === "completed" && (outcome === null || typeof value.result_ref !== "string")) ||
    (state !== "completed" && (outcome !== null || value.result_ref !== null || value.text !== null))) {
    throw new Error("Fugue returned an invalid task result.");
  }
  return value as unknown as TaskResult;
}

export async function closePersistentTask(
  submissionId: string,
  reservationAttempt: number,
): Promise<TaskSessionCloseResult> {
  if (!SAFE_ID.test(submissionId) || !Number.isInteger(reservationAttempt) || reservationAttempt < 1 || reservationAttempt > 32) {
    throw new Error("The task identity is invalid.");
  }
  const value = await invoke<unknown>("task_close", {
    input: { submission_id: submissionId, reservation_attempt: reservationAttempt },
  });
  if (!isRecord(value)) throw new Error("Fugue returned an invalid close result.");
  const expected = ["reason", "reservation_attempt", "state", "submission_id"];
  if (Object.keys(value).sort().join("|") !== expected.sort().join("|") ||
    value.submission_id !== submissionId || value.reservation_attempt !== reservationAttempt ||
    !["closed", "attention"].includes(String(value.state)) ||
    !((value.state === "closed" && value.reason === null) ||
      (value.state === "attention" && value.reason === "persistent_session_attention"))) {
    throw new Error("Fugue returned an invalid close result.");
  }
  return value as unknown as TaskSessionCloseResult;
}
