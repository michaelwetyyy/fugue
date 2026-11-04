import { invoke } from "@tauri-apps/api/core";
import type { SourceInbox } from "./model";

export type SourceRuntimeStatus = "not_loaded" | "idle" | "system_error" | "active";

export interface SourceThread {
  id: string;
  name: string | null;
  cwd: string;
  source: string;
  createdAt: number;
  updatedAt: number;
  runtimeStatus: SourceRuntimeStatus;
  activeFlags: string[];
}

export type SourceChangeMethod = "thread/status/changed" | "turn/started" | "turn/completed";

export interface SourceChange {
  method: SourceChangeMethod;
}

export interface SourceTranscriptTurn {
  id: string;
  status: string;
  lines: Array<{ role: "user" | "agent"; text: string }>;
}

export interface SourceInspection {
  threadId: string;
  activeTurnId: string | null;
  turns: SourceTranscriptTurn[];
}

export type SourceDeliveryState = "queued" | "accepted" | "committed" | "failed" | "unknown";

export interface SourceDeliveryOutcome {
  endpoint: "turn/steer" | "turn/start";
  messageId: string;
  routeId: string | null;
  state: SourceDeliveryState;
  turnId: string | null;
  reason: string;
  transitions: Array<{ messageId: string; state: SourceDeliveryState; reason: string }>;
}

export class SourceInboxUnsupportedError extends Error {
  constructor() {
    super("source_inbox_unsupported");
    this.name = "SourceInboxUnsupportedError";
  }
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("source_protocol_invalid");
  return value as Record<string, unknown>;
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const item = record(value);
  const actual = Object.keys(item).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error("source_protocol_invalid");
  return item;
}

function integer(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new Error("source_protocol_invalid");
  return value;
}

function utcTimestamp(value: unknown): string {
  const text = string(value, 64);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(text) || Number.isNaN(Date.parse(text))) throw new Error("source_protocol_invalid");
  return text;
}

function string(value: unknown, maximum = 16_384): string {
  if (typeof value !== "string" || !value || value.length > maximum) throw new Error("source_protocol_invalid");
  return value;
}

function nullableString(value: unknown, maximum = 16_384): string | null {
  return value === null || value === undefined ? null : string(value, maximum);
}

function runtime(value: unknown): { status: SourceRuntimeStatus; flags: string[] } {
  const item = record(value);
  const status = string(item.type, 32) as SourceRuntimeStatus;
  if (!["not_loaded", "idle", "system_error", "active"].includes(status)) throw new Error("source_protocol_invalid");
  if (status !== "active") return { status, flags: [] };
  if (!Array.isArray(item.active_flags) || item.active_flags.length > 32) throw new Error("source_protocol_invalid");
  return { status, flags: item.active_flags.map((flag) => string(flag, 128)) };
}

export function parseSourceInbox(value: unknown, expectedThreadId: string): SourceInbox {
  const inbox = exactRecord(value, [
    "status", "source_id", "runtime_status", "active_turn_id", "items",
    "total", "total_status", "lower_bound", "truncated",
  ]);
  if (inbox.status !== "available") throw new Error("source_protocol_invalid");
  const sourceId = string(inbox.source_id, 128);
  if (sourceId !== expectedThreadId) throw new Error("source_binding_changed");
  const runtimeStatus = string(inbox.runtime_status, 32) as SourceInbox["runtime_status"];
  if (!["active", "idle", "unavailable"].includes(runtimeStatus)) throw new Error("source_protocol_invalid");
  const activeTurnId = nullableString(inbox.active_turn_id, 128);
  if (!Array.isArray(inbox.items) || inbox.items.length > 12) throw new Error("source_protocol_invalid");
  const items = inbox.items.map((raw) => {
    const item = exactRecord(raw, ["id", "kind", "origin", "work_id", "state", "queued_at", "reason"]);
    const kind = string(item.kind, 32);
    if (kind !== "completion_nudge") throw new Error("source_protocol_invalid");
    const state = string(item.state, 32) as SourceInbox["items"][number]["state"];
    if (!["queued", "delivering", "accepted", "attention"].includes(state)) throw new Error("source_protocol_invalid");
    const reason = nullableString(item.reason, 1024);
    if ((state === "attention") !== (reason !== null)) throw new Error("source_protocol_invalid");
    return {
      id: string(item.id, 256),
      kind: "completion_nudge" as const,
      origin: string(item.origin, 256),
      work_id: nullableString(item.work_id, 256),
      state,
      queued_at: utcTimestamp(item.queued_at),
      reason,
    };
  });
  const totalStatus = string(inbox.total_status, 16) as SourceInbox["total_status"];
  if (totalStatus !== "exact" && totalStatus !== "capped") throw new Error("source_protocol_invalid");
  const total = inbox.total === null ? null : integer(inbox.total);
  const lowerBound = integer(inbox.lower_bound);
  if (typeof inbox.truncated !== "boolean") throw new Error("source_protocol_invalid");
  if (totalStatus === "exact") {
    if (total !== items.length || inbox.truncated || lowerBound !== items.length) throw new Error("source_protocol_invalid");
  } else if (total !== null || !inbox.truncated || items.length !== 12 || lowerBound !== 13) {
    throw new Error("source_protocol_invalid");
  }
  return {
    status: "available",
    source_id: sourceId,
    runtime_status: runtimeStatus,
    active_turn_id: activeTurnId,
    items,
    total,
    total_status: totalStatus,
    lower_bound: lowerBound,
    truncated: inbox.truncated,
  };
}

export function parseSourceChange(value: unknown): SourceChange {
  const item = record(value);
  if (Object.keys(item).length !== 1 || !("method" in item)) throw new Error("source_protocol_invalid");
  const method = string(item.method, 32) as SourceChangeMethod;
  if (!["thread/status/changed", "turn/started", "turn/completed"].includes(method)) throw new Error("source_protocol_invalid");
  return { method };
}

export function parseSourceThreads(value: unknown): SourceThread[] {
  const page = record(value);
  if (!Array.isArray(page.data) || page.data.length > 24) throw new Error("source_protocol_invalid");
  return page.data.map((raw) => {
    const thread = record(raw);
    const state = runtime(thread.status);
    if (typeof thread.created_at !== "number" || typeof thread.updated_at !== "number") throw new Error("source_protocol_invalid");
    return {
      id: string(thread.id, 128),
      name: nullableString(thread.name, 1024),
      cwd: string(thread.cwd),
      source: string(thread.source, 128),
      createdAt: thread.created_at,
      updatedAt: thread.updated_at,
      runtimeStatus: state.status,
      activeFlags: state.flags,
    };
  });
}

function textFromContent(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 64).flatMap((raw) => {
    const content = record(raw);
    if (content.type !== "text" || typeof content.text !== "string") return [];
    const text = content.text.slice(0, 8_192);
    return text.trim() ? [text] : [];
  });
}

function inspectTurn(value: unknown): SourceTranscriptTurn {
  const turn = record(value);
  const items = Array.isArray(turn.items) ? turn.items.slice(0, 128) : [];
  const lines: SourceTranscriptTurn["lines"] = [];
  for (const raw of items) {
    const item = record(raw);
    const role = item.type === "userMessage" ? "user" : item.type === "agentMessage" ? "agent" : null;
    if (role === null) continue;
    const texts = typeof item.text === "string" ? [item.text.slice(0, 8_192)] : textFromContent(item.content);
    for (const text of texts) if (text.trim()) lines.push({ role, text });
  }
  return { id: string(turn.id, 128), status: string(turn.status, 64), lines };
}

export function parseSourceInspection(value: unknown, expectedThreadId: string): SourceInspection {
  const envelope = record(value);
  const threadId = string(envelope.thread_id, 128);
  if (threadId !== expectedThreadId) throw new Error("source_binding_changed");
  const thread = record(envelope.thread);
  if (string(thread.id, 128) !== expectedThreadId || !Array.isArray(thread.turns) || thread.turns.length > 512) throw new Error("source_protocol_invalid");
  const activeTurnId = nullableString(envelope.active_turn_id, 128);
  const turns = thread.turns.map(inspectTurn);
  if (activeTurnId !== null && !turns.some((turn) => turn.id === activeTurnId && turn.status === "inProgress")) throw new Error("source_protocol_invalid");
  return { threadId, activeTurnId, turns };
}

function uuid4(): string {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function parseSourceDelivery(value: unknown, expectedThreadId: string, expectedMessageId: string): SourceDeliveryOutcome {
  const envelope = record(value);
  const endpoint = string(envelope.endpoint, 32);
  if (endpoint !== "turn/steer" && endpoint !== "turn/start") throw new Error("source_protocol_invalid");
  if (string(envelope.thread_id, 128) !== expectedThreadId) throw new Error("source_binding_changed");
  const receipt = record(envelope.receipt);
  const messageId = string(receipt.message_id, 36);
  if (messageId !== expectedMessageId) throw new Error("source_binding_changed");
  const state = string(receipt.state, 16) as SourceDeliveryState;
  if (!["queued", "accepted", "committed", "failed", "unknown"].includes(state)) throw new Error("source_protocol_invalid");
  if (!Array.isArray(envelope.transitions) || envelope.transitions.length > 4) throw new Error("source_protocol_invalid");
  const transitions = envelope.transitions.map((raw) => {
    const transition = record(raw);
    const transitionState = string(transition.state, 16) as SourceDeliveryState;
    if (string(transition.message_id, 36) !== messageId || !["queued", "accepted", "committed", "failed", "unknown"].includes(transitionState)) throw new Error("source_protocol_invalid");
    return { messageId, state: transitionState, reason: string(transition.reason, 128) };
  });
  return {
    endpoint,
    messageId,
    routeId: nullableString(receipt.route_id, 256),
    state,
    turnId: nullableString(receipt.turn_id, 128),
    reason: string(receipt.reason, 128),
    transitions,
  };
}

export async function fetchSourceThreads(): Promise<SourceThread[]> {
  return parseSourceThreads(await invoke<unknown>("source_threads"));
}

let sourceWatchFlight: Promise<SourceChange> | null = null;

export function watchSourceChanges(): Promise<SourceChange> {
  if (sourceWatchFlight !== null) return sourceWatchFlight;
  const flight = invoke<unknown>("source_watch").then(parseSourceChange);
  sourceWatchFlight = flight;
  flight.then(
    () => { if (sourceWatchFlight === flight) sourceWatchFlight = null; },
    () => { if (sourceWatchFlight === flight) sourceWatchFlight = null; },
  );
  return flight;
}

export async function fetchSourceInbox(threadId: string): Promise<SourceInbox> {
  let value: unknown;
  try {
    value = await invoke<unknown>("source_inbox", { input: { thread_id: threadId } });
  } catch (error) {
    if (error && typeof error === "object" && !Array.isArray(error)) {
      const candidate = error as Record<string, unknown>;
      if (
        Object.keys(candidate).sort().join("|") === "code|message"
        && candidate.code === "unsupported_operation"
        && typeof candidate.message === "string"
      ) throw new SourceInboxUnsupportedError();
    }
    throw error;
  }
  return parseSourceInbox(value, threadId);
}

export async function inspectSourceThread(threadId: string): Promise<SourceInspection> {
  return parseSourceInspection(await invoke<unknown>("source_inspect", { input: { thread_id: threadId } }), threadId);
}

export async function sendSourceMessage(inspection: SourceInspection, text: string): Promise<SourceDeliveryOutcome> {
  const messageId = uuid4();
  const value = await invoke<unknown>("source_compose", { input: {
    thread_id: inspection.threadId,
    expected_turn_id: inspection.activeTurnId,
    message_id: messageId,
    text,
  } });
  return parseSourceDelivery(value, inspection.threadId, messageId);
}
