import { invoke } from "@tauri-apps/api/core";
import {
  parseArchivedTranscriptBundle,
  parseComposerReceipt,
  parseComposerSubmit,
  parseTranscriptBundle,
  type ArchivedTranscriptBundle,
  type ArchivedTranscriptTarget,
  type ComposerReceipt,
  type TranscriptBundle,
  type WorkerTranscriptTarget,
} from "./model";

export async function fetchWorkerTranscript(
  target: WorkerTranscriptTarget,
): Promise<TranscriptBundle> {
  return parseTranscriptBundle(
    await invoke<unknown>("worker_transcript", { input: target }),
    target,
  );
}

export async function fetchArchivedWorkerTranscript(
  target: ArchivedTranscriptTarget,
): Promise<ArchivedTranscriptBundle> {
  return parseArchivedTranscriptBundle(
    await invoke<unknown>("worker_transcript_archive", { input: target }),
    target,
  );
}

function uuid4(): string {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export async function sendWorkerMessage(
  transcript: TranscriptBundle,
  text: string,
): Promise<ComposerReceipt> {
  const submit = parseComposerSubmit({
    thread_id: transcript.thread_id,
    slot_id: transcript.slot_id,
    work_id: transcript.work_id,
    generation: transcript.generation,
    idempotency_key: uuid4(),
    text,
    ...(transcript.anchor_item_id ? { anchor_item_id: transcript.anchor_item_id } : {}),
  }, transcript);
  const receipt = await invoke<unknown>("worker_compose", { input: submit });
  return parseComposerReceipt(receipt, transcript);
}
