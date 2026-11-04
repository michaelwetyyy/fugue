import { invoke } from "@tauri-apps/api/core";
import { parseCockpitSnapshot, type CockpitSnapshot } from "./model";

/** Start the one managed local lifecycle before reading controller state. */
export async function startFugueLifecycle(): Promise<void> {
  await invoke("app_lifecycle_start");
}

/** Read the normalized controller projection. */
export async function fetchCockpitSnapshot(): Promise<CockpitSnapshot> {
  const payload = await invoke<unknown>("cockpit_snapshot");
  return parseCockpitSnapshot(payload);
}

/** Wait for the next committed controller event, then read its normalized projection. */
export async function watchCockpitSnapshot(afterEventSequence: number): Promise<CockpitSnapshot> {
  if (!Number.isSafeInteger(afterEventSequence) || afterEventSequence < 0) {
    throw new Error("invalid_event_sequence");
  }
  const payload = await invoke<unknown>("cockpit_watch", { afterEventSequence });
  const snapshot = parseCockpitSnapshot(payload);
  const nextSequence = snapshot.snapshot_version.event_sequence;
  if (nextSequence === null || nextSequence <= afterEventSequence) {
    throw new Error("stale_event_sequence");
  }
  return snapshot;
}
