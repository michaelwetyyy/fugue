import { invoke } from "@tauri-apps/api/core";

export interface IntegrationStatus {
  armed: boolean;
  ready: boolean;
  trust_mode: "secure";
  backend_ready: boolean;
  notifier_ready: boolean;
  codex_cli: boolean;
  pending_callbacks: number;
  queued_dispatches: number;
}

const KEYS = [
  "armed",
  "ready",
  "trust_mode",
  "backend_ready",
  "notifier_ready",
  "codex_cli",
  "pending_callbacks",
  "queued_dispatches",
].sort();

export function parseIntegrationStatus(value: unknown): IntegrationStatus {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_integration_status");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join("|") !== KEYS.join("|")) throw new Error("invalid_integration_status");
  for (const key of ["armed", "ready", "backend_ready", "notifier_ready", "codex_cli"] as const) {
    if (typeof record[key] !== "boolean") throw new Error("invalid_integration_status");
  }
  for (const key of ["pending_callbacks", "queued_dispatches"] as const) {
    if (!Number.isSafeInteger(record[key]) || (record[key] as number) < 0) throw new Error("invalid_integration_status");
  }
  if (
    record.trust_mode !== "secure"
    || record.ready !== (record.armed && record.backend_ready && record.notifier_ready && record.codex_cli)
    || (!record.armed && (record.backend_ready || record.notifier_ready))
  ) throw new Error("invalid_integration_status");
  return record as unknown as IntegrationStatus;
}

export async function fetchIntegrationStatus(): Promise<IntegrationStatus> {
  return parseIntegrationStatus(await invoke<unknown>("integration_status"));
}

export async function setIntegrationEnabled(enabled: boolean): Promise<IntegrationStatus> {
  if (typeof enabled !== "boolean") throw new Error("invalid_integration_target");
  const status = parseIntegrationStatus(
    await invoke<unknown>("integration_set_enabled", { enabled }),
  );
  if (status.armed !== enabled) throw new Error("integration_target_mismatch");
  return status;
}

export interface LlmBehaviourStatus {
  available: boolean;
  supported_models: string[];
  supported_efforts_by_model: Record<string, string[]>;
  current_model: string | null;
  current_effort: string | null;
  effective_model: string | null;
  effective_effort: string | null;
}

const LLM_KEYS = [
  "available", "current_effort", "current_model", "effective_effort",
  "effective_model", "supported_efforts_by_model", "supported_models",
].sort();

function isCode(value: unknown): value is string {
  return typeof value === "string"
    && value.length > 0
    && value.length <= 128
    && /^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/.test(value);
}

function parseCodeList(value: unknown, maximum: number): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > maximum) {
    throw new Error("invalid_llm_behaviour_status");
  }
  if (!value.every(isCode) || new Set(value).size !== value.length) {
    throw new Error("invalid_llm_behaviour_status");
  }
  return [...value];
}

export function parseLlmBehaviourStatus(value: unknown): LlmBehaviourStatus {
  let cloned: unknown;
  try { cloned = structuredClone(value); } catch { throw new Error("invalid_llm_behaviour_status"); }
  if (!cloned || typeof cloned !== "object" || Array.isArray(cloned)) throw new Error("invalid_llm_behaviour_status");
  const record = cloned as Record<string, unknown>;
  if (Object.keys(record).sort().join("|") !== LLM_KEYS.join("|")) throw new Error("invalid_llm_behaviour_status");
  if (typeof record.available !== "boolean") throw new Error("invalid_llm_behaviour_status");
  if (!record.available) {
    if (!Array.isArray(record.supported_models) || record.supported_models.length !== 0) throw new Error("invalid_llm_behaviour_status");
    const efforts = record.supported_efforts_by_model;
    if (!efforts || typeof efforts !== "object" || Array.isArray(efforts) || Object.keys(efforts).length !== 0) throw new Error("invalid_llm_behaviour_status");
    for (const key of ["current_model", "current_effort", "effective_model", "effective_effort"] as const) {
      if (record[key] !== null) throw new Error("invalid_llm_behaviour_status");
    }
    return record as unknown as LlmBehaviourStatus;
  }

  const models = parseCodeList(record.supported_models, 32);
  const effortsRaw = record.supported_efforts_by_model;
  if (!effortsRaw || typeof effortsRaw !== "object" || Array.isArray(effortsRaw)) throw new Error("invalid_llm_behaviour_status");
  const effortsByModel = effortsRaw as Record<string, unknown>;
  if (Object.keys(effortsByModel).sort().join("|") !== [...models].sort().join("|")) throw new Error("invalid_llm_behaviour_status");
  for (const model of models) parseCodeList(effortsByModel[model], 16);
  for (const key of ["current_model", "current_effort", "effective_model", "effective_effort"] as const) {
    if (!isCode(record[key])) throw new Error("invalid_llm_behaviour_status");
  }
  const currentModel = record.current_model as string;
  const currentEffort = record.current_effort as string;
  const effectiveModel = record.effective_model as string;
  const effectiveEffort = record.effective_effort as string;
  if (!models.includes(currentModel) || !(effortsByModel[currentModel] as string[]).includes(currentEffort)) throw new Error("invalid_llm_behaviour_status");
  if (!models.includes(effectiveModel) || !(effortsByModel[effectiveModel] as string[]).includes(effectiveEffort)) throw new Error("invalid_llm_behaviour_status");
  return record as unknown as LlmBehaviourStatus;
}

export function isSupportedLlmPair(status: LlmBehaviourStatus, model: unknown, effort: unknown): boolean {
  if (!status.available || !isCode(model) || !isCode(effort)) return false;
  const efforts = status.supported_efforts_by_model[model];
  return Array.isArray(efforts) && efforts.includes(effort);
}

export function effortsForLlmModel(status: LlmBehaviourStatus, model: unknown): string[] {
  if (!status.available || !isCode(model)) return [];
  const efforts = status.supported_efforts_by_model[model];
  return Array.isArray(efforts) ? [...efforts] : [];
}

export async function fetchLlmBehaviourStatus(): Promise<LlmBehaviourStatus> {
  return parseLlmBehaviourStatus(await invoke<unknown>("llm_behaviour_status"));
}

export async function applyLlmBehaviour(model: string, effort: string): Promise<LlmBehaviourStatus> {
  if (!isCode(model) || !isCode(effort)) throw new Error("invalid_llm_behaviour_target");
  const status = parseLlmBehaviourStatus(
    await invoke<unknown>("llm_behaviour_apply", { model, effort }),
  );
  if (
    !status.available || status.current_model !== model ||
    status.current_effort !== effort || status.effective_model !== model ||
    status.effective_effort !== effort || !isSupportedLlmPair(status, model, effort)
  ) throw new Error("llm_behaviour_target_mismatch");
  return status;
}
