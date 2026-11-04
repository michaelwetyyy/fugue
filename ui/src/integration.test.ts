import { invoke } from "@tauri-apps/api/core";
import {
  applyLlmBehaviour,
  effortsForLlmModel,
  fetchIntegrationStatus,
  isSupportedLlmPair,
  parseIntegrationStatus,
  parseLlmBehaviourStatus,
  setIntegrationEnabled,
} from "./integration";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

const status = (armed = true) => ({
  armed,
  ready: armed,
  trust_mode: "secure",
  backend_ready: armed,
  notifier_ready: armed,
  codex_cli: true,
  pending_callbacks: 0,
  queued_dispatches: 0,
});

const llmStatus = () => ({
  available: true,
  supported_models: ["provider/model-a", "provider/model-b"],
  supported_efforts_by_model: {
    "provider/model-a": ["low", "high"],
    "provider/model-b": ["medium"],
  },
  current_model: "provider/model-a",
  current_effort: "low",
  effective_model: "provider/model-a",
  effective_effort: "low",
});

describe("integration command adapter", () => {
  it("reads one exact secure integration status", async () => {
    vi.mocked(invoke).mockResolvedValue(status());
    await expect(fetchIntegrationStatus()).resolves.toMatchObject({ armed: true, ready: true });
    expect(invoke).toHaveBeenCalledWith("integration_status");
  });

  it("sets one exact boolean target and verifies the returned state", async () => {
    vi.mocked(invoke).mockResolvedValue(status(false));
    await expect(setIntegrationEnabled(false)).resolves.toMatchObject({ armed: false });
    expect(invoke).toHaveBeenCalledWith("integration_set_enabled", { enabled: false });
  });

  it("rejects unknown, inconsistent, insecure and unsafe-number shapes", () => {
    for (const invalid of [
      { ...status(), extra: true },
      { ...status(), ready: false },
      { ...status(), trust_mode: "insecure" },
      { ...status(), pending_callbacks: Number.MAX_SAFE_INTEGER + 1 },
    ]) expect(() => parseIntegrationStatus(invalid)).toThrow("invalid_integration_status");
  });

  it("validates bounded LLM rosters and applies only an exact supported pair", async () => {
    const parsed = parseLlmBehaviourStatus(llmStatus());
    expect(parsed.supported_models).toEqual(["provider/model-a", "provider/model-b"]);
    expect(effortsForLlmModel(parsed, "provider/model-a")).toEqual(["low", "high"]);
    expect(isSupportedLlmPair(parsed, "provider/model-a", "high")).toBe(true);
    expect(isSupportedLlmPair(parsed, "provider/model-b", "high")).toBe(false);

    vi.mocked(invoke).mockResolvedValue({
      ...llmStatus(),
      current_model: "provider/model-b",
      current_effort: "medium",
      effective_model: "provider/model-b",
      effective_effort: "medium",
    });
    await expect(applyLlmBehaviour("provider/model-b", "medium")).resolves.toMatchObject({ effective_model: "provider/model-b", effective_effort: "medium" });
    expect(invoke).toHaveBeenCalledWith("llm_behaviour_apply", { model: "provider/model-b", effort: "medium" });
  });

  it("rejects unavailable, unbounded and inconsistent LLM status shapes", () => {
    expect(() => parseLlmBehaviourStatus({
      available: false,
      supported_models: [],
      supported_efforts_by_model: {},
      current_model: null,
      current_effort: null,
      effective_model: null,
      effective_effort: null,
    })).not.toThrow();
    expect(() => parseLlmBehaviourStatus({ ...llmStatus(), extra: true })).toThrow("invalid_llm_behaviour_status");
    expect(() => parseLlmBehaviourStatus({ ...llmStatus(), supported_models: ["x".repeat(129)] })).toThrow("invalid_llm_behaviour_status");
    expect(() => parseLlmBehaviourStatus({ ...llmStatus(), current_effort: "medium" })).toThrow("invalid_llm_behaviour_status");
  });

  it("rejects an apply response whose durable current target does not match", async () => {
    vi.mocked(invoke).mockResolvedValue({
      ...llmStatus(),
      effective_model: "provider/model-b",
      effective_effort: "medium",
    });
    await expect(applyLlmBehaviour("provider/model-b", "medium")).rejects.toThrow("llm_behaviour_target_mismatch");
  });
});
