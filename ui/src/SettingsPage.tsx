import { useEffect, useRef, useState } from "react";
import { Brain, LockKeyhole, MonitorCog, RefreshCw, RotateCcw, ShieldCheck, SlidersHorizontal, X } from "lucide-react";
import {
  applyLlmBehaviour,
  effortsForLlmModel,
  fetchIntegrationStatus,
  fetchLlmBehaviourStatus,
  isSupportedLlmPair,
  setIntegrationEnabled,
  type IntegrationStatus,
  type LlmBehaviourStatus,
} from "./integration";

export interface TopologySettings {
  autoRotate: boolean;
  rotationSpeed: number;
  showLabels: boolean;
  showDispatch: boolean;
  showCallbacks: boolean;
  showDepthField: boolean;
  showHalos: boolean;
  useFog: boolean;
  galaxyIdealDistance: number;
  galaxyCohesion: number;
  galaxyRepulsion: number;
  galaxyGravity: number;
  galaxyDamping: number;
  agentWindowMode: "events" | "hours";
  agentWindowEvents: number;
  agentWindowHours: number;
}

export const DEFAULT_TOPOLOGY_SETTINGS: TopologySettings = {
  autoRotate: true,
  rotationSpeed: .55,
  showLabels: true,
  showDispatch: true,
  showCallbacks: true,
  showDepthField: true,
  showHalos: true,
  useFog: true,
  galaxyIdealDistance: 2.8,
  galaxyCohesion: .45,
  galaxyRepulsion: 1.1,
  galaxyGravity: .12,
  galaxyDamping: 3.2,
  agentWindowMode: "events",
  agentWindowEvents: 200,
  agentWindowHours: 24,
};
export const GALAXY_BOUNDS = {
  idealDistance: { min: 1, max: 6, step: .1 },
  cohesion: { min: 0, max: 1.5, step: .05 },
  repulsion: { min: 0, max: 3, step: .05 },
  gravity: { min: 0, max: .5, step: .01 },
  damping: { min: 1, max: 8, step: .1 },
} as const;
export const AGENT_WINDOW_BOUNDS = {
  events: { min: 25, max: 200, step: 25 },
  hours: { min: 1, max: 168, step: 1 },
} as const;
const STORAGE_KEY = "fugue.topology-settings.v1";
const BOOLEAN_KEYS = ["autoRotate", "showLabels", "showDispatch", "showCallbacks", "showDepthField", "showHalos", "useFog"] as const;
const NUMBER_BOUNDS: Record<string, { min: number; max: number }> = {
  rotationSpeed: { min: 0, max: 1.5 },
  galaxyIdealDistance: GALAXY_BOUNDS.idealDistance,
  galaxyCohesion: GALAXY_BOUNDS.cohesion,
  galaxyRepulsion: GALAXY_BOUNDS.repulsion,
  galaxyGravity: GALAXY_BOUNDS.gravity,
  galaxyDamping: GALAXY_BOUNDS.damping,
  agentWindowEvents: AGENT_WINDOW_BOUNDS.events,
  agentWindowHours: AGENT_WINDOW_BOUNDS.hours,
};
const LEGACY_KEYS = [...BOOLEAN_KEYS, "rotationSpeed"].sort();
const CURRENT_KEYS = [...BOOLEAN_KEYS, ...Object.keys(NUMBER_BOUNDS), "agentWindowMode"].sort();

function validBooleanSettings(record: Record<string, unknown>): boolean {
  return !BOOLEAN_KEYS.some((key) => typeof record[key] !== "boolean");
}

function validNumbers(record: Record<string, unknown>, keys: string[]): boolean {
  return keys.every((key) => {
    const bounds = NUMBER_BOUNDS[key];
    const value = record[key];
    return bounds !== undefined && typeof value === "number" && Number.isFinite(value)
      && value >= bounds.min && value <= bounds.max;
  });
}

export function loadTopologySettings(): TopologySettings {
  try {
    const value: unknown = JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "null");
    if (!value || typeof value !== "object" || Array.isArray(value)) return { ...DEFAULT_TOPOLOGY_SETTINGS };
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    if (keys.join("|") === LEGACY_KEYS.join("|")) {
      if (!validBooleanSettings(record) || !validNumbers(record, ["rotationSpeed"])) return { ...DEFAULT_TOPOLOGY_SETTINGS };
      return { ...DEFAULT_TOPOLOGY_SETTINGS, ...record } as TopologySettings;
    }
    if (keys.join("|") !== CURRENT_KEYS.join("|") || !validBooleanSettings(record)) return { ...DEFAULT_TOPOLOGY_SETTINGS };
    if (!validNumbers(record, Object.keys(NUMBER_BOUNDS))) return { ...DEFAULT_TOPOLOGY_SETTINGS };
    if (record.agentWindowMode !== "events" && record.agentWindowMode !== "hours") return { ...DEFAULT_TOPOLOGY_SETTINGS };
    return record as unknown as TopologySettings;
  } catch { return { ...DEFAULT_TOPOLOGY_SETTINGS }; }
}

export function saveTopologySettings(settings: TopologySettings): void {
  try { window.localStorage.setItem(STORAGE_KEY, JSON.stringify(settings)); } catch { /* Preferences remain session-local when storage is unavailable. */ }
}

interface SettingsPageProps {
  open: boolean;
  settings: TopologySettings;
  reducedMotion: boolean;
  onChange: (next: TopologySettings) => void;
  onClose: () => void;
  onReset: () => void;
  loadIntegration?: () => Promise<IntegrationStatus>;
  changeIntegration?: (enabled: boolean) => Promise<IntegrationStatus>;
  loadLlmBehaviour?: () => Promise<LlmBehaviourStatus>;
  changeLlmBehaviour?: (model: string, effort: string) => Promise<LlmBehaviourStatus>;
}

type SettingsSection = "general" | "gui" | "llm";
type IntegrationState =
  | { phase: "loading" | "changing"; value: IntegrationStatus | null; message: null }
  | { phase: "ready"; value: IntegrationStatus; message: null }
  | { phase: "error"; value: IntegrationStatus | null; message: string };
type LlmBehaviourState =
  | { phase: "loading" | "changing"; value: LlmBehaviourStatus | null; message: null }
  | { phase: "ready"; value: LlmBehaviourStatus; message: null }
  | { phase: "error"; value: LlmBehaviourStatus | null; message: string };

const SECTION_ORDER: SettingsSection[] = ["general", "gui", "llm"];

function Toggle({ label, hint, checked, onToggle, disabled = false, enforced = false }: { label: string; hint: string; checked: boolean; onToggle?: (next: boolean) => void; disabled?: boolean; enforced?: boolean }) {
  return <label className={`settings-control${disabled ? " is-disabled" : ""}`}><span className="settings-control-copy"><strong>{label}</strong><small>{hint}</small>{enforced && <em><LockKeyhole size={9} /> ENFORCED</em>}</span><input type="checkbox" role="switch" aria-label={label} checked={checked} disabled={disabled} onChange={(event) => onToggle?.(event.target.checked)} /><i aria-hidden="true" /></label>;
}

function integrationHeadline(state: IntegrationState): string {
  if (state.phase === "loading") return "READING STATE";
  if (state.phase === "changing") return "CHANGING STATE";
  const status = state.value;
  if (!status) return "STATE UNKNOWN";
  if (status.ready) return "ARMED + READY";
  if (!status.armed) return "DISARMED";
  const unavailable = [!status.backend_ready && "BACKEND", !status.notifier_ready && "CALLBACKS", !status.codex_cli && "CODEX"].filter(Boolean).join(" + ");
  return `ARMED · ${unavailable} OFFLINE`;
}

function GeneralSettings({ state, onToggle, onReload }: { state: IntegrationState; onToggle: (enabled: boolean) => void; onReload: () => void }) {
  const status = state.value;
  const armed = status?.armed ?? false;
  return <div className="settings-panel" role="tabpanel" id="settings-panel-general" aria-labelledby="settings-tab-general">
    <div className={`integration-card integration-${state.phase === "error" ? "error" : status?.ready ? "ready" : armed ? "partial" : status ? "off" : "unknown"}`}><div><span className="terminal-label">INTEGRATION · READ ON OPEN</span><strong>{integrationHeadline(state)}</strong></div><span><i />{status?.trust_mode?.toUpperCase() ?? "UNKNOWN"}</span></div>
    {state.phase === "error" && <div className="settings-error" role="status"><span>{state.message} Refresh state before trying again.</span><button type="button" onClick={onReload}><RefreshCw size={12} /> REFRESH STATE</button></div>}
    <section aria-labelledby="settings-routing"><h3 id="settings-routing">ROUTING</h3><Toggle label="OpenCode offload" hint={armed ? "Codex can route eligible work into Fugue" : "New offloads are blocked; durable records remain"} checked={armed} disabled={state.phase === "loading" || state.phase === "changing" || state.phase === "error"} onToggle={onToggle} /><Toggle label="Secure mode" hint="PUBLIC scope capsules only; credentials and production actions denied" checked disabled enforced /></section>
    <section aria-labelledby="settings-agents"><h3 id="settings-agents">AGENTS</h3><Toggle label="Bounded child agents" hint="Root agents may delegate analysis to at most three children" checked disabled enforced /><Toggle label="Direct file broker" hint="Explicit work tasks may replace one admitted existing file" checked disabled enforced /></section>
    <section aria-labelledby="settings-runtime"><h3 id="settings-runtime">RUNTIME</h3><Toggle label="Live change feed" hint="Graph wakes on durable events; no refresh polling" checked disabled enforced /><Toggle label="Keep running in background" hint="Closing the window hides Fugue; Quit stops the app" checked disabled enforced /></section>
    {status && <dl className="integration-facts"><div><dt>Backend</dt><dd>{status.backend_ready ? "READY" : "OFFLINE"}</dd></div><div><dt>Callbacks</dt><dd>{status.notifier_ready ? "READY" : "PAUSED"}</dd></div><div><dt>Pending</dt><dd>{status.pending_callbacks}</dd></div><div><dt>Queued</dt><dd>{status.queued_dispatches}</dd></div></dl>}
  </div>;
}

function GuiSettings({ settings, reducedMotion, onChange, onReset }: { settings: TopologySettings; reducedMotion: boolean; onChange: (next: TopologySettings) => void; onReset: () => void }) {
  const set = (patch: Partial<TopologySettings>) => onChange({ ...settings, ...patch });
  const effectiveAutoRotate = settings.autoRotate && !reducedMotion;
  return <div className="settings-panel" role="tabpanel" id="settings-panel-gui" aria-labelledby="settings-tab-gui">
    {reducedMotion && <p className="settings-motion-note" role="status">Reduced motion is active. Auto-rotation remains paused.</p>}
    <section aria-labelledby="settings-motion"><h3 id="settings-motion">MOTION</h3><Toggle label="Auto-rotate" hint={reducedMotion ? "Paused by your system reduced-motion setting" : effectiveAutoRotate ? "Slow orbit enabled" : "Orbit paused"} checked={effectiveAutoRotate} disabled={reducedMotion} enforced={reducedMotion} onToggle={(next) => set({ autoRotate: next })} /><label className="settings-control settings-range"><span className="settings-control-copy"><strong>Rotation speed</strong><small>{settings.rotationSpeed.toFixed(2)} · default 0.55</small></span><input type="range" aria-label="Rotation speed" min={0} max={1.5} step={.05} value={settings.rotationSpeed} onChange={(event) => set({ rotationSpeed: Number(event.target.value) })} /></label></section>
    <section aria-labelledby="settings-galaxy"><h3 id="settings-galaxy">GALAXY FORCES</h3>
      <label className="settings-control settings-range"><span className="settings-control-copy"><strong>Ideal distance</strong><small>{settings.galaxyIdealDistance.toFixed(1)} · default 2.8</small></span><input type="range" aria-label="Ideal distance" min={GALAXY_BOUNDS.idealDistance.min} max={GALAXY_BOUNDS.idealDistance.max} step={GALAXY_BOUNDS.idealDistance.step} value={settings.galaxyIdealDistance} onChange={(event) => set({ galaxyIdealDistance: Number(event.target.value) })} /></label>
      <label className="settings-control settings-range"><span className="settings-control-copy"><strong>Pool cohesion</strong><small>{settings.galaxyCohesion.toFixed(2)} · default 0.45</small></span><input type="range" aria-label="Pool cohesion" min={GALAXY_BOUNDS.cohesion.min} max={GALAXY_BOUNDS.cohesion.max} step={GALAXY_BOUNDS.cohesion.step} value={settings.galaxyCohesion} onChange={(event) => set({ galaxyCohesion: Number(event.target.value) })} /></label>
      <label className="settings-control settings-range"><span className="settings-control-copy"><strong>Inter-pool repulsion</strong><small>{settings.galaxyRepulsion.toFixed(2)} · default 1.10</small></span><input type="range" aria-label="Inter-pool repulsion" min={GALAXY_BOUNDS.repulsion.min} max={GALAXY_BOUNDS.repulsion.max} step={GALAXY_BOUNDS.repulsion.step} value={settings.galaxyRepulsion} onChange={(event) => set({ galaxyRepulsion: Number(event.target.value) })} /></label>
      <label className="settings-control settings-range"><span className="settings-control-copy"><strong>World gravity</strong><small>{settings.galaxyGravity.toFixed(2)} · default 0.12</small></span><input type="range" aria-label="World gravity" min={GALAXY_BOUNDS.gravity.min} max={GALAXY_BOUNDS.gravity.max} step={GALAXY_BOUNDS.gravity.step} value={settings.galaxyGravity} onChange={(event) => set({ galaxyGravity: Number(event.target.value) })} /></label>
      <label className="settings-control settings-range"><span className="settings-control-copy"><strong>Damping</strong><small>{settings.galaxyDamping.toFixed(1)} · default 3.2</small></span><input type="range" aria-label="Damping" min={GALAXY_BOUNDS.damping.min} max={GALAXY_BOUNDS.damping.max} step={GALAXY_BOUNDS.damping.step} value={settings.galaxyDamping} onChange={(event) => set({ galaxyDamping: Number(event.target.value) })} /></label>
    </section>
    <section aria-labelledby="settings-visibility"><h3 id="settings-visibility">AGENT VISIBILITY</h3>
      <label className="settings-select-field" htmlFor="agent-window-mode"><span>Visibility window</span><small>{settings.agentWindowMode === "events" ? `${settings.agentWindowEvents} Fugue events` : `Last ${settings.agentWindowHours} hours`}</small><select id="agent-window-mode" aria-label="Agent visibility window" value={settings.agentWindowMode} onChange={(event) => set({ agentWindowMode: event.target.value === "hours" ? "hours" : "events" })}><option value="events">Fugue event count</option><option value="hours">Elapsed time</option></select></label>
      {settings.agentWindowMode === "events"
        ? <label className="settings-control settings-range"><span className="settings-control-copy"><strong>Event count</strong><small>{settings.agentWindowEvents} · default 200</small></span><input type="range" aria-label="Event count" min={AGENT_WINDOW_BOUNDS.events.min} max={AGENT_WINDOW_BOUNDS.events.max} step={AGENT_WINDOW_BOUNDS.events.step} value={settings.agentWindowEvents} onChange={(event) => set({ agentWindowEvents: Number(event.target.value) })} /></label>
        : <label className="settings-control settings-range"><span className="settings-control-copy"><strong>Elapsed hours</strong><small>{settings.agentWindowHours}h · default 24h</small></span><input type="range" aria-label="Elapsed hours" min={AGENT_WINDOW_BOUNDS.hours.min} max={AGENT_WINDOW_BOUNDS.hours.max} step={AGENT_WINDOW_BOUNDS.hours.step} value={settings.agentWindowHours} onChange={(event) => set({ agentWindowHours: Number(event.target.value) })} /></label>}
    </section>
    <section aria-labelledby="settings-routes"><h3 id="settings-routes">ROUTE LAYERS</h3><Toggle label="Dispatch routes" hint="Fugue to workers" checked={settings.showDispatch} onToggle={(next) => set({ showDispatch: next })} /><Toggle label="Callback routes" hint="Workers to source agent" checked={settings.showCallbacks} onToggle={(next) => set({ showCallbacks: next })} /></section>
    <section aria-labelledby="settings-depth"><h3 id="settings-depth">DEPTH</h3><Toggle label="Depth field" hint="Sparse amber parallax" checked={settings.showDepthField} onToggle={(next) => set({ showDepthField: next })} /><Toggle label="Node halos" hint="Wireframe lifecycle echo" checked={settings.showHalos} onToggle={(next) => set({ showHalos: next })} /><Toggle label="Distance fog" hint="Fade far geometry" checked={settings.useFog} onToggle={(next) => set({ useFog: next })} /></section>
    <section aria-labelledby="settings-labels"><h3 id="settings-labels">LABELS</h3><Toggle label="Screen-facing labels" hint="Clickable metadata overlay" checked={settings.showLabels} onToggle={(next) => set({ showLabels: next })} /></section>
    <button type="button" className="settings-reset" onClick={onReset}><RotateCcw size={13} /> RESTORE GUI DEFAULTS</button>
  </div>;
}

function llmHeadline(state: LlmBehaviourState): string {
  if (state.phase === "loading") return "READING MODEL STATE";
  if (state.phase === "changing") return "APPLYING MODEL";
  if (!state.value?.available) return "MODEL CONTROL UNAVAILABLE";
  return "MODEL CONTROL READY";
}

function LlmBehaviourSettings({ state, draftModel, draftEffort, onDraftModel, onDraftEffort, onRequestApply, onReload }: {
  state: LlmBehaviourState;
  draftModel: string;
  draftEffort: string;
  onDraftModel: (model: string) => void;
  onDraftEffort: (effort: string) => void;
  onRequestApply: () => void;
  onReload: () => void;
}) {
  const status = state.value;
  const available = state.phase === "ready" && status?.available === true;
  const busy = state.phase === "loading" || state.phase === "changing";
  const models = available && status ? status.supported_models : [];
  const efforts = available && status ? effortsForLlmModel(status, draftModel) : [];
  const pairValid = !!status && isSupportedLlmPair(status, draftModel, draftEffort);
  const unchanged = !!status && status.available
    && status.current_model === draftModel && status.current_effort === draftEffort;
  const show = (value: string | null | undefined) => value ?? "—";
  return <div className="settings-panel" role="tabpanel" id="settings-panel-llm" aria-labelledby="settings-tab-llm">
    <div className={`integration-card integration-${state.phase === "error" ? "error" : available ? "ready" : "unknown"}`}><div><span className="terminal-label">LLM BEHAVIOUR · FUTURE OFFLOADS</span><strong>{llmHeadline(state)}</strong></div><span><i />{available ? "NATIVE" : "OFFLINE"}</span></div>
    {state.phase === "error" && <div className="settings-error" role="status"><span>{state.message} Refresh state before trying again.</span><button type="button" onClick={onReload}><RefreshCw size={12} /> REFRESH STATE</button></div>}
    {!available && state.phase === "ready" && <p className="settings-motion-note" role="status">The authoritative model roster is unavailable. Nothing can be changed from this panel yet.</p>}
    <section aria-labelledby="settings-llm-target"><h3 id="settings-llm-target">TARGET</h3>
      <label className="settings-select-field" htmlFor="llm-model-select"><span>Model</span><small>{available ? `${models.length} supported` : "Unavailable"}</small><select id="llm-model-select" aria-label="Model" value={draftModel} disabled={!available || busy} onChange={(event) => onDraftModel(event.target.value)}>{models.map((model) => <option key={model} value={model}>{model}</option>)}{!available && <option value="">—</option>}</select></label>
      <label className="settings-select-field" htmlFor="llm-effort-select"><span>Reasoning effort</span><small>{available ? `${efforts.length} supported for this model` : "Unavailable"}</small><select id="llm-effort-select" aria-label="Reasoning effort" value={draftEffort} disabled={!available || busy || efforts.length === 0} onChange={(event) => onDraftEffort(event.target.value)}>{efforts.map((effort) => <option key={effort} value={effort}>{effort}</option>)}{(!available || efforts.length === 0) && <option value="">—</option>}</select></label>
    </section>
    <section aria-labelledby="settings-llm-state"><h3 id="settings-llm-state">APPLIED STATE</h3><dl className="integration-facts"><div><dt>Current</dt><dd>{show(status?.current_model)} · {show(status?.current_effort)}</dd></div><div><dt>Effective</dt><dd>{show(status?.effective_model)} · {show(status?.effective_effort)}</dd></div></dl></section>
    {available && <p className="settings-motion-note" role="status">Applies to newly dispatched root tasks. Running agents and their consolidation turns keep their existing model.</p>}
    {available && !pairValid && <p className="settings-motion-note" role="status">Choose a supported model and effort pair.</p>}
    {available && pairValid && unchanged && <p className="settings-motion-note" role="status">Selection matches the current defaults.</p>}
    <button type="button" className="settings-reset" disabled={!available || !pairValid || unchanged || busy} onClick={onRequestApply}>{busy ? "WORKING…" : "REVIEW & APPLY"}</button>
  </div>;
}

export default function SettingsPage({ open, settings, reducedMotion, onChange, onClose, onReset, loadIntegration = fetchIntegrationStatus, changeIntegration = setIntegrationEnabled, loadLlmBehaviour = fetchLlmBehaviourStatus, changeLlmBehaviour = applyLlmBehaviour }: SettingsPageProps) {
  const [section, setSection] = useState<SettingsSection>("general");
  const [integration, setIntegration] = useState<IntegrationState>({ phase: "loading", value: null, message: null });
  const [llm, setLlm] = useState<LlmBehaviourState>({ phase: "loading", value: null, message: null });
  const [draftModel, setDraftModel] = useState("");
  const [draftEffort, setDraftEffort] = useState("");
  const [pendingTarget, setPendingTarget] = useState<boolean | null>(null);
  const [pendingLlm, setPendingLlm] = useState<{ model: string; effort: string } | null>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const generalTabRef = useRef<HTMLButtonElement>(null);
  const guiTabRef = useRef<HTMLButtonElement>(null);
  const llmTabRef = useRef<HTMLButtonElement>(null);
  const tabRefFor = (value: SettingsSection) => value === "general" ? generalTabRef : value === "gui" ? guiTabRef : llmTabRef;
  const reload = () => { setIntegration((current) => ({ phase: "loading", value: current.value, message: null })); void loadIntegration().then((value) => setIntegration({ phase: "ready", value, message: null })).catch(() => setIntegration((current) => ({ phase: "error", value: current.value, message: "Integration state is unavailable." }))); };
  const reloadLlm = () => {
    setPendingLlm(null);
    setLlm((current) => ({ phase: "loading", value: current.value, message: null }));
    void loadLlmBehaviour().then((value) => {
      setLlm({ phase: "ready", value, message: null });
      setDraftModel(value.available ? value.current_model ?? "" : "");
      setDraftEffort(value.available ? value.current_effort ?? "" : "");
    }).catch(() => setLlm((current) => ({ phase: "error", value: current.value, message: "LLM behaviour state is unavailable." })));
  };
  useEffect(() => {
    if (!open) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setSection("general");
    setPendingTarget(null);
    setPendingLlm(null);
    reload();
    reloadLlm();
    const focusFrame = window.requestAnimationFrame(() => generalTabRef.current?.focus());
    const containFocus = (event: KeyboardEvent) => {
      if (event.key === "Escape") { onClose(); return; }
      if (event.key !== "Tab" || !dialogRef.current) return;
      const controls = [...dialogRef.current.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), [tabindex="0"]')];
      if (!controls.length) return;
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (event.shiftKey && (document.activeElement === first || !dialogRef.current.contains(document.activeElement))) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", containFocus);
    return () => { window.cancelAnimationFrame(focusFrame); document.removeEventListener("keydown", containFocus); opener?.focus(); };
  }, [open, onClose, loadIntegration, loadLlmBehaviour]);
  if (!open) return null;
  const toggleIntegration = (enabled: boolean) => { setPendingTarget(null); setIntegration((current) => ({ phase: "changing", value: current.value, message: null })); void changeIntegration(enabled).then((value) => setIntegration({ phase: "ready", value, message: null })).catch(() => setIntegration((current) => ({ phase: "error", value: current.value, message: "Fugue could not change the integration state." }))); };
  const chooseTab = (next: SettingsSection) => { setSection(next); window.requestAnimationFrame(() => tabRefFor(next).current?.focus()); };
  const tabKeys = (event: React.KeyboardEvent) => {
    const index = SECTION_ORDER.indexOf(section);
    if (event.key === "ArrowRight" || event.key === "ArrowDown") { event.preventDefault(); chooseTab(SECTION_ORDER[(index + 1) % SECTION_ORDER.length]); }
    else if (event.key === "ArrowLeft" || event.key === "ArrowUp") { event.preventDefault(); chooseTab(SECTION_ORDER[(index + SECTION_ORDER.length - 1) % SECTION_ORDER.length]); }
  };
  const draftModelChange = (model: string) => {
    setDraftModel(model);
    const efforts = llm.value ? effortsForLlmModel(llm.value, model) : [];
    if (!efforts.includes(draftEffort)) setDraftEffort(efforts[0] ?? "");
  };
  const confirmLlm = (target: { model: string; effort: string }) => {
    if (!llm.value || !isSupportedLlmPair(llm.value, target.model, target.effort)) return;
    setPendingLlm(null);
    setLlm((current) => ({ phase: "changing", value: current.value, message: null }));
    void changeLlmBehaviour(target.model, target.effort).then((value) => {
      setLlm({ phase: "ready", value, message: null });
      if (value.available) { setDraftModel(value.current_model ?? target.model); setDraftEffort(value.current_effort ?? target.effort); }
    }).catch(() => setLlm((current) => ({ phase: "error", value: current.value, message: "Fugue could not apply the LLM behaviour." })));
  };
  return <div className="settings-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
    <aside ref={dialogRef} id="fugue-settings" className="settings-dialog" role="dialog" aria-modal="true" aria-labelledby="settings-title">
      <header className="settings-header"><div><span className="terminal-label">$ fugue settings</span><h2 id="settings-title">Settings</h2><p>Operational safety and local interface preferences.</p></div><button type="button" className="settings-close" aria-label="Close settings" onClick={onClose}><X size={15} /></button></header>
      <div className="settings-layout">
        <nav className="settings-nav" aria-label="Settings sections" role="tablist" aria-orientation="vertical" onKeyDown={tabKeys}>
          <button ref={generalTabRef} id="settings-tab-general" type="button" role="tab" tabIndex={section === "general" ? 0 : -1} aria-selected={section === "general"} aria-controls="settings-panel-general" onClick={() => chooseTab("general")}><MonitorCog size={14} /><span>GENERAL<small>Runtime & safety</small></span></button>
          <button ref={guiTabRef} id="settings-tab-gui" type="button" role="tab" tabIndex={section === "gui" ? 0 : -1} aria-selected={section === "gui"} aria-controls="settings-panel-gui" onClick={() => chooseTab("gui")}><SlidersHorizontal size={14} /><span>GUI<small>Graph & motion</small></span></button>
          <button ref={llmTabRef} id="settings-tab-llm" type="button" role="tab" tabIndex={section === "llm" ? 0 : -1} aria-selected={section === "llm"} aria-controls="settings-panel-llm" onClick={() => chooseTab("llm")}><Brain size={14} /><span>LLM BEHAVIOUR<small>Model & effort</small></span></button>
        </nav>
        <div className="settings-content">
          {section === "general" ? <GeneralSettings state={integration} onToggle={setPendingTarget} onReload={reload} /> : section === "gui" ? <GuiSettings settings={settings} reducedMotion={reducedMotion} onChange={onChange} onReset={onReset} /> : <LlmBehaviourSettings state={llm} draftModel={draftModel} draftEffort={draftEffort} onDraftModel={draftModelChange} onDraftEffort={setDraftEffort} onRequestApply={() => { if (draftModel && draftEffort) setPendingLlm({ model: draftModel, effort: draftEffort }); }} onReload={reloadLlm} />}
        </div>
      </div>
      {pendingTarget !== null && <div className="settings-confirm" role="alertdialog" aria-labelledby="integration-confirm-title"><div><strong id="integration-confirm-title">{pendingTarget ? "Arm OpenCode offload?" : "Disarm OpenCode offload?"}</strong><small>{pendingTarget ? "Eligible work can be routed to Fugue again." : "New offloads stop; existing durable records are preserved."}</small></div><div><button type="button" onClick={() => setPendingTarget(null)}>CANCEL</button><button type="button" className="confirm-primary" onClick={() => toggleIntegration(pendingTarget)}>CONFIRM {pendingTarget ? "ARM" : "DISARM"}</button></div></div>}
      {pendingLlm !== null && <div className="settings-confirm" role="alertdialog" aria-labelledby="llm-confirm-title"><div><strong id="llm-confirm-title">Apply LLM behaviour?</strong><small>{pendingLlm.model} · {pendingLlm.effort}. Nothing changes until confirmed.</small></div><div><button type="button" onClick={() => setPendingLlm(null)}>CANCEL</button><button type="button" className="confirm-primary" onClick={() => confirmLlm(pendingLlm)}>CONFIRM APPLY</button></div></div>}
      <footer className="privacy-seal"><ShieldCheck size={13} /> Secure local control · explicit changes only</footer>
    </aside>
  </div>;
}
