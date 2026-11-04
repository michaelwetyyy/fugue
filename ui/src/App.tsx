import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties, ReactNode } from "react";
import { AlertTriangle, PanelRightClose, PanelRightOpen, RefreshCw, Send, Settings as SettingsIcon, ShieldCheck } from "lucide-react";
import { fetchCockpitSnapshot, startFugueLifecycle, watchCockpitSnapshot } from "./cockpit";
import { attentionGroups, collectionCount, formatReason, shortIdentity, type ArchivedTranscriptBundle, type ArchivedTranscriptTarget, type CockpitSnapshot, type ComposerReceipt, type SourceInbox, type TranscriptArchiveItem, type TranscriptBundle, type Worker, type WorkerTranscriptTarget } from "./model";
import { fetchArchivedWorkerTranscript, fetchWorkerTranscript, sendWorkerMessage } from "./transcript";
import { fetchSourceInbox, fetchSourceThreads, inspectSourceThread, sendSourceMessage, SourceInboxUnsupportedError, watchSourceChanges, type SourceChange, type SourceDeliveryOutcome, type SourceInspection, type SourceThread } from "./source";
import TopologyGraph from "./TopologyGraph";
import SettingsPage, { DEFAULT_TOPOLOGY_SETTINGS, loadTopologySettings, saveTopologySettings, type TopologySettings } from "./SettingsPage";
import type { IntegrationStatus, LlmBehaviourStatus } from "./integration";
import "./settings.css";

type LoadState =
  | { phase: "loading"; snapshot: null; message: null }
  | { phase: "ready" | "refreshing"; snapshot: CockpitSnapshot; message: null }
  | { phase: "error"; snapshot: CockpitSnapshot | null; message: string };
interface AppProps {
  loadSnapshot?: () => Promise<CockpitSnapshot>;
  startLifecycle?: () => Promise<void>;
  watchSnapshot?: ((afterEventSequence: number) => Promise<CockpitSnapshot>) | null;
  loadIntegration?: () => Promise<IntegrationStatus>;
  changeIntegration?: (enabled: boolean) => Promise<IntegrationStatus>;
  loadLlmBehaviour?: () => Promise<LlmBehaviourStatus>;
  changeLlmBehaviour?: (model: string, effort: string) => Promise<LlmBehaviourStatus>;
  loadTranscript?: (target: WorkerTranscriptTarget) => Promise<TranscriptBundle>;
  loadArchivedTranscript?: (target: ArchivedTranscriptTarget) => Promise<ArchivedTranscriptBundle>;
  composeWorker?: (transcript: TranscriptBundle, text: string) => Promise<ComposerReceipt>;
  loadSourceThreads?: (() => Promise<SourceThread[]>) | null;
  loadSourceInbox?: ((threadId: string) => Promise<SourceInbox>) | null;
  watchSourceChanges?: (() => Promise<SourceChange>) | null;
  inspectSource?: (threadId: string) => Promise<SourceInspection>;
  composeSource?: (inspection: SourceInspection, text: string) => Promise<SourceDeliveryOutcome>;
}
type GraphFilter = "all" | "dispatch" | "callbacks";
type InspectorTab = "state" | "routes" | "transcript";
type ConversationTranscriptBundle = TranscriptBundle | ArchivedTranscriptBundle;
type TranscriptLoadState =
  | { phase: "idle" | "loading"; bundle: null; message: string | null }
  | { phase: "ready" | "sending"; bundle: ConversationTranscriptBundle; message: string | null }
  | { phase: "error"; bundle: ConversationTranscriptBundle | null; message: string };

function isArchivedTranscript(bundle: ConversationTranscriptBundle): bundle is ArchivedTranscriptBundle {
  return "read_only" in bundle && bundle.read_only === true;
}
type SourceInspectionState =
  | { phase: "idle" | "loading"; inspection: null; message: string | null }
  | { phase: "ready" | "sending"; inspection: SourceInspection; message: string | null }
  | { phase: "error"; inspection: SourceInspection | null; message: string };
type SourceInboxLoadState =
  | { phase: "idle" | "loading" | "unsupported"; inbox: null; message: string | null }
  | { phase: "ready"; inbox: SourceInbox; message: null }
  | { phase: "error"; inbox: null; message: string };
const EMPTY_STATE: LoadState = { phase: "loading", snapshot: null, message: null };
const INSPECTOR_WIDTH_KEY = "fugue.inspector.width.v1";
const DEFAULT_INSPECTOR_WIDTH = 360;
const MIN_INSPECTOR_WIDTH = 280;
const MAX_INSPECTOR_WIDTH = 680;

export function clampInspectorWidth(value: number): number {
  return Math.min(MAX_INSPECTOR_WIDTH, Math.max(MIN_INSPECTOR_WIDTH, Math.round(value)));
}

function loadInspectorWidth(): number {
  try {
    const stored = Number(window.localStorage.getItem(INSPECTOR_WIDTH_KEY));
    return Number.isFinite(stored) && stored > 0 ? clampInspectorWidth(stored) : DEFAULT_INSPECTOR_WIDTH;
  } catch {
    return DEFAULT_INSPECTOR_WIDTH;
  }
}

function persistInspectorWidth(width: number): void {
  try {
    window.localStorage.setItem(INSPECTOR_WIDTH_KEY, String(clampInspectorWidth(width)));
  } catch {
    // Storage is optional; the current window remains usable.
  }
}

function InspectorPane({ width, onWidth, onCollapse, children }: { width: number; onWidth: (width: number) => void; onCollapse: () => void; children: ReactNode }) {
  const beginResize = (event: React.PointerEvent<HTMLDivElement>) => {
    event.preventDefault();
    const startX = event.clientX;
    const startWidth = width;
    const move = (next: PointerEvent) => onWidth(startWidth + startX - next.clientX);
    const finish = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", finish);
      window.removeEventListener("pointercancel", finish);
      document.body.classList.remove("inspector-resizing");
    };
    document.body.classList.add("inspector-resizing");
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", finish, { once: true });
    window.addEventListener("pointercancel", finish, { once: true });
  };
  return <section id="fugue-inspector" className="inspector-pane">
    <div
      className="inspector-resizer"
      role="separator"
      aria-label="Resize inspector"
      aria-orientation="vertical"
      aria-valuemin={MIN_INSPECTOR_WIDTH}
      aria-valuemax={MAX_INSPECTOR_WIDTH}
      aria-valuenow={width}
      aria-valuetext={`${width} pixels`}
      tabIndex={0}
      onPointerDown={beginResize}
      onDoubleClick={() => onWidth(DEFAULT_INSPECTOR_WIDTH)}
      onKeyDown={(event) => {
        if (event.key !== "ArrowLeft" && event.key !== "ArrowRight" && event.key !== "Home" && event.key !== "End") return;
        event.preventDefault();
        onWidth(event.key === "Home" ? DEFAULT_INSPECTOR_WIDTH : event.key === "End" ? MIN_INSPECTOR_WIDTH : width + (event.key === "ArrowLeft" ? 24 : -24));
      }}
    />
    <button type="button" className="inspector-collapse" onClick={onCollapse} aria-controls="fugue-inspector" aria-expanded="true">
      <PanelRightClose size={14} /> <span>COLLAPSE</span>
    </button>
    {children}
  </section>;
}

function loadFailureMessage(error: unknown): string {
  const value = error instanceof Error ? error.message : typeof error === "string" ? error : "";
  const safeCode = value.match(/^[a-zA-Z0-9_.:-]{1,80}$/)?.[0];
  return safeCode ? `The controller did not return a snapshot (${safeCode}).` : "The controller did not return a snapshot. Fugue has left the view unchanged.";
}

function transcriptFailureMessage(error: unknown): string {
  const value = error instanceof Error ? error.message : typeof error === "string" ? error : "";
  const allowed = new Set([
    "Fugue controller is unavailable",
    "Fugue controller endpoint failed local security validation",
    "Fugue controller returned an invalid response",
    "Fugue controller rejected the request",
    "Worker transcript is unavailable",
  ]);
  return allowed.has(value) ? value : "This transcript is unavailable or the assignment changed.";
}

export function activityAgentIsRecent(snapshot: CockpitSnapshot, agentId: string, settings: TopologySettings, now = Date.now()): boolean {
  const activity = snapshot.recent_activity;
  if (!activity || activity.status !== "available") return true;
  const agent = activity.agents.find((item) => item.agent_id === agentId);
  if (!agent) return false;
  if (settings.agentWindowMode === "events") {
    const latest = snapshot.snapshot_version.event_sequence ?? agent.last_sequence;
    return agent.last_sequence > latest - settings.agentWindowEvents;
  }
  return Date.parse(agent.last_occurred_at) >= now - settings.agentWindowHours * 60 * 60 * 1000;
}

function graphWorkers(snapshot: CockpitSnapshot, settings: TopologySettings, selectedSlot: string | null): Worker[] {
  const attention = attentionGroups(snapshot);
  const retainedByAttention = (worker: Worker) => [...attention.operator.items, ...attention.automatic.items].some((item) =>
    (worker.work_id !== null && item.work_id === worker.work_id)
    || (worker.recovery.target_id !== null && item.target_id === worker.recovery.target_id));
  return snapshot.worker_graph.workers.filter((worker) =>
    worker.slot_state === "assigned"
    || worker.slot_id === selectedSlot
    || retainedByAttention(worker)
    || activityAgentIsRecent(snapshot, worker.slot_id, settings));
}

function lifecycleLabel(worker: Worker): string {
  if (worker.slot_state !== "assigned") return "available";
  return worker.agent_lifecycle ?? "metadata pending";
}

function workerState(worker: Worker): string {
  if (worker.slot_state === "assigned") {
    return worker.transport.status === "unavailable" ? "active · metadata pending" : worker.transport.state;
  }
  return worker.slot_state === "unavailable" ? "unavailable" : "available";
}

function InspectorField({ label, value }: { label: string; value: string }) {
  return <div className="inspector-field"><dt>{label}</dt><dd>{value}</dd></div>;
}

function EventLine({ from, to, text }: { from: string; to: string; text: string }) {
  return <div className="event-line"><i aria-hidden="true" /><div><strong>{from} → {to}</strong><p>{text}</p></div></div>;
}

function WorkerInspector({ worker, tab, onTab, transcript, receipt, onCompose, archiveItems, selectedArchiveId, onSelectArchive }: { worker: Worker; tab: InspectorTab; onTab: (tab: InspectorTab) => void; transcript: TranscriptLoadState; receipt: ComposerReceipt | null; onCompose: (text: string) => Promise<void>; archiveItems: TranscriptArchiveItem[]; selectedArchiveId: string | null; onSelectArchive: (archiveId: string) => void }) {
  const [draft, setDraft] = useState("");
  useEffect(() => { setDraft(""); }, [worker.slot_id, worker.work_id, worker.transport.generation]);
  const isIdleCapacity = worker.slot_state !== "assigned";
  const archivedBundle = transcript.bundle && isArchivedTranscript(transcript.bundle) ? transcript.bundle : null;
  const archived = archivedBundle !== null;
  const routes = [
    ["Work", worker.work_id, worker.work_id ? "runs" : "idle"],
    ["Transport", worker.transport.id, worker.transport.state],
    ["Completion", worker.completion.id, worker.completion.callback_state],
    ["Recovery", worker.recovery.target_id, worker.recovery.phase],
  ] as const;
  const transcriptMeta = transcript.bundle
    ? archived
      ? `${archivedBundle!.turns.length} bounded turns · ${formatReason(archivedBundle!.outcome)} · read only`
      : `${transcript.bundle.turns.length} bounded turns · follows Fugue events`
    : isIdleCapacity && archiveItems.length
      ? `${archiveItems.length} recent completion snapshot${archiveItems.length === 1 ? "" : "s"}`
      : "exact assignment binding";
  return (
    <aside className="inspector" aria-label={`${worker.slot_id} details`}>
      <header className="inspector-header"><span className="terminal-label">SELECTED AGENT</span><h2>{worker.slot_id}</h2><div className={`lifecycle-badge lifecycle-${worker.agent_lifecycle ?? "idle"}`}>{lifecycleLabel(worker).toUpperCase()}</div><p>{worker.display_name}</p><div className="inspector-status"><i aria-hidden="true" />{formatReason(workerState(worker))}</div></header>
      <div className="inspector-tabs" role="tablist" aria-label="Worker details">{(["state", "routes", "transcript"] as const).map((value) => <button key={value} type="button" role="tab" aria-selected={tab === value} onClick={() => onTab(value)}>{value.toUpperCase()}</button>)}</div>
      <div className={`inspector-body ${tab === "transcript" ? "inspector-body-transcript" : ""}`}>
        {tab === "state" && <dl className="inspector-fields"><InspectorField label="Capacity" value={worker.slot_state === "assigned" ? "bound to active assignment" : worker.slot_state === "unavailable" ? "unavailable — no capacity" : "idle capacity — ready for work"} /><InspectorField label="Current work" value={worker.work_id ? shortIdentity(worker.work_id) : "unbound"} /><InspectorField label="Lifecycle" value={lifecycleLabel(worker)} /><InspectorField label="Lane" value={`${formatReason(worker.lane)} · position ${worker.position}`} /><InspectorField label="Assignment" value={worker.assignment_id ? shortIdentity(worker.assignment_id) : "unbound"} /><InspectorField label="Attempt" value={worker.attempt === null ? "—" : String(worker.attempt)} />{isIdleCapacity && <div className="capacity-note" role="status"><strong>AVAILABLE CAPACITY</strong><p>This is an empty worker slot, not a paused conversation. Fugue can inspect and message it only after work is bound.</p></div>}</dl>}
        {tab === "routes" && <div className="route-stack">{routes.map(([label, id, state]) => <div className="route-row" key={label}><span>{label}</span><strong>{shortIdentity(id)}</strong><em>{formatReason(state)}</em></div>)}</div>}
        {tab === "transcript" && <section className="conversation-panel" aria-label="Conversation">
          <header className="conversation-toolbar"><div><strong>{archived ? "ARCHIVED CONVERSATION" : "LIVE CONVERSATION"}</strong><span>{transcriptMeta}</span></div></header>
          {isIdleCapacity && archiveItems.length > 0 && <nav className="archive-selector" aria-label="Transcript history">{archiveItems.map((item) => <button key={item.archive_id} type="button" aria-pressed={selectedArchiveId === item.archive_id} onClick={() => onSelectArchive(item.archive_id)}><strong>{shortIdentity(item.work_id)}</strong><span>{formatReason(item.outcome)} · {item.turn_count} turns</span></button>)}</nav>}
          <div className="conversation-scroll">
            {transcript.phase === "loading" && <div className="conversation-empty"><strong>LOADING CONVERSATION</strong><p>{isIdleCapacity ? "Fetching the sanitized completion snapshot for this prior assignment." : "Fetching the bounded text view for this exact assignment."}</p></div>}
            {transcript.phase === "idle" && <div className="conversation-empty"><strong>NO ACTIVE CONVERSATION</strong><p>{archiveItems.length ? "Select a retained completion snapshot above." : "This cube is available capacity and has no retained transcript in the current archive window."}</p></div>}
            {transcript.phase === "error" && <div className="conversation-empty conversation-error" role="alert"><strong>CONVERSATION UNAVAILABLE</strong><p>{transcript.message}</p></div>}
            {transcript.bundle && (transcript.bundle.turns.length ? <ol className="conversation-thread" aria-label="Worker transcript">{transcript.bundle.turns.map((turn) => <li key={turn.seq} className={`conversation-message message-${turn.role}`}><header><strong>{turn.role === "agent" ? "AGENT" : turn.role.toUpperCase()}</strong><span>{formatReason(turn.kind)} · {formatReason(turn.state)}</span><small>#{turn.seq + 1}</small></header><p>{turn.preview}</p></li>)}</ol> : <div className="conversation-empty"><strong>NO VISIBLE TEXT</strong><p>Tool payloads, private reasoning and blocked durable content remain excluded from this view.</p></div>)}
          </div>
          {transcript.bundle && !archived && <form className="conversation-composer" onSubmit={(event) => { event.preventDefault(); const text = draft; if (!text.trim()) return; void onCompose(text).then(() => setDraft("")); }}>
            <label htmlFor={`worker-message-${worker.slot_id}`}>MESSAGE THIS AGENT</label>
            <textarea id={`worker-message-${worker.slot_id}`} aria-label="Message this agent" placeholder="Add a follow-up to this exact assignment…" value={draft} maxLength={2000} rows={4} onChange={(event) => setDraft(event.target.value)} disabled={transcript.phase === "sending"} />
            <div><span>{draft.length} / 2000</span><button type="submit" disabled={transcript.phase === "sending" || !draft.trim()}><Send size={13} />{transcript.phase === "sending" ? "SENDING" : "SEND ONCE"}</button></div>
          </form>}
          {receipt && !archived && <p className="conversation-receipt" role={receipt.state === "uncertain" ? "alert" : "status"}>Delivery: {formatReason(receipt.state)}{receipt.reason ? ` · ${formatReason(receipt.reason)}` : ""}{receipt.state === "uncertain" ? " · Fugue will not retry automatically." : ""}</p>}
        </section>}
      </div>
      <section className="event-stream" aria-labelledby="event-stream-title"><header><h3 id="event-stream-title">ROUTE STATE</h3><span>SNAPSHOT</span></header><EventLine from="Fugue" to={worker.slot_id} text={worker.work_id ? `${lifecycleLabel(worker)} · ${shortIdentity(worker.work_id)}` : "slot available"} /><EventLine from={worker.slot_id} to="transport" text={formatReason(worker.transport.state)} /><EventLine from={worker.slot_id} to="callback" text={worker.completion.callback_state === "delivered" ? "queued to Codex" : formatReason(worker.completion.callback_state)} /></section>
      <footer className="privacy-seal"><ShieldCheck size={13} /> {archived ? "Sanitized completion snapshot · read only · composer disabled" : "Transcript held in memory only · tool payloads excluded"}</footer>
    </aside>
  );
}

function SourceInspector({ thread, inbox, inboxState, inspection, receipt, onCompose, onReload }: { thread: SourceThread; inbox: SourceInbox | undefined; inboxState: SourceInboxLoadState; inspection: SourceInspectionState; receipt: SourceDeliveryOutcome | null; onCompose: (text: string) => Promise<void>; onReload: () => void }) {
  const items = inbox?.items ?? [];
  const exactEmpty = inbox?.total_status === "exact" && inbox.total === 0 && items.length === 0;
  const [draft, setDraft] = useState("");
  const boundInspection = inspection.inspection?.threadId === thread.id ? inspection.inspection : null;
  const runtimeStatus = inbox?.runtime_status ?? (inboxState.phase === "error" ? "unavailable" : thread.runtimeStatus);
  const visibleLines = boundInspection?.turns.flatMap((turn) => turn.lines.map((line, index) => ({ ...line, key: `${turn.id}-${index}`, turnStatus: turn.status }))) ?? [];
  return (
    <aside className="inspector" aria-label={`${thread.name ?? thread.id} source thread`}>
      <header className="inspector-header"><span className="terminal-label">SELECTED CODEX THREAD</span><h2>{thread.name ?? thread.id}</h2><div className="lifecycle-badge lifecycle-persistent">SOURCE</div><p>{thread.cwd}</p><div className="inspector-status"><i aria-hidden="true" />{formatReason(runtimeStatus)}</div></header>
      <div className="source-summary"><dl><InspectorField label="Runtime" value={formatReason(runtimeStatus)} /><InspectorField label="Active turn" value={shortIdentity(boundInspection?.activeTurnId)} /><InspectorField label="Pending items" value={inbox ? collectionCount(inbox) : inboxState.phase === "loading" ? "loading" : "—"} /><InspectorField label="Delivery rule" value={boundInspection?.activeTurnId ? "exact active-turn steer" : "durable idle route"} /></dl></div>
      <section className="conversation-panel source-conversation" aria-label="Conversation">
        <header className="conversation-toolbar"><div><strong>CONVERSATION</strong><span>{boundInspection?.activeTurnId ? "live turn" : "durable thread route"}</span></div><button type="button" onClick={onReload} disabled={inspection.phase === "loading" || inspection.phase === "sending"} aria-label="Refresh thread"><RefreshCw size={13} /></button></header>
        <div className="conversation-scroll">
          {inspection.phase === "loading" && <div className="conversation-empty"><strong>LOADING THREAD</strong><p>Fetching this Codex task’s bounded conversation view.</p></div>}
          {inspection.phase === "error" && <div className="conversation-empty conversation-error" role="alert"><strong>THREAD UNAVAILABLE</strong><p>{inspection.message}</p></div>}
          {boundInspection && (visibleLines.length ? <ol className="conversation-thread" aria-label="Source transcript">{visibleLines.map((line, index) => <li key={line.key} className={`conversation-message message-${line.role}`}><header><strong>{line.role === "agent" ? "CODEX" : "YOU"}</strong><span>{formatReason(line.turnStatus)}</span><small>#{index + 1}</small></header><p>{line.text}</p></li>)}</ol> : <div className="conversation-empty"><strong>NO VISIBLE TEXT</strong><p>This task has no bounded user or agent text to show.</p></div>)}
        </div>
        {boundInspection && <form className="conversation-composer" onSubmit={(event) => { event.preventDefault(); const text = draft; if (!text.trim()) return; void onCompose(text).then(() => setDraft("")); }}>
          <label htmlFor={`source-message-${thread.id}`}>MESSAGE THIS CODEX THREAD</label>
          <textarea id={`source-message-${thread.id}`} aria-label="Message this Codex thread" placeholder={boundInspection.activeTurnId ? "Steer the active turn…" : "Queue a message through the durable idle route…"} value={draft} maxLength={8192} rows={4} onChange={(event) => setDraft(event.target.value)} disabled={inspection.phase === "sending"} />
          <div><span>{draft.length} / 8192</span><button type="submit" disabled={inspection.phase === "sending" || !draft.trim()}><Send size={13} />{inspection.phase === "sending" ? "SENDING" : "SEND ONCE"}</button></div>
        </form>}
        {receipt && <p className="conversation-receipt" role={receipt.state === "unknown" ? "alert" : "status"}>{receipt.endpoint} · {formatReason(receipt.state)}{receipt.state === "unknown" ? " · Fugue will not retry automatically." : ""}</p>}
      </section>
      <section className="event-stream" aria-labelledby="source-inbox-title"><header><h3 id="source-inbox-title">SOURCE INBOX</h3><span>{items.length} VISIBLE</span></header>{items.length ? <ol className="turn-list">{items.map((item) => <li key={item.id}><i aria-hidden="true" /><div><strong>{formatReason(item.kind)} · {formatReason(item.state)}</strong><span>{item.origin}{item.work_id ? ` · ${shortIdentity(item.work_id)}` : ""}</span><time>{item.queued_at}</time></div></li>)}</ol> : exactEmpty ? <p className="metadata-empty">No source-bound messages are queued.</p> : inbox ? <p className="metadata-empty">Source inbox count is not exact.</p> : inboxState.phase === "loading" ? <p className="metadata-empty">Loading source-bound delivery metadata.</p> : inboxState.phase === "error" ? <p className="metadata-empty" role="alert">Source inbox unavailable. Queue state is not being inferred.</p> : inboxState.phase === "unsupported" ? <p className="metadata-empty">This controller version does not expose a per-thread Source inbox.</p> : <p className="metadata-empty">Source inbox metadata is unavailable.</p>}</section>
      <footer className="privacy-seal"><ShieldCheck size={13} /> Transcript held in this panel only · graph and logs remain metadata-only</footer>
    </aside>
  );
}

function QueueDock({ snapshot }: { snapshot: CockpitSnapshot }) {
  return <section className="queue-dock" aria-label="Work queue"><h2>QUEUE · {collectionCount(snapshot.queue)}</h2>{snapshot.queue.items.length ? <ol>{snapshot.queue.items.slice(0, 5).map((item) => <li key={`${item.work_id}-${item.queue_order}`}><i>{String(item.queue_order).padStart(2, "0")}</i><strong>{shortIdentity(item.work_id)}</strong><em>{formatReason(item.lane)}</em></li>)}</ol> : <p>No work waiting</p>}</section>;
}

const MAX_ACTIVITY_ENTRIES = 6;

interface ActivityEntry {
  id: string;
  text: string;
  signature: string;
}

function activityEventLabel(eventType: string): string {
  if (eventType === "callback.delivered" || eventType === "callback.queued_for_codex") return "callback queued to Codex";
  return formatReason(eventType);
}

function ActivityLog({ snapshot, workers, sourceThreads, sourceActivity }: { snapshot: CockpitSnapshot; workers: Worker[]; sourceThreads: SourceThread[]; sourceActivity?: { sequence: number; threadId: string; outcome: SourceDeliveryOutcome } | null }) {
  const [entries, setEntries] = useState<ActivityEntry[]>([]);
  const eventSequence = snapshot.snapshot_version.event_sequence;
  const activeCount = snapshot.worker_graph.workers.filter((worker) => worker.slot_state === "assigned").length;
  const queuedCount = collectionCount(snapshot.queue);
  const attention = attentionGroups(snapshot);
  const actionCount = attention.operator.items.length + attention.automatic.items.length;
  const deliveryCount = attention.delivery.items.length;
  const availabilityStatus = snapshot.availability.status;
  useEffect(() => {
    if (snapshot.recent_activity?.status === "available") {
      const name = (id: string) => {
        if (id.startsWith("source:")) {
          const sourceId = id.slice("source:".length);
          return sourceThreads.find((thread) => thread.id === sourceId)?.name ?? `Codex ${shortIdentity(sourceId)}`;
        }
        return workers.find((worker) => worker.slot_id === id)?.slot_id ?? formatReason(id);
      };
      setEntries(snapshot.recent_activity.items.slice(-MAX_ACTIVITY_ENTRIES).map((item) => ({
        id: `event-${item.sequence}`,
        signature: `${item.origin}:${item.destination}:${item.event_type}`,
        text: `${name(item.origin)} → ${name(item.destination)}: ${activityEventLabel(item.event_type)}`,
      })));
      return;
    }
    const parts: string[] = [];
    parts.push(activeCount === 0 ? "no active agents" : activeCount === 1 ? "1 active" : `${activeCount} active`);
    parts.push(queuedCount === "1" ? "1 queued" : `${queuedCount} queued`);
    if (actionCount > 0) parts.push(actionCount === 1 ? "1 needs attention" : `${actionCount} need attention`);
    if (deliveryCount > 0) parts.push(deliveryCount === 1 ? "1 delivery notice" : `${deliveryCount} delivery notices`);
    if (availabilityStatus !== "available") parts.push(formatReason(availabilityStatus));
    const signature = parts.join(" · ");
    const text = eventSequence === null || eventSequence === undefined ? signature : `Event ${eventSequence} · ${signature}`;
    const id = eventSequence === null || eventSequence === undefined ? `snapshot-${signature}` : `event-${eventSequence}`;
    setEntries((previous) => {
      const last = previous.length > 0 ? previous[previous.length - 1] : undefined;
      if (last?.id === id || last?.signature === signature) return previous;
      if (previous.some((entry) => entry.id === id)) return previous;
      return [...previous, { id, text, signature }].slice(-MAX_ACTIVITY_ENTRIES);
    });
  }, [eventSequence, activeCount, queuedCount, actionCount, deliveryCount, availabilityStatus, snapshot.recent_activity, sourceThreads, workers]);
  useEffect(() => {
    if (!sourceActivity) return;
    const { outcome, sequence, threadId } = sourceActivity;
    const signature = `${outcome.endpoint}:${outcome.state}:${threadId}`;
    setEntries((previous) => [...previous.filter((entry) => entry.signature !== signature), {
      id: `source-${sequence}`,
      signature,
      text: `Codex ${shortIdentity(threadId)} · ${outcome.endpoint} · ${formatReason(outcome.state)}`,
    }].slice(-MAX_ACTIVITY_ENTRIES));
  }, [sourceActivity?.sequence]);
  return (
    <section className="activity-log" aria-label="Activity log">
      <h2>ACTIVITY</h2>
      {entries.length ? (
        <ol role="log" aria-live="polite">
          {entries.map((entry) => <li key={entry.id} className="activity-entry">{entry.text}</li>)}
        </ol>
      ) : (
        <p>No activity yet</p>
      )}
    </section>
  );
}

export default function App({ loadSnapshot = fetchCockpitSnapshot, startLifecycle = startFugueLifecycle, watchSnapshot, loadIntegration, changeIntegration, loadLlmBehaviour, changeLlmBehaviour, loadTranscript = fetchWorkerTranscript, loadArchivedTranscript = fetchArchivedWorkerTranscript, composeWorker = sendWorkerMessage, loadSourceThreads, loadSourceInbox, watchSourceChanges: watchSourceChangesProp, inspectSource = inspectSourceThread, composeSource = sendSourceMessage }: AppProps) {
  const [state, setState] = useState<LoadState>(EMPTY_STATE);
  const [filter, setFilter] = useState<GraphFilter>("all");
  const [selectedSlot, setSelectedSlot] = useState<string | null>(null);
  const [selectedView, setSelectedView] = useState<"worker" | "source">("worker");
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>("state");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settings, setSettings] = useState<TopologySettings>(loadTopologySettings);
  const [watchEpoch, setWatchEpoch] = useState(0);
  const [sourceWatchRestartEpoch, setSourceWatchRestartEpoch] = useState(0);
  const [sourceInboxRefreshEpoch, setSourceInboxRefreshEpoch] = useState(0);
  const [inspectorWidth, setInspectorWidth] = useState(loadInspectorWidth);
  const [inspectorCollapsed, setInspectorCollapsed] = useState(false);
  const [transcript, setTranscript] = useState<TranscriptLoadState>({ phase: "idle", bundle: null, message: null });
  const [composerReceipt, setComposerReceipt] = useState<ComposerReceipt | null>(null);
  const [selectedArchiveId, setSelectedArchiveId] = useState<string | null>(null);
  const [sourceThreads, setSourceThreads] = useState<SourceThread[]>([]);
  const [sourceInboxState, setSourceInboxState] = useState<SourceInboxLoadState>({ phase: "idle", inbox: null, message: null });
  const [selectedSourceId, setSelectedSourceId] = useState<string | null>(null);
  const [sourceInspection, setSourceInspection] = useState<SourceInspectionState>({ phase: "idle", inspection: null, message: null });
  const [sourceReceipt, setSourceReceipt] = useState<SourceDeliveryOutcome | null>(null);
  const [sourceActivity, setSourceActivity] = useState<{ sequence: number; threadId: string; outcome: SourceDeliveryOutcome } | null>(null);
  const sourceRequest = useRef(0);
  const sourceInboxRequest = useRef(0);
  const sourceInboxFlights = useRef(new Map<string, { dirty: boolean; loader: (threadId: string) => Promise<SourceInbox> }>());
  const selectedSourceBinding = useRef<string | null>(null);
  const sourceActivitySequence = useRef(0);
  const sourceWatchFailed = useRef(false);
  const transcriptRequest = useRef(0);
  const selectedBinding = useRef<string | null>(null);
  const liveWatch = watchSnapshot === undefined
    ? (loadSnapshot === fetchCockpitSnapshot ? watchCockpitSnapshot : null)
    : watchSnapshot;
  const sourceLoader = loadSourceThreads === undefined
    ? (loadSnapshot === fetchCockpitSnapshot ? fetchSourceThreads : null)
    : loadSourceThreads;
  const sourceInboxLoader = loadSourceInbox === undefined
    ? (loadSnapshot === fetchCockpitSnapshot ? fetchSourceInbox : null)
    : loadSourceInbox;
  const sourceWatcher = watchSourceChangesProp === undefined
    ? (loadSnapshot === fetchCockpitSnapshot ? watchSourceChanges : null)
    : watchSourceChangesProp;
  const reducedMotion = useMemo(() => typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches, []);
  const closeSettings = useCallback(() => setSettingsOpen(false), []);
  const updateSettings = useCallback((next: TopologySettings) => { setSettings(next); saveTopologySettings(next); }, []);
  const resetSettings = useCallback(() => updateSettings({ ...DEFAULT_TOPOLOGY_SETTINGS }), [updateSettings]);
  const updateInspectorWidth = useCallback((next: number) => {
    const width = clampInspectorWidth(next);
    setInspectorWidth(width);
    persistInspectorWidth(width);
  }, []);
  const selectWorker = useCallback((worker: Worker) => {
    sourceRequest.current += 1;
    sourceInboxRequest.current += 1;
    selectedSourceBinding.current = null;
    setInspectorCollapsed(false);
    setSelectedView("worker");
    setSelectedSlot(worker.slot_id);
    setSelectedSourceId(null);
    setSourceInspection({ phase: "idle", inspection: null, message: null });
    setSourceInboxState({ phase: "idle", inbox: null, message: null });
    setSourceReceipt(null);
    setInspectorTab("transcript");
    setComposerReceipt(null);
    setSelectedArchiveId(null);
  }, []);
  const selectSource = useCallback((thread: SourceThread) => {
    sourceRequest.current += 1;
    sourceInboxRequest.current += 1;
    selectedSourceBinding.current = thread.id;
    setSourceInspection({ phase: "idle", inspection: null, message: null });
    setSourceInboxState({ phase: "idle", inbox: null, message: null });
    setInspectorCollapsed(false);
    setSelectedView("source");
    setSelectedSlot(null);
    setSelectedSourceId(thread.id);
    setSourceReceipt(null);
  }, []);
  const load = useCallback(async (refresh = false) => {
    setState((current) => current.snapshot && refresh ? { phase: "refreshing", snapshot: current.snapshot, message: null } : { phase: "loading", snapshot: null, message: null });
    try {
      setState({ phase: "ready", snapshot: await loadSnapshot(), message: null });
      if (refresh) {
        setWatchEpoch((value) => value + 1);
        if (sourceWatchFailed.current) {
          sourceWatchFailed.current = false;
          setSourceWatchRestartEpoch((value) => value + 1);
        }
      }
    }
    catch (error) { setState((current) => ({ phase: "error", snapshot: current.snapshot, message: loadFailureMessage(error) })); }
  }, [loadSnapshot]);
  const startAndLoad = useCallback(async () => { try { await startLifecycle(); } catch { setState({ phase: "error", snapshot: null, message: "Fugue could not start its controller." }); return; } await load(); }, [load, startLifecycle]);
  useEffect(() => { void startAndLoad(); }, [startAndLoad]);
  useEffect(() => {
    if (!sourceLoader) { setSourceThreads([]); return; }
    let active = true;
    void sourceLoader().then((threads) => {
      if (active) setSourceThreads(threads.slice(0, 24));
    }).catch(() => {
      if (active) setSourceThreads([]);
    });
    return () => { active = false; };
  }, [sourceLoader, watchEpoch]);
  useEffect(() => {
    if (!sourceLoader || !sourceWatcher) return;
    let active = true;
    const run = async () => {
      while (active) {
        try {
          await sourceWatcher();
          if (!active) return;
          sourceWatchFailed.current = false;
          setSourceInboxRefreshEpoch((value) => value + 1);
          const threads = await sourceLoader();
          if (active) setSourceThreads(threads.slice(0, 24));
        } catch {
          if (active) sourceWatchFailed.current = true;
          return;
        }
      }
    };
    void run();
    return () => { active = false; };
  }, [sourceLoader, sourceWatcher, sourceWatchRestartEpoch]);
  const snapshot = state.snapshot;
  const eventSequence = snapshot?.snapshot_version.event_sequence ?? null;
  useEffect(() => {
    if (liveWatch === null || eventSequence === null || state.phase === "loading") return;
    let active = true;
    void liveWatch(eventSequence).then((next) => {
      if (active) setState({ phase: "ready", snapshot: next, message: null });
    }).catch(() => {
      if (active) {
        setState((current) => current.snapshot
          ? { phase: "error", snapshot: current.snapshot, message: "Live updates paused. The last validated snapshot remains visible." }
          : { phase: "error", snapshot: null, message: "Live updates are unavailable." });
      }
    });
    return () => { active = false; };
  }, [eventSequence, liveWatch, state.phase === "loading", watchEpoch]);
  const visibleWorkers = useMemo(() => snapshot ? graphWorkers(snapshot, settings, selectedSlot) : [], [selectedSlot, settings, snapshot]);
  const selectedWorker = useMemo(() => snapshot ? snapshot.worker_graph.workers.find((worker) => worker.slot_id === selectedSlot) ?? visibleWorkers[0] ?? snapshot.worker_graph.workers[0] ?? null : null, [selectedSlot, snapshot, visibleWorkers]);
  const selectedSource = useMemo(() => sourceThreads.find((thread) => thread.id === selectedSourceId) ?? null, [selectedSourceId, sourceThreads]);
  const visibleSourceThreads = useMemo(() => snapshot ? sourceThreads.filter((thread) =>
    thread.runtimeStatus === "active"
    || thread.id === selectedSourceId
    || activityAgentIsRecent(snapshot, `source:${thread.id}`, settings)) : sourceThreads, [selectedSourceId, settings, snapshot, sourceThreads]);
  selectedSourceBinding.current = selectedSource?.id ?? null;
  useEffect(() => {
    sourceInboxRequest.current += 1;
    if (!selectedSource || !sourceInboxLoader) {
      setSourceInboxState({ phase: "idle", inbox: null, message: null });
      return;
    }
    const threadId = selectedSource.id;
    const existing = sourceInboxFlights.current.get(threadId);
    if (existing) {
      existing.dirty = true;
      existing.loader = sourceInboxLoader;
      return;
    }
    const flight = { dirty: false, loader: sourceInboxLoader };
    sourceInboxFlights.current.set(threadId, flight);
    const run = async () => {
      try {
        while (selectedSourceBinding.current === threadId) {
          flight.dirty = false;
          const request = sourceInboxRequest.current;
          setSourceInboxState({ phase: "loading", inbox: null, message: null });
          try {
            const inbox = await flight.loader(threadId);
            if (sourceInboxRequest.current === request && selectedSourceBinding.current === threadId && inbox.source_id === threadId) {
              setSourceInboxState({ phase: "ready", inbox, message: null });
            }
          } catch (error: unknown) {
            if (sourceInboxRequest.current === request && selectedSourceBinding.current === threadId) {
              if (error instanceof SourceInboxUnsupportedError) {
                setSourceInboxState({ phase: "unsupported", inbox: null, message: "Per-thread Source inbox is unsupported by this controller version." });
              } else {
                setSourceInboxState({ phase: "error", inbox: null, message: "Source inbox metadata is unavailable." });
              }
            }
          }
          if (!flight.dirty || selectedSourceBinding.current !== threadId) break;
        }
      } finally {
        sourceInboxFlights.current.delete(threadId);
      }
    };
    void run();
  }, [eventSequence, selectedSource?.id, sourceInboxLoader, sourceInboxRefreshEpoch, watchEpoch]);
  const reloadSourceInspection = useCallback(() => {
    const request = ++sourceRequest.current;
    if (!selectedSource) {
      setSourceInspection({ phase: "idle", inspection: null, message: null });
      return;
    }
    const threadId = selectedSource.id;
    setSourceInspection({ phase: "loading", inspection: null, message: null });
    void inspectSource(threadId).then((inspection) => {
      if (sourceRequest.current !== request || selectedSourceBinding.current !== threadId) return;
      if (inspection.threadId !== threadId) {
        setSourceInspection({ phase: "error", inspection: null, message: "This Codex thread returned a mismatched inspection." });
        return;
      }
      setSourceInspection({ phase: "ready", inspection, message: null });
    }).catch(() => {
      if (sourceRequest.current === request && selectedSourceBinding.current === threadId) setSourceInspection({ phase: "error", inspection: null, message: "This Codex thread could not be inspected." });
    });
  }, [inspectSource, selectedSource?.id]);
  useEffect(() => { reloadSourceInspection(); }, [reloadSourceInspection]);
  const composeSelectedSource = useCallback(async (text: string) => {
    if (!selectedSource || !sourceInspection.inspection || sourceInspection.phase === "sending") return;
    const inspection = sourceInspection.inspection;
    if (inspection.threadId !== selectedSource.id || selectedSourceBinding.current !== selectedSource.id) return;
    const request = ++sourceRequest.current;
    setSourceReceipt(null);
    setSourceInspection({ phase: "sending", inspection, message: null });
    try {
      const outcome = await composeSource(inspection, text);
      if (sourceRequest.current !== request || selectedSourceBinding.current !== inspection.threadId) return;
      setSourceReceipt(outcome);
      setSourceActivity({ sequence: ++sourceActivitySequence.current, threadId: inspection.threadId, outcome });
      setSourceInspection({ phase: "ready", inspection, message: null });
    } catch {
      if (sourceRequest.current !== request || selectedSourceBinding.current !== inspection.threadId) return;
      setSourceInspection({ phase: "error", inspection, message: "The message was rejected before an authoritative receipt was returned." });
    }
  }, [composeSource, selectedSource?.id, sourceInspection]);
  useEffect(() => {
    if (snapshot || sourceInspection.inspection === null) return;
    sourceRequest.current += 1;
    setSourceInspection({ phase: "idle", inspection: null, message: null });
    setSourceReceipt(null);
  }, [snapshot, sourceInspection.inspection]);
  const selectedTarget = useMemo<WorkerTranscriptTarget | null>(() => {
    const generation = selectedWorker?.transport.generation;
    if (selectedView !== "worker" || selectedSlot === null || !selectedWorker?.work_id || typeof generation !== "number" || selectedWorker.slot_state !== "assigned") return null;
    return { slot_id: selectedWorker.slot_id, work_id: selectedWorker.work_id, generation };
  }, [selectedSlot, selectedView, selectedWorker?.slot_id, selectedWorker?.slot_state, selectedWorker?.work_id, selectedWorker?.transport.generation]);
  const selectedArchives = useMemo<TranscriptArchiveItem[]>(() => {
    if (selectedView !== "worker" || !selectedWorker || selectedWorker.slot_state === "assigned") return [];
    return snapshot?.transcript_archive?.items.filter((item) => item.slot_id === selectedWorker.slot_id) ?? [];
  }, [selectedView, selectedWorker?.slot_id, selectedWorker?.slot_state, snapshot?.transcript_archive]);
  const selectedArchive = useMemo(() => {
    if (!selectedArchives.length) return null;
    return selectedArchives.find((item) => item.archive_id === selectedArchiveId) ?? selectedArchives[0];
  }, [selectedArchiveId, selectedArchives]);
  const selectedArchiveTarget = useMemo<ArchivedTranscriptTarget | null>(() => selectedArchive ? {
    archive_id: selectedArchive.archive_id,
    slot_id: selectedArchive.slot_id,
    work_id: selectedArchive.work_id,
    generation: selectedArchive.generation,
  } : null, [selectedArchive]);
  const selectedTargetKey = selectedTarget
    ? `live:${selectedTarget.slot_id}:${selectedTarget.work_id}:${selectedTarget.generation}`
    : selectedArchiveTarget
      ? `archive:${selectedArchiveTarget.archive_id}:${selectedArchiveTarget.slot_id}:${selectedArchiveTarget.work_id}:${selectedArchiveTarget.generation}`
      : null;
  selectedBinding.current = selectedTargetKey;
  const reloadTranscript = useCallback((options?: { silent?: boolean }) => {
    const request = ++transcriptRequest.current;
    if (!selectedTarget && !selectedArchiveTarget) {
      setTranscript({ phase: "idle", bundle: null, message: null });
      return;
    }
    const binding = selectedTargetKey;
    if (options?.silent) {
      setTranscript((prev) => (prev.bundle ? prev : { phase: "loading", bundle: null, message: null }));
    } else {
      setTranscript({ phase: "loading", bundle: null, message: null });
    }
    const requestTranscript = selectedTarget
      ? loadTranscript(selectedTarget)
      : loadArchivedTranscript(selectedArchiveTarget!);
    void requestTranscript.then((bundle) => {
      if (transcriptRequest.current !== request) return;
      if (selectedBinding.current !== binding) return;
      setTranscript({ phase: "ready", bundle, message: null });
    }).catch((error) => {
      if (transcriptRequest.current !== request) return;
      if (selectedBinding.current !== binding) return;
      setTranscript((prev) => {
        if (options?.silent && prev.bundle) {
          return { phase: "error", bundle: prev.bundle, message: transcriptFailureMessage(error) };
        }
        return { phase: "error", bundle: null, message: transcriptFailureMessage(error) };
      });
    });
  }, [loadArchivedTranscript, loadTranscript, selectedArchiveTarget, selectedTarget, selectedTargetKey]);
  useEffect(() => { reloadTranscript(); }, [reloadTranscript]);
  const lastSilentBindingRef = useRef<string | null>(null);
  const lastSilentSeqRef = useRef<number | null>(null);
  useEffect(() => {
    if (!selectedTarget || eventSequence === null) {
      lastSilentBindingRef.current = selectedTargetKey;
      lastSilentSeqRef.current = eventSequence;
      return;
    }
    if (lastSilentSeqRef.current === eventSequence && lastSilentBindingRef.current === selectedTargetKey) return;
    const isSameBinding = lastSilentBindingRef.current === selectedTargetKey;
    lastSilentSeqRef.current = eventSequence;
    lastSilentBindingRef.current = selectedTargetKey;
    if (!isSameBinding) return;
    reloadTranscript({ silent: true });
  }, [eventSequence, selectedTargetKey, selectedTarget, reloadTranscript]);
  const composeSelectedWorker = useCallback(async (text: string) => {
    if (!transcript.bundle || isArchivedTranscript(transcript.bundle) || transcript.phase === "sending") return;
    const bundle = transcript.bundle;
    const binding = `live:${bundle.slot_id}:${bundle.work_id}:${bundle.generation}`;
    setComposerReceipt(null);
    setTranscript({ phase: "sending", bundle, message: null });
    try {
      const receipt = await composeWorker(bundle, text);
      if (selectedBinding.current !== binding) return;
      setComposerReceipt(receipt);
      setTranscript({ phase: "ready", bundle, message: null });
      reloadTranscript({ silent: true });
    } catch {
      if (selectedBinding.current !== binding) return;
      setTranscript({ phase: "error", bundle, message: "The message was rejected before an authoritative receipt was returned." });
    }
  }, [composeWorker, reloadTranscript, transcript]);

  if (state.phase === "loading") return <main className="loading-screen"><div className="loading-glyph">ƒ</div><p>$ opening fugue --observe</p></main>;
  if (!snapshot) return <main className="unavailable-screen"><section><span className="terminal-label">FUGUE // OFFLINE</span><h1>Controller view unavailable</h1><p>{state.message}</p><button type="button" onClick={() => void startAndLoad()}><RefreshCw size={15} /> TRY AGAIN</button><small>No controller state was changed.</small></section></main>;

  const activeCount = snapshot.worker_graph.workers.filter((worker) => worker.slot_state === "assigned").length;
  const attention = attentionGroups(snapshot);
  const actionCount = attention.operator.items.length + attention.automatic.items.length;
  const deliveryCount = attention.delivery.items.length;
  const matchingLegacySourceInbox = selectedSource && snapshot.source_inbox?.source_id === selectedSource.id ? snapshot.source_inbox : undefined;
  const legacySourceInbox = matchingLegacySourceInbox?.status === "available" ? matchingLegacySourceInbox : undefined;
  const selectedSourceInbox = sourceInboxState.phase === "ready" && sourceInboxState.inbox.source_id === selectedSource?.id
    ? sourceInboxState.inbox
    : (sourceInboxState.phase === "unsupported" ? legacySourceInbox : undefined);
  const selectedSourceInboxState: SourceInboxLoadState = sourceInboxState.phase === "unsupported" && matchingLegacySourceInbox?.status === "unavailable"
    ? { phase: "error", inbox: null, message: "Legacy Source inbox metadata is unavailable." }
    : sourceInboxState;
  const inspectorStyle = { "--inspector-width": inspectorCollapsed ? "44px" : `${inspectorWidth}px` } as CSSProperties;
  return (
    <main className={`graph-shell ${inspectorCollapsed ? "inspector-is-collapsed" : ""}`} style={inspectorStyle}>
      <section className="graph-workspace">
        <header className="graph-header"><div className="graph-brand"><span>ƒ</span><strong>Fugue</strong><em>OFFLOAD TOPOLOGY</em></div><div className="graph-summary"><span><strong>{activeCount}</strong> ACTIVE</span><span><strong>{collectionCount(snapshot.queue)}</strong> QUEUED</span><span className={actionCount ? "summary-attention" : ""}><strong>{actionCount}</strong> ACTION</span>{deliveryCount > 0 && <span><strong>{deliveryCount}</strong> DELIVERY</span>}<span>EVENT <strong>{snapshot.snapshot_version.event_sequence ?? "—"}</strong></span></div><div className="graph-actions"><span className={`system-status system-${snapshot.availability.status}`}><i />{snapshot.availability.status === "available" ? "READY" : snapshot.availability.status.toUpperCase()}</span><button type="button" className="settings-control-button" aria-label="Open settings" aria-expanded={settingsOpen} aria-controls="fugue-settings" onClick={() => setSettingsOpen(true)}><SettingsIcon size={14} /> SETTINGS</button><button type="button" className="refresh-control" onClick={() => void load(true)} disabled={state.phase === "refreshing"} aria-label="Refresh snapshot"><RefreshCw size={14} className={state.phase === "refreshing" ? "spinning" : ""} /></button></div></header>
        {(state.phase === "error" || snapshot.availability.status !== "available") && <div className="snapshot-warning" role="status"><AlertTriangle size={14} />{state.message ?? snapshot.availability.errors.map(formatReason).join(" · ")}</div>}
        <div className="graph-toolbar"><div><span className="terminal-label">$ inspect offloads --snapshot</span><h1>Agent graph</h1></div><div className="graph-filters">{(["all", "dispatch", "callbacks"] as const).map((value) => <button type="button" key={value} aria-pressed={filter === value} onClick={() => setFilter(value)}>{value.toUpperCase()}</button>)}</div><div className="lifecycle-legend"><span><i className="legend-persistent">P</i>Persistent</span><span><i className="legend-disposable">D</i>Disposable</span><span><i className="legend-available" />Available</span></div></div>
        <div className="graph-canvas"><TopologyGraph snapshot={snapshot} workers={visibleWorkers} selectedSlot={selectedView === "worker" ? selectedWorker?.slot_id ?? null : null} sourceThreads={visibleSourceThreads} selectedSourceId={selectedView === "source" ? selectedSourceId : null} sourceActivity={sourceActivity} filter={filter} settings={settings} onSelect={selectWorker} onSelectSource={selectSource} /><QueueDock snapshot={snapshot} /><ActivityLog snapshot={snapshot} workers={snapshot.worker_graph.workers} sourceThreads={sourceThreads} sourceActivity={sourceActivity} /></div>
      </section>
      {inspectorCollapsed ? <div className="inspector-collapsed"><button type="button" onClick={() => setInspectorCollapsed(false)} aria-expanded="false" aria-controls="fugue-inspector" aria-label="Expand inspector"><PanelRightOpen size={15} /><span>DETAILS</span></button></div> : <InspectorPane width={inspectorWidth} onWidth={updateInspectorWidth} onCollapse={() => setInspectorCollapsed(true)}>{selectedView === "source" && selectedSource ? <SourceInspector key={selectedSource.id} thread={selectedSource} inbox={selectedSourceInbox} inboxState={selectedSourceInboxState} inspection={sourceInspection} receipt={sourceReceipt} onCompose={composeSelectedSource} onReload={reloadSourceInspection} /> : selectedWorker && <WorkerInspector worker={selectedWorker} tab={inspectorTab} onTab={setInspectorTab} transcript={transcript} receipt={composerReceipt} onCompose={composeSelectedWorker} archiveItems={selectedArchives} selectedArchiveId={selectedArchive?.archive_id ?? null} onSelectArchive={setSelectedArchiveId} />}</InspectorPane>}
      <SettingsPage open={settingsOpen} settings={settings} reducedMotion={reducedMotion} onChange={updateSettings} onClose={closeSettings} onReset={resetSettings} loadIntegration={loadIntegration} changeIntegration={changeIntegration} loadLlmBehaviour={loadLlmBehaviour} changeLlmBehaviour={changeLlmBehaviour} />
    </main>
  );
}
