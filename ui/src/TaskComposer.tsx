import { useMemo, useState } from "react";
import { ArrowRight, Bot, GitBranch, ShieldCheck, Sparkles, X } from "lucide-react";
import { LANE_META } from "./model";
import {
  parseScope,
  submitTask,
  validateSubmission,
  type AgentLifecycle,
  type TaskSubmission,
  type TaskSubmissionResult,
} from "./submission";

interface TaskComposerProps {
  onClose: () => void;
  onSubmitted: (result: TaskSubmissionResult, input: TaskSubmission) => void;
  submit?: (input: TaskSubmission) => Promise<TaskSubmissionResult>;
  initial?: Pick<TaskSubmission, "lane" | "repository" | "scope" | "agent_lifecycle">;
  continuation?: boolean;
}

function safeFailure(error: unknown): string {
  if (error instanceof Error && error.message.length <= 160 && !/[\/\\]/.test(error.message)) return error.message;
  return "Fugue could not submit this task. Your draft is unchanged.";
}

export default function TaskComposer({ onClose, onSubmitted, submit = submitTask, initial, continuation = false }: TaskComposerProps) {
  const [submissionId] = useState(() => crypto.randomUUID());
  const [lane, setLane] = useState(initial?.lane ?? "homelab");
  const [repository, setRepository] = useState(initial?.repository ?? "");
  const [scopeText, setScopeText] = useState(initial?.scope.join("\n") ?? "");
  const [objective, setObjective] = useState("");
  const [lifecycle, setLifecycle] = useState<AgentLifecycle>(initial?.agent_lifecycle ?? "disposable");
  const [reservationAttempt, setReservationAttempt] = useState(1);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const input = useMemo<TaskSubmission>(() => ({
    submission_id: submissionId,
    lane,
    repository: repository.trim(),
    scope: parseScope(scopeText),
    objective: objective.trim(),
    agent_lifecycle: lifecycle,
    reservation_attempt: reservationAttempt,
  }), [submissionId, lane, repository, scopeText, objective, lifecycle, reservationAttempt]);

  const issue = validateSubmission(input);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (issue || submitting) { setError(issue); return; }
    setSubmitting(true);
    setError(null);
    try {
      const result = await submit(input);
      if (result.state === "busy") {
        setReservationAttempt((current) => current + 1);
        setError("This lane is full. Nothing was claimed; retry when capacity is available.");
        setSubmitting(false);
        return;
      }
      onSubmitted(result, input);
    } catch (caught) {
      setError(safeFailure(caught));
      setSubmitting(false);
    }
  }

  return (
    <div className="drawer-backdrop composer-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && !submitting && onClose()}>
      <aside className="task-composer" role="dialog" aria-modal="true" aria-labelledby="new-task-title">
        <button type="button" className="drawer-close" onClick={onClose} disabled={submitting} aria-label="Close new task"><X /></button>
        <span className="eyebrow">Controller admission</span>
        <h2 id="new-task-title">{continuation ? "Continue task" : "New task"}</h2>
        <p className="composer-intro">{continuation ? "This turn returns to the same retained session and exact scope." : "Fugue will claim the exact scope before any worker receives it."}</p>
        <form onSubmit={handleSubmit}>
          <label className="field-label" htmlFor="task-objective">Objective</label>
          <textarea id="task-objective" value={objective} onChange={(event) => setObjective(event.target.value)} rows={4} placeholder="What outcome should the agent produce?" autoFocus />

          <fieldset className="form-section">
            <legend>Task lifespan</legend>
            <div className="lifecycle-grid">
              <label className={`choice-card ${lifecycle === "disposable" ? "choice-selected" : ""}`}>
                <input type="radio" name="lifecycle" value="disposable" checked={lifecycle === "disposable"} onChange={() => setLifecycle("disposable")} disabled={continuation} />
                <Sparkles /><strong>Disposable</strong><span>Fresh context for one bounded outcome, then closes automatically.</span>
              </label>
              <label className={`choice-card ${lifecycle === "persistent" ? "choice-selected" : ""}`}>
                <input type="radio" name="lifecycle" value="persistent" checked={lifecycle === "persistent"} onChange={() => setLifecycle("persistent")} disabled={continuation} />
                <GitBranch /><strong>Persistent</strong><span>Same repository and scope return to one secure session for orchestrator follow-ups.</span>
              </label>
            </div>
          </fieldset>

          <fieldset className="form-section">
            <legend>Lane</legend>
            <div className="lane-choices">
              {LANE_META.map((item) => (
                <label className={lane === item.id ? "lane-choice lane-choice-selected" : "lane-choice"} key={item.id}>
                  <input type="radio" name="lane" value={item.id} checked={lane === item.id} onChange={() => setLane(item.id)} disabled={continuation} />
                  <span>{item.symbol}</span>{item.label}
                </label>
              ))}
            </div>
          </fieldset>

          <label className="field-label" htmlFor="task-repository">Repository</label>
          <input id="task-repository" value={repository} onChange={(event) => setRepository(event.target.value)} placeholder="/absolute/path/to/project" spellCheck={false} disabled={continuation} />
          <label className="field-label" htmlFor="task-scope">Scope</label>
          <textarea id="task-scope" value={scopeText} onChange={(event) => setScopeText(event.target.value)} rows={3} placeholder={"src/feature.ts\ntests/feature.test.ts"} spellCheck={false} disabled={continuation} />
          <small className="field-help">One repository-relative path per line. Fugue rejects duplicates and unsafe files.</small>

          <div className="delegation-notice"><Bot /><div><strong>Child agents enabled</strong><span>Both lifespans may delegate bounded analysis to non-recursive children inside this task’s trust boundary.</span></div></div>
          <div className="security-notice"><ShieldCheck /> Secure mode · PUBLIC material only</div>
          {error && <p className="composer-error" role="alert">{error}</p>}
          <button className="primary-button composer-submit" type="submit" disabled={submitting}>
            {submitting ? "Submitting" : "Start task"}<ArrowRight size={16} />
          </button>
        </form>
      </aside>
    </div>
  );
}
