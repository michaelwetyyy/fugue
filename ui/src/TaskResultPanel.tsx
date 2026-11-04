import { useState } from "react";
import { ArrowRight, Clock3, History, RefreshCw, X } from "lucide-react";
import {
  closePersistentTask,
  fetchTaskResult,
  type TaskResult,
  type TaskSessionCloseResult,
  type TaskSubmission,
  type TaskSubmissionResult,
} from "./submission";

interface TaskResultPanelProps {
  task: { input: TaskSubmission; submission: TaskSubmissionResult };
  onClose: () => void;
  onFollowup: (input: TaskSubmission) => void;
  read?: (submissionId: string, attempt: number) => Promise<TaskResult>;
  closeSession?: (submissionId: string, attempt: number) => Promise<TaskSessionCloseResult>;
}

export interface SavedTask {
  input: TaskSubmission;
  submission: TaskSubmissionResult;
}

export function TaskHistoryPanel({
  tasks,
  onClose,
  onSelect,
}: {
  tasks: SavedTask[];
  onClose: () => void;
  onSelect: (task: SavedTask) => void;
}) {
  return (
    <div className="drawer-backdrop composer-backdrop" role="presentation">
      <aside className="task-composer result-panel" role="dialog" aria-modal="true" aria-labelledby="task-history-title">
        <button type="button" className="drawer-close" onClick={onClose} aria-label="Close task history"><X /></button>
        <span className="eyebrow">Durable client registry</span>
        <h2 id="task-history-title">Recent tasks</h2>
        <div className="task-history-list">
          {tasks.length === 0 ? (
            <div className="result-waiting"><History /><strong>No tasks saved yet</strong></div>
          ) : tasks.map((task) => (
            <button type="button" key={`${task.input.submission_id}-${task.input.reservation_attempt}`} onClick={() => onSelect(task)}>
              <span className="policy-tag">{task.input.agent_lifecycle}</span>
              <strong>{task.input.objective}</strong>
              <small>{task.input.lane} · attempt {task.input.reservation_attempt}</small>
              <ArrowRight size={15} />
            </button>
          ))}
        </div>
      </aside>
    </div>
  );
}

export default function TaskResultPanel({
  task,
  onClose,
  onFollowup,
  read = fetchTaskResult,
  closeSession = closePersistentTask,
}: TaskResultPanelProps) {
  const [result, setResult] = useState<TaskResult | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmClose, setConfirmClose] = useState(false);
  const [closing, setClosing] = useState(false);

  async function check() {
    if (checking) return;
    setChecking(true);
    setError(null);
    try {
      setResult(await read(task.submission.submission_id, task.submission.reservation_attempt));
    } catch {
      setError("Fugue could not read this result. The task itself was left unchanged.");
    } finally {
      setChecking(false);
    }
  }

  async function closeRetainedSession() {
    if (closing || !result || result.persistent_session_state !== "active") return;
    setClosing(true);
    setError(null);
    try {
      const closed = await closeSession(task.submission.submission_id, task.submission.reservation_attempt);
      setResult({ ...result, persistent_session_state: closed.state });
      setConfirmClose(false);
      if (closed.state === "attention") {
        setError("Fugue could not prove the retained session was fully deleted. It has been fenced for operator attention and will not be reused.");
      }
    } catch {
      setError("Fugue did not close the retained session. No blind retry was performed.");
    } finally {
      setClosing(false);
    }
  }

  return (
    <div className="drawer-backdrop composer-backdrop" role="presentation">
      <aside className="task-composer result-panel" role="dialog" aria-modal="true" aria-labelledby="task-result-title">
        <button type="button" className="drawer-close" onClick={onClose} aria-label="Close task result"><X /></button>
        <span className="eyebrow">{task.input.agent_lifecycle} task</span>
        <h2 id="task-result-title">Task result</h2>
        {!result || result.state === "waiting" ? (
          <div className="result-waiting">
            <Clock3 />
            <strong>{result ? "Still working" : "Task started"}</strong>
            <p>Check when you want an update. Fugue does not poll in the background.</p>
          </div>
        ) : result.state === "not_started" ? (
          <div className="result-waiting"><strong>Task did not start</strong></div>
        ) : (
          <div className="result-complete">
            <span className={`policy-tag policy-${result.outcome}`}>{result.outcome}</span>
            <pre>{result.text ?? "The worker completed without a text result."}</pre>
          </div>
        )}
        {error && <p className="composer-error" role="alert">{error}</p>}
        <div className="result-actions">
          <button className="refresh-button" type="button" onClick={() => void check()} disabled={checking}>
            <RefreshCw size={16} className={checking ? "spin" : ""} />
            {checking ? "Checking" : "Check result"}
          </button>
          {task.input.agent_lifecycle === "persistent" && result?.state === "completed" && result.persistent_session_state === "active" && (
            <>
              <button className="primary-button" type="button" onClick={() => onFollowup(task.input)}>
                Continue task <ArrowRight size={16} />
              </button>
              {!confirmClose ? (
                <button className="refresh-button" type="button" onClick={() => setConfirmClose(true)}>
                  Close retained session
                </button>
              ) : (
                <>
                  <button className="refresh-button" type="button" onClick={() => void closeRetainedSession()} disabled={closing}>
                    {closing ? "Closing" : "Confirm close"}
                  </button>
                  <button className="refresh-button" type="button" onClick={() => setConfirmClose(false)} disabled={closing}>Cancel</button>
                </>
              )}
            </>
          )}
          {task.input.agent_lifecycle === "persistent" && result?.persistent_session_state === "closed" && (
            <span className="policy-tag">RETAINED SESSION CLOSED</span>
          )}
          {task.input.agent_lifecycle === "persistent" && result?.persistent_session_state === "attention" && (
            <span className="policy-tag policy-failed">SESSION FENCED · ATTENTION</span>
          )}
        </div>
      </aside>
    </div>
  );
}
