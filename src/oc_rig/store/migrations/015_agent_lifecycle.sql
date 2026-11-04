ALTER TABLE scheduler_admission_decisions
ADD COLUMN agent_lifecycle TEXT NOT NULL DEFAULT 'persistent'
    CHECK(agent_lifecycle IN ('disposable','persistent'));

ALTER TABLE scheduler_admission_decisions
ADD COLUMN allow_child_agents INTEGER NOT NULL DEFAULT 0
    CHECK(allow_child_agents IN (0, 1));

-- Before lifecycle authority existed, read-only scope capsules always used an
-- isolated disposable session. Preserve that meaning for durable deliveries
-- which were already recorded before this migration.
DROP TRIGGER scheduler_admission_decisions_are_immutable_update;
UPDATE scheduler_admission_decisions
SET agent_lifecycle = 'disposable'
WHERE id IN (
    SELECT delivery.admission_decision_id
    FROM transport_deliveries AS delivery
    WHERE substr(
              json_extract(delivery.payload_json, '$.prompt'),
              1,
              length('RIG_READ_ONLY_REVIEW_V1') + 1
          ) = 'RIG_READ_ONLY_REVIEW_V1' || char(10)
);
CREATE TRIGGER scheduler_admission_decisions_are_immutable_update
BEFORE UPDATE ON scheduler_admission_decisions BEGIN
    SELECT RAISE(ABORT, 'scheduler admission decision is immutable');
END;

CREATE TABLE gui_task_submissions (
    submission_key TEXT PRIMARY KEY,
    request_fingerprint TEXT NOT NULL CHECK(
        length(request_fingerprint) = 64 AND
        request_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    canonical_json TEXT NOT NULL CHECK(
        json_valid(canonical_json) AND json_type(canonical_json) = 'object'
    ),
    state TEXT NOT NULL CHECK(state IN ('prepared','completed')),
    outcome_json TEXT CHECK(
        outcome_json IS NULL OR
        (json_valid(outcome_json) AND json_type(outcome_json) = 'object')
    ),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK(
        (state = 'prepared' AND outcome_json IS NULL AND completed_at IS NULL) OR
        (state = 'completed' AND outcome_json IS NOT NULL AND completed_at IS NOT NULL)
    )
) STRICT;
CREATE TRIGGER gui_task_submission_identity_is_immutable
BEFORE UPDATE OF submission_key, request_fingerprint, canonical_json, created_at
ON gui_task_submissions BEGIN
    SELECT RAISE(ABORT, 'GUI task submission identity is immutable');
END;
CREATE TRIGGER gui_task_submission_completes_once
BEFORE UPDATE OF state, outcome_json, completed_at ON gui_task_submissions
WHEN NOT (
    OLD.state = 'prepared' AND NEW.state = 'completed' AND
    OLD.outcome_json IS NULL AND NEW.outcome_json IS NOT NULL AND
    OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL
) BEGIN
    SELECT RAISE(ABORT, 'GUI task submission completes exactly once');
END;

CREATE TABLE opencode_persistent_sessions (
    scope_hash TEXT PRIMARY KEY CHECK(
        length(scope_hash) = 64 AND scope_hash NOT GLOB '*[^0-9a-f]*'
    ),
    pool TEXT NOT NULL,
    worker TEXT NOT NULL,
    title TEXT NOT NULL UNIQUE,
    session_id TEXT UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('intended','active','closed','attention')),
    error TEXT,
    claim_token TEXT,
    claim_started_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER opencode_persistent_session_identity_is_immutable
BEFORE UPDATE OF scope_hash, pool, worker, title, created_at
ON opencode_persistent_sessions
BEGIN
    SELECT RAISE(ABORT, 'persistent session identity is immutable');
END;
CREATE TRIGGER opencode_persistent_session_binding_is_immutable
BEFORE UPDATE OF session_id ON opencode_persistent_sessions
WHEN OLD.session_id IS NOT NULL OR NEW.session_id IS NULL
BEGIN
    SELECT RAISE(ABORT, 'persistent session binding is immutable');
END;

ALTER TABLE opencode_deliveries
ADD COLUMN agent_lifecycle TEXT NOT NULL DEFAULT 'persistent'
    CHECK(agent_lifecycle IN ('disposable','persistent'));
UPDATE opencode_deliveries
SET agent_lifecycle = 'disposable'
WHERE isolated_session_id IS NOT NULL;
DROP INDEX opencode_isolated_session_is_single_use;
CREATE UNIQUE INDEX opencode_disposable_session_is_single_use
ON opencode_deliveries(isolated_session_id)
WHERE isolated_session_id IS NOT NULL AND agent_lifecycle = 'disposable';

DROP TRIGGER opencode_cleanup_requires_isolated_session;
CREATE TRIGGER opencode_cleanup_requires_isolated_session
BEFORE UPDATE OF cleanup_state ON opencode_deliveries
WHEN NEW.isolated_session_id IS NULL OR NEW.agent_lifecycle != 'disposable' OR NOT (
    (OLD.cleanup_state = 'none' AND NEW.cleanup_state = 'pending') OR
    (OLD.cleanup_state IN ('pending','ambiguous') AND NEW.cleanup_state = 'in_flight') OR
    (OLD.cleanup_state = 'in_flight' AND NEW.cleanup_state IN ('succeeded','ambiguous','failed'))
) BEGIN
    SELECT RAISE(ABORT, 'invalid isolated session cleanup transition');
END;
DROP TRIGGER opencode_cleanup_enqueue_after_release;
CREATE TRIGGER opencode_cleanup_enqueue_after_release
AFTER UPDATE OF lease_state ON opencode_deliveries
WHEN NEW.lease_state = 'released'
 AND NEW.isolated_session_id IS NOT NULL
 AND NEW.agent_lifecycle = 'disposable'
BEGIN
    UPDATE opencode_deliveries SET cleanup_state = 'pending'
    WHERE transport_id = NEW.transport_id AND cleanup_state = 'none';
END;
