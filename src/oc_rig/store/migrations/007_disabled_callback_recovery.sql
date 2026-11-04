CREATE TABLE milestone_seven_remediation_guard (
    valid INTEGER NOT NULL CHECK(valid = 1)
) STRICT;
INSERT INTO milestone_seven_remediation_guard(valid)
SELECT CASE WHEN
    NOT EXISTS (
        SELECT 1 FROM callbacks AS callback
        LEFT JOIN outbox ON outbox.callback_id = callback.id
        WHERE outbox.id IS NULL OR callback.state != outbox.state
    ) AND
    NOT EXISTS (
        SELECT 1 FROM outbox
        LEFT JOIN callbacks AS callback ON callback.id = outbox.callback_id
        WHERE callback.id IS NULL
    ) AND
    NOT EXISTS (
        SELECT 1 FROM callbacks
        WHERE state = 'delivered'
    ) AND
    NOT EXISTS (
        SELECT 1 FROM callbacks AS callback
        WHERE callback.state = 'delivering' AND NOT EXISTS (
            SELECT 1 FROM callback_delivery_attempts AS attempt
            WHERE attempt.callback_id = callback.id
              AND attempt.attempt_number = callback.attempts
              AND attempt.delivery_key = callback.delivery_key
              AND attempt.state = 'delivering'
        )
    ) AND
    NOT EXISTS (
        SELECT 1 FROM callback_delivery_attempts AS attempt
        JOIN callbacks AS callback ON callback.id = attempt.callback_id
        WHERE attempt.state = 'delivering' AND callback.state != 'delivering'
    )
THEN 1 ELSE 0 END;
DROP TABLE milestone_seven_remediation_guard;

ALTER TABLE outbox ADD COLUMN disabled_reason TEXT;

UPDATE callbacks
SET state = 'blocked', failure_class = NULL,
    attention_reason = 'callback_adapter_disabled'
WHERE state IN ('blocked','pending');
UPDATE outbox
SET state = 'blocked', disabled_reason = 'callback_adapter_disabled'
WHERE state IN ('blocked','pending');
UPDATE outbox
SET disabled_reason = 'delivery_unknown_after_restart'
WHERE state = 'attention' AND EXISTS (
    SELECT 1 FROM callbacks AS callback
    WHERE callback.id = outbox.callback_id
      AND callback.failure_class = 'delivery_unknown'
);

CREATE TRIGGER callback_blocked_requires_disabled_reason_insert
BEFORE INSERT ON callbacks
WHEN NEW.state = 'blocked' AND NEW.attention_reason IS NULL BEGIN
    SELECT RAISE(ABORT, 'blocked callback requires disabled reason');
END;
CREATE TRIGGER callback_blocked_requires_disabled_reason_update
BEFORE UPDATE OF state, attention_reason ON callbacks
WHEN NEW.state = 'blocked' AND NEW.attention_reason IS NULL BEGIN
    SELECT RAISE(ABORT, 'blocked callback requires disabled reason');
END;
CREATE TRIGGER outbox_blocked_requires_disabled_reason_insert
BEFORE INSERT ON outbox
WHEN NEW.state = 'blocked' AND NEW.disabled_reason IS NULL BEGIN
    SELECT RAISE(ABORT, 'blocked outbox requires disabled reason');
END;
CREATE TRIGGER outbox_blocked_requires_disabled_reason_update
BEFORE UPDATE OF state, disabled_reason ON outbox
WHEN NEW.state = 'blocked' AND NEW.disabled_reason IS NULL BEGIN
    SELECT RAISE(ABORT, 'blocked outbox requires disabled reason');
END;

DROP TRIGGER recovery_attempt_identity_is_immutable;
DROP TRIGGER recovery_attempt_safe_state_update;
ALTER TABLE recovery_attempts RENAME TO recovery_attempts_v6;
CREATE TABLE recovery_attempts (
    id TEXT PRIMARY KEY,
    episode_id TEXT NOT NULL REFERENCES recovery_episodes(id),
    timer_id TEXT NOT NULL UNIQUE REFERENCES recovery_timers(id),
    attempt_number INTEGER NOT NULL CHECK(attempt_number BETWEEN 1 AND 6),
    tier TEXT NOT NULL CHECK(tier IN ('fast','normal')),
    state TEXT NOT NULL CHECK(state IN (
        'due','succeeded','no_progress','terminal','cancelled'
    )),
    failure_class TEXT CHECK(failure_class IN (
        'transient','deterministic','permission','policy','delivery_unknown'
    )),
    reason TEXT NOT NULL,
    due_at_us INTEGER NOT NULL CHECK(due_at_us >= 0),
    finished_at_us INTEGER,
    UNIQUE(episode_id, attempt_number)
) STRICT;
INSERT INTO recovery_attempts(
    id, episode_id, timer_id, attempt_number, tier, state,
    failure_class, reason, due_at_us, finished_at_us
)
SELECT
    id, episode_id, timer_id, attempt_number, tier, state,
    failure_class, reason, due_at_us, finished_at_us
FROM recovery_attempts_v6;
DROP TABLE recovery_attempts_v6;
CREATE TRIGGER recovery_attempt_identity_is_immutable
BEFORE UPDATE OF id, episode_id, timer_id, attempt_number, tier, reason, due_at_us
ON recovery_attempts BEGIN
    SELECT RAISE(ABORT, 'recovery attempt identity is immutable');
END;
CREATE TRIGGER recovery_attempt_safe_state_update
BEFORE UPDATE OF state ON recovery_attempts
WHEN NOT (
    OLD.state = 'due' AND NEW.state IN (
        'succeeded','no_progress','terminal','cancelled'
    )
) BEGIN
    SELECT RAISE(ABORT, 'invalid recovery attempt transition');
END;
