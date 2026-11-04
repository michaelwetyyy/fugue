CREATE TABLE scheduler_topology_upgrade_guard (
    valid INTEGER NOT NULL CHECK(valid = 1)
) STRICT;
INSERT INTO scheduler_topology_upgrade_guard(valid)
SELECT CASE WHEN (
    SELECT group_concat(identity, ',')
    FROM (
        SELECT id || ':' || lane || ':' || position AS identity
        FROM scheduler_slots
        ORDER BY id
    )
) = 'control-1:control:1,hands-off-1:hands-off:1,homelab-1:homelab:1,homelab-2:homelab:2,homelab-3:homelab:3,personal-1:personal:1,personal-2:personal:2,personal-3:personal:3,tensorhost-1:tensorhost:1,tensorhost-2:tensorhost:2,tensorhost-3:tensorhost:3'
AND (SELECT count(*) FROM scheduler_slots) = 11
AND NOT EXISTS (
    SELECT 1 FROM scheduler_slots
    WHERE state != 'clear' OR active_assignment_id IS NOT NULL OR
          active_work_id IS NOT NULL OR owner_id IS NOT NULL OR
          attempt IS NOT NULL OR fence_token IS NOT NULL OR
          last_used_sequence != 0
)
AND NOT EXISTS (SELECT 1 FROM scheduler_work)
AND NOT EXISTS (SELECT 1 FROM scheduler_assignments)
AND NOT EXISTS (
    SELECT 1 FROM events
    WHERE aggregate_type IN ('scheduler_work', 'scheduler_assignment')
       OR event_type LIKE 'scheduler.%'
)
THEN 1 ELSE 0 END;
DROP TABLE scheduler_topology_upgrade_guard;

CREATE TRIGGER scheduler_slot_topology_rejects_insert
BEFORE INSERT ON scheduler_slots BEGIN
    SELECT RAISE(ABORT, 'scheduler slot topology is immutable');
END;
CREATE TRIGGER scheduler_slot_topology_rejects_delete
BEFORE DELETE ON scheduler_slots BEGIN
    SELECT RAISE(ABORT, 'scheduler slot topology is immutable');
END;

ALTER TABLE scheduler_work ADD COLUMN queue_order INTEGER NOT NULL DEFAULT 0
    CHECK(queue_order >= 0);
UPDATE scheduler_work SET queue_order = sequence;
CREATE INDEX ix_scheduler_work_queue_order
    ON scheduler_work(state, lane, queue_order, sequence);

CREATE TABLE scheduler_queue_clock (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    current_value INTEGER NOT NULL CHECK(current_value >= 0)
) STRICT;
INSERT INTO scheduler_queue_clock(singleton, current_value)
SELECT 1, coalesce(max(sequence), 0) FROM scheduler_work;
CREATE TRIGGER scheduler_queue_clock_rejects_insert
BEFORE INSERT ON scheduler_queue_clock BEGIN
    SELECT RAISE(ABORT, 'scheduler queue clock is fixed');
END;
CREATE TRIGGER scheduler_queue_clock_rejects_delete
BEFORE DELETE ON scheduler_queue_clock BEGIN
    SELECT RAISE(ABORT, 'scheduler queue clock is fixed');
END;
CREATE TRIGGER scheduler_queue_clock_increments_only
BEFORE UPDATE OF singleton, current_value ON scheduler_queue_clock
WHEN NEW.singleton != 1 OR OLD.singleton != 1 OR
     NEW.current_value != OLD.current_value + 1 BEGIN
    SELECT RAISE(ABORT, 'scheduler queue clock must increment exactly once');
END;
CREATE TRIGGER scheduler_queue_order_changes_only_on_requeue
BEFORE UPDATE OF queue_order ON scheduler_work
WHEN NOT (
    OLD.state = 'assigned' AND NEW.state = 'queued' AND
    NEW.queue_order > OLD.queue_order
) BEGIN
    SELECT RAISE(ABORT, 'scheduler queue order changes only on requeue');
END;

CREATE TABLE scheduler_admission_decisions (
    id TEXT PRIMARY KEY,
    work_id TEXT NOT NULL UNIQUE REFERENCES scheduler_work(id),
    policy_version TEXT NOT NULL,
    policy_hash TEXT NOT NULL CHECK(
        length(policy_hash) = 64 AND policy_hash NOT GLOB '*[^0-9a-f]*'
    ),
    decision_hash TEXT NOT NULL CHECK(
        length(decision_hash) = 64 AND decision_hash NOT GLOB '*[^0-9a-f]*'
    ),
    content_hash TEXT NOT NULL CHECK(
        length(content_hash) = 64 AND content_hash NOT GLOB '*[^0-9a-f]*'
    ),
    scope_hash TEXT NOT NULL CHECK(
        length(scope_hash) = 64 AND scope_hash NOT GLOB '*[^0-9a-f]*'
    ),
    allowed INTEGER NOT NULL CHECK(allowed IN (0, 1)),
    reasons_json TEXT NOT NULL CHECK(
        json_valid(reasons_json) AND json_type(reasons_json) = 'array'
    ),
    scope_claim_id TEXT NOT NULL REFERENCES scope_claims(id),
    scope_key TEXT NOT NULL,
    scope_owner_id TEXT NOT NULL,
    scope_claim_attempt INTEGER NOT NULL CHECK(scope_claim_attempt > 0),
    scope_claim_fence TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER scheduler_admission_decisions_are_immutable_update
BEFORE UPDATE ON scheduler_admission_decisions BEGIN
    SELECT RAISE(ABORT, 'scheduler admission decision is immutable');
END;
CREATE TRIGGER scheduler_admission_decisions_are_immutable_delete
BEFORE DELETE ON scheduler_admission_decisions BEGIN
    SELECT RAISE(ABORT, 'scheduler admission decision is immutable');
END;
CREATE TRIGGER scheduler_work_admission_requires_decision
AFTER UPDATE OF scope_key, scope_owner_id, policy_decision_id,
                policy_allowed, admission_idempotency_key
ON scheduler_work
WHEN NEW.admission_idempotency_key IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM scheduler_admission_decisions AS decision
    WHERE decision.id = NEW.policy_decision_id
      AND decision.work_id = NEW.id
      AND decision.scope_key = NEW.scope_key
      AND decision.scope_owner_id = NEW.scope_owner_id
      AND decision.allowed = NEW.policy_allowed
) BEGIN
    SELECT RAISE(ABORT, 'scheduler admission requires an immutable decision');
END;
CREATE TRIGGER scheduler_assignment_requires_live_decision
BEFORE INSERT ON scheduler_assignments
WHEN NOT EXISTS (
    SELECT 1
    FROM scheduler_work AS work
    JOIN scheduler_admission_decisions AS decision
      ON decision.id = work.policy_decision_id
     AND decision.work_id = work.id
     AND decision.allowed = 1
    JOIN scope_claims AS claim
      ON claim.id = decision.scope_claim_id
     AND claim.scope_key = decision.scope_key
     AND claim.owner_operation_id = decision.scope_owner_id
     AND claim.attempt = decision.scope_claim_attempt
     AND claim.fence_token = decision.scope_claim_fence
     AND claim.state = 'active'
    WHERE work.id = NEW.work_id
      AND decision.scope_owner_id = NEW.owner_id
) BEGIN
    SELECT RAISE(ABORT, 'scheduler assignment lacks a live immutable decision');
END;

CREATE TABLE daemon_request_outcomes (
    idempotency_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL CHECK(
        length(fingerprint) = 64 AND fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    operation TEXT NOT NULL,
    ok INTEGER NOT NULL CHECK(ok IN (0, 1)),
    outcome_json TEXT NOT NULL CHECK(
        json_valid(outcome_json) AND json_type(outcome_json) = 'object'
    ),
    completed_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER daemon_request_outcomes_are_immutable_update
BEFORE UPDATE ON daemon_request_outcomes BEGIN
    SELECT RAISE(ABORT, 'daemon request outcome is immutable');
END;
CREATE TRIGGER daemon_request_outcomes_are_immutable_delete
BEFORE DELETE ON daemon_request_outcomes BEGIN
    SELECT RAISE(ABORT, 'daemon request outcome is immutable');
END;
