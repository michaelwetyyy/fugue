CREATE TABLE transport_upgrade_guard (
    valid INTEGER NOT NULL CHECK(valid = 1)
) STRICT;
INSERT INTO transport_upgrade_guard(valid)
SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM transport_attempts)
            THEN 1 ELSE 0 END;
DROP TABLE transport_upgrade_guard;

CREATE TABLE transport_deliveries (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    request_fingerprint TEXT NOT NULL CHECK(
        length(request_fingerprint) = 64 AND
        request_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    work_id TEXT NOT NULL REFERENCES scheduler_work(id),
    pool TEXT NOT NULL CHECK(
        pool IN ('tensorhost','homelab','personal','control','hands-off')
    ),
    assignment_id TEXT NOT NULL REFERENCES scheduler_assignments(id),
    owner_id TEXT NOT NULL,
    assignment_attempt INTEGER NOT NULL CHECK(assignment_attempt > 0),
    assignment_fence TEXT NOT NULL,
    admission_decision_id TEXT NOT NULL REFERENCES scheduler_admission_decisions(id),
    scope_claim_id TEXT NOT NULL REFERENCES scope_claims(id),
    scope_claim_attempt INTEGER NOT NULL CHECK(scope_claim_attempt > 0),
    scope_claim_fence TEXT NOT NULL,
    adapter_kind TEXT NOT NULL CHECK(adapter_kind = 'disabled'),
    payload_json TEXT NOT NULL CHECK(
        json_valid(payload_json) AND json_type(payload_json) = 'object'
    ),
    state TEXT NOT NULL CHECK(state IN (
        'reserved','prepared','sending','accepted','delivery_unknown',
        'definite_failed','cancelled'
    )),
    active_attempt_id TEXT,
    acknowledgement_id TEXT,
    error_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    finished_at TEXT,
    UNIQUE(work_id, assignment_attempt),
    CHECK(
        (state IN ('reserved','prepared') AND active_attempt_id IS NULL AND
         acknowledgement_id IS NULL AND error_code IS NULL AND finished_at IS NULL) OR
        (state = 'sending' AND active_attempt_id IS NOT NULL AND
         acknowledgement_id IS NULL AND error_code IS NULL AND finished_at IS NULL) OR
        (state = 'accepted' AND active_attempt_id IS NOT NULL AND
         acknowledgement_id IS NOT NULL AND error_code IS NULL AND finished_at IS NOT NULL) OR
        (state IN ('delivery_unknown','definite_failed') AND active_attempt_id IS NOT NULL AND
         acknowledgement_id IS NULL AND error_code IS NOT NULL AND finished_at IS NOT NULL) OR
        (state = 'cancelled' AND acknowledgement_id IS NULL AND
         error_code IS NOT NULL AND finished_at IS NOT NULL)
    )
) STRICT;
CREATE INDEX ix_transport_work ON transport_deliveries(work_id, pool, state);

CREATE TABLE transport_completion_registrations (
    id TEXT PRIMARY KEY,
    transport_id TEXT NOT NULL UNIQUE REFERENCES transport_deliveries(id),
    work_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL,
    assignment_attempt INTEGER NOT NULL CHECK(assignment_attempt > 0),
    assignment_fence TEXT NOT NULL,
    registration_key TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('pending','completed','cancelled')),
    created_at TEXT NOT NULL,
    completed_at TEXT
) STRICT;

CREATE TABLE transport_callback_registrations (
    id TEXT PRIMARY KEY,
    transport_id TEXT NOT NULL UNIQUE REFERENCES transport_deliveries(id),
    completion_registration_id TEXT NOT NULL UNIQUE
        REFERENCES transport_completion_registrations(id),
    callback_key TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('pending','cancelled')),
    created_at TEXT NOT NULL,
    cancelled_at TEXT
) STRICT;

CREATE TABLE daemon_outcome_reservations (
    idempotency_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL CHECK(
        length(fingerprint) = 64 AND fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    operation TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER daemon_outcome_reservation_identity_is_immutable
BEFORE UPDATE ON daemon_outcome_reservations BEGIN
    SELECT RAISE(ABORT, 'daemon outcome reservation is immutable');
END;

DROP TABLE transport_attempts;
CREATE TABLE transport_attempts (
    id TEXT PRIMARY KEY,
    transport_id TEXT NOT NULL REFERENCES transport_deliveries(id),
    attempt_number INTEGER NOT NULL CHECK(attempt_number > 0),
    state TEXT NOT NULL CHECK(state IN (
        'sending','accepted','delivery_unknown','definite_failed','cancelled'
    )),
    executable_path TEXT,
    executable_device INTEGER,
    executable_inode INTEGER,
    executable_mode INTEGER,
    executable_size INTEGER,
    executable_digest TEXT CHECK(
        executable_digest IS NULL OR (
            length(executable_digest) = 64 AND
            executable_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    source_path TEXT,
    source_device INTEGER,
    source_inode INTEGER,
    source_digest TEXT CHECK(
        source_digest IS NULL OR (
            length(source_digest) = 64 AND
            source_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    supervisor_pid INTEGER CHECK(supervisor_pid IS NULL OR supervisor_pid > 0),
    target_pid INTEGER CHECK(target_pid IS NULL OR target_pid > 0),
    process_token TEXT,
    acknowledgement_id TEXT,
    error_code TEXT,
    exit_code INTEGER,
    output_json TEXT CHECK(output_json IS NULL OR json_valid(output_json)),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    UNIQUE(transport_id, attempt_number),
    CHECK(
        (state = 'sending' AND finished_at IS NULL AND acknowledgement_id IS NULL AND
         error_code IS NULL) OR
        (state = 'accepted' AND finished_at IS NOT NULL AND acknowledgement_id IS NOT NULL AND
         error_code IS NULL) OR
        (state IN ('delivery_unknown','definite_failed','cancelled') AND
         finished_at IS NOT NULL AND acknowledgement_id IS NULL AND error_code IS NOT NULL)
    ),
    CHECK(
        (executable_path IS NULL AND executable_device IS NULL AND
         executable_inode IS NULL AND executable_mode IS NULL AND executable_size IS NULL AND
         executable_digest IS NULL AND source_path IS NULL AND source_device IS NULL AND
         source_inode IS NULL AND source_digest IS NULL) OR
        (executable_path IS NOT NULL AND executable_device IS NOT NULL AND
         executable_inode IS NOT NULL AND executable_mode IS NOT NULL AND
         executable_size IS NOT NULL AND executable_digest IS NOT NULL AND
         source_path IS NOT NULL AND source_device IS NOT NULL AND
         source_inode IS NOT NULL AND source_digest IS NOT NULL)
    ),
    CHECK(
        (supervisor_pid IS NULL AND target_pid IS NULL AND process_token IS NULL) OR
        (supervisor_pid IS NOT NULL AND target_pid IS NOT NULL AND process_token IS NOT NULL)
    )
) STRICT;

CREATE TRIGGER transport_insert_requires_exact_live_authority
BEFORE INSERT ON transport_deliveries
WHEN NOT EXISTS (
    SELECT 1
    FROM scheduler_assignments AS assignment
    JOIN scheduler_work AS work
      ON work.id = assignment.work_id
     AND work.state = 'assigned'
     AND work.active_assignment_id = assignment.id
     AND work.policy_allowed = 1
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
    WHERE assignment.id = NEW.assignment_id
      AND assignment.work_id = NEW.work_id
      AND assignment.lane = NEW.pool
      AND assignment.owner_id = NEW.owner_id
      AND assignment.attempt = NEW.assignment_attempt
      AND assignment.fence_token = NEW.assignment_fence
      AND assignment.state = 'active'
      AND decision.id = NEW.admission_decision_id
      AND claim.id = NEW.scope_claim_id
      AND claim.attempt = NEW.scope_claim_attempt
      AND claim.fence_token = NEW.scope_claim_fence
) BEGIN
    SELECT RAISE(ABORT, 'transport lacks exact live scheduler authority');
END;

CREATE TRIGGER transport_prepared_requires_registrations
BEFORE UPDATE OF state ON transport_deliveries
WHEN NEW.state = 'prepared' AND NOT (
    OLD.state = 'reserved' AND
    EXISTS (
        SELECT 1 FROM transport_completion_registrations
        WHERE transport_id = NEW.id
          AND work_id = NEW.work_id
          AND assignment_id = NEW.assignment_id
          AND assignment_attempt = NEW.assignment_attempt
          AND assignment_fence = NEW.assignment_fence
          AND state = 'pending'
    ) AND
    EXISTS (
        SELECT 1 FROM transport_callback_registrations
        WHERE transport_id = NEW.id AND state = 'pending'
    )
) BEGIN
    SELECT RAISE(ABORT, 'transport registration must precede preparation');
END;

CREATE TRIGGER transport_sending_requires_exact_live_authority
BEFORE UPDATE OF state ON transport_deliveries
WHEN NEW.state = 'sending' AND NOT (
    OLD.state = 'prepared' AND NEW.active_attempt_id IS NOT NULL AND
    EXISTS (
        SELECT 1
        FROM scheduler_assignments AS assignment
        JOIN scheduler_work AS work
          ON work.id = assignment.work_id
         AND work.state = 'assigned'
         AND work.active_assignment_id = assignment.id
        JOIN scheduler_admission_decisions AS decision
          ON decision.id = work.policy_decision_id
         AND decision.allowed = 1
        JOIN scope_claims AS claim
          ON claim.id = decision.scope_claim_id
         AND claim.state = 'active'
         AND claim.attempt = decision.scope_claim_attempt
         AND claim.fence_token = decision.scope_claim_fence
        WHERE assignment.id = NEW.assignment_id
          AND assignment.work_id = NEW.work_id
          AND assignment.lane = NEW.pool
          AND assignment.owner_id = NEW.owner_id
          AND assignment.attempt = NEW.assignment_attempt
          AND assignment.fence_token = NEW.assignment_fence
          AND assignment.state = 'active'
          AND decision.id = NEW.admission_decision_id
          AND claim.id = NEW.scope_claim_id
          AND claim.attempt = NEW.scope_claim_attempt
          AND claim.fence_token = NEW.scope_claim_fence
    )
) BEGIN
    SELECT RAISE(ABORT, 'transport send lacks exact live scheduler authority');
END;

CREATE TRIGGER transport_safe_state_update
BEFORE UPDATE OF state ON transport_deliveries
WHEN NOT (
    (OLD.state = 'reserved' AND NEW.state IN ('prepared','cancelled')) OR
    (OLD.state = 'prepared' AND NEW.state IN ('sending','cancelled')) OR
    (OLD.state = 'sending' AND NEW.state IN (
        'accepted','delivery_unknown','definite_failed','cancelled'
    ))
) BEGIN
    SELECT RAISE(ABORT, 'invalid transport state transition');
END;

CREATE TRIGGER transport_identity_is_immutable
BEFORE UPDATE OF id, idempotency_key, request_fingerprint, work_id, pool,
                 assignment_id, owner_id, assignment_attempt, assignment_fence,
                 admission_decision_id, scope_claim_id, scope_claim_attempt,
                 scope_claim_fence, adapter_kind, payload_json, created_at
ON transport_deliveries BEGIN
    SELECT RAISE(ABORT, 'transport identity is immutable');
END;

CREATE TRIGGER transport_attempt_identity_is_immutable
BEFORE UPDATE OF id, transport_id, attempt_number, executable_path,
                 executable_device, executable_inode, executable_mode,
                 executable_size, executable_digest, source_path, source_device,
                 source_inode, source_digest, started_at
ON transport_attempts BEGIN
    SELECT RAISE(ABORT, 'transport attempt identity is immutable');
END;

CREATE TRIGGER transport_attempt_safe_state_update
BEFORE UPDATE OF state ON transport_attempts
WHEN NOT (
    OLD.state = 'sending' AND NEW.state IN (
        'accepted','delivery_unknown','definite_failed','cancelled'
    )
) BEGIN
    SELECT RAISE(ABORT, 'invalid transport attempt state transition');
END;
CREATE TRIGGER transport_attempt_process_identity_is_write_once
BEFORE UPDATE OF supervisor_pid, target_pid, process_token ON transport_attempts
WHEN NOT (
    OLD.supervisor_pid IS NULL AND OLD.target_pid IS NULL AND
    OLD.process_token IS NULL AND NEW.supervisor_pid IS NOT NULL AND
    NEW.target_pid IS NOT NULL AND NEW.process_token IS NOT NULL
) BEGIN
    SELECT RAISE(ABORT, 'transport process identity is write-once');
END;

CREATE TRIGGER transport_completion_registration_is_immutable
BEFORE UPDATE OF id, transport_id, work_id, assignment_id, assignment_attempt,
                 assignment_fence, registration_key, created_at
ON transport_completion_registrations BEGIN
    SELECT RAISE(ABORT, 'completion registration identity is immutable');
END;
CREATE TRIGGER transport_completion_registration_safe_state_update
BEFORE UPDATE OF state ON transport_completion_registrations
WHEN NOT (
    OLD.state = 'pending' AND NEW.state IN ('completed','cancelled')
) BEGIN
    SELECT RAISE(ABORT, 'invalid completion registration state transition');
END;

CREATE TRIGGER transport_callback_registration_is_immutable
BEFORE UPDATE OF id, transport_id, completion_registration_id, callback_key,
                 created_at
ON transport_callback_registrations BEGIN
    SELECT RAISE(ABORT, 'callback registration identity is immutable');
END;
CREATE TRIGGER transport_callback_registration_safe_state_update
BEFORE UPDATE OF state ON transport_callback_registrations
WHEN NOT (OLD.state = 'pending' AND NEW.state = 'cancelled') BEGIN
    SELECT RAISE(ABORT, 'invalid callback registration state transition');
END;
