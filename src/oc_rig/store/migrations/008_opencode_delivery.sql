CREATE TABLE opencode_slot_generations (
    slot_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    worker TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(slot_id, generation),
    UNIQUE(session_id, generation)
) STRICT;

CREATE TABLE opencode_deliveries (
    transport_id TEXT PRIMARY KEY,
    request_fingerprint TEXT NOT NULL CHECK(
        length(request_fingerprint) = 64 AND
        request_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    work_id TEXT NOT NULL,
    pool TEXT NOT NULL CHECK(
        pool IN ('tensorhost','homelab','personal','control','hands-off')
    ),
    completion_registration_id TEXT NOT NULL UNIQUE,
    callback_registration_id TEXT NOT NULL UNIQUE,
    slot_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    worker TEXT NOT NULL,
    assignment_generation INTEGER NOT NULL CHECK(assignment_generation > 0),
    prompt_message_id TEXT NOT NULL UNIQUE,
    delivery_capability TEXT NOT NULL UNIQUE CHECK(
        length(delivery_capability) = 64 AND
        delivery_capability NOT GLOB '*[^0-9a-f]*'
    ),
    delivery_state TEXT NOT NULL CHECK(delivery_state IN (
        'in_flight','accepted','delivery_unknown','definite_failed','cancelled'
    )),
    acknowledgement_id TEXT,
    error_code TEXT,
    lease_state TEXT NOT NULL CHECK(lease_state IN ('active','aborting','released')),
    abort_state TEXT NOT NULL CHECK(abort_state IN ('none','in_flight','terminal')),
    abort_capability TEXT UNIQUE CHECK(
        abort_capability IS NULL OR (
            length(abort_capability) = 64 AND
            abort_capability NOT GLOB '*[^0-9a-f]*'
        )
    ),
    abort_disposition TEXT CHECK(abort_disposition IN (
        'delivery_unknown','definite_failed','cancelled'
    )),
    abort_error_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    finished_at TEXT,
    abort_started_at TEXT,
    abort_finished_at TEXT,
    UNIQUE(slot_id, assignment_generation),
    FOREIGN KEY(slot_id, assignment_generation)
        REFERENCES opencode_slot_generations(slot_id, generation),
    CHECK(
        (delivery_state = 'in_flight' AND acknowledgement_id IS NULL AND
         error_code IS NULL AND finished_at IS NULL) OR
        (delivery_state = 'accepted' AND acknowledgement_id IS NOT NULL AND
         error_code IS NULL AND finished_at IS NOT NULL) OR
        (delivery_state IN ('delivery_unknown','definite_failed','cancelled') AND
         acknowledgement_id IS NULL AND error_code IS NOT NULL AND finished_at IS NOT NULL)
    ),
    CHECK(
        (abort_state = 'none' AND abort_capability IS NULL AND
         abort_disposition IS NULL AND abort_error_code IS NULL AND
         abort_started_at IS NULL AND abort_finished_at IS NULL) OR
        (abort_state = 'in_flight' AND abort_capability IS NOT NULL AND
         abort_disposition IS NULL AND abort_error_code IS NULL AND
         abort_started_at IS NOT NULL AND abort_finished_at IS NULL) OR
        (abort_state = 'terminal' AND abort_capability IS NOT NULL AND
         abort_disposition IS NOT NULL AND abort_error_code IS NOT NULL AND
         abort_started_at IS NOT NULL AND abort_finished_at IS NOT NULL)
    ),
    CHECK(abort_state != 'in_flight' OR lease_state = 'aborting')
) STRICT;

CREATE UNIQUE INDEX opencode_one_live_assignment_per_slot
ON opencode_deliveries(slot_id)
WHERE lease_state IN ('active','aborting');
CREATE INDEX ix_opencode_delivery_work
ON opencode_deliveries(work_id, pool, delivery_state);

CREATE TRIGGER opencode_slot_generation_appends_once
BEFORE INSERT ON opencode_slot_generations
WHEN NOT (
    (
        NEW.generation = 1 AND NOT EXISTS (
            SELECT 1 FROM opencode_slot_generations
            WHERE slot_id = NEW.slot_id
        )
    ) OR (
        NEW.generation = (
            SELECT MAX(previous.generation) + 1
            FROM opencode_slot_generations AS previous
            WHERE previous.slot_id = NEW.slot_id
        ) AND
        NEW.session_id = (
            SELECT previous.session_id
            FROM opencode_slot_generations AS previous
            WHERE previous.slot_id = NEW.slot_id
            ORDER BY previous.generation DESC LIMIT 1
        ) AND
        NEW.worker = (
            SELECT previous.worker
            FROM opencode_slot_generations AS previous
            WHERE previous.slot_id = NEW.slot_id
            ORDER BY previous.generation DESC LIMIT 1
        )
    )
) BEGIN
    SELECT RAISE(ABORT, 'opencode slot generation must append exactly once');
END;

CREATE TRIGGER opencode_slot_generation_is_immutable
BEFORE UPDATE ON opencode_slot_generations BEGIN
    SELECT RAISE(ABORT, 'opencode slot generation history is immutable');
END;
CREATE TRIGGER opencode_slot_generation_is_not_deleted
BEFORE DELETE ON opencode_slot_generations BEGIN
    SELECT RAISE(ABORT, 'opencode slot generation history is immutable');
END;

CREATE TRIGGER opencode_delivery_requires_current_slot_generation
BEFORE INSERT ON opencode_deliveries
WHEN NOT EXISTS (
    SELECT 1 FROM opencode_slot_generations AS slot
    WHERE slot.slot_id = NEW.slot_id
      AND slot.session_id = NEW.session_id
      AND slot.worker = NEW.worker
      AND slot.generation = NEW.assignment_generation
      AND slot.generation = (
          SELECT MAX(current.generation)
          FROM opencode_slot_generations AS current
          WHERE current.slot_id = NEW.slot_id
      )
) BEGIN
    SELECT RAISE(ABORT, 'opencode delivery lacks current slot generation');
END;

CREATE TRIGGER opencode_delivery_identity_is_immutable
BEFORE UPDATE OF transport_id, request_fingerprint, work_id, pool,
                 completion_registration_id, callback_registration_id,
                 slot_id, session_id, worker, assignment_generation,
                 prompt_message_id, delivery_capability, created_at
ON opencode_deliveries BEGIN
    SELECT RAISE(ABORT, 'opencode delivery identity is immutable');
END;

CREATE TRIGGER opencode_delivery_state_is_monotonic
BEFORE UPDATE OF delivery_state ON opencode_deliveries
WHEN NOT (
    OLD.delivery_state = 'in_flight' AND NEW.delivery_state IN (
        'accepted','delivery_unknown','definite_failed','cancelled'
    )
) BEGIN
    SELECT RAISE(ABORT, 'invalid opencode delivery transition');
END;

CREATE TRIGGER opencode_delivery_outcome_is_write_once
BEFORE UPDATE OF acknowledgement_id, error_code, finished_at
ON opencode_deliveries
WHEN NOT (
    OLD.delivery_state = 'in_flight' AND
    NEW.delivery_state IN (
        'accepted','delivery_unknown','definite_failed','cancelled'
    ) AND
    OLD.acknowledgement_id IS NULL AND OLD.error_code IS NULL AND
    OLD.finished_at IS NULL AND NEW.finished_at IS NOT NULL
) BEGIN
    SELECT RAISE(ABORT, 'opencode delivery outcome evidence is write-once');
END;

CREATE TRIGGER opencode_abort_state_is_monotonic
BEFORE UPDATE OF abort_state ON opencode_deliveries
WHEN NOT (
    (OLD.abort_state = 'none' AND NEW.abort_state = 'in_flight') OR
    (OLD.abort_state = 'in_flight' AND NEW.abort_state = 'terminal')
) BEGIN
    SELECT RAISE(ABORT, 'invalid opencode abort transition');
END;

CREATE TRIGGER opencode_abort_capability_is_write_once
BEFORE UPDATE OF abort_capability ON opencode_deliveries
WHEN NOT (OLD.abort_capability IS NULL AND NEW.abort_capability IS NOT NULL) BEGIN
    SELECT RAISE(ABORT, 'opencode abort capability is write-once');
END;

CREATE TRIGGER opencode_abort_start_is_write_once
BEFORE UPDATE OF abort_started_at ON opencode_deliveries
WHEN NOT (
    OLD.abort_state = 'none' AND NEW.abort_state = 'in_flight' AND
    OLD.abort_started_at IS NULL AND NEW.abort_started_at IS NOT NULL
) BEGIN
    SELECT RAISE(ABORT, 'opencode abort start evidence is write-once');
END;

CREATE TRIGGER opencode_abort_outcome_is_write_once
BEFORE UPDATE OF abort_disposition, abort_error_code, abort_finished_at
ON opencode_deliveries
WHEN NOT (
    OLD.abort_state = 'in_flight' AND NEW.abort_state = 'terminal' AND
    OLD.abort_disposition IS NULL AND OLD.abort_error_code IS NULL AND
    OLD.abort_finished_at IS NULL AND NEW.abort_disposition IS NOT NULL AND
    NEW.abort_error_code IS NOT NULL AND NEW.abort_finished_at IS NOT NULL
) BEGIN
    SELECT RAISE(ABORT, 'opencode abort outcome evidence is write-once');
END;

CREATE TRIGGER opencode_lease_state_is_monotonic
BEFORE UPDATE OF lease_state ON opencode_deliveries
WHEN NOT (
    (OLD.lease_state = 'active' AND NEW.lease_state IN ('aborting','released')) OR
    (OLD.lease_state = 'aborting' AND NEW.lease_state IN ('active','released'))
) BEGIN
    SELECT RAISE(ABORT, 'invalid opencode lease transition');
END;

CREATE TRIGGER opencode_deliveries_are_not_deleted
BEFORE DELETE ON opencode_deliveries BEGIN
    SELECT RAISE(ABORT, 'opencode delivery history is immutable');
END;
