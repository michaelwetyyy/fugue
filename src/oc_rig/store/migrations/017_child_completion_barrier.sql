CREATE TABLE completion_child_barriers (
    transport_id TEXT PRIMARY KEY REFERENCES transport_deliveries(id),
    completion_registration_id TEXT NOT NULL UNIQUE
        REFERENCES transport_completion_registrations(id),
    work_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    root_session_id TEXT NOT NULL,
    turn_started_at_ms INTEGER NOT NULL CHECK(turn_started_at_ms >= 0),
    child_set_sha256 TEXT NOT NULL CHECK(
        length(child_set_sha256) = 64 AND
        child_set_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    child_count INTEGER NOT NULL CHECK(child_count BETWEEN 0 AND 1024),
    state TEXT NOT NULL CHECK(state IN (
        'waiting','consolidation_prepared','consolidation_sent','ready','attention'
    )),
    consolidation_message_id TEXT UNIQUE,
    consolidation_idempotency_key TEXT UNIQUE,
    authorized_assistant_message_id TEXT,
    attention_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(work_id, generation),
    CHECK(
        (state = 'waiting' AND child_count BETWEEN 1 AND 3 AND
         consolidation_message_id IS NULL AND
         consolidation_idempotency_key IS NULL AND
         authorized_assistant_message_id IS NULL AND attention_reason IS NULL) OR
        (state IN ('consolidation_prepared','consolidation_sent') AND
         child_count BETWEEN 1 AND 3 AND consolidation_message_id IS NOT NULL AND
         consolidation_idempotency_key IS NOT NULL AND
         authorized_assistant_message_id IS NULL AND attention_reason IS NULL) OR
        (state = 'ready' AND authorized_assistant_message_id IS NOT NULL AND
         attention_reason IS NULL AND (
             (child_count = 0 AND consolidation_message_id IS NULL AND
              consolidation_idempotency_key IS NULL) OR
             (child_count BETWEEN 1 AND 3 AND consolidation_message_id IS NOT NULL AND
              consolidation_idempotency_key IS NOT NULL)
         )) OR
        (state = 'attention' AND attention_reason IS NOT NULL)
    )
) STRICT;

CREATE TABLE completion_child_sessions (
    transport_id TEXT NOT NULL REFERENCES completion_child_barriers(transport_id),
    child_session_id TEXT NOT NULL,
    parent_session_id TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    state TEXT NOT NULL CHECK(state IN ('waiting','terminal')),
    terminal_assistant_message_id TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(transport_id, child_session_id),
    CHECK(
        (state = 'waiting' AND terminal_assistant_message_id IS NULL) OR
        (state = 'terminal' AND terminal_assistant_message_id IS NOT NULL)
    )
) STRICT;

CREATE TRIGGER completion_child_barrier_identity_is_immutable
BEFORE UPDATE OF transport_id, completion_registration_id, work_id, generation,
                 root_session_id, turn_started_at_ms, child_set_sha256,
                 child_count, created_at
ON completion_child_barriers BEGIN
    SELECT RAISE(ABORT, 'completion child barrier identity is immutable');
END;

CREATE TRIGGER completion_child_barrier_safe_transition
BEFORE UPDATE OF state ON completion_child_barriers
WHEN NOT (
    (OLD.state = 'waiting' AND NEW.state IN (
        'waiting','consolidation_prepared','attention'
    )) OR
    (OLD.state = 'consolidation_prepared' AND NEW.state IN (
        'consolidation_prepared','consolidation_sent','attention'
    )) OR
    (OLD.state = 'consolidation_sent' AND NEW.state IN (
        'consolidation_sent','ready','attention'
    )) OR
    (OLD.state = 'ready' AND NEW.state IN ('ready','attention')) OR
    (OLD.state = 'attention' AND NEW.state = 'attention')
) BEGIN
    SELECT RAISE(ABORT, 'invalid completion child barrier transition');
END;

CREATE TRIGGER completion_child_barrier_consolidation_binding_is_immutable
BEFORE UPDATE OF consolidation_message_id, consolidation_idempotency_key
ON completion_child_barriers
WHEN NOT (
    (NEW.consolidation_message_id IS OLD.consolidation_message_id AND
     NEW.consolidation_idempotency_key IS OLD.consolidation_idempotency_key) OR
    (OLD.state = 'waiting' AND NEW.state = 'consolidation_prepared' AND
     OLD.consolidation_message_id IS NULL AND
     OLD.consolidation_idempotency_key IS NULL AND
     NEW.consolidation_message_id IS NOT NULL AND
     NEW.consolidation_idempotency_key IS NOT NULL)
) BEGIN
    SELECT RAISE(ABORT, 'completion consolidation binding is immutable');
END;

CREATE TRIGGER completion_child_barrier_final_authority_is_immutable
BEFORE UPDATE OF authorized_assistant_message_id
ON completion_child_barriers
WHEN NOT (
    NEW.authorized_assistant_message_id IS OLD.authorized_assistant_message_id OR
    (OLD.state = 'consolidation_sent' AND NEW.state = 'ready' AND
     OLD.authorized_assistant_message_id IS NULL AND
     NEW.authorized_assistant_message_id IS NOT NULL)
) BEGIN
    SELECT RAISE(ABORT, 'completion child barrier final authority is immutable');
END;

CREATE TRIGGER completion_child_barrier_attention_reason_is_immutable
BEFORE UPDATE OF attention_reason ON completion_child_barriers
WHEN NOT (
    NEW.attention_reason IS OLD.attention_reason OR
    (NEW.state = 'attention' AND OLD.attention_reason IS NULL AND
     NEW.attention_reason IS NOT NULL)
) BEGIN
    SELECT RAISE(ABORT, 'completion child barrier attention reason is immutable');
END;

CREATE TRIGGER completion_child_session_identity_is_immutable
BEFORE UPDATE OF transport_id, child_session_id, parent_session_id, created_at_ms
ON completion_child_sessions BEGIN
    SELECT RAISE(ABORT, 'completion child session identity is immutable');
END;

CREATE TRIGGER completion_child_session_safe_transition
BEFORE UPDATE OF state ON completion_child_sessions
WHEN NOT (
    (OLD.state = 'waiting' AND NEW.state IN ('waiting','terminal')) OR
    (OLD.state = 'terminal' AND NEW.state = 'terminal')
) BEGIN
    SELECT RAISE(ABORT, 'invalid completion child session transition');
END;

CREATE TRIGGER completion_child_session_terminal_binding_is_immutable
BEFORE UPDATE OF terminal_assistant_message_id ON completion_child_sessions
WHEN NOT (
    NEW.terminal_assistant_message_id IS OLD.terminal_assistant_message_id OR
    (OLD.state = 'waiting' AND NEW.state = 'terminal' AND
     OLD.terminal_assistant_message_id IS NULL AND
     NEW.terminal_assistant_message_id IS NOT NULL)
) BEGIN
    SELECT RAISE(ABORT, 'completion child terminal binding is immutable');
END;

CREATE TRIGGER completion_event_requires_child_barrier
BEFORE INSERT ON completion_events
WHEN EXISTS (
    SELECT 1
    FROM transport_deliveries AS delivery
    JOIN scheduler_admission_decisions AS decision
      ON decision.id = delivery.admission_decision_id
    WHERE delivery.id = NEW.transport_id
      AND decision.allow_child_agents = 1
) AND NOT EXISTS (
    SELECT 1
    FROM completion_child_barriers AS barrier
    WHERE barrier.transport_id = NEW.transport_id
      AND barrier.completion_registration_id = NEW.completion_registration_id
      AND barrier.work_id = NEW.work_id
      AND barrier.generation = NEW.generation
      AND barrier.state = 'ready'
) BEGIN
    SELECT RAISE(ABORT, 'completion lacks a ready child barrier');
END;

CREATE TRIGGER completion_result_requires_barrier_authority
BEFORE INSERT ON completion_results
WHEN EXISTS (
    SELECT 1
    FROM transport_deliveries AS delivery
    JOIN scheduler_admission_decisions AS decision
      ON decision.id = delivery.admission_decision_id
    WHERE delivery.id = NEW.transport_id
      AND decision.allow_child_agents = 1
) AND NOT EXISTS (
    SELECT 1
    FROM completion_child_barriers AS barrier
    WHERE barrier.transport_id = NEW.transport_id
      AND barrier.completion_registration_id = NEW.completion_registration_id
      AND barrier.work_id = NEW.work_id
      AND barrier.generation = NEW.generation
      AND barrier.root_session_id = NEW.session_id
      AND barrier.authorized_assistant_message_id = NEW.assistant_message_id
      AND barrier.state = 'ready'
) BEGIN
    SELECT RAISE(ABORT, 'completion result lacks child barrier authority');
END;
