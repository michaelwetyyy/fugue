CREATE TABLE callback_delivery_reconciliations (
    callback_id TEXT PRIMARY KEY REFERENCES callbacks(id),
    attempt_number INTEGER NOT NULL CHECK(attempt_number BETWEEN 1 AND 3),
    delivery_key TEXT NOT NULL UNIQUE,
    proof_kind TEXT NOT NULL CHECK(proof_kind = 'codex_thread_history_exact_message'),
    reconciled_at_us INTEGER NOT NULL CHECK(reconciled_at_us >= 0),
    UNIQUE(callback_id, attempt_number),
    FOREIGN KEY(callback_id, attempt_number)
        REFERENCES callback_delivery_attempts(callback_id, attempt_number)
) STRICT;

CREATE TRIGGER callback_delivery_reconciliation_requires_attention
BEFORE INSERT ON callback_delivery_reconciliations
WHEN NOT EXISTS (
    SELECT 1
    FROM callbacks AS callback
    JOIN outbox ON outbox.callback_id = callback.id
      AND outbox.delivery_key = callback.delivery_key
    JOIN return_routes AS route
      ON route.id = callback.return_route_id
    JOIN local_codex_return_routes AS local
      ON local.return_route_id = callback.return_route_id
    JOIN completion_events AS event
      ON event.id = callback.completion_event_id
    JOIN transport_callback_registrations AS registration
      ON registration.transport_id = event.transport_id
      AND registration.completion_registration_id = event.completion_registration_id
      AND registration.return_route_id = callback.return_route_id
    JOIN callback_delivery_attempts AS attempt
      ON attempt.callback_id = callback.id
      AND attempt.attempt_number = callback.attempts
      AND attempt.delivery_key = callback.delivery_key
    WHERE callback.id = NEW.callback_id
      AND callback.delivery_key = NEW.delivery_key
      AND callback.attempts = NEW.attempt_number
      AND callback.state = 'attention'
      AND callback.failure_class = 'delivery_unknown'
      AND outbox.state = 'attention'
      AND route.state = 'ready'
      AND registration.state = 'pending'
      AND attempt.state = 'attention'
      AND attempt.failure_class = 'delivery_unknown'
) BEGIN
    SELECT RAISE(ABORT, 'callback reconciliation lacks exact ambiguous delivery authority');
END;

CREATE TRIGGER callback_delivery_reconciliations_are_immutable_update
BEFORE UPDATE ON callback_delivery_reconciliations BEGIN
    SELECT RAISE(ABORT, 'callback delivery reconciliations are immutable');
END;

CREATE TRIGGER callback_delivery_reconciliations_are_immutable_delete
BEFORE DELETE ON callback_delivery_reconciliations BEGIN
    SELECT RAISE(ABORT, 'callback delivery reconciliations are immutable');
END;

DROP TRIGGER callback_attempt_safe_state_update;
CREATE TRIGGER callback_attempt_safe_state_update
BEFORE UPDATE OF state ON callback_delivery_attempts
WHEN NOT (
    (OLD.state = 'delivering' AND
     NEW.state IN ('retry_scheduled','delivered','attention')) OR
    (OLD.state = 'attention' AND NEW.state = 'delivered' AND
     OLD.failure_class = 'delivery_unknown' AND
     EXISTS (
         SELECT 1 FROM callback_delivery_reconciliations AS reconciliation
         WHERE reconciliation.callback_id = OLD.callback_id
           AND reconciliation.attempt_number = OLD.attempt_number
           AND reconciliation.delivery_key = OLD.delivery_key
           AND reconciliation.proof_kind = 'codex_thread_history_exact_message'
     ))
) BEGIN
    SELECT RAISE(ABORT, 'invalid callback attempt transition');
END;

CREATE TRIGGER callback_attention_delivery_requires_reconciliation
BEFORE UPDATE OF state ON callbacks
WHEN OLD.state = 'attention' AND NEW.state = 'delivered' AND NOT EXISTS (
    SELECT 1 FROM callback_delivery_reconciliations AS reconciliation
    WHERE reconciliation.callback_id = OLD.id
      AND reconciliation.attempt_number = OLD.attempts
      AND reconciliation.delivery_key = OLD.delivery_key
) BEGIN
    SELECT RAISE(ABORT, 'callback attention delivery lacks reconciliation proof');
END;

CREATE TRIGGER outbox_attention_delivery_requires_reconciliation
BEFORE UPDATE OF state ON outbox
WHEN OLD.state = 'attention' AND NEW.state = 'delivered' AND NOT EXISTS (
    SELECT 1 FROM callback_delivery_reconciliations AS reconciliation
    WHERE reconciliation.callback_id = OLD.callback_id
      AND reconciliation.delivery_key = OLD.delivery_key
) BEGIN
    SELECT RAISE(ABORT, 'outbox attention delivery lacks reconciliation proof');
END;
