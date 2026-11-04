ALTER TABLE opencode_deliveries ADD COLUMN cleanup_state TEXT NOT NULL DEFAULT 'none'
CHECK(cleanup_state IN ('none','pending','in_flight','succeeded','ambiguous','failed'));
ALTER TABLE opencode_deliveries ADD COLUMN cleanup_attempts INTEGER NOT NULL DEFAULT 0
CHECK(cleanup_attempts >= 0 AND cleanup_attempts <= 3);
ALTER TABLE opencode_deliveries ADD COLUMN cleanup_error TEXT;

CREATE TRIGGER opencode_cleanup_requires_isolated_session
BEFORE UPDATE OF cleanup_state ON opencode_deliveries
WHEN NEW.isolated_session_id IS NULL OR NOT (
    (OLD.cleanup_state = 'none' AND NEW.cleanup_state = 'pending') OR
    (OLD.cleanup_state IN ('pending','ambiguous') AND NEW.cleanup_state = 'in_flight') OR
    (OLD.cleanup_state = 'in_flight' AND NEW.cleanup_state IN ('succeeded','ambiguous','failed'))
) BEGIN
    SELECT RAISE(ABORT, 'invalid isolated session cleanup transition');
END;

CREATE TRIGGER opencode_cleanup_pending_requires_exact_completion
BEFORE UPDATE OF cleanup_state ON opencode_deliveries
WHEN NEW.cleanup_state = 'pending' AND NOT EXISTS (
    SELECT 1 FROM transport_deliveries AS delivery
    JOIN transport_completion_registrations AS registration
      ON registration.transport_id = delivery.id AND registration.state = 'completed'
    JOIN completion_events AS completion
      ON completion.transport_id = delivery.id
     AND completion.completion_registration_id = registration.id
    JOIN scheduler_assignments AS assignment
      ON assignment.id = delivery.assignment_id AND assignment.state = 'released'
    JOIN scope_claims AS claim
      ON claim.id = delivery.scope_claim_id AND claim.state = 'released'
    WHERE delivery.id = NEW.transport_id
      AND delivery.work_id = NEW.work_id
) BEGIN
    SELECT RAISE(ABORT, 'isolated cleanup lacks exact completion release join');
END;

CREATE TRIGGER opencode_cleanup_enqueue_after_release
AFTER UPDATE OF lease_state ON opencode_deliveries
WHEN NEW.lease_state = 'released' AND NEW.isolated_session_id IS NOT NULL
BEGIN
    UPDATE opencode_deliveries SET cleanup_state = 'pending'
    WHERE transport_id = NEW.transport_id AND cleanup_state = 'none';
END;

UPDATE opencode_deliveries SET cleanup_state = 'pending'
WHERE isolated_session_id IS NOT NULL AND lease_state = 'released'
  AND cleanup_state = 'none'
  AND EXISTS (
    SELECT 1 FROM transport_deliveries AS delivery
    JOIN transport_completion_registrations AS registration
      ON registration.transport_id = delivery.id AND registration.state = 'completed'
    JOIN completion_events AS completion
      ON completion.transport_id = delivery.id
     AND completion.completion_registration_id = registration.id
    JOIN scheduler_assignments AS assignment
      ON assignment.id = delivery.assignment_id AND assignment.state = 'released'
    JOIN scope_claims AS claim
      ON claim.id = delivery.scope_claim_id AND claim.state = 'released'
    WHERE delivery.id = opencode_deliveries.transport_id
      AND delivery.work_id = opencode_deliveries.work_id
  );
