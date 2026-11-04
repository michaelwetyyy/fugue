DROP TRIGGER opencode_cleanup_pending_requires_exact_completion;
CREATE TRIGGER opencode_cleanup_pending_requires_exact_completion
BEFORE UPDATE OF cleanup_state ON opencode_deliveries
WHEN NEW.cleanup_state = 'pending' AND NOT (
    EXISTS (
        SELECT 1 FROM transport_deliveries AS delivery
        JOIN transport_completion_registrations AS registration
          ON registration.transport_id = delivery.id
         AND registration.state = 'completed'
        JOIN completion_events AS completion
          ON completion.transport_id = delivery.id
         AND completion.completion_registration_id = registration.id
        JOIN scheduler_assignments AS assignment
          ON assignment.id = delivery.assignment_id
         AND assignment.state = 'released'
        JOIN scope_claims AS claim
          ON claim.id = delivery.scope_claim_id AND claim.state = 'released'
        WHERE delivery.id = NEW.transport_id
          AND delivery.work_id = NEW.work_id
    ) OR EXISTS (
        SELECT 1 FROM transport_deliveries AS delivery
        JOIN scheduler_assignments AS assignment
          ON assignment.id = delivery.assignment_id
         AND assignment.state = 'released'
         AND assignment.release_outcome = 'cancelled'
        JOIN scope_claims AS claim
          ON claim.id = delivery.scope_claim_id AND claim.state = 'released'
        WHERE delivery.id = NEW.transport_id
          AND delivery.work_id = NEW.work_id
    )
) BEGIN
    SELECT RAISE(ABORT, 'isolated cleanup lacks exact terminal release join');
END;
