DROP TRIGGER completion_child_barrier_identity_is_immutable;

UPDATE completion_child_barriers AS barrier
SET generation = (
    SELECT completion.assignment_attempt
    FROM transport_completion_registrations AS completion
    WHERE completion.id = barrier.completion_registration_id
      AND completion.transport_id = barrier.transport_id
      AND completion.work_id = barrier.work_id
)
WHERE EXISTS (
    SELECT 1
    FROM transport_completion_registrations AS completion
    WHERE completion.id = barrier.completion_registration_id
      AND completion.transport_id = barrier.transport_id
      AND completion.work_id = barrier.work_id
      AND completion.assignment_attempt != barrier.generation
);

CREATE TRIGGER completion_child_barrier_identity_is_immutable
BEFORE UPDATE OF transport_id, completion_registration_id, work_id, generation,
                 root_session_id, turn_started_at_ms, child_set_sha256,
                 child_count, created_at
ON completion_child_barriers BEGIN
    SELECT RAISE(ABORT, 'completion child barrier identity is immutable');
END;
