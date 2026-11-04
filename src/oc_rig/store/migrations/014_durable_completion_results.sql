CREATE TABLE completion_results (
    result_ref TEXT PRIMARY KEY,
    completion_event_id TEXT NOT NULL UNIQUE REFERENCES completion_events(id),
    completion_key TEXT NOT NULL UNIQUE,
    transport_id TEXT NOT NULL UNIQUE REFERENCES transport_deliveries(id),
    completion_registration_id TEXT NOT NULL UNIQUE
        REFERENCES transport_completion_registrations(id),
    callback_registration_id TEXT NOT NULL UNIQUE
        REFERENCES transport_callback_registrations(id),
    work_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    session_id TEXT NOT NULL,
    prompt_message_id TEXT NOT NULL,
    assistant_message_id TEXT,
    outcome TEXT NOT NULL CHECK(outcome IN ('succeeded','failed','cancelled')),
    content_state TEXT NOT NULL CHECK(content_state IN (
        'available','no_text','historical_unavailable'
    )),
    final_text TEXT,
    final_text_sha256 TEXT CHECK(
        final_text_sha256 IS NULL OR (
            length(final_text_sha256) = 64 AND
            final_text_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    binding_sha256 TEXT CHECK(
        binding_sha256 IS NULL OR (
            length(binding_sha256) = 64 AND
            binding_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    created_at_us INTEGER NOT NULL CHECK(created_at_us >= 0),
    CHECK(
        (content_state = 'available' AND assistant_message_id IS NOT NULL AND
         final_text IS NOT NULL AND length(CAST(final_text AS BLOB)) BETWEEN 1 AND 49152 AND
         final_text_sha256 IS NOT NULL AND binding_sha256 IS NOT NULL) OR
        (content_state = 'no_text' AND assistant_message_id IS NOT NULL AND
         final_text IS NULL AND final_text_sha256 IS NULL AND binding_sha256 IS NOT NULL) OR
        (content_state = 'historical_unavailable' AND assistant_message_id IS NULL AND
         final_text IS NULL AND final_text_sha256 IS NULL AND binding_sha256 IS NULL)
    )
) STRICT;

CREATE TRIGGER completion_results_are_immutable_update
BEFORE UPDATE ON completion_results BEGIN
    SELECT RAISE(ABORT, 'completion results are immutable');
END;
CREATE TRIGGER completion_results_are_immutable_delete
BEFORE DELETE ON completion_results BEGIN
    SELECT RAISE(ABORT, 'completion results are immutable');
END;

INSERT INTO completion_results(
    result_ref, completion_event_id, completion_key, transport_id,
    completion_registration_id, callback_registration_id, work_id, generation,
    session_id, prompt_message_id, assistant_message_id, outcome, content_state,
    final_text, final_text_sha256, binding_sha256, created_at_us
)
SELECT 'completion-result-historical-' || event.id,
       event.id, event.completion_key, event.transport_id,
       event.completion_registration_id, delivery.callback_registration_id,
       event.work_id, event.generation,
       coalesce(delivery.isolated_session_id, delivery.session_id),
       delivery.prompt_message_id, NULL, event.outcome,
       'historical_unavailable', NULL, NULL, NULL, event.received_at_us
FROM completion_events AS event
JOIN opencode_deliveries AS delivery
  ON delivery.transport_id = event.transport_id
 AND delivery.completion_registration_id = event.completion_registration_id
WHERE NOT EXISTS (
    SELECT 1 FROM completion_results AS result
    WHERE result.completion_event_id = event.id
);
