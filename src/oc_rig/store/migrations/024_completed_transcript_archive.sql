CREATE TABLE completed_transcript_snapshots (
    result_ref TEXT PRIMARY KEY REFERENCES completion_results(result_ref),
    transport_id TEXT NOT NULL UNIQUE REFERENCES transport_deliveries(id),
    work_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    slot_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    captured_at_us INTEGER NOT NULL CHECK(captured_at_us >= 0),
    turn_count INTEGER NOT NULL CHECK(turn_count BETWEEN 0 AND 16),
    redaction_count INTEGER NOT NULL CHECK(redaction_count BETWEEN 0 AND 64),
    transcript_json TEXT NOT NULL CHECK(
        length(CAST(transcript_json AS BLOB)) BETWEEN 25 AND 49152
    ),
    transcript_sha256 TEXT NOT NULL CHECK(
        length(transcript_sha256) = 64 AND
        transcript_sha256 NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TRIGGER completed_transcript_snapshot_requires_exact_completion
BEFORE INSERT ON completed_transcript_snapshots
WHEN NOT EXISTS (
    SELECT 1
    FROM completion_results AS result
    JOIN opencode_deliveries AS delivery
      ON delivery.transport_id = result.transport_id
    WHERE result.result_ref = NEW.result_ref
      AND result.transport_id = NEW.transport_id
      AND result.work_id = NEW.work_id
      AND result.generation = NEW.generation
      AND result.session_id = NEW.session_id
      AND delivery.slot_id = NEW.slot_id
) BEGIN
    SELECT RAISE(ABORT, 'transcript snapshot lacks exact completion authority');
END;

CREATE TRIGGER completed_transcript_snapshots_are_immutable_update
BEFORE UPDATE ON completed_transcript_snapshots BEGIN
    SELECT RAISE(ABORT, 'completed transcript snapshots are immutable');
END;

CREATE TRIGGER completed_transcript_snapshots_are_immutable_delete
BEFORE DELETE ON completed_transcript_snapshots BEGIN
    SELECT RAISE(ABORT, 'completed transcript snapshots are immutable');
END;
