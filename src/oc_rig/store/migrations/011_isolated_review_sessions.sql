ALTER TABLE opencode_deliveries
ADD COLUMN isolated_session_id TEXT;

CREATE UNIQUE INDEX opencode_isolated_session_is_single_use
ON opencode_deliveries(isolated_session_id)
WHERE isolated_session_id IS NOT NULL;

CREATE TRIGGER opencode_isolated_session_is_immutable
BEFORE UPDATE OF isolated_session_id ON opencode_deliveries BEGIN
    SELECT RAISE(ABORT, 'opencode isolated session identity is immutable');
END;
