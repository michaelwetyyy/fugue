CREATE INDEX ix_opencode_persistent_delivery_session_lease
ON opencode_deliveries(isolated_session_id, lease_state)
WHERE agent_lifecycle = 'persistent' AND isolated_session_id IS NOT NULL;

CREATE TRIGGER opencode_persistent_session_state_is_monotonic
BEFORE UPDATE OF state ON opencode_persistent_sessions
WHEN NOT (
    NEW.state = OLD.state OR
    (OLD.state = 'intended' AND NEW.state = 'active') OR
    (OLD.state = 'active' AND NEW.state IN ('closed','attention'))
) BEGIN
    SELECT RAISE(ABORT, 'invalid persistent session transition');
END;

CREATE TRIGGER opencode_persistent_session_claim_shape_is_valid_insert
BEFORE INSERT ON opencode_persistent_sessions
WHEN NOT (
    (NEW.claim_token IS NULL AND NEW.claim_started_at IS NULL) OR
    (
        NEW.claim_token IS NOT NULL AND NEW.claim_started_at IS NOT NULL AND
        length(NEW.claim_token) = 64 AND
        NEW.claim_token NOT GLOB '*[^0-9a-f]*'
    )
) BEGIN
    SELECT RAISE(ABORT, 'persistent session claim is invalid');
END;

CREATE TRIGGER opencode_persistent_session_claim_shape_is_valid_update
BEFORE UPDATE OF claim_token, claim_started_at ON opencode_persistent_sessions
WHEN NOT (
    (NEW.claim_token IS NULL AND NEW.claim_started_at IS NULL) OR
    (
        NEW.claim_token IS NOT NULL AND NEW.claim_started_at IS NOT NULL AND
        length(NEW.claim_token) = 64 AND
        NEW.claim_token NOT GLOB '*[^0-9a-f]*'
    )
) BEGIN
    SELECT RAISE(ABORT, 'persistent session claim is invalid');
END;

CREATE TRIGGER opencode_persistent_session_terminal_shape_is_valid_insert
BEFORE INSERT ON opencode_persistent_sessions
WHEN
    (NEW.state = 'closed' AND (
        NEW.error IS NOT NULL OR NEW.claim_token IS NOT NULL OR
        NEW.claim_started_at IS NOT NULL
    )) OR
    (NEW.state = 'attention' AND (
        NEW.error IS NULL OR NEW.claim_token IS NOT NULL OR
        NEW.claim_started_at IS NOT NULL
    ))
BEGIN
    SELECT RAISE(ABORT, 'persistent session terminal state is invalid');
END;

CREATE TRIGGER opencode_persistent_session_terminal_shape_is_valid
BEFORE UPDATE OF state, error, claim_token, claim_started_at
ON opencode_persistent_sessions
WHEN
    (NEW.state = 'closed' AND (
        NEW.error IS NOT NULL OR NEW.claim_token IS NOT NULL OR
        NEW.claim_started_at IS NOT NULL
    )) OR
    (NEW.state = 'attention' AND (
        NEW.error IS NULL OR NEW.claim_token IS NOT NULL OR
        NEW.claim_started_at IS NOT NULL
    ))
BEGIN
    SELECT RAISE(ABORT, 'persistent session terminal state is invalid');
END;

CREATE TRIGGER opencode_persistent_session_terminal_is_immutable
BEFORE UPDATE OF state, error, claim_token, claim_started_at
ON opencode_persistent_sessions
WHEN OLD.state IN ('closed','attention') AND NOT (
    NEW.state IS OLD.state AND
    NEW.error IS OLD.error AND
    NEW.claim_token IS OLD.claim_token AND
    NEW.claim_started_at IS OLD.claim_started_at
) BEGIN
    SELECT RAISE(ABORT, 'persistent session terminal state is immutable');
END;
