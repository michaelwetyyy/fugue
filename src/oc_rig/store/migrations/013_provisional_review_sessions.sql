CREATE TABLE opencode_provisional_sessions (
    transport_id TEXT PRIMARY KEY,
    work_id TEXT NOT NULL,
    pool TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    completion_registration_id TEXT NOT NULL,
    callback_registration_id TEXT NOT NULL,
    title TEXT NOT NULL UNIQUE,
    session_id TEXT UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('intended','bound','cleanup','consumed','cleaned','attention')),
    error TEXT,
    claim_token TEXT,
    claim_started_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TRIGGER opencode_provisional_binding_is_immutable
BEFORE UPDATE OF session_id ON opencode_provisional_sessions
WHEN OLD.session_id IS NOT NULL AND NEW.session_id IS NOT OLD.session_id
BEGIN
    SELECT RAISE(ABORT, 'provisional isolated session binding is immutable');
END;
