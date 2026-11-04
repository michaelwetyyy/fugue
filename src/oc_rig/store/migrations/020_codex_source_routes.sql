CREATE TABLE codex_source_routes (
    route_id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL UNIQUE,
    thread_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state = 'committed'),
    idempotency_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    CHECK(length(route_id) BETWEEN 1 AND 128),
    CHECK(length(message_id) = 36),
    CHECK(length(thread_id) BETWEEN 1 AND 128)
) STRICT;

CREATE TRIGGER codex_source_route_is_immutable
BEFORE UPDATE ON codex_source_routes BEGIN
    SELECT RAISE(ABORT, 'codex source route is immutable');
END;

CREATE TRIGGER codex_source_route_cannot_be_deleted
BEFORE DELETE ON codex_source_routes BEGIN
    SELECT RAISE(ABORT, 'codex source route cannot be deleted');
END;
