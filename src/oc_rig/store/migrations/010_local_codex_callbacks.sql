CREATE TABLE local_codex_return_routes (
    return_route_id TEXT PRIMARY KEY REFERENCES return_routes(id),
    thread_id TEXT NOT NULL,
    created_at_us INTEGER NOT NULL CHECK(created_at_us >= 0)
) STRICT;

CREATE TRIGGER local_codex_return_routes_are_immutable_update
BEFORE UPDATE ON local_codex_return_routes BEGIN
    SELECT RAISE(ABORT, 'local Codex return routes are immutable');
END;
CREATE TRIGGER local_codex_return_routes_are_immutable_delete
BEFORE DELETE ON local_codex_return_routes BEGIN
    SELECT RAISE(ABORT, 'local Codex return routes are immutable');
END;
