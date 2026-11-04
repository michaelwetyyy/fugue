CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL CHECK(json_valid(value_json)),
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE controller_runs (
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK(state IN ('starting','running','stopping','succeeded','failed','crashed')),
    started_at TEXT NOT NULL,
    heartbeat_at TEXT,
    finished_at TEXT,
    error_summary TEXT
) STRICT;

CREATE TABLE operations (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    idempotency_key TEXT UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('pending','running','waiting','succeeded','failed','cancelled')),
    controller_run_id TEXT REFERENCES controller_runs(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    finished_at TEXT,
    error_summary TEXT
) STRICT;

CREATE TABLE session_bindings (
    id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES operations(id),
    session_ref TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','released')),
    bound_at TEXT NOT NULL,
    released_at TEXT
) STRICT;
CREATE UNIQUE INDEX uq_active_session_binding
    ON session_bindings(session_ref) WHERE state = 'active';
CREATE UNIQUE INDEX uq_operation_active_session
    ON session_bindings(operation_id) WHERE state = 'active';

CREATE TABLE scope_claims (
    id TEXT PRIMARY KEY,
    scope_key TEXT NOT NULL,
    owner_operation_id TEXT NOT NULL REFERENCES operations(id),
    state TEXT NOT NULL CHECK(state IN ('active','released')),
    claimed_at TEXT NOT NULL,
    released_at TEXT
) STRICT;
CREATE UNIQUE INDEX uq_active_scope_claim
    ON scope_claims(scope_key) WHERE state = 'active';

CREATE TABLE dispatches (
    id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES operations(id),
    session_binding_id TEXT REFERENCES session_bindings(id),
    state TEXT NOT NULL CHECK(state IN ('pending','dispatching','dispatched','completed','failed','cancelled')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    finished_at TEXT,
    error_summary TEXT
) STRICT;

CREATE TABLE transport_attempts (
    id TEXT PRIMARY KEY,
    dispatch_id TEXT NOT NULL REFERENCES dispatches(id),
    attempt_number INTEGER NOT NULL CHECK(attempt_number > 0),
    state TEXT NOT NULL CHECK(state IN ('pending','sent','acknowledged','failed','abandoned')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    error_summary TEXT,
    UNIQUE(dispatch_id, attempt_number)
) STRICT;

CREATE TABLE completion_events (
    id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES operations(id),
    external_ref TEXT UNIQUE,
    outcome TEXT NOT NULL CHECK(outcome IN ('succeeded','failed','cancelled')),
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    received_at TEXT NOT NULL
) STRICT;

CREATE TABLE return_routes (
    id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES operations(id),
    route_kind TEXT NOT NULL,
    route_ref TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','released')),
    created_at TEXT NOT NULL,
    released_at TEXT
) STRICT;
CREATE UNIQUE INDEX uq_active_return_route
    ON return_routes(operation_id) WHERE state = 'active';

CREATE TABLE callbacks (
    id TEXT PRIMARY KEY,
    completion_event_id TEXT NOT NULL REFERENCES completion_events(id),
    return_route_id TEXT NOT NULL REFERENCES return_routes(id),
    state TEXT NOT NULL CHECK(state IN ('pending','delivering','delivered','failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    created_at TEXT NOT NULL,
    delivered_at TEXT,
    error_summary TEXT,
    UNIQUE(completion_event_id, return_route_id)
) STRICT;

CREATE TABLE outbox (
    id TEXT PRIMARY KEY,
    topic TEXT NOT NULL,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    state TEXT NOT NULL CHECK(state IN ('pending','delivering','delivered','failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    available_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    delivered_at TEXT
) STRICT;
CREATE INDEX ix_outbox_delivery ON outbox(state, available_at, id);

CREATE TABLE recovery_episodes (
    id TEXT PRIMARY KEY,
    controller_run_id TEXT NOT NULL REFERENCES controller_runs(id),
    operation_id TEXT REFERENCES operations(id),
    state TEXT NOT NULL CHECK(state IN ('open','recovered','failed')),
    reason TEXT NOT NULL,
    opened_at TEXT NOT NULL,
    closed_at TEXT,
    error_summary TEXT
) STRICT;

CREATE TABLE pane_bindings (
    id TEXT PRIMARY KEY,
    session_binding_id TEXT NOT NULL REFERENCES session_bindings(id),
    pane_ref TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','released')),
    bound_at TEXT NOT NULL,
    released_at TEXT
) STRICT;
CREATE UNIQUE INDEX uq_active_pane_binding
    ON pane_bindings(pane_ref) WHERE state = 'active';
CREATE UNIQUE INDEX uq_session_active_pane
    ON pane_bindings(session_binding_id) WHERE state = 'active';

CREATE TABLE events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    occurred_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER events_are_append_only_update
BEFORE UPDATE ON events BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;
CREATE TRIGGER events_are_append_only_delete
BEFORE DELETE ON events BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER operations_safe_state_update
BEFORE UPDATE OF state ON operations
WHEN NOT (
    (OLD.state = 'pending' AND NEW.state IN ('running','failed','cancelled')) OR
    (OLD.state = 'running' AND NEW.state IN ('waiting','succeeded','failed','cancelled')) OR
    (OLD.state = 'waiting' AND NEW.state IN ('running','succeeded','failed','cancelled'))
) BEGIN
    SELECT RAISE(ABORT, 'invalid operation state transition');
END;
