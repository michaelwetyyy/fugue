ALTER TABLE scope_claims ADD COLUMN attempt INTEGER NOT NULL DEFAULT 1 CHECK(attempt > 0);
ALTER TABLE scope_claims ADD COLUMN fence_token TEXT NOT NULL DEFAULT 'legacy-migration-fence';
ALTER TABLE scope_claims ADD COLUMN idempotency_key TEXT;
CREATE UNIQUE INDEX uq_scope_claim_idempotency
    ON scope_claims(idempotency_key) WHERE idempotency_key IS NOT NULL;

ALTER TABLE session_bindings ADD COLUMN attempt INTEGER NOT NULL DEFAULT 1 CHECK(attempt > 0);
ALTER TABLE session_bindings ADD COLUMN fence_token TEXT NOT NULL DEFAULT 'legacy-migration-fence';
ALTER TABLE session_bindings ADD COLUMN idempotency_key TEXT;
CREATE UNIQUE INDEX uq_session_binding_idempotency
    ON session_bindings(idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE work_queue (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    operation_id TEXT REFERENCES operations(id),
    idempotency_key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK(kind IN ('dispatch','recovery','callback')),
    priority INTEGER NOT NULL DEFAULT 0 CHECK(priority BETWEEN -100 AND 100),
    state TEXT NOT NULL CHECK(state IN ('queued','claimed','completed','rejected')),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK(attempt >= 0),
    owner_id TEXT,
    fence_token TEXT,
    enqueued_at TEXT NOT NULL,
    claimed_at TEXT,
    finished_at TEXT,
    CHECK(
        (state = 'queued' AND owner_id IS NULL AND fence_token IS NULL) OR
        (state = 'claimed' AND owner_id IS NOT NULL AND fence_token IS NOT NULL) OR
        (state IN ('completed','rejected') AND owner_id IS NOT NULL AND fence_token IS NOT NULL)
    )
) STRICT;
CREATE INDEX ix_work_queue_ready
    ON work_queue(state, priority DESC, sequence ASC);

CREATE TRIGGER scope_claim_identity_is_immutable
BEFORE UPDATE OF scope_key, owner_operation_id, attempt, fence_token, idempotency_key
ON scope_claims BEGIN
    SELECT RAISE(ABORT, 'scope claim identity is immutable');
END;
CREATE TRIGGER scope_claim_release_only
BEFORE UPDATE OF state ON scope_claims
WHEN NOT (OLD.state = 'active' AND NEW.state = 'released') BEGIN
    SELECT RAISE(ABORT, 'invalid scope claim state transition');
END;

CREATE TRIGGER session_binding_identity_is_immutable
BEFORE UPDATE OF operation_id, session_ref, attempt, fence_token, idempotency_key
ON session_bindings BEGIN
    SELECT RAISE(ABORT, 'session binding identity is immutable');
END;
CREATE TRIGGER session_binding_release_only
BEFORE UPDATE OF state ON session_bindings
WHEN NOT (OLD.state = 'active' AND NEW.state = 'released') BEGIN
    SELECT RAISE(ABORT, 'invalid session binding state transition');
END;

CREATE TRIGGER work_queue_safe_state_update
BEFORE UPDATE OF state ON work_queue
WHEN NOT (
    (OLD.state = 'queued' AND NEW.state IN ('claimed','rejected')) OR
    (OLD.state = 'claimed' AND NEW.state IN ('queued','completed','rejected'))
) BEGIN
    SELECT RAISE(ABORT, 'invalid work queue state transition');
END;
