CREATE TABLE scheduler_work (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    idempotency_key TEXT NOT NULL UNIQUE,
    lane TEXT NOT NULL CHECK(lane IN ('tensorhost','homelab','personal','control','hands-off')),
    state TEXT NOT NULL CHECK(state IN ('queued','assigned','completed','cancelled','rejected')),
    scope_key TEXT,
    scope_owner_id TEXT,
    policy_decision_id TEXT,
    policy_allowed INTEGER CHECK(policy_allowed IN (0, 1)),
    admission_idempotency_key TEXT UNIQUE,
    cancellation_idempotency_key TEXT UNIQUE,
    attempt INTEGER NOT NULL DEFAULT 0 CHECK(attempt >= 0),
    active_assignment_id TEXT,
    enqueued_at TEXT NOT NULL,
    assigned_at TEXT,
    finished_at TEXT,
    CHECK(
        (scope_key IS NULL AND scope_owner_id IS NULL AND
         policy_decision_id IS NULL AND policy_allowed IS NULL AND
         admission_idempotency_key IS NULL) OR
        (scope_key IS NOT NULL AND scope_owner_id IS NOT NULL AND
         policy_decision_id IS NOT NULL AND policy_allowed IS NOT NULL AND
         admission_idempotency_key IS NOT NULL)
    ),
    CHECK(
        (state = 'queued' AND active_assignment_id IS NULL AND finished_at IS NULL) OR
        (state = 'assigned' AND active_assignment_id IS NOT NULL AND
         assigned_at IS NOT NULL AND finished_at IS NULL) OR
        (state IN ('completed','cancelled','rejected') AND active_assignment_id IS NULL AND
         finished_at IS NOT NULL)
    )
) STRICT;
CREATE INDEX ix_scheduler_work_ready
    ON scheduler_work(state, lane, sequence);

CREATE TABLE scheduler_slots (
    id TEXT PRIMARY KEY,
    lane TEXT NOT NULL CHECK(lane IN ('tensorhost','homelab','personal','control','hands-off')),
    position INTEGER NOT NULL CHECK(position BETWEEN 1 AND 3),
    state TEXT NOT NULL CHECK(state IN ('clear','assigned')),
    active_assignment_id TEXT,
    active_work_id TEXT,
    owner_id TEXT,
    attempt INTEGER,
    fence_token TEXT,
    last_used_sequence INTEGER NOT NULL DEFAULT 0 CHECK(last_used_sequence >= 0),
    UNIQUE(lane, position),
    CHECK(
        (state = 'clear' AND active_assignment_id IS NULL AND
         active_work_id IS NULL AND owner_id IS NULL AND
         attempt IS NULL AND fence_token IS NULL) OR
        (state = 'assigned' AND active_assignment_id IS NOT NULL AND
         active_work_id IS NOT NULL AND owner_id IS NOT NULL AND
         attempt IS NOT NULL AND attempt > 0 AND fence_token IS NOT NULL)
    )
) STRICT;
CREATE INDEX ix_scheduler_slots_lru
    ON scheduler_slots(lane, state, last_used_sequence, position);

INSERT INTO scheduler_slots(id, lane, position, state) VALUES
    ('tensorhost-1', 'tensorhost', 1, 'clear'),
    ('tensorhost-2', 'tensorhost', 2, 'clear'),
    ('tensorhost-3', 'tensorhost', 3, 'clear'),
    ('homelab-1', 'homelab', 1, 'clear'),
    ('homelab-2', 'homelab', 2, 'clear'),
    ('homelab-3', 'homelab', 3, 'clear'),
    ('personal-1', 'personal', 1, 'clear'),
    ('personal-2', 'personal', 2, 'clear'),
    ('personal-3', 'personal', 3, 'clear'),
    ('control-1', 'control', 1, 'clear'),
    ('hands-off-1', 'hands-off', 1, 'clear');

CREATE TABLE scheduler_assignments (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    work_id TEXT NOT NULL REFERENCES scheduler_work(id),
    slot_id TEXT NOT NULL REFERENCES scheduler_slots(id),
    lane TEXT NOT NULL CHECK(lane IN ('tensorhost','homelab','personal','control','hands-off')),
    owner_id TEXT NOT NULL,
    attempt INTEGER NOT NULL CHECK(attempt > 0),
    fence_token TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','released')),
    release_outcome TEXT CHECK(release_outcome IN ('requeued','completed','cancelled')),
    assigned_at TEXT NOT NULL,
    released_at TEXT,
    UNIQUE(work_id, attempt),
    CHECK(
        (state = 'active' AND release_outcome IS NULL AND released_at IS NULL) OR
        (state = 'released' AND release_outcome IS NOT NULL AND released_at IS NOT NULL)
    )
) STRICT;
CREATE UNIQUE INDEX uq_scheduler_active_work
    ON scheduler_assignments(work_id) WHERE state = 'active';
CREATE UNIQUE INDEX uq_scheduler_active_slot
    ON scheduler_assignments(slot_id) WHERE state = 'active';

CREATE TRIGGER scheduler_slot_topology_is_immutable
BEFORE UPDATE OF id, lane, position ON scheduler_slots BEGIN
    SELECT RAISE(ABORT, 'scheduler slot topology is immutable');
END;

CREATE TRIGGER scheduler_slot_safe_state_update
BEFORE UPDATE OF state ON scheduler_slots
WHEN NOT (
    (OLD.state = 'clear' AND NEW.state = 'assigned') OR
    (OLD.state = 'assigned' AND NEW.state = 'clear')
) BEGIN
    SELECT RAISE(ABORT, 'invalid scheduler slot state transition');
END;

CREATE TRIGGER scheduler_work_identity_is_immutable
BEFORE UPDATE OF id, idempotency_key, lane, sequence ON scheduler_work BEGIN
    SELECT RAISE(ABORT, 'scheduler work identity is immutable');
END;

CREATE TRIGGER scheduler_work_safe_state_update
BEFORE UPDATE OF state ON scheduler_work
WHEN NOT (
    (OLD.state = 'queued' AND NEW.state IN ('assigned','cancelled','rejected')) OR
    (OLD.state = 'assigned' AND NEW.state IN ('queued','completed','cancelled'))
) BEGIN
    SELECT RAISE(ABORT, 'invalid scheduler work state transition');
END;

CREATE TRIGGER scheduler_admission_is_write_once
BEFORE UPDATE OF scope_key, scope_owner_id, policy_decision_id,
                 policy_allowed, admission_idempotency_key
ON scheduler_work
WHEN OLD.admission_idempotency_key IS NOT NULL BEGIN
    SELECT RAISE(ABORT, 'scheduler admission is immutable');
END;

CREATE TRIGGER scheduler_assignment_prerequisites
BEFORE INSERT ON scheduler_assignments
WHEN NOT EXISTS (
    SELECT 1
    FROM scheduler_work AS work
    JOIN scheduler_slots AS slot ON slot.id = NEW.slot_id
    WHERE work.id = NEW.work_id
      AND work.state = 'queued'
      AND work.lane = NEW.lane
      AND work.scope_key IS NOT NULL
      AND work.scope_owner_id = NEW.owner_id
      AND work.policy_decision_id IS NOT NULL
      AND work.policy_allowed = 1
      AND slot.lane = NEW.lane
      AND slot.state = 'clear'
) BEGIN
    SELECT RAISE(ABORT, 'scheduler assignment prerequisites are not satisfied');
END;

CREATE TRIGGER scheduler_assignment_identity_is_immutable
BEFORE UPDATE OF id, work_id, slot_id, lane, owner_id, attempt, fence_token,
                 assigned_at
ON scheduler_assignments BEGIN
    SELECT RAISE(ABORT, 'scheduler assignment identity is immutable');
END;

CREATE TRIGGER scheduler_assignment_release_only
BEFORE UPDATE OF state ON scheduler_assignments
WHEN NOT (OLD.state = 'active' AND NEW.state = 'released') BEGIN
    SELECT RAISE(ABORT, 'invalid scheduler assignment state transition');
END;
