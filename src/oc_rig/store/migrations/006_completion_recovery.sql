CREATE TABLE milestone_seven_upgrade_guard (
    valid INTEGER NOT NULL CHECK(valid = 1)
) STRICT;
INSERT INTO milestone_seven_upgrade_guard(valid)
SELECT CASE WHEN
    NOT EXISTS (SELECT 1 FROM completion_events) AND
    NOT EXISTS (SELECT 1 FROM return_routes) AND
    NOT EXISTS (SELECT 1 FROM callbacks) AND
    NOT EXISTS (SELECT 1 FROM outbox) AND
    NOT EXISTS (SELECT 1 FROM recovery_episodes)
THEN 1 ELSE 0 END;
DROP TABLE milestone_seven_upgrade_guard;

DROP TRIGGER transport_callback_registration_is_immutable;
DROP TRIGGER transport_callback_registration_safe_state_update;
CREATE TABLE transport_callback_registrations_v5 AS
    SELECT * FROM transport_callback_registrations;
DROP TABLE transport_callback_registrations;
DROP TABLE callbacks;
DROP TABLE outbox;
DROP TABLE return_routes;
DROP TABLE completion_events;
DROP TABLE recovery_episodes;

CREATE TABLE completion_events (
    id TEXT PRIMARY KEY,
    completion_key TEXT NOT NULL UNIQUE,
    completion_registration_id TEXT NOT NULL UNIQUE
        REFERENCES transport_completion_registrations(id),
    transport_id TEXT NOT NULL UNIQUE REFERENCES transport_deliveries(id),
    work_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    outcome TEXT NOT NULL CHECK(outcome IN ('succeeded','failed','cancelled')),
    received_at_us INTEGER NOT NULL CHECK(received_at_us >= 0),
    UNIQUE(work_id, generation)
) STRICT;
CREATE TRIGGER completion_events_are_immutable_update
BEFORE UPDATE ON completion_events BEGIN
    SELECT RAISE(ABORT, 'completion events are immutable');
END;
CREATE TRIGGER completion_events_are_immutable_delete
BEFORE DELETE ON completion_events BEGIN
    SELECT RAISE(ABORT, 'completion events are immutable');
END;
CREATE TABLE return_routes (
    id TEXT PRIMARY KEY,
    transport_id TEXT NOT NULL UNIQUE REFERENCES transport_deliveries(id),
    completion_registration_id TEXT NOT NULL UNIQUE
        REFERENCES transport_completion_registrations(id),
    work_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    assignment_id TEXT NOT NULL REFERENCES scheduler_assignments(id),
    assignment_fence TEXT NOT NULL,
    scope_claim_id TEXT NOT NULL REFERENCES scope_claims(id),
    scope_claim_attempt INTEGER NOT NULL CHECK(scope_claim_attempt > 0),
    scope_claim_fence TEXT NOT NULL,
    route_kind TEXT NOT NULL CHECK(route_kind = 'disabled'),
    route_ref TEXT NOT NULL CHECK(route_ref = 'disabled'),
    state TEXT NOT NULL CHECK(state IN ('registered','ready','consumed','cancelled')),
    created_at_us INTEGER NOT NULL CHECK(created_at_us >= 0),
    ready_at_us INTEGER,
    consumed_at_us INTEGER,
    cancelled_at_us INTEGER,
    CHECK(
        (state = 'registered' AND ready_at_us IS NULL AND consumed_at_us IS NULL AND
         cancelled_at_us IS NULL) OR
        (state = 'ready' AND ready_at_us IS NOT NULL AND consumed_at_us IS NULL AND
         cancelled_at_us IS NULL) OR
        (state = 'consumed' AND ready_at_us IS NOT NULL AND consumed_at_us IS NOT NULL AND
         cancelled_at_us IS NULL) OR
        (state = 'cancelled' AND consumed_at_us IS NULL AND cancelled_at_us IS NOT NULL)
    )
) STRICT;
INSERT INTO return_routes(
    id, transport_id, completion_registration_id, work_id, generation,
    assignment_id, assignment_fence, scope_claim_id, scope_claim_attempt,
    scope_claim_fence, route_kind, route_ref, state, created_at_us,
    cancelled_at_us
)
SELECT
    'return-route-upgrade-' || callback.id,
    delivery.id,
    completion.id,
    delivery.work_id,
    delivery.assignment_attempt,
    delivery.assignment_id,
    delivery.assignment_fence,
    delivery.scope_claim_id,
    delivery.scope_claim_attempt,
    delivery.scope_claim_fence,
    'disabled',
    'disabled',
    CASE WHEN callback.state = 'pending' AND completion.state = 'pending'
         THEN 'registered' ELSE 'cancelled' END,
    0,
    CASE WHEN callback.state = 'pending' AND completion.state = 'pending'
         THEN NULL ELSE 0 END
FROM transport_callback_registrations_v5 AS callback
JOIN transport_completion_registrations AS completion
  ON completion.id = callback.completion_registration_id
 AND completion.transport_id = callback.transport_id
JOIN transport_deliveries AS delivery ON delivery.id = callback.transport_id;
CREATE TRIGGER return_route_identity_is_immutable
BEFORE UPDATE OF id, transport_id, completion_registration_id, work_id,
                 generation, assignment_id, assignment_fence, scope_claim_id,
                 scope_claim_attempt, scope_claim_fence, route_kind, route_ref,
                 created_at_us
ON return_routes BEGIN
    SELECT RAISE(ABORT, 'return route identity is immutable');
END;
CREATE TRIGGER return_route_safe_state_update
BEFORE UPDATE OF state ON return_routes
WHEN NOT (
    (OLD.state = 'registered' AND NEW.state IN ('ready','cancelled')) OR
    (OLD.state = 'ready' AND NEW.state IN ('consumed','cancelled'))
) BEGIN
    SELECT RAISE(ABORT, 'invalid return route state transition');
END;
CREATE TRIGGER return_route_ready_requires_exact_release_join
BEFORE UPDATE OF state ON return_routes
WHEN NEW.state = 'ready' AND NOT EXISTS (
    SELECT 1
    FROM completion_events AS completion
    JOIN scheduler_assignments AS assignment
      ON assignment.id = NEW.assignment_id
     AND assignment.work_id = NEW.work_id
     AND assignment.attempt = NEW.generation
     AND assignment.fence_token = NEW.assignment_fence
     AND assignment.state = 'released'
    JOIN scope_claims AS claim
      ON claim.id = NEW.scope_claim_id
     AND claim.attempt = NEW.scope_claim_attempt
     AND claim.fence_token = NEW.scope_claim_fence
     AND claim.state = 'released'
    WHERE completion.completion_registration_id = NEW.completion_registration_id
      AND completion.transport_id = NEW.transport_id
      AND completion.work_id = NEW.work_id
      AND completion.generation = NEW.generation
) BEGIN
    SELECT RAISE(ABORT, 'return route lacks exact release join');
END;
CREATE TRIGGER completion_requires_exact_registered_generation
BEFORE INSERT ON completion_events
WHEN NOT EXISTS (
    SELECT 1
    FROM transport_completion_registrations AS registration
    JOIN return_routes AS route
      ON route.completion_registration_id = registration.id
     AND route.transport_id = registration.transport_id
     AND route.work_id = registration.work_id
     AND route.generation = registration.assignment_attempt
    WHERE registration.id = NEW.completion_registration_id
      AND registration.transport_id = NEW.transport_id
      AND registration.work_id = NEW.work_id
      AND registration.assignment_attempt = NEW.generation
      AND registration.state = 'pending'
      AND route.state = 'registered'
) BEGIN
    SELECT RAISE(ABORT, 'completion lacks exact registered generation');
END;

CREATE TABLE transport_callback_registrations (
    id TEXT PRIMARY KEY,
    transport_id TEXT NOT NULL UNIQUE REFERENCES transport_deliveries(id),
    completion_registration_id TEXT NOT NULL UNIQUE
        REFERENCES transport_completion_registrations(id),
    return_route_id TEXT NOT NULL UNIQUE REFERENCES return_routes(id),
    work_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    callback_key TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('pending','consumed','cancelled')),
    created_at TEXT NOT NULL,
    consumed_at TEXT,
    cancelled_at TEXT,
    CHECK(
        (state = 'pending' AND consumed_at IS NULL AND cancelled_at IS NULL) OR
        (state = 'consumed' AND consumed_at IS NOT NULL AND cancelled_at IS NULL) OR
        (state = 'cancelled' AND consumed_at IS NULL AND cancelled_at IS NOT NULL)
    )
) STRICT;
INSERT INTO transport_callback_registrations(
    id, transport_id, completion_registration_id, return_route_id, work_id,
    generation, callback_key, state, created_at, cancelled_at
)
SELECT
    callback.id,
    callback.transport_id,
    callback.completion_registration_id,
    'return-route-upgrade-' || callback.id,
    completion.work_id,
    completion.assignment_attempt,
    callback.callback_key,
    CASE WHEN callback.state = 'pending' AND completion.state = 'pending'
         THEN 'pending' ELSE 'cancelled' END,
    callback.created_at,
    CASE WHEN callback.state = 'pending' AND completion.state = 'pending'
         THEN NULL ELSE coalesce(callback.cancelled_at, callback.created_at) END
FROM transport_callback_registrations_v5 AS callback
JOIN transport_completion_registrations AS completion
  ON completion.id = callback.completion_registration_id
 AND completion.transport_id = callback.transport_id;
DROP TABLE transport_callback_registrations_v5;
CREATE TRIGGER transport_callback_registration_is_immutable
BEFORE UPDATE OF id, transport_id, completion_registration_id, return_route_id,
                 work_id, generation, callback_key, created_at
ON transport_callback_registrations BEGIN
    SELECT RAISE(ABORT, 'callback registration identity is immutable');
END;
CREATE TRIGGER transport_callback_registration_safe_state_update
BEFORE UPDATE OF state ON transport_callback_registrations
WHEN NOT (OLD.state = 'pending' AND NEW.state IN ('consumed','cancelled')) BEGIN
    SELECT RAISE(ABORT, 'invalid callback registration state transition');
END;

CREATE TABLE callbacks (
    id TEXT PRIMARY KEY,
    completion_event_id TEXT NOT NULL UNIQUE REFERENCES completion_events(id),
    return_route_id TEXT NOT NULL UNIQUE REFERENCES return_routes(id),
    delivery_key TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('blocked','pending','delivering','delivered','attention')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
    available_at_us INTEGER NOT NULL CHECK(available_at_us >= 0),
    created_at_us INTEGER NOT NULL CHECK(created_at_us >= 0),
    delivered_at_us INTEGER,
    failure_class TEXT CHECK(failure_class IN (
        'transient','deterministic','permission','policy','delivery_unknown'
    )),
    attention_reason TEXT,
    CHECK(
        (state IN ('blocked','pending','delivering') AND delivered_at_us IS NULL) OR
        (state = 'delivered' AND delivered_at_us IS NOT NULL AND failure_class IS NULL AND
         attention_reason IS NULL) OR
        (state = 'attention' AND delivered_at_us IS NULL AND
         failure_class IS NOT NULL AND attention_reason IS NOT NULL)
    )
) STRICT;

CREATE TABLE outbox (
    id TEXT PRIMARY KEY,
    callback_id TEXT NOT NULL UNIQUE REFERENCES callbacks(id),
    delivery_key TEXT NOT NULL UNIQUE,
    topic TEXT NOT NULL CHECK(topic = 'completion.callback.v1'),
    aggregate_type TEXT NOT NULL CHECK(aggregate_type = 'work'),
    aggregate_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('blocked','pending','delivering','delivered','attention')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
    available_at_us INTEGER NOT NULL CHECK(available_at_us >= 0),
    created_at_us INTEGER NOT NULL CHECK(created_at_us >= 0),
    delivered_at_us INTEGER,
    CHECK(
        (state IN ('blocked','pending','delivering','attention') AND delivered_at_us IS NULL) OR
        (state = 'delivered' AND delivered_at_us IS NOT NULL)
    )
) STRICT;
CREATE INDEX ix_outbox_delivery
    ON outbox(state, available_at_us, id);
CREATE TRIGGER callback_pending_requires_ready_route
BEFORE UPDATE OF state ON callbacks
WHEN NEW.state = 'pending' AND NOT EXISTS (
    SELECT 1 FROM return_routes
    WHERE id = NEW.return_route_id AND state = 'ready'
) BEGIN
    SELECT RAISE(ABORT, 'callback is not joined to a ready route');
END;
CREATE TRIGGER callback_delivery_requires_ready_route
BEFORE UPDATE OF state ON callbacks
WHEN NEW.state = 'delivering' AND NOT EXISTS (
    SELECT 1 FROM return_routes
    WHERE id = NEW.return_route_id AND state = 'ready'
) BEGIN
    SELECT RAISE(ABORT, 'callback route is not ready');
END;
CREATE TRIGGER outbox_pending_requires_pending_callback
BEFORE UPDATE OF state ON outbox
WHEN NEW.state = 'pending' AND NOT EXISTS (
    SELECT 1 FROM callbacks
    WHERE id = NEW.callback_id AND delivery_key = NEW.delivery_key
      AND state = 'pending'
) BEGIN
    SELECT RAISE(ABORT, 'outbox callback is not pending');
END;
CREATE TRIGGER outbox_delivery_requires_delivering_callback
BEFORE UPDATE OF state ON outbox
WHEN NEW.state = 'delivering' AND NOT EXISTS (
    SELECT 1 FROM callbacks
    WHERE id = NEW.callback_id AND delivery_key = NEW.delivery_key
      AND state = 'delivering'
) BEGIN
    SELECT RAISE(ABORT, 'outbox callback is not delivering');
END;
CREATE TRIGGER return_route_consumed_requires_delivered_callback
BEFORE UPDATE OF state ON return_routes
WHEN NEW.state = 'consumed' AND NOT EXISTS (
    SELECT 1 FROM callbacks
    WHERE return_route_id = NEW.id AND state = 'delivered'
) BEGIN
    SELECT RAISE(ABORT, 'return route consumption lacks delivered callback');
END;

CREATE TABLE callback_delivery_attempts (
    id TEXT PRIMARY KEY,
    callback_id TEXT NOT NULL REFERENCES callbacks(id),
    attempt_number INTEGER NOT NULL CHECK(attempt_number BETWEEN 1 AND 3),
    delivery_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('delivering','retry_scheduled','delivered','attention')),
    failure_class TEXT CHECK(failure_class IN (
        'transient','deterministic','permission','policy','delivery_unknown'
    )),
    started_at_us INTEGER NOT NULL CHECK(started_at_us >= 0),
    finished_at_us INTEGER,
    UNIQUE(callback_id, attempt_number)
) STRICT;
CREATE TRIGGER callback_attempt_identity_is_immutable
BEFORE UPDATE OF id, callback_id, attempt_number, delivery_key, started_at_us
ON callback_delivery_attempts BEGIN
    SELECT RAISE(ABORT, 'callback attempt identity is immutable');
END;
CREATE TRIGGER callback_attempt_safe_state_update
BEFORE UPDATE OF state ON callback_delivery_attempts
WHEN NOT (
    OLD.state = 'delivering' AND
    NEW.state IN ('retry_scheduled','delivered','attention')
) BEGIN
    SELECT RAISE(ABORT, 'invalid callback attempt transition');
END;

CREATE TABLE recovery_targets (
    target_id TEXT PRIMARY KEY,
    work_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    phase TEXT NOT NULL CHECK(phase IN (
        'queued','active','handed_off','tool_flow','busy','thinking','corpse',
        'completed','attention'
    )),
    productive INTEGER NOT NULL CHECK(productive IN (0,1)),
    current_timer_id TEXT,
    episode_id TEXT,
    circuit_state TEXT NOT NULL CHECK(circuit_state IN ('closed','open')),
    last_observed_at_us INTEGER NOT NULL CHECK(last_observed_at_us >= 0),
    updated_at_us INTEGER NOT NULL CHECK(updated_at_us >= 0),
    UNIQUE(work_id, generation)
) STRICT;

CREATE TABLE recovery_episodes (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES recovery_targets(target_id),
    work_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    state TEXT NOT NULL CHECK(state IN ('open','recovered','attention')),
    reason TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 6),
    opened_at_us INTEGER NOT NULL CHECK(opened_at_us >= 0),
    closed_at_us INTEGER,
    attention_reason TEXT,
    CHECK(
        (state = 'open' AND closed_at_us IS NULL AND attention_reason IS NULL) OR
        (state = 'recovered' AND closed_at_us IS NOT NULL AND attention_reason IS NULL) OR
        (state = 'attention' AND closed_at_us IS NOT NULL AND attention_reason IS NOT NULL)
    )
) STRICT;
CREATE UNIQUE INDEX uq_recovery_open_episode
    ON recovery_episodes(target_id, generation) WHERE state = 'open';

CREATE TABLE recovery_timers (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES recovery_targets(target_id),
    generation INTEGER NOT NULL CHECK(generation > 0),
    episode_id TEXT REFERENCES recovery_episodes(id),
    kind TEXT NOT NULL CHECK(kind IN ('heuristic','recovery')),
    reason TEXT NOT NULL,
    attempt_number INTEGER CHECK(attempt_number BETWEEN 1 AND 6),
    state TEXT NOT NULL CHECK(state IN ('scheduled','fired','cancelled')),
    clock_epoch TEXT NOT NULL,
    scheduled_wall_us INTEGER NOT NULL CHECK(scheduled_wall_us >= 0),
    scheduled_mono_ns INTEGER NOT NULL CHECK(scheduled_mono_ns >= 0),
    due_wall_us INTEGER NOT NULL CHECK(due_wall_us >= scheduled_wall_us),
    due_mono_ns INTEGER NOT NULL CHECK(due_mono_ns >= scheduled_mono_ns),
    fired_at_us INTEGER,
    cancelled_at_us INTEGER,
    CHECK(
        (state = 'scheduled' AND fired_at_us IS NULL AND cancelled_at_us IS NULL) OR
        (state = 'fired' AND fired_at_us IS NOT NULL AND cancelled_at_us IS NULL) OR
        (state = 'cancelled' AND fired_at_us IS NULL AND cancelled_at_us IS NOT NULL)
    )
) STRICT;
CREATE UNIQUE INDEX uq_recovery_scheduled_timer
    ON recovery_timers(target_id, generation) WHERE state = 'scheduled';
CREATE INDEX ix_recovery_due
    ON recovery_timers(state, due_wall_us, id);

CREATE TABLE recovery_attempts (
    id TEXT PRIMARY KEY,
    episode_id TEXT NOT NULL REFERENCES recovery_episodes(id),
    timer_id TEXT NOT NULL UNIQUE REFERENCES recovery_timers(id),
    attempt_number INTEGER NOT NULL CHECK(attempt_number BETWEEN 1 AND 6),
    tier TEXT NOT NULL CHECK(tier IN ('fast','normal')),
    state TEXT NOT NULL CHECK(state IN ('due','succeeded','no_progress','terminal')),
    failure_class TEXT CHECK(failure_class IN (
        'transient','deterministic','permission','policy','delivery_unknown'
    )),
    reason TEXT NOT NULL,
    due_at_us INTEGER NOT NULL CHECK(due_at_us >= 0),
    finished_at_us INTEGER,
    UNIQUE(episode_id, attempt_number)
) STRICT;

CREATE TABLE recovery_clock_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    clock_epoch TEXT NOT NULL,
    wall_us INTEGER NOT NULL CHECK(wall_us >= 0),
    mono_ns INTEGER NOT NULL CHECK(mono_ns >= 0)
) STRICT;

CREATE TRIGGER recovery_timer_identity_is_immutable
BEFORE UPDATE OF id, target_id, generation, episode_id, kind, reason,
                 attempt_number, clock_epoch, scheduled_wall_us,
                 scheduled_mono_ns, due_wall_us, due_mono_ns
ON recovery_timers BEGIN
    SELECT RAISE(ABORT, 'recovery timer identity is immutable');
END;
CREATE TRIGGER recovery_timer_safe_state_update
BEFORE UPDATE OF state ON recovery_timers
WHEN NOT (OLD.state = 'scheduled' AND NEW.state IN ('fired','cancelled')) BEGIN
    SELECT RAISE(ABORT, 'invalid recovery timer transition');
END;
CREATE TRIGGER recovery_attempt_identity_is_immutable
BEFORE UPDATE OF id, episode_id, timer_id, attempt_number, tier, reason, due_at_us
ON recovery_attempts BEGIN
    SELECT RAISE(ABORT, 'recovery attempt identity is immutable');
END;
CREATE TRIGGER recovery_attempt_safe_state_update
BEFORE UPDATE OF state ON recovery_attempts
WHEN NOT (
    OLD.state = 'due' AND NEW.state IN ('succeeded','no_progress','terminal')
) BEGIN
    SELECT RAISE(ABORT, 'invalid recovery attempt transition');
END;
