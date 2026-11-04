from __future__ import annotations

import copy
import hashlib
import json
import os
import socket
import sqlite3
import stat
import tempfile
import threading
import time
import unittest
import weakref
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from pathlib import Path
from unittest.mock import patch

from oc_rig.adapters.opencode import OpenCodeSlot, OpenCodeTopology
from oc_rig.cockpit import CockpitClient, normalize_snapshot, render_terminal
from oc_rig.daemon.controller import _RigController
from oc_rig.daemon.identity import ServiceIdentityPolicy
from oc_rig.daemon.security import PrivateSocketPath
from oc_rig.daemon.server import RigDaemon, _DurableChildDaemon
from oc_rig.protocol.client import RigClient, RigClientError
from oc_rig.store import PrivateRuntimeDirectory, RigStore, StoreQuiescenceError
from oc_rig.store import snapshot as snapshot_module
from oc_rig.store.snapshot import _CockpitSnapshotProjection
from oc_rig.terminal_lifecycle import snapshot_is_quiescent


def _configured_topology() -> OpenCodeTopology:
    sizes = {
        "tensorhost": 3,
        "homelab": 3,
        "personal": 3,
        "control": 3,
        "hands-off": 1,
    }
    counter = 0
    pools: dict[str, tuple[OpenCodeSlot, ...]] = {}
    for lane, size in sizes.items():
        members = []
        for position in range(1, size + 1):
            counter += 1
            members.append(
                OpenCodeSlot(
                    f"{lane}-{position}", f"session-{counter}", "secure-worker"
                )
            )
        pools[lane] = tuple(members)
    return OpenCodeTopology(pools)


def _database_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _event_count(path: Path) -> int:
    with closing(sqlite3.connect(path)) as connection:
        row = connection.execute("SELECT count(*) FROM events").fetchone()
    assert row is not None
    return int(row[0])


def _runtime_manifest(root: Path) -> dict[str, tuple[object, ...]]:
    manifest: dict[str, tuple[object, ...]] = {}
    for path in sorted(root.rglob("*")):
        details = path.lstat()
        relative = str(path.relative_to(root))
        if stat.S_ISREG(details.st_mode):
            manifest[relative] = (
                "file",
                stat.S_IMODE(details.st_mode),
                details.st_size,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        elif stat.S_ISDIR(details.st_mode):
            manifest[relative] = ("directory", stat.S_IMODE(details.st_mode))
        elif stat.S_ISSOCK(details.st_mode):
            manifest[relative] = ("socket", stat.S_IMODE(details.st_mode))
        else:
            manifest[relative] = ("other", stat.S_IMODE(details.st_mode))
    return manifest


def _seed_active_worker(path: Path, *, agent_lifecycle: str = "persistent") -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """INSERT INTO operations(id, kind, state, created_at, updated_at)
               VALUES ('owner-1', 'dispatch', 'running', 't0', 't0')"""
        )
        connection.execute(
            """INSERT INTO scope_claims(
                   id, scope_key, owner_operation_id, state, claimed_at,
                   attempt, fence_token, idempotency_key
               ) VALUES ('claim-1', ?, 'owner-1', 'active', 't0', 1,
                         'scope-fence-1', 'claim-idem-1')""",
            ("0" * 64,),
        )
        connection.execute(
            """INSERT INTO scheduler_work(
                   id, idempotency_key, lane, state, scope_key, scope_owner_id,
                   policy_decision_id, policy_allowed, admission_idempotency_key,
                   attempt, enqueued_at, queue_order
               ) VALUES ('work-1', 'work-idem-1', 'tensorhost', 'queued', ?,
                         'owner-1', 'decision-1', 1, 'admit-idem-1', 0,
                         't0', 1)""",
            ("0" * 64,),
        )
        connection.execute(
            """INSERT INTO scheduler_admission_decisions(
                   id, work_id, policy_version, policy_hash, decision_hash,
                   content_hash, scope_hash, allowed, reasons_json, scope_claim_id,
                   scope_key, scope_owner_id, scope_claim_attempt,
                   scope_claim_fence, created_at, agent_lifecycle
               ) VALUES ('decision-1', 'work-1', 'v1', ?, ?, ?, ?, 1, '[]',
                         'claim-1', ?, 'owner-1', 1, 'scope-fence-1', 't0', ?)""",
            ("1" * 64, "2" * 64, "3" * 64, "0" * 64, "0" * 64, agent_lifecycle),
        )
        connection.execute(
            """INSERT INTO scheduler_assignments(
                   id, work_id, slot_id, lane, owner_id, attempt, fence_token,
                   state, assigned_at
               ) VALUES ('assignment-1', 'work-1', 'tensorhost-1', 'tensorhost',
                         'owner-1', 1, 'assignment-fence-1', 'active', 't1')"""
        )
        connection.execute(
            """UPDATE scheduler_work SET state = 'assigned', attempt = 1,
                   active_assignment_id = 'assignment-1', assigned_at = 't1'
               WHERE id = 'work-1'"""
        )
        connection.execute(
            """UPDATE scheduler_slots SET state = 'assigned',
                   active_assignment_id = 'assignment-1', active_work_id = 'work-1',
                   owner_id = 'owner-1', attempt = 1,
                   fence_token = 'assignment-fence-1'
               WHERE id = 'tensorhost-1'"""
        )
        connection.execute(
            """INSERT INTO session_bindings(
                   id, operation_id, session_ref, state, bound_at,
                   attempt, fence_token, idempotency_key
               ) VALUES ('session-binding-1', 'owner-1', 'session-alpha',
                         'active', 't1', 1, 'session-fence-1', 'session-idem-1')"""
        )
        connection.execute(
            """INSERT INTO pane_bindings(
                   id, session_binding_id, pane_ref, state, bound_at
               ) VALUES ('pane-binding-1', 'session-binding-1', 'pane-1',
                         'active', 't1')"""
        )
        connection.execute(
            """INSERT INTO transport_deliveries(
                   id, idempotency_key, request_fingerprint, work_id, pool,
                   assignment_id, owner_id, assignment_attempt, assignment_fence,
                   admission_decision_id, scope_claim_id, scope_claim_attempt,
                   scope_claim_fence, adapter_kind, payload_json, state,
                   created_at, updated_at
               ) VALUES ('transport-1', 'transport-idem-1', ?, 'work-1',
                         'tensorhost', 'assignment-1', 'owner-1', 1,
                         'assignment-fence-1', 'decision-1', 'claim-1', 1,
                         'scope-fence-1', 'disabled', '{}', 'reserved', 't1', 't1')""",
            ("4" * 64,),
        )
        connection.execute(
            """INSERT INTO transport_completion_registrations(
                   id, transport_id, work_id, assignment_id, assignment_attempt,
                   assignment_fence, registration_key, state, created_at
               ) VALUES ('completion-registration-1', 'transport-1', 'work-1',
                         'assignment-1', 1, 'assignment-fence-1',
                         'registration-key-1', 'pending', 't1')"""
        )
        connection.execute(
            """INSERT INTO return_routes(
                   id, transport_id, completion_registration_id, work_id,
                   generation, assignment_id, assignment_fence, scope_claim_id,
                   scope_claim_attempt, scope_claim_fence, route_kind, route_ref,
                   state, created_at_us
               ) VALUES ('route-1', 'transport-1', 'completion-registration-1',
                         'work-1', 1, 'assignment-1', 'assignment-fence-1',
                         'claim-1', 1, 'scope-fence-1', 'disabled', 'disabled',
                         'registered', 1)"""
        )
        connection.execute(
            """INSERT INTO transport_callback_registrations(
                   id, transport_id, completion_registration_id, return_route_id,
                   work_id, generation, callback_key, state, created_at
               ) VALUES ('transport-callback-1', 'transport-1',
                         'completion-registration-1', 'route-1', 'work-1', 1,
                         'callback-key-1', 'pending', 't1')"""
        )
        connection.execute(
            """INSERT INTO completion_events(
                   id, completion_key, completion_registration_id, transport_id,
                   work_id, generation, outcome, received_at_us
               ) VALUES ('completion-1', 'completion-key-1',
                         'completion-registration-1', 'transport-1', 'work-1',
                         1, 'succeeded', 2)"""
        )
        connection.execute(
            """INSERT INTO callbacks(
                   id, completion_event_id, return_route_id, delivery_key, state,
                   attempts, available_at_us, created_at_us, attention_reason
               ) VALUES ('callback-1', 'completion-1', 'route-1', 'delivery-key-1',
                         'blocked', 0, 3, 3, 'callback_adapter_disabled')"""
        )
        connection.execute(
            """INSERT INTO outbox(
                   id, callback_id, delivery_key, topic, aggregate_type,
                   aggregate_id, state, attempts, available_at_us, created_at_us,
                   disabled_reason
               ) VALUES ('outbox-1', 'callback-1', 'delivery-key-1',
                         'completion.callback.v1', 'work', 'work-1', 'blocked',
                         0, 3, 3, 'callback_adapter_disabled')"""
        )
        connection.execute(
            """INSERT INTO recovery_targets(
                   target_id, work_id, generation, phase, productive,
                   circuit_state, last_observed_at_us, updated_at_us
               ) VALUES ('target-1', 'work-1', 1, 'thinking', 1, 'closed', 4, 4)"""
        )
        connection.execute(
            """INSERT INTO recovery_episodes(
                   id, target_id, work_id, generation, state, reason, attempts,
                   opened_at_us
               ) VALUES ('episode-1', 'target-1', 'work-1', 1, 'open',
                         'no_progress', 1, 5)"""
        )
        connection.execute(
            """INSERT INTO recovery_timers(
                   id, target_id, generation, episode_id, kind, reason,
                   attempt_number, state, clock_epoch, scheduled_wall_us,
                   scheduled_mono_ns, due_wall_us, due_mono_ns
               ) VALUES ('timer-1', 'target-1', 1, 'episode-1', 'recovery',
                         'no_progress', 2, 'scheduled', 'clock-1', 5, 5, 10, 10)"""
        )
        connection.execute(
            """UPDATE recovery_targets SET current_timer_id = 'timer-1',
                   episode_id = 'episode-1' WHERE target_id = 'target-1'"""
        )
        connection.execute(
            """INSERT INTO events(
                   event_id, aggregate_type, aggregate_id, event_type,
                   payload_json, occurred_at
               ) VALUES ('event-1', 'scheduler_work', 'work-1',
                         'scheduler.work.assigned', '{}', 't1')"""
        )
        connection.commit()


class CockpitProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.store = RigStore(
            PrivateRuntimeDirectory(self.root / "state", self.root)
        )
        self.store.initialize()
        self.connection = sqlite3.connect(
            self.store.path,
            isolation_level=None,
            check_same_thread=False,
        )
        self.addCleanup(self.connection.close)

    def capture(
        self, projection: _CockpitSnapshotProjection | None = None
    ) -> dict[str, object]:
        self.connection.execute("BEGIN")
        try:
            return dict((projection or _CockpitSnapshotProjection()).capture(self.connection))
        finally:
            self.connection.rollback()

    def downgrade_to_migration_012(self) -> None:
        self.connection.execute("DROP INDEX ix_opencode_persistent_delivery_session_lease")
        for trigger in (
            "opencode_persistent_session_state_is_monotonic",
            "opencode_persistent_session_claim_shape_is_valid_insert",
            "opencode_persistent_session_claim_shape_is_valid_update",
            "opencode_persistent_session_terminal_shape_is_valid_insert",
            "opencode_persistent_session_terminal_shape_is_valid",
            "opencode_persistent_session_terminal_is_immutable",
        ):
            self.connection.execute(f'DROP TRIGGER "{trigger}"')
        self.connection.execute("DROP INDEX ix_local_codex_return_routes_thread_route")
        self.connection.execute("DROP TRIGGER codex_source_route_is_immutable")
        self.connection.execute("DROP TRIGGER codex_source_route_cannot_be_deleted")
        self.connection.execute("DROP TABLE codex_source_routes")
        self.connection.execute("DROP TRIGGER llm_behaviour_singleton_is_immutable")
        self.connection.execute("DROP TRIGGER llm_behaviour_revision_is_monotonic")
        self.connection.execute("DROP TRIGGER llm_behaviour_row_cannot_be_deleted")
        self.connection.execute("DROP TABLE llm_behaviour_settings")
        self.connection.execute("DROP TRIGGER scheduler_slot_topology_rejects_delete")
        self.connection.execute(
            "DELETE FROM scheduler_slots WHERE id IN ('control-2', 'control-3')"
        )
        self.connection.executescript(
            """CREATE TRIGGER scheduler_slot_topology_rejects_delete
               BEFORE DELETE ON scheduler_slots BEGIN
                   SELECT RAISE(ABORT, 'scheduler slot topology is immutable');
               END;"""
        )
        for trigger in (
            "completion_event_requires_child_barrier",
            "completion_result_requires_barrier_authority",
            "completion_child_barrier_identity_is_immutable",
            "completion_child_barrier_safe_transition",
            "completion_child_barrier_consolidation_binding_is_immutable",
            "completion_child_barrier_final_authority_is_immutable",
            "completion_child_barrier_attention_reason_is_immutable",
            "completion_child_session_identity_is_immutable",
            "completion_child_session_safe_transition",
            "completion_child_session_terminal_binding_is_immutable",
        ):
            self.connection.execute(f'DROP TRIGGER "{trigger}"')
        self.connection.execute("DROP TABLE completion_child_sessions")
        self.connection.execute("DROP TABLE completion_child_barriers")
        self.connection.execute("DROP TRIGGER opencode_cleanup_requires_isolated_session")
        self.connection.execute(
            "DROP TRIGGER opencode_cleanup_pending_requires_exact_completion"
        )
        self.connection.execute("DROP TRIGGER opencode_cleanup_enqueue_after_release")
        self.connection.execute("DROP INDEX opencode_disposable_session_is_single_use")
        self.connection.execute(
            """CREATE UNIQUE INDEX opencode_isolated_session_is_single_use
               ON opencode_deliveries(isolated_session_id)
               WHERE isolated_session_id IS NOT NULL"""
        )
        self.connection.execute(
            "ALTER TABLE opencode_deliveries DROP COLUMN agent_lifecycle"
        )
        self.connection.executescript(
            """CREATE TRIGGER opencode_cleanup_requires_isolated_session
               BEFORE UPDATE OF cleanup_state ON opencode_deliveries
               WHEN NEW.isolated_session_id IS NULL OR NOT (
                   (OLD.cleanup_state = 'none' AND NEW.cleanup_state = 'pending') OR
                   (OLD.cleanup_state IN ('pending','ambiguous') AND NEW.cleanup_state = 'in_flight') OR
                   (OLD.cleanup_state = 'in_flight' AND NEW.cleanup_state IN ('succeeded','ambiguous','failed'))
               ) BEGIN
                   SELECT RAISE(ABORT, 'invalid isolated session cleanup transition');
               END;
               CREATE TRIGGER opencode_cleanup_pending_requires_exact_completion
               BEFORE UPDATE OF cleanup_state ON opencode_deliveries
               WHEN NEW.cleanup_state = 'pending' AND NOT EXISTS (
                   SELECT 1 FROM transport_deliveries AS delivery
                   JOIN transport_completion_registrations AS registration
                     ON registration.transport_id = delivery.id
                    AND registration.state = 'completed'
                   JOIN completion_events AS completion
                     ON completion.transport_id = delivery.id
                    AND completion.completion_registration_id = registration.id
                   JOIN scheduler_assignments AS assignment
                     ON assignment.id = delivery.assignment_id
                    AND assignment.state = 'released'
                   JOIN scope_claims AS claim
                     ON claim.id = delivery.scope_claim_id AND claim.state = 'released'
                   WHERE delivery.id = NEW.transport_id
                     AND delivery.work_id = NEW.work_id
               ) BEGIN
                   SELECT RAISE(ABORT, 'isolated cleanup lacks exact completion release join');
               END;
               CREATE TRIGGER opencode_cleanup_enqueue_after_release
               AFTER UPDATE OF lease_state ON opencode_deliveries
               WHEN NEW.lease_state = 'released' AND NEW.isolated_session_id IS NOT NULL
               BEGIN
                   UPDATE opencode_deliveries SET cleanup_state = 'pending'
                   WHERE transport_id = NEW.transport_id AND cleanup_state = 'none';
               END;"""
        )
        self.connection.execute("DROP TABLE gui_task_submissions")
        self.connection.execute("DROP TABLE opencode_persistent_sessions")
        for trigger in (
            "callback_delivery_reconciliation_requires_attention",
            "callback_delivery_reconciliations_are_immutable_update",
            "callback_delivery_reconciliations_are_immutable_delete",
            "callback_attention_delivery_requires_reconciliation",
            "outbox_attention_delivery_requires_reconciliation",
        ):
            self.connection.execute(f'DROP TRIGGER "{trigger}"')
        self.connection.execute("DROP TABLE callback_delivery_reconciliations")
        self.connection.execute("DROP TRIGGER callback_attempt_safe_state_update")
        self.connection.executescript(
            """CREATE TRIGGER callback_attempt_safe_state_update
               BEFORE UPDATE OF state ON callback_delivery_attempts
               WHEN NOT (
                   OLD.state = 'delivering' AND
                   NEW.state IN ('retry_scheduled','delivered','attention')
               ) BEGIN
                   SELECT RAISE(ABORT, 'invalid callback attempt transition');
               END;"""
        )
        self.connection.execute(
            "ALTER TABLE scheduler_admission_decisions DROP COLUMN allow_child_agents"
        )
        self.connection.execute(
            "ALTER TABLE scheduler_admission_decisions DROP COLUMN agent_lifecycle"
        )
        self.connection.execute("DROP TRIGGER completed_transcript_snapshot_requires_exact_completion")
        self.connection.execute("DROP TRIGGER completed_transcript_snapshots_are_immutable_update")
        self.connection.execute("DROP TRIGGER completed_transcript_snapshots_are_immutable_delete")
        self.connection.execute("DROP TABLE completed_transcript_snapshots")
        self.connection.execute("DROP TRIGGER completion_results_are_immutable_update")
        self.connection.execute("DROP TRIGGER completion_results_are_immutable_delete")
        self.connection.execute("DROP TABLE completion_results")
        self.connection.execute(
            "DROP TRIGGER opencode_provisional_binding_is_immutable"
        )
        self.connection.execute("DROP TABLE opencode_provisional_sessions")
        self.connection.execute(
            """DELETE FROM schema_migrations
               WHERE version IN (
                   '013_provisional_review_sessions.sql',
                   '014_durable_completion_results.sql',
                   '015_agent_lifecycle.sql',
                   '016_cancelled_session_cleanup.sql',
                   '017_child_completion_barrier.sql',
                   '018_llm_behaviour.sql',
                   '019_control_pool_expansion.sql',
                   '020_codex_source_routes.sql',
                   '021_slot_session_rebind.sql',
                   '022_child_barrier_generation.sql',
                   '023_descendant_budget.sql',
                   '024_completed_transcript_archive.sql',
                   '025_callback_delivery_reconciliation.sql',
                   '026_source_inbox_read_indexes.sql',
                   '027_persistent_session_close.sql'
               )"""
        )
        self.connection.commit()

    def downgrade_to_migration_010(self) -> None:
        self.downgrade_to_migration_012()
        for trigger in (
            "opencode_cleanup_requires_isolated_session",
            "opencode_cleanup_pending_requires_exact_completion",
            "opencode_cleanup_enqueue_after_release",
        ):
            self.connection.execute(f'DROP TRIGGER "{trigger}"')
        for column in ("cleanup_error", "cleanup_attempts", "cleanup_state"):
            self.connection.execute(
                f'ALTER TABLE opencode_deliveries DROP COLUMN "{column}"'
            )
        self.connection.execute("DROP TRIGGER opencode_isolated_session_is_immutable")
        self.connection.execute("DROP INDEX opencode_isolated_session_is_single_use")
        self.connection.execute(
            "ALTER TABLE opencode_deliveries DROP COLUMN isolated_session_id"
        )
        self.connection.execute(
            """DELETE FROM schema_migrations
               WHERE version IN (
                   '011_isolated_review_sessions.sql',
                   '012_isolated_session_cleanup.sql'
               )"""
        )
        self.connection.commit()

    def _start_durable_daemon(
        self, label: str
    ) -> tuple[_DurableChildDaemon, threading.Thread, PrivateRuntimeDirectory, Path]:
        durable_root = self.root / label
        durable_root.mkdir(mode=0o710)
        durable_root.chmod(0o710)
        runtime = PrivateRuntimeDirectory(durable_root / "state", durable_root)
        store = RigStore(runtime)
        store.initialize()
        runtime.root.joinpath("rigd.lock").touch(mode=0o600)
        runtime.root.joinpath("rigd.lock").chmod(0o600)
        socket_path = durable_root / "socket" / "rig.sock"
        socket_path.parent.mkdir(mode=0o710)
        socket_path.parent.chmod(0o710)
        identity = ServiceIdentityPolicy(
            os.geteuid(),
            frozenset({os.geteuid()}),
            os.getegid(),
        )

        def request_handler(daemon: _DurableChildDaemon):
            reference = weakref.ref(daemon)

            def handle(connection: socket.socket) -> None:
                current = reference()
                if current is None:
                    connection.close()
                    return
                current._serve_client(connection, lambda _connection: os.geteuid())

            return handle

        with patch.object(
            _DurableChildDaemon,
            "_validate_durable_topology",
            lambda _daemon, _runtime, _identity: None,
        ), patch.object(
            _DurableChildDaemon,
            "_create_request_handler",
            request_handler,
        ):
            daemon = _DurableChildDaemon(
                PrivateSocketPath(socket_path, durable_root),
                runtime=runtime,
                identity_policy=identity,
            )
            thread = daemon.start_background()
        return daemon, thread, runtime, socket_path

    def test_projection_is_query_only_versioned_and_complete(self) -> None:
        _seed_active_worker(self.store.path)
        before_hash = _database_hash(self.store.path)
        before_events = _event_count(self.store.path)
        snapshot = self.capture()
        self.assertEqual(_database_hash(self.store.path), before_hash)
        self.assertEqual(_event_count(self.store.path), before_events)
        self.assertEqual(snapshot["projection_version"], 1)
        self.assertEqual(snapshot["snapshot_version"]["event_sequence"], 1)
        self.assertRegex(snapshot["snapshot_version"]["digest"], r"[0-9a-f]{64}\Z")
        self.assertEqual(len(snapshot["slots"]), 13)
        worker = snapshot["worker_graph"]["workers"][0]
        self.assertEqual(worker["display_name"], "session-alpha · work-1")
        self.assertEqual(worker["agent_lifecycle"], "persistent")
        self.assertEqual(worker["transport"]["state"], "reserved")
        self.assertEqual(worker["transport"]["adapter"]["status"], "disabled")
        self.assertEqual(worker["completion"]["callback_state"], "blocked")
        self.assertEqual(worker["recovery"]["phase"], "thinking")
        self.assertEqual(snapshot["attention"]["automatic_recovery"]["total"], 1)
        self.assertEqual(snapshot["attention"]["operator_required"]["total"], 0)
        self.assertEqual(snapshot["metrics"]["token_total"]["status"], "unavailable")
        self.assertFalse(snapshot["recent_turns"]["content_included"])
        self.assertEqual(snapshot["recent_activity"]["window_events"], 200)
        self.assertFalse(snapshot["recent_activity"]["content_included"])
        self.assertEqual(snapshot["recent_activity"]["agents"][0]["agent_id"], "tensorhost-1")
        self.assertEqual(
            snapshot["recent_activity"]["items"][0]["event_type"],
            "scheduler.work.assigned",
        )

    def test_projection_exposes_disposable_agent_lifecycle(self) -> None:
        _seed_active_worker(self.store.path, agent_lifecycle="disposable")

        snapshot = self.capture()

        self.assertEqual(
            snapshot["worker_graph"]["workers"][0]["agent_lifecycle"],
            "disposable",
        )

    def test_lookup_identity_is_never_replaced_by_bounded_display_text(self) -> None:
        identity = "gui-work-attempt-1-" + ("a" * 64)
        projection = _CockpitSnapshotProjection()

        self.assertEqual(projection._lookup_identity(identity), identity)
        self.assertNotEqual(projection._text(identity), identity)

    def test_worker_transport_exposes_opencode_generation_not_task_attempt(self) -> None:
        _seed_active_worker(self.store.path)
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            for generation in range(1, 10):
                connection.execute(
                    """INSERT INTO opencode_slot_generations(
                           slot_id, session_id, worker, generation, updated_at
                       ) VALUES ('tensorhost-1', 'persistent-session',
                                 'secure-worker', ?, 't2')""",
                    (generation,),
                )
            connection.execute(
                """INSERT INTO opencode_deliveries(
                       transport_id, request_fingerprint, work_id, pool,
                       completion_registration_id, callback_registration_id,
                       slot_id, session_id, worker, assignment_generation,
                       prompt_message_id, delivery_capability, delivery_state,
                       acknowledgement_id, lease_state, abort_state,
                       created_at, updated_at, finished_at
                   ) VALUES (
                       'transport-1', ?, 'work-1', 'tensorhost',
                       'completion-registration-1', 'transport-callback-1',
                       'tensorhost-1', 'persistent-session', 'secure-worker', 9,
                       'prompt-9', ?, 'accepted', 'ack-9', 'active', 'none',
                       't2', 't2', 't2'
                   )""",
                ("5" * 64, "6" * 64),
            )
            connection.commit()

        worker = self.capture()["worker_graph"]["workers"][0]
        self.assertEqual(worker["attempt"], 1)
        self.assertEqual(worker["transport"]["generation"], 9)

    def test_worker_projects_exact_execution_session_when_transport_slot_differs(self) -> None:
        _seed_active_worker(self.store.path)
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(
                """INSERT INTO opencode_slot_generations(
                       slot_id, session_id, worker, generation, updated_at
                   ) VALUES ('tensorhost-2', 'persistent-session',
                             'secure-worker', 4, 't2')"""
            )
            connection.execute(
                """INSERT INTO opencode_deliveries(
                       transport_id, request_fingerprint, work_id, pool,
                       completion_registration_id, callback_registration_id,
                       slot_id, session_id, isolated_session_id, worker,
                       assignment_generation, prompt_message_id,
                       delivery_capability, delivery_state, acknowledgement_id,
                       lease_state, abort_state, created_at, updated_at, finished_at
                   ) VALUES (
                       'transport-1', ?, 'work-1', 'tensorhost',
                       'completion-registration-1', 'transport-callback-1',
                       'tensorhost-2', 'persistent-session', 'isolated-session',
                       'secure-worker', 4, 'prompt-4', ?, 'accepted', 'ack-4',
                       'active', 'none', 't2', 't2', 't2'
                   )""",
                ("5" * 64, "6" * 64),
            )
            connection.commit()

        worker = self.capture()["worker_graph"]["workers"][0]

        self.assertEqual(worker["slot_id"], "tensorhost-1")
        self.assertEqual(worker["session"], {"status": "available", "ref": "isolated-session"})
        self.assertIn("isolated-session", worker["display_name"])

    def test_retry_without_current_transport_does_not_project_prior_source_or_transport(self) -> None:
        _seed_active_worker(self.store.path)
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(
                "INSERT INTO local_codex_return_routes(return_route_id, thread_id, created_at_us) "
                "VALUES ('route-1', 'codex-thread-attempt-1', 1)"
            )
            connection.execute(
                """UPDATE scheduler_assignments
                   SET state = 'released', release_outcome = 'requeued', released_at = 't2'
                   WHERE id = 'assignment-1'"""
            )
            connection.execute(
                """UPDATE scheduler_slots
                   SET state = 'clear', active_assignment_id = NULL, active_work_id = NULL,
                       owner_id = NULL, attempt = NULL, fence_token = NULL
                   WHERE id = 'tensorhost-1'"""
            )
            connection.execute(
                """UPDATE scheduler_work
                   SET state = 'queued', active_assignment_id = NULL, assigned_at = NULL,
                       queue_order = queue_order + 1
                   WHERE id = 'work-1'"""
            )
            connection.execute(
                """INSERT INTO scheduler_assignments(
                       id, work_id, slot_id, lane, owner_id, attempt, fence_token,
                       state, assigned_at
                   ) VALUES ('assignment-2', 'work-1', 'tensorhost-1', 'tensorhost',
                             'owner-1', 2, 'assignment-fence-2', 'active', 't2')"""
            )
            connection.execute(
                """UPDATE scheduler_work
                   SET state = 'assigned', attempt = 2,
                       active_assignment_id = 'assignment-2', assigned_at = 't2'
                   WHERE id = 'work-1'"""
            )
            connection.execute(
                """UPDATE scheduler_slots
                   SET state = 'assigned', active_assignment_id = 'assignment-2',
                       active_work_id = 'work-1', owner_id = 'owner-1', attempt = 2,
                       fence_token = 'assignment-fence-2'
                   WHERE id = 'tensorhost-1'"""
            )
            connection.commit()

        snapshot = self.capture()
        worker = snapshot["worker_graph"]["workers"][0]
        self.assertEqual(worker["slot_state"], "assigned")
        self.assertEqual(worker["assignment_id"], "assignment-2")
        self.assertEqual(worker["attempt"], 2)
        self.assertIsNone(worker["source_id"])
        self.assertIsNone(worker["transport"]["id"])
        self.assertEqual(worker["transport"]["state"], "unavailable")
        self.assertEqual(worker["transport"]["reason"], "no_durable_transport")
        self.assertNotIn(
            {"from": "tensorhost-1", "to": "transport-1", "kind": "transport"},
            snapshot["worker_graph"]["edges"],
        )

    def test_active_worker_projects_source_from_registered_local_route_before_callback(self) -> None:
        _seed_active_worker(self.store.path)
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("DELETE FROM outbox WHERE callback_id = 'callback-1'")
            connection.execute("DELETE FROM callbacks WHERE id = 'callback-1'")
            connection.execute(
                """INSERT INTO local_codex_return_routes(
                       return_route_id, thread_id, created_at_us
                   ) VALUES ('route-1', 'codex-thread-live', 1)"""
            )
            connection.commit()

        worker = self.capture()["worker_graph"]["workers"][0]
        self.assertEqual(worker["slot_state"], "assigned")
        self.assertEqual(worker["source_id"], "codex-thread-live")
        self.assertEqual(worker["completion"]["callback_state"], "unavailable")

    def test_projection_exposes_exact_source_and_bounded_child_topology(self) -> None:
        _seed_active_worker(self.store.path)
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(
                """INSERT INTO opencode_slot_generations(
                       slot_id, session_id, worker, generation, updated_at
                   ) VALUES ('tensorhost-1', 'slot-session', 'secure-worker', 1, 't2')"""
            )
            connection.execute(
                """INSERT INTO opencode_deliveries(
                       transport_id, request_fingerprint, work_id, pool,
                       completion_registration_id, callback_registration_id,
                       slot_id, session_id, worker, assignment_generation,
                       prompt_message_id, delivery_capability, delivery_state,
                       acknowledgement_id, lease_state, abort_state,
                       created_at, updated_at, finished_at
                   ) VALUES (
                       'transport-1', ?, 'work-1', 'tensorhost',
                       'completion-registration-1', 'transport-callback-1',
                       'tensorhost-1', 'slot-session', 'secure-worker', 1,
                       'prompt-1', ?, 'accepted', 'ack-1', 'active', 'none',
                       't2', 't2', 't2'
                   )""",
                ("5" * 64, "6" * 64),
            )
            connection.execute(
                """INSERT INTO local_codex_return_routes(
                       return_route_id, thread_id, created_at_us
                   ) VALUES ('route-1', 'codex-thread-1', 1)"""
            )
            connection.execute(
                """INSERT INTO completion_child_barriers(
                       transport_id, completion_registration_id, work_id,
                       generation, root_session_id, turn_started_at_ms,
                       child_set_sha256, child_count, state,
                       consolidation_message_id,
                       consolidation_idempotency_key,
                       authorized_assistant_message_id, attention_reason,
                       created_at, updated_at
                   ) VALUES (
                       'transport-1', 'completion-registration-1', 'work-1', 1,
                       'root-session', 1, ?, 2, 'waiting', NULL, NULL, NULL,
                       NULL, 't2', 't2'
                   )""",
                ("7" * 64,),
            )
            connection.execute(
                """INSERT INTO completion_child_sessions(
                       transport_id, child_session_id, parent_session_id,
                       created_at_ms, state, terminal_assistant_message_id,
                       updated_at
                   ) VALUES ('transport-1', 'child-session-1', 'root-session',
                             2, 'waiting', NULL, 't2')"""
            )
            connection.execute(
                """INSERT INTO completion_child_sessions(
                       transport_id, child_session_id, parent_session_id,
                       created_at_ms, state, terminal_assistant_message_id,
                       updated_at
                   ) VALUES ('transport-1', 'child-session-2', 'child-session-1',
                             3, 'waiting', NULL, 't2')"""
            )
            connection.execute(
                """UPDATE completion_child_sessions
                   SET state = 'terminal', terminal_assistant_message_id = 'child-final-1',
                       updated_at = 't3'
                   WHERE child_session_id = 'child-session-1'"""
            )
            connection.execute(
                """UPDATE completion_child_sessions
                   SET state = 'terminal', terminal_assistant_message_id = 'child-final-2',
                       updated_at = 't4'
                   WHERE child_session_id = 'child-session-2'"""
            )
            connection.commit()

        graph = self.capture()["worker_graph"]
        self.assertEqual(graph["workers"][0]["source_id"], "codex-thread-1")
        self.assertEqual(
            graph["subagents"],
            [
                {
                    "id": "child-session-2",
                    "parent_session_id": "child-session-1",
                    "parent_slot_id": "tensorhost-1",
                    "parent_work_id": "work-1",
                    "state": "terminal",
                    "updated_at": "t4",
                },
                {
                    "id": "child-session-1",
                    "parent_session_id": "root-session",
                    "parent_slot_id": "tensorhost-1",
                    "parent_work_id": "work-1",
                    "state": "terminal",
                    "updated_at": "t3",
                }
            ],
        )
        self.assertIn(
            {"from": "tensorhost-1", "to": "child-session-1", "kind": "delegates"},
            graph["edges"],
        )
        self.assertIn(
            {"from": "child-session-1", "to": "child-session-2", "kind": "delegates"},
            graph["edges"],
        )

    def test_terminal_child_expires_after_two_parent_turns_without_contact(self) -> None:
        _seed_active_worker(self.store.path)

        def insert_parent_turn(generation: int) -> None:
            with closing(sqlite3.connect(self.store.path)) as connection:
                connection.execute(
                    """INSERT INTO opencode_slot_generations(
                           slot_id, session_id, worker, generation, updated_at
                       ) VALUES ('tensorhost-1', 'slot-session', 'secure-worker', ?, ?)""",
                    (generation, f"t{generation}"),
                )
                connection.execute(
                    """INSERT INTO opencode_deliveries(
                           transport_id, request_fingerprint, work_id, pool,
                           completion_registration_id, callback_registration_id,
                           slot_id, session_id, worker, assignment_generation,
                           prompt_message_id, delivery_capability, delivery_state,
                           acknowledgement_id, lease_state, abort_state,
                           created_at, updated_at, finished_at
                       ) VALUES (?, ?, ?, 'tensorhost', ?, ?, 'tensorhost-1',
                                 'slot-session', 'secure-worker', ?, ?, ?,
                                 'accepted', ?, 'released', 'none', ?, ?, ?)""",
                    (
                        f"transport-turn-{generation}",
                        f"{generation}" * 64,
                        f"work-turn-{generation}",
                        f"completion-turn-{generation}",
                        f"callback-turn-{generation}",
                        generation,
                        f"prompt-turn-{generation}",
                        format(generation + 5, "x") * 64,
                        f"ack-turn-{generation}",
                        f"t{generation}",
                        f"t{generation}",
                        f"t{generation}",
                    ),
                )
                connection.commit()

        insert_parent_turn(1)
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.execute(
                """INSERT INTO completion_child_barriers(
                       transport_id, completion_registration_id, work_id,
                       generation, root_session_id, turn_started_at_ms,
                       child_set_sha256, child_count, state,
                       consolidation_message_id,
                       consolidation_idempotency_key,
                       authorized_assistant_message_id, attention_reason,
                       created_at, updated_at
                   ) VALUES ('transport-turn-1', 'completion-turn-1',
                             'work-turn-1', 1, 'root-session', 1, ?, 1,
                             'waiting', NULL, NULL, NULL, NULL, 't1', 't1')""",
                ("7" * 64,),
            )
            connection.execute(
                """INSERT INTO completion_child_sessions(
                       transport_id, child_session_id, parent_session_id,
                       created_at_ms, state, terminal_assistant_message_id,
                       updated_at
                   ) VALUES ('transport-turn-1', 'child-session', 'root-session',
                             2, 'waiting', NULL, 't1')"""
            )
            connection.execute(
                """UPDATE completion_child_sessions
                   SET state = 'terminal',
                       terminal_assistant_message_id = 'child-final-1',
                       updated_at = 't2'
                   WHERE transport_id = 'transport-turn-1'"""
            )
            connection.commit()

        self.assertEqual(
            [item["id"] for item in self.capture()["worker_graph"]["subagents"]],
            ["child-session"],
        )
        insert_parent_turn(2)
        self.assertEqual(
            [item["id"] for item in self.capture()["worker_graph"]["subagents"]],
            ["child-session"],
        )
        insert_parent_turn(3)
        self.assertEqual(self.capture()["worker_graph"]["subagents"], [])

        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.execute(
                """INSERT INTO completion_child_barriers(
                       transport_id, completion_registration_id, work_id,
                       generation, root_session_id, turn_started_at_ms,
                       child_set_sha256, child_count, state,
                       consolidation_message_id,
                       consolidation_idempotency_key,
                       authorized_assistant_message_id, attention_reason,
                       created_at, updated_at
                   ) VALUES ('transport-turn-3', 'completion-turn-3',
                             'work-turn-3', 3, 'root-session', 3, ?, 1,
                             'waiting', NULL, NULL, NULL, NULL, 't3', 't3')""",
                ("8" * 64,),
            )
            connection.execute(
                """INSERT INTO completion_child_sessions(
                       transport_id, child_session_id, parent_session_id,
                       created_at_ms, state, terminal_assistant_message_id,
                       updated_at
                   ) VALUES ('transport-turn-3', 'child-session', 'root-session',
                             4, 'waiting', NULL, 't3')"""
            )
            connection.execute(
                """UPDATE completion_child_sessions
                   SET state = 'terminal',
                       terminal_assistant_message_id = 'child-final-3',
                       updated_at = 't4'
                   WHERE transport_id = 'transport-turn-3'"""
            )
            connection.commit()

        renewed = self.capture()["worker_graph"]["subagents"]
        self.assertEqual(len(renewed), 1)
        self.assertEqual(renewed[0]["parent_work_id"], "work-turn-3")
        insert_parent_turn(4)
        self.assertEqual(len(self.capture()["worker_graph"]["subagents"]), 1)
        insert_parent_turn(5)
        self.assertEqual(self.capture()["worker_graph"]["subagents"], [])

    def test_persistent_close_attention_is_globally_visible_without_private_authority(self) -> None:
        scope_hash = "9" * 64
        session_id = "retained-private-session"
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.execute(
                """INSERT INTO opencode_persistent_sessions(
                       scope_hash, pool, worker, title, session_id, state,
                       error, claim_token, claim_started_at, created_at, updated_at
                   ) VALUES (?, 'homelab', 'secure-worker', ?, ?, 'attention',
                             'persistent_delete_uncertain', NULL, NULL, 't1', 't2')""",
                (scope_hash, f"fugue-persistent-{scope_hash}", session_id),
            )
            connection.commit()

        raw = self.capture()
        collection = raw["attention"]["operator_required"]
        items = [
            item for item in collection["items"]
            if item["kind"] == "persistent_session_attention"
        ]
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]["id"].startswith("persistent-"))
        self.assertIsNone(items[0]["work_id"])
        self.assertEqual(items[0]["generation"], 0)
        self.assertEqual(items[0]["state"], "attention")
        self.assertEqual(items[0]["reason"], "persistent_delete_uncertain")
        encoded = json.dumps(items[0], sort_keys=True)
        self.assertNotIn(scope_hash, encoded)
        self.assertNotIn(session_id, encoded)

        normalized = normalize_snapshot(raw)
        normalized_items = [
            item for item in normalized["attention"]["operator_required"]["items"]
            if item["kind"] == "persistent_session_attention"
        ]
        self.assertEqual(normalized_items, items)
        terminal = render_terminal(raw, width=100)
        self.assertIn("persistent-", terminal)
        self.assertNotIn(scope_hash, terminal)
        self.assertNotIn(session_id, terminal)

    def test_transport_failure_is_not_operator_attention_after_owned_recovery(self) -> None:
        _seed_active_worker(self.store.path)
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.execute(
                "UPDATE transport_deliveries SET state = 'prepared' WHERE id = 'transport-1'"
            )
            connection.execute(
                """INSERT INTO transport_attempts(
                       id, transport_id, attempt_number, state, started_at
                   ) VALUES ('attempt-1', 'transport-1', 1, 'sending', 't2')"""
            )
            connection.execute(
                """UPDATE transport_deliveries
                   SET state = 'sending', active_attempt_id = 'attempt-1', updated_at = 't2'
                   WHERE id = 'transport-1'"""
            )
            connection.execute(
                """UPDATE transport_attempts
                   SET state = 'definite_failed', error_code = 'review_agent_invalid',
                       finished_at = 't3'
                   WHERE id = 'attempt-1'"""
            )
            connection.execute(
                """UPDATE transport_deliveries
                   SET state = 'definite_failed', error_code = 'review_agent_invalid',
                       finished_at = 't3', updated_at = 't3'
                   WHERE id = 'transport-1'"""
            )
            connection.commit()

        recovered = self.capture()
        self.assertEqual(recovered["attention"]["operator_required"]["total"], 0)
        self.assertEqual(recovered["attention"]["automatic_recovery"]["total"], 1)

        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.execute(
                """INSERT INTO events(
                       event_id, aggregate_type, aggregate_id, event_type,
                       payload_json, occurred_at
                   ) VALUES ('event-release-attention',
                             'transport_release_attention', 'transport-1',
                             'transport.release_ownership_conflict', ?, 't3')""",
                (
                    json.dumps(
                        {
                            "work_id": "work-1",
                            "generation": 1,
                            "state": "attention",
                            "reason": "scope_release_failed",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
            connection.commit()

        unresolved = self.capture()
        self.assertEqual(unresolved["attention"]["operator_required"]["total"], 1)
        self.assertEqual(
            unresolved["attention"]["operator_required"]["items"][0]["kind"],
            "transport_release_attention",
        )

    def test_migration_012_terminal_proof_bootstraps_013_and_restarts(self) -> None:
        self.downgrade_to_migration_012()
        before = self.capture()
        self.assertEqual(
            before["snapshot_version"]["migration_version"],
            "012_isolated_session_cleanup.sql",
        )
        self.assertEqual(before["attention"]["operator_required"]["total"], 0)
        self.assertEqual(snapshot_is_quiescent(before), (True, "quiescent"))

        self.store.initialize()
        migrated = self.capture()
        self.assertEqual(
            migrated["snapshot_version"]["migration_version"],
            "027_persistent_session_close.sql",
        )
        self.assertEqual(migrated["attention"]["operator_required"]["total"], 0)
        self.assertEqual(snapshot_is_quiescent(migrated), (True, "quiescent"))

        with closing(sqlite3.connect(self.store.path, isolation_level=None)) as restarted:
            restarted.execute("BEGIN")
            after_restart = dict(_CockpitSnapshotProjection().capture(restarted))
            restarted.rollback()
        self.assertEqual(after_restart, migrated)

    def test_historical_migration_010_retained_snapshot_replays_exact_digest(self) -> None:
        self.downgrade_to_migration_010()
        self.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        uri = f"file:{self.store.path}?mode=ro&immutable=1"

        snapshots = []
        for _index in range(2):
            with closing(
                sqlite3.connect(uri, uri=True, isolation_level=None)
            ) as retained:
                retained.execute("BEGIN")
                snapshots.append(
                    dict(_CockpitSnapshotProjection().capture(retained))
                )
                retained.rollback()

        self.assertEqual(snapshots[0], snapshots[1])
        self.assertEqual(
            snapshots[0]["snapshot_version"]["migration_version"],
            "010_local_codex_callbacks.sql",
        )
        self.assertRegex(
            snapshots[0]["snapshot_version"]["digest"], r"[0-9a-f]{64}\Z"
        )
        self.assertEqual(snapshot_is_quiescent(snapshots[0]), (True, "quiescent"))

    def assert_historical_migration_010_rejects(self) -> None:
        self.connection.commit()
        snapshot = self.capture()
        self.assertEqual(
            snapshot["availability"]["errors"],
            ["cockpit_projection_provisional_schema_authority_invalid"],
        )

    def test_historical_migration_010_rejects_altered_checksum(self) -> None:
        self.downgrade_to_migration_010()
        self.connection.execute(
            """UPDATE schema_migrations SET checksum = ?
               WHERE version = '003_scheduler.sql'""",
            ("0" * 64,),
        )
        self.assert_historical_migration_010_rejects()

    def test_historical_migration_010_rejects_missing_migration(self) -> None:
        self.downgrade_to_migration_010()
        self.connection.execute(
            "DELETE FROM schema_migrations WHERE version = '006_completion_recovery.sql'"
        )
        self.assert_historical_migration_010_rejects()

    def test_historical_migration_010_rejects_partial_011_profile(self) -> None:
        self.downgrade_to_migration_010()
        self.connection.execute(
            "ALTER TABLE opencode_deliveries ADD COLUMN isolated_session_id TEXT"
        )
        self.connection.execute(
            """CREATE UNIQUE INDEX opencode_isolated_session_is_single_use
               ON opencode_deliveries(isolated_session_id)
               WHERE isolated_session_id IS NOT NULL"""
        )
        self.connection.execute(
            """CREATE TRIGGER opencode_isolated_session_is_immutable
               BEFORE UPDATE OF isolated_session_id ON opencode_deliveries BEGIN
                   SELECT RAISE(ABORT,
                       'opencode isolated session identity is immutable');
               END"""
        )
        self.connection.execute(
            """INSERT INTO schema_migrations(version, checksum, applied_at)
               VALUES ('011_isolated_review_sessions.sql', ?, 't0')""",
            (
                "f02d4f94716c04267d1bec8fdc29159dbf614384a039f531385f4c6483d9a546",
            ),
        )
        self.assert_historical_migration_010_rejects()

    def test_historical_migration_010_rejects_provisional_schema(self) -> None:
        self.downgrade_to_migration_010()
        self.connection.execute(
            "CREATE TABLE opencode_provisional_sessions(transport_id TEXT)"
        )
        self.assert_historical_migration_010_rejects()

    def test_migration_012_rejects_unowned_provisional_table(self) -> None:
        self.downgrade_to_migration_012()
        self.connection.execute(
            "CREATE TABLE opencode_provisional_sessions(transport_id TEXT)"
        )
        self.connection.commit()
        snapshot = self.capture()
        self.assertEqual(snapshot["availability"]["status"], "unavailable")
        self.assertEqual(
            snapshot["availability"]["errors"],
            ["cockpit_projection_provisional_schema_authority_invalid"],
        )

    def test_migration_012_rejects_lineage_checksum_drift(self) -> None:
        self.downgrade_to_migration_012()
        self.connection.execute(
            """UPDATE schema_migrations SET checksum = ?
               WHERE version = '012_isolated_session_cleanup.sql'""",
            ("0" * 64,),
        )
        self.connection.commit()
        snapshot = self.capture()
        self.assertEqual(
            snapshot["availability"]["errors"],
            ["cockpit_projection_provisional_schema_authority_invalid"],
        )

    def test_migration_013_rejects_missing_provisional_schema(self) -> None:
        self.connection.execute(
            "DROP TRIGGER opencode_provisional_binding_is_immutable"
        )
        self.connection.execute("DROP TABLE opencode_provisional_sessions")
        self.connection.commit()
        snapshot = self.capture()
        self.assertEqual(
            snapshot["availability"]["errors"],
            ["cockpit_projection_provisional_schema_authority_invalid"],
        )

    def test_migration_013_rejects_wrong_provisional_schema(self) -> None:
        self.connection.execute(
            "DROP TRIGGER opencode_provisional_binding_is_immutable"
        )
        self.connection.execute("DROP TABLE opencode_provisional_sessions")
        self.connection.execute(
            """CREATE TABLE opencode_provisional_sessions(
                   transport_id TEXT PRIMARY KEY)"""
        )
        self.connection.commit()
        snapshot = self.capture()
        self.assertEqual(
            snapshot["availability"]["errors"],
            ["cockpit_projection_provisional_schema_authority_invalid"],
        )

    def test_migration_013_rejects_checksum_authority_drift(self) -> None:
        self.connection.execute(
            """UPDATE schema_migrations SET checksum = ?
               WHERE version = '013_provisional_review_sessions.sql'""",
            ("0" * 64,),
        )
        self.connection.commit()
        snapshot = self.capture()
        self.assertEqual(
            snapshot["availability"]["errors"],
            ["cockpit_projection_provisional_schema_authority_invalid"],
        )

    def test_migration_013_rejects_earlier_checksum_drift(self) -> None:
        self.connection.execute(
            """UPDATE schema_migrations SET checksum = ?
               WHERE version = '004_scheduler_authority.sql'""",
            ("0" * 64,),
        )
        self.connection.commit()
        snapshot = self.capture()
        self.assertEqual(
            snapshot["availability"]["errors"],
            ["cockpit_projection_provisional_schema_authority_invalid"],
        )

    def test_migration_013_rejects_missing_earlier_migration(self) -> None:
        self.connection.execute(
            "DELETE FROM schema_migrations WHERE version = '007_disabled_callback_recovery.sql'"
        )
        self.connection.commit()
        snapshot = self.capture()
        self.assertEqual(
            snapshot["availability"]["errors"],
            ["cockpit_projection_provisional_schema_authority_invalid"],
        )

    def test_migration_013_rejects_unknown_extra_migration(self) -> None:
        self.connection.execute(
            """INSERT INTO schema_migrations(version, checksum, applied_at)
               VALUES ('014_unknown.sql', ?, 't0')""",
            ("f" * 64,),
        )
        self.connection.commit()
        snapshot = self.capture()
        self.assertEqual(
            snapshot["availability"]["errors"],
            ["cockpit_projection_provisional_schema_authority_invalid"],
        )

    def test_controller_global_backend_attention_has_no_invented_work(self) -> None:
        class AuthorizedTransport:
            def _assert_authority(self, _capability: object) -> None:
                return None

        class ReadOnlyStore:
            def __init__(self, connection: sqlite3.Connection) -> None:
                self.connection = connection

            @contextmanager
            def _daemon_read_transaction(self, _authority: object):
                self.connection.execute("BEGIN")
                try:
                    yield self.connection
                finally:
                    self.connection.rollback()

        controller = object.__new__(_RigController)
        controller.store = ReadOnlyStore(self.connection)  # type: ignore[assignment]
        controller._transport = AuthorizedTransport()  # type: ignore[assignment]
        controller._authority = object()
        controller._topology = None
        controller._backend_status = lambda: {
            "configured": True,
            "healthy": False,
            "reason": "sse_retries_exhausted",
        }
        backend_item = {
            "kind": "backend_attention",
            "id": "opencode-completion-monitor",
            "scope": "controller",
            "state": "attention",
            "reason": "sse_retries_exhausted",
        }
        work_item = {
            "kind": "transport_attention",
            "id": "transport-1",
            "work_id": "work-1",
            "generation": 1,
            "state": "delivery_unknown",
            "reason": "request_deadline_exceeded",
        }
        base = self.capture()
        real_finalize = _CockpitSnapshotProjection._finalize
        cases = (
            (
                "exact",
                {
                    "status": "available",
                    "items": [work_item],
                    "total": 1,
                    "total_status": "exact",
                    "lower_bound": 1,
                    "truncated": False,
                },
                {"total": 2, "total_status": "exact", "lower_bound": 2},
                {"total": 2, "total_status": "exact", "lower_bound": 2},
                "available",
                "operator required: 2",
            ),
            (
                "capped",
                {
                    "status": "available",
                    "items": [work_item],
                    "total": None,
                    "total_status": "capped",
                    "lower_bound": 8,
                    "truncated": True,
                },
                {"total": None, "total_status": "capped", "lower_bound": 9},
                {"total": None, "total_status": "capped", "lower_bound": 2},
                "unavailable",
                "operator required: ≥2 · truncated",
            ),
            (
                "unknown_unavailable",
                {
                    "status": "unavailable",
                    "items": [],
                    "total": None,
                    "total_status": "unknown",
                    "lower_bound": 0,
                    "truncated": False,
                },
                {"total": None, "total_status": "unknown", "lower_bound": 1},
                {"total": None, "total_status": "unknown", "lower_bound": 1},
                "unavailable",
                "operator required: unknown",
            ),
        )
        for (
            label,
            source,
            expected_raw_counts,
            expected_normalized_counts,
            expected_status,
            rendered_total,
        ) in cases:
            with self.subTest(label=label):
                source_snapshot = copy.deepcopy(base)
                source_snapshot["attention"]["operator_required"] = source

                class ControlledProjection:
                    def __init__(
                        self,
                        *,
                        topology: object = None,
                        callback_adapter_configured: bool = False,
                    ) -> None:
                        del topology, callback_adapter_configured

                    def capture(self, _connection: sqlite3.Connection) -> object:
                        return source_snapshot

                    @staticmethod
                    def _finalize(projection: object) -> object:
                        return real_finalize(projection)  # type: ignore[arg-type]

                with patch(
                    "oc_rig.daemon.controller._CockpitSnapshotProjection",
                    ControlledProjection,
                ):
                    raw = controller.cockpit_snapshot(object())
                collection = raw["attention"]["operator_required"]
                self.assertEqual(collection["status"], source["status"])
                self.assertEqual(collection["truncated"], source["truncated"])
                for key, value in expected_raw_counts.items():
                    self.assertEqual(collection[key], value)
                self.assertEqual(collection["items"][-1], backend_item)

                normalized = normalize_snapshot(raw)
                normalized_collection = normalized["attention"]["operator_required"]
                self.assertEqual(normalized["availability"]["status"], "degraded")
                self.assertEqual(
                    normalized["availability"]["errors"],
                    ["sse_retries_exhausted"],
                )
                self.assertEqual(normalized_collection["status"], expected_status)
                for key, value in expected_normalized_counts.items():
                    self.assertEqual(normalized_collection[key], value)
                self.assertIn(backend_item, normalized_collection["items"])

                terminal = render_terminal(raw, width=100)
                self.assertIn(rendered_total, terminal)
                self.assertIn(
                    "controller · backend_attention · attention · "
                    "sse_retries_exhausted",
                    terminal,
                )
                self.assertNotIn("None · backend_attention", terminal)

    def test_callback_attention_is_delivery_not_operator_attention(self) -> None:
        raw = self.capture()
        callback_item = {
            "kind": "callback_attention",
            "id": "callback-1",
            "work_id": "work-1",
            "generation": 1,
            "state": "attention",
            "reason": "codex_nonzero_exit_7",
        }
        backend_item = {
            "kind": "backend_attention",
            "id": "backend-1",
            "scope": "controller",
            "state": "attention",
            "reason": "backend_degraded",
        }
        raw["attention"]["operator_required"] = {
            "status": "available",
            "items": [callback_item, backend_item],
            "total": 2,
            "total_status": "exact",
            "lower_bound": 2,
            "truncated": False,
        }

        normalized = normalize_snapshot(raw)

        self.assertEqual(normalized["attention"]["delivery_attention"]["total"], 1)
        self.assertEqual(
            normalized["attention"]["delivery_attention"]["items"],
            [callback_item],
        )
        self.assertEqual(normalized["attention"]["operator_required"]["total"], 1)
        self.assertEqual(
            normalized["attention"]["operator_required"]["items"],
            [backend_item],
        )

    def test_callback_partition_fails_closed_when_source_is_saturated(self) -> None:
        raw = self.capture()
        callbacks = [
            {
                "kind": "callback_attention",
                "id": f"callback-{index:02d}",
                "work_id": f"work-{index:02d}",
                "generation": 1,
                "state": "attention",
                "reason": "codex_nonzero_exit_1",
            }
            for index in range(64)
        ]
        backend_item = {
            "kind": "backend_attention",
            "id": "backend-1",
            "scope": "controller",
            "state": "attention",
            "reason": "backend_degraded",
        }
        raw["attention"]["operator_required"] = {
            "status": "available",
            "items": [*callbacks, backend_item],
            "total": None,
            "total_status": "capped",
            "lower_bound": 66,
            "truncated": True,
        }

        normalized = normalize_snapshot(raw)

        delivery = normalized["attention"]["delivery_attention"]
        operator = normalized["attention"]["operator_required"]
        self.assertEqual(delivery["lower_bound"], 64)
        self.assertEqual(delivery["total_status"], "capped")
        self.assertEqual(operator["status"], "unavailable")
        self.assertEqual(operator["lower_bound"], 1)
        self.assertEqual(operator["items"], [backend_item])

        coloured = render_terminal(raw, width=100, ansi=True)
        self.assertIn("operator required: ≥1 · truncated", coloured)
        self.assertIn("\x1b[31m⚠\x1b[0m ATTENTION", coloured)

    def test_callback_partition_rejects_inconsistent_exact_metadata(self) -> None:
        raw = self.capture()
        raw["attention"]["operator_required"] = {
            "status": "available",
            "items": [
                {
                    "kind": "callback_attention",
                    "id": "callback-1",
                    "work_id": "work-1",
                    "generation": 1,
                    "state": "attention",
                    "reason": "codex_nonzero_exit_1",
                }
            ],
            "total": 2,
            "total_status": "exact",
            "lower_bound": 2,
            "truncated": False,
        }

        normalized = normalize_snapshot(raw)

        self.assertEqual(
            normalized["attention"]["operator_required"]["status"],
            "unavailable",
        )
        self.assertIsNone(
            normalized["attention"]["operator_required"]["total"]
        )
        coloured = render_terminal(raw, width=100, ansi=True)
        self.assertIn("operator required: unknown", coloured)
        self.assertIn("\x1b[31m⚠\x1b[0m ATTENTION", coloured)

    def test_configured_clear_slots_project_exact_idle_sessions(self) -> None:
        snapshot = self.capture(
            _CockpitSnapshotProjection(topology=_configured_topology())
        )
        workers = snapshot["worker_graph"]["workers"]
        self.assertEqual(
            [worker["session"]["ref"] for worker in workers],
            [f"session-{index}" for index in range(1, 14)],
        )
        self.assertEqual(
            [worker["display_name"] for worker in workers],
            [
                f"session-{index} · {worker['slot_id']}"
                for index, worker in enumerate(workers, start=1)
            ],
        )
        for worker in workers:
            self.assertIsNone(worker["agent_lifecycle"])
            self.assertEqual(worker["session"]["status"], "available")
            self.assertEqual(worker["transport"]["state"], "idle")
            self.assertEqual(
                worker["completion"]["registration_state"], "not-applicable"
            )
            self.assertEqual(worker["recovery"]["phase"], "not-applicable")

    def test_compact_labels_preserve_quiescence_projection_contract(self) -> None:
        snapshot = self.capture(
            _CockpitSnapshotProjection(topology=_configured_topology())
        )
        durable_before = copy.deepcopy(snapshot)
        normalized_before = normalize_snapshot(snapshot)

        compact = render_terminal(snapshot, width=100)

        self.assertEqual(snapshot, durable_before)
        self.assertEqual(normalize_snapshot(snapshot), normalized_before)
        self.assertEqual(snapshot_is_quiescent(snapshot), (True, "quiescent"))
        self.assertEqual(
            snapshot["snapshot_version"]["digest"],
            "d3c303f4cc9e91c099ecaf3b398f5365dcfa022777a26db53907c52a4d17c4d1",
        )
        self.assertEqual(
            normalized_before["worker_graph"]["workers"][0]["display_name"],
            "session-1 · tensorhost-1",
        )
        self.assertIn("WORKER GRAPH\n  (no active workers)", compact)
        self.assertNotIn("○ tensorhost-1", compact)
        self.assertNotIn("session-1", compact)

    def test_historical_cutover_projection_preserves_pre_lifecycle_digest(self) -> None:
        snapshot = self.capture(
            _CockpitSnapshotProjection(
                topology=_configured_topology(),
                include_agent_lifecycle=False,
            )
        )

        self.assertNotIn(
            "agent_lifecycle", snapshot["worker_graph"]["workers"][0]
        )
        self.assertEqual(
            snapshot["snapshot_version"]["digest"],
            "2dadda46c87613ecd8d6b9b3c22112d4314dbc7c950c49b35f5eed0a8c387c84",
        )

    def test_authenticated_socket_refresh_bypasses_controller_and_journal(self) -> None:
        class RecordingController:
            def __init__(self) -> None:
                self.calls = 0

            def execute(self, _operation: str, _params: object) -> dict[str, object]:
                self.calls += 1
                raise AssertionError("cockpit reached controller mutation dispatch")

        controller = RecordingController()
        provider_calls = 0

        def read_snapshot() -> dict[str, object]:
            nonlocal provider_calls
            provider_calls += 1
            return self.capture()

        socket_path = self.root / "socket" / "rig.sock"
        daemon = RigDaemon(
            PrivateSocketPath(socket_path, self.root),
            controller=controller,
            read_snapshot_provider=read_snapshot,
        )
        thread = daemon.start_background()
        before_hash = _database_hash(self.store.path)
        before_events = _event_count(self.store.path)
        try:
            snapshot = CockpitClient(
                socket_path,
                approved_root=self.root,
                identity_profile="local-user",
            ).refresh()
            self.assertEqual(snapshot["projection_version"], 1)
            self.assertEqual(provider_calls, 1)
            self.assertEqual(controller.calls, 0)
            self.assertEqual(len(daemon._idempotency), 0)
            self.assertEqual(_database_hash(self.store.path), before_hash)
            self.assertEqual(_event_count(self.store.path), before_events)
            with self.assertRaises(RigClientError) as caught:
                RigClient(
                    socket_path,
                    approved_root=self.root,
                    identity_profile="local-user",
                ).call(
                    "cockpit.snapshot.v1", {"unexpected": True}
                )
            self.assertEqual(caught.exception.code, "invalid_params")
            self.assertEqual(provider_calls, 1)
        finally:
            daemon.shutdown()
            thread.join(timeout=2)

    def test_concurrent_commits_produce_one_consistent_snapshot_version(self) -> None:
        finished = threading.Event()
        failures: list[BaseException] = []

        def writer() -> None:
            try:
                with closing(sqlite3.connect(self.store.path, timeout=5)) as connection:
                    for index in range(1, 33):
                        connection.execute("BEGIN IMMEDIATE")
                        row = connection.execute(
                            "SELECT current_value FROM scheduler_queue_clock WHERE singleton = 1"
                        ).fetchone()
                        assert row is not None
                        queue_order = int(row[0]) + 1
                        connection.execute(
                            "UPDATE scheduler_queue_clock SET current_value = ? WHERE singleton = 1",
                            (queue_order,),
                        )
                        connection.execute(
                            """INSERT INTO scheduler_work(
                                   id, idempotency_key, lane, state, enqueued_at,
                                   queue_order
                               ) VALUES (?, ?, 'control', 'queued', 't', ?)""",
                            (f"work-{index}", f"idem-{index}", queue_order),
                        )
                        connection.execute(
                            """INSERT INTO events(
                                   event_id, aggregate_type, aggregate_id,
                                   event_type, payload_json, occurred_at
                               ) VALUES (?, 'scheduler_work', ?,
                                         'scheduler.work.enqueued', '{}', 't')""",
                            (f"event-{index}", f"work-{index}"),
                        )
                        connection.commit()
            except BaseException as error:
                failures.append(error)
            finally:
                finished.set()

        thread = threading.Thread(target=writer)
        thread.start()
        projection = _CockpitSnapshotProjection()
        observations = 0
        while not finished.is_set():
            snapshot = self.capture(projection)
            event_sequence = snapshot["snapshot_version"]["event_sequence"]
            if snapshot["queue"]["total_status"] == "exact":
                self.assertEqual(event_sequence, snapshot["queue"]["total"])
            else:
                self.assertGreaterEqual(event_sequence, snapshot["queue"]["lower_bound"])
            observations += 1
        thread.join(timeout=5)
        self.assertFalse(failures)
        final = self.capture(projection)
        self.assertEqual(final["snapshot_version"]["event_sequence"], 32)
        self.assertIsNone(final["queue"]["total"])
        self.assertEqual(final["queue"]["total_status"], "capped")
        self.assertEqual(len(final["queue"]["items"]), 8)
        self.assertTrue(final["queue"]["truncated"])
        self.assertLess(
            len(json.dumps({"snapshot": final}, ensure_ascii=False).encode("utf-8")),
            64 * 1024,
        )
        self.assertGreater(observations, 0)

    def test_public_cockpit_surface_has_no_mutation_or_polling_methods(self) -> None:
        public_methods = {
            name
            for name in dir(CockpitClient)
            if not name.startswith("_") and callable(getattr(CockpitClient, name))
        }
        self.assertEqual(public_methods, {"refresh"})
        forbidden = {"dispatch", "cancel", "repair", "nudge", "poll", "watch"}
        self.assertTrue(public_methods.isdisjoint(forbidden))

    def test_projection_has_no_cold_path_or_symlink_capture_api(self) -> None:
        self.assertFalse(hasattr(snapshot_module, "CockpitSnapshotProjection"))
        with self.assertRaises(TypeError):
            _CockpitSnapshotProjection(self.store.path)  # type: ignore[call-arg]
        with self.assertRaisesRegex(TypeError, "validated OpenCodeTopology required"):
            _CockpitSnapshotProjection(topology=object())  # type: ignore[arg-type]
        with self.assertRaisesRegex(TypeError, "configured state must be boolean"):
            _CockpitSnapshotProjection(callback_adapter_configured=1)  # type: ignore[arg-type]
        with self.assertRaises(RuntimeError):
            _CockpitSnapshotProjection().capture(self.store.path)  # type: ignore[arg-type]
        alias = self.root / "database-alias"
        alias.symlink_to(self.store.path)
        with self.assertRaises(RuntimeError):
            _CockpitSnapshotProjection().capture(alias)  # type: ignore[arg-type]
        self.assertFalse(hasattr(_CockpitSnapshotProjection(), "database"))

    def test_callback_adapter_projection_uses_daemon_runtime_configuration(self) -> None:
        _seed_active_worker(self.store.path)
        disabled = self.capture()
        configured = self.capture(
            _CockpitSnapshotProjection(callback_adapter_configured=True)
        )
        disabled_completion = disabled["worker_graph"]["workers"][0]["completion"]
        configured_completion = configured["worker_graph"]["workers"][0]["completion"]
        self.assertEqual(
            disabled_completion["callback_adapter"],
            {"status": "disabled", "reason": "callback_adapter_disabled"},
        )
        self.assertEqual(configured_completion["callback_adapter"]["status"], "available")
        self.assertEqual(
            configured_completion["callback_adapter"]["reason"],
            "awaiting_exact_release",
        )
        self.assertEqual(disabled["attention"]["operator_required"]["total"], 0)

        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.execute(
                """UPDATE callbacks SET attention_reason = 'local_codex_route_missing'
                   WHERE id = 'callback-1'"""
            )
            connection.execute(
                """UPDATE outbox SET disabled_reason = 'local_codex_route_missing'
                   WHERE id = 'outbox-1'"""
            )
            connection.commit()
        missing = self.capture(
            _CockpitSnapshotProjection(callback_adapter_configured=True)
        )
        self.assertEqual(
            missing["worker_graph"]["workers"][0]["completion"]["callback_adapter"],
            {"status": "available", "reason": "local_codex_route_missing"},
        )
        self.assertEqual(missing["attention"]["operator_required"]["total"], 1)

    def test_two_hundred_thousand_rows_exhaust_bounded_budget_without_partial_health(self) -> None:
        rows = (
            (
                f"bulk-work-{index}",
                f"bulk-idem-{index}",
                index,
            )
            for index in range(200_000)
        )
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.executemany(
                """INSERT INTO scheduler_work(
                       id, idempotency_key, lane, state, enqueued_at, queue_order
                   ) VALUES (?, ?, 'control', 'queued', 't', ?)""",
                rows,
            )
            connection.commit()
        started = time.monotonic()
        snapshot = self.capture(
            _CockpitSnapshotProjection(deadline_seconds=0.5, max_vm_steps=5_000)
        )
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.5)
        self.assertEqual(snapshot["availability"]["status"], "unavailable")
        self.assertIn(
            "cockpit_projection_budget_exhausted",
            snapshot["availability"]["errors"],
        )
        self.assertEqual(snapshot["queue"]["status"], "unavailable")
        self.assertEqual(snapshot["queue"]["total_status"], "unknown")
        self.assertTrue(
            all(slot["state"] == "unavailable" for slot in snapshot["slots"])
        )
        self.assertEqual(self.connection.execute("SELECT 1").fetchone(), (1,))

    def test_authenticated_refresh_after_real_mutation_is_byte_identical(self) -> None:
        daemon, thread, runtime, socket_path = self._start_durable_daemon("durable")
        durable_root = socket_path.parents[1]
        try:
            client = RigClient(
                socket_path,
                approved_root=durable_root,
                service_uid=os.geteuid(),
                client_gid=os.getegid(),
            )
            result = client.call(
                "operation.create.v1",
                {"operation_id": "cockpit-baseline-owner", "kind": "dispatch"},
                request_id="cockpit-baseline-request",
                idempotency_id="cockpit-baseline-mutation",
            )
            self.assertEqual(result["operation_id"], "cockpit-baseline-owner")
            wal_path = runtime.root / f"{runtime.database.name}-wal"
            self.assertTrue(wal_path.exists())
            self.assertEqual(wal_path.stat().st_size, 0)
            before = _runtime_manifest(durable_root)
            snapshot = CockpitClient(
                socket_path,
                approved_root=durable_root,
                service_uid=os.geteuid(),
                client_gid=os.getegid(),
            ).refresh()
            after = _runtime_manifest(durable_root)
            self.assertEqual(after, before)
            self.assertEqual(snapshot["snapshot_version"]["event_sequence"], 1)
            self.assertEqual(snapshot["availability"]["status"], "available")
        finally:
            daemon.shutdown()
            thread.join(timeout=2)

    def test_checkpoint_failure_is_explicit_and_idempotent_retry_recovers(self) -> None:
        daemon, thread, _runtime, socket_path = self._start_durable_daemon("cf")
        durable_root = socket_path.parents[1]
        client = RigClient(
            socket_path,
            approved_root=durable_root,
            service_uid=os.geteuid(),
            client_gid=os.getegid(),
        )
        try:
            with patch.object(
                RigStore,
                "_checkpoint_wal",
                side_effect=StoreQuiescenceError("injected failure"),
            ):
                with self.assertRaises(RigClientError) as caught:
                    client.call(
                        "operation.create.v1",
                        {"operation_id": "committed-owner", "kind": "dispatch"},
                        request_id="checkpoint-failure-request",
                        idempotency_id="checkpoint-failure-mutation",
                    )
            self.assertEqual(caught.exception.code, "store_not_quiescent")
            retry = client.call(
                "operation.create.v1",
                {"operation_id": "committed-owner", "kind": "dispatch"},
                request_id="checkpoint-retry-request",
                idempotency_id="checkpoint-failure-mutation",
            )
            self.assertEqual(retry["operation_id"], "committed-owner")
        finally:
            daemon.shutdown()
            thread.join(timeout=2)

    def test_durable_cockpit_watch_wakes_on_committed_controller_event(self) -> None:
        daemon, thread, _runtime, socket_path = self._start_durable_daemon("watch")
        durable_root = socket_path.parents[1]
        client = RigClient(
            socket_path,
            approved_root=durable_root,
            service_uid=os.geteuid(),
            client_gid=os.getegid(),
        )
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                waiting = executor.submit(
                    client.call,
                    "cockpit.watch.v1",
                    {"after_event_sequence": 0},
                )
                client.call(
                    "operation.create.v1",
                    {"operation_id": "watch-owner", "kind": "dispatch"},
                    idempotency_id="watch-mutation",
                )
                snapshot = waiting.result(timeout=2)["snapshot"]
            self.assertEqual(snapshot["snapshot_version"]["event_sequence"], 1)
        finally:
            daemon.shutdown()
            thread.join(timeout=2)

    def test_concurrent_mutation_clients_leave_quiescent_runtime(self) -> None:
        daemon, thread, runtime, socket_path = self._start_durable_daemon("cc")
        durable_root = socket_path.parents[1]

        def mutate(index: int) -> object:
            return RigClient(
                socket_path,
                approved_root=durable_root,
                service_uid=os.geteuid(),
                client_gid=os.getegid(),
            ).call(
                "operation.create.v1",
                {"operation_id": f"concurrent-owner-{index}", "kind": "dispatch"},
                request_id=f"concurrent-request-{index}",
                idempotency_id=f"concurrent-mutation-{index}",
            )

        try:
            with ThreadPoolExecutor(max_workers=8) as executor:
                results = list(executor.map(mutate, range(16)))
            self.assertEqual(len(results), 16)
            self.assertEqual(
                (runtime.root / f"{runtime.database.name}-wal").stat().st_size,
                0,
            )
            before = _runtime_manifest(durable_root)
            CockpitClient(
                socket_path,
                approved_root=durable_root,
                service_uid=os.geteuid(),
                client_gid=os.getegid(),
            ).refresh()
            self.assertEqual(_runtime_manifest(durable_root), before)
        finally:
            daemon.shutdown()
            thread.join(timeout=2)

    def test_connection_bound_snapshot_waits_through_mutation_checkpoint(self) -> None:
        daemon, thread, _runtime, socket_path = self._start_durable_daemon("ordering")
        resources = getattr(daemon, "_RigDaemonBase__resources")
        durable_execute = resources.controller
        read_snapshot = resources.read_snapshot
        assert callable(durable_execute)
        assert callable(read_snapshot)
        checkpoint_entered = threading.Event()
        release_checkpoint = threading.Event()
        snapshot_started = threading.Event()
        snapshot_done = threading.Event()
        failures: list[BaseException] = []
        captured: list[dict[str, object]] = []
        original_checkpoint = RigStore._checkpoint_wal

        def blocking_checkpoint(
            store: RigStore, connection: sqlite3.Connection
        ) -> None:
            original_checkpoint(store, connection)
            checkpoint_entered.set()
            if not release_checkpoint.wait(timeout=2):
                raise AssertionError("checkpoint ordering test timed out")

        def mutate() -> None:
            try:
                durable_execute(
                    "ordering-mutation",
                    "0" * 64,
                    "operation.create.v1",
                    {"operation_id": "ordering-owner", "kind": "dispatch"},
                )
            except BaseException as error:
                failures.append(error)

        def snapshot() -> None:
            snapshot_started.set()
            try:
                captured.append(dict(read_snapshot()))
            except BaseException as error:
                failures.append(error)
            finally:
                snapshot_done.set()

        mutation_thread = threading.Thread(target=mutate)
        snapshot_thread = threading.Thread(target=snapshot)
        try:
            with patch.object(RigStore, "_checkpoint_wal", blocking_checkpoint):
                mutation_thread.start()
                self.assertTrue(checkpoint_entered.wait(timeout=2))
                snapshot_thread.start()
                self.assertTrue(snapshot_started.wait(timeout=2))
                self.assertFalse(snapshot_done.wait(timeout=0.05))
                release_checkpoint.set()
                mutation_thread.join(timeout=2)
                snapshot_thread.join(timeout=2)
            self.assertFalse(mutation_thread.is_alive())
            self.assertFalse(snapshot_thread.is_alive())
            self.assertFalse(failures)
            self.assertEqual(
                captured[0]["snapshot_version"]["event_sequence"], 1
            )
        finally:
            release_checkpoint.set()
            daemon.shutdown()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
