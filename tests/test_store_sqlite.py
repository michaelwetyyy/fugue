from __future__ import annotations

import hashlib
import gc
import json
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import weakref
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from importlib import resources
from pathlib import Path
from unittest.mock import patch

from oc_rig.domain import OperationKind, OperationState, SettingKey, WorkKind
from oc_rig.scheduler.service import _Scheduler
from oc_rig.store import (
    CredentialDataError,
    DaemonAuthorityError,
    IdempotencyConflict,
    PrivateRuntimeDirectory,
    ReadOnlySnapshot,
    RigStore,
    StoreQuiescenceError,
)
from oc_rig.store import database as store_database
from oc_rig.store.database import _split_sql
from oc_rig.store.runtime import RuntimeContainmentError


_MILESTONE_SEVEN_MIGRATION = "006_completion_recovery.sql"
_MILESTONE_SEVEN_CHECKSUM = (
    "d570c78241c52fa1b72e5519381103e263e37f90b746dfc20015bc3846efe02c"
)
_COMMIT_35C3C625_MIGRATION = "008_opencode_delivery.sql"
_COMMIT_35C3C625_CHECKSUM = (
    "1599d092ec8cfaa95b325a4647117c9160ad9c94c256c6372e8f511dc54ff060"
)


def _initialize_milestone_seven(store: RigStore) -> None:
    """Apply the exact through-4075c64 migration set to one private store."""
    names = (
        "001_initial.sql",
        "002_queue_and_fences.sql",
        "003_scheduler.sql",
        "004_scheduler_authority.sql",
        "005_transport.sql",
        _MILESTONE_SEVEN_MIGRATION,
    )
    migration_root = resources.files("oc_rig.store.migrations")
    with closing(sqlite3.connect(store.path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """CREATE TABLE schema_migrations (
                   version TEXT PRIMARY KEY,
                   checksum TEXT NOT NULL,
                   applied_at TEXT NOT NULL
               ) STRICT"""
        )
        connection.commit()
        for name in names:
            script = migration_root.joinpath(name).read_text(encoding="utf-8")
            checksum = hashlib.sha256(script.encode("utf-8")).hexdigest()
            if name == _MILESTONE_SEVEN_MIGRATION:
                if checksum != _MILESTONE_SEVEN_CHECKSUM:
                    raise AssertionError("migration 006 no longer matches commit 4075c64")
            connection.execute("BEGIN IMMEDIATE")
            try:
                for statement in _split_sql(script):
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO schema_migrations VALUES (?, ?, 'legacy')",
                    (name, checksum),
                )
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()


def _initialize_commit_35c3c625(store: RigStore) -> None:
    """Apply the exact accepted migration set at commit 35c3c625."""

    names = (
        "001_initial.sql",
        "002_queue_and_fences.sql",
        "003_scheduler.sql",
        "004_scheduler_authority.sql",
        "005_transport.sql",
        "006_completion_recovery.sql",
        "007_disabled_callback_recovery.sql",
        _COMMIT_35C3C625_MIGRATION,
    )
    migration_root = resources.files("oc_rig.store.migrations")
    with closing(sqlite3.connect(store.path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """CREATE TABLE schema_migrations (
                   version TEXT PRIMARY KEY,
                   checksum TEXT NOT NULL,
                   applied_at TEXT NOT NULL
               ) STRICT"""
        )
        connection.commit()
        for name in names:
            script = migration_root.joinpath(name).read_text(encoding="utf-8")
            checksum = hashlib.sha256(script.encode("utf-8")).hexdigest()
            if (
                name == _COMMIT_35C3C625_MIGRATION
                and checksum != _COMMIT_35C3C625_CHECKSUM
            ):
                raise AssertionError("migration 008 no longer matches commit 35c3c625")
            connection.execute("BEGIN IMMEDIATE")
            try:
                for statement in _split_sql(script):
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO schema_migrations VALUES (?, ?, '35c3c625')",
                    (name, checksum),
                )
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()


def _insert_milestone_seven_completion(
    connection: sqlite3.Connection,
    label: str,
    callback_state: str,
) -> None:
    """Insert one internally consistent milestone-seven completion join."""
    owner = f"owner-{label}"
    claim = f"claim-{label}"
    work = f"work-{label}"
    decision = f"decision-{label}"
    assignment = f"assignment-{label}"
    transport = f"transport-{label}"
    registration = f"registration-{label}"
    route = f"route-{label}"
    transport_callback = f"transport-callback-{label}"
    completion = f"completion-{label}"
    callback = f"callback-{label}"
    delivery_key = f"delivery-{label}"
    connection.execute(
        """INSERT INTO operations(id, kind, state, created_at, updated_at)
           VALUES (?, 'dispatch', 'pending', 'legacy', 'legacy')""",
        (owner,),
    )
    connection.execute(
        """INSERT INTO scope_claims(
               id, scope_key, owner_operation_id, state, claimed_at,
               attempt, fence_token, idempotency_key
           ) VALUES (?, ?, ?, 'active', 'legacy', 1, ?, ?)""",
        (claim, f"scope-{label}", owner, f"claim-fence-{label}", f"claim-idem-{label}"),
    )
    connection.execute(
        """INSERT INTO scheduler_work(
               id, idempotency_key, lane, state, scope_key, scope_owner_id,
               policy_decision_id, policy_allowed, admission_idempotency_key,
               enqueued_at
           ) VALUES (?, ?, 'control', 'queued', ?, ?, ?, 1, ?, 'legacy')""",
        (
            work,
            f"work-idem-{label}",
            f"scope-{label}",
            owner,
            decision,
            f"admission-idem-{label}",
        ),
    )
    connection.execute(
        """INSERT INTO scheduler_admission_decisions(
               id, work_id, policy_version, policy_hash, decision_hash,
               content_hash, scope_hash, allowed, reasons_json, scope_claim_id,
               scope_key, scope_owner_id, scope_claim_attempt,
               scope_claim_fence, created_at
           ) VALUES (?, ?, 'legacy', ?, ?, ?, ?, 1, '[]', ?, ?, ?, 1, ?, 'legacy')""",
        (
            decision,
            work,
            "0" * 64,
            "1" * 64,
            "2" * 64,
            "3" * 64,
            claim,
            f"scope-{label}",
            owner,
            f"claim-fence-{label}",
        ),
    )
    connection.execute(
        """INSERT INTO scheduler_assignments(
               id, work_id, slot_id, lane, owner_id, attempt, fence_token,
               state, assigned_at
           ) VALUES (?, ?, 'control-1', 'control', ?, 1, ?, 'active', 'legacy')""",
        (assignment, work, owner, f"assignment-fence-{label}"),
    )
    connection.execute(
        """UPDATE scheduler_work
           SET state = 'assigned', active_assignment_id = ?, attempt = 1,
               assigned_at = 'legacy'
           WHERE id = ?""",
        (assignment, work),
    )
    connection.execute(
        """UPDATE scheduler_slots
           SET state = 'assigned', active_assignment_id = ?, active_work_id = ?,
               owner_id = ?, attempt = 1, fence_token = ?
           WHERE id = 'control-1'""",
        (assignment, work, owner, f"assignment-fence-{label}"),
    )
    connection.execute(
        """INSERT INTO transport_deliveries(
               id, idempotency_key, request_fingerprint, work_id, pool,
               assignment_id, owner_id, assignment_attempt, assignment_fence,
               admission_decision_id, scope_claim_id, scope_claim_attempt,
               scope_claim_fence, adapter_kind, payload_json, state,
               created_at, updated_at
           ) VALUES (?, ?, ?, ?, 'control', ?, ?, 1, ?, ?, ?, 1, ?,
                     'disabled', '{}', 'reserved', 'legacy', 'legacy')""",
        (
            transport,
            f"transport-idem-{label}",
            "4" * 64,
            work,
            assignment,
            owner,
            f"assignment-fence-{label}",
            decision,
            claim,
            f"claim-fence-{label}",
        ),
    )
    connection.execute(
        """INSERT INTO transport_completion_registrations(
               id, transport_id, work_id, assignment_id, assignment_attempt,
               assignment_fence, registration_key, state, created_at
           ) VALUES (?, ?, ?, ?, 1, ?, ?, 'pending', 'legacy')""",
        (
            registration,
            transport,
            work,
            assignment,
            f"assignment-fence-{label}",
            f"registration-key-{label}",
        ),
    )
    connection.execute(
        """INSERT INTO return_routes(
               id, transport_id, completion_registration_id, work_id,
               generation, assignment_id, assignment_fence, scope_claim_id,
               scope_claim_attempt, scope_claim_fence, route_kind, route_ref,
               state, created_at_us
           ) VALUES (?, ?, ?, ?, 1, ?, ?, ?, 1, ?, 'disabled', 'disabled',
                     'registered', 10)""",
        (
            route,
            transport,
            registration,
            work,
            assignment,
            f"assignment-fence-{label}",
            claim,
            f"claim-fence-{label}",
        ),
    )
    connection.execute(
        """INSERT INTO transport_callback_registrations(
               id, transport_id, completion_registration_id, return_route_id,
               work_id, generation, callback_key, state, created_at
           ) VALUES (?, ?, ?, ?, ?, 1, ?, 'pending', 'legacy')""",
        (
            transport_callback,
            transport,
            registration,
            route,
            work,
            f"callback-key-{label}",
        ),
    )
    connection.execute(
        """INSERT INTO completion_events(
               id, completion_key, completion_registration_id, transport_id,
               work_id, generation, outcome, received_at_us
           ) VALUES (?, ?, ?, ?, ?, 1, 'succeeded', 20)""",
        (completion, f"completion-key-{label}", registration, transport, work),
    )
    connection.execute(
        """UPDATE transport_completion_registrations
           SET state = 'completed', completed_at = 'legacy' WHERE id = ?""",
        (registration,),
    )
    connection.execute(
        """UPDATE scheduler_assignments
           SET state = 'released', release_outcome = 'completed',
               released_at = 'legacy' WHERE id = ?""",
        (assignment,),
    )
    connection.execute(
        """UPDATE scope_claims SET state = 'released', released_at = 'legacy'
           WHERE id = ?""",
        (claim,),
    )
    connection.execute(
        """UPDATE return_routes SET state = 'ready', ready_at_us = 30
           WHERE id = ?""",
        (route,),
    )
    connection.execute(
        """UPDATE scheduler_work
           SET state = 'completed', active_assignment_id = NULL,
               finished_at = 'legacy' WHERE id = ?""",
        (work,),
    )
    connection.execute(
        """UPDATE scheduler_slots
           SET state = 'clear', active_assignment_id = NULL,
               active_work_id = NULL, owner_id = NULL, attempt = NULL,
               fence_token = NULL WHERE id = 'control-1'"""
    )
    attempts = 0 if callback_state == "pending" else 1
    delivered_at = 50 if callback_state == "delivered" else None
    connection.execute(
        """INSERT INTO callbacks(
               id, completion_event_id, return_route_id, delivery_key, state,
               attempts, available_at_us, created_at_us, delivered_at_us
           ) VALUES (?, ?, ?, ?, ?, ?, 40, 40, ?)""",
        (
            callback,
            completion,
            route,
            delivery_key,
            callback_state,
            attempts,
            delivered_at,
        ),
    )
    connection.execute(
        """INSERT INTO outbox(
               id, callback_id, delivery_key, topic, aggregate_type,
               aggregate_id, state, attempts, available_at_us, created_at_us,
               delivered_at_us
           ) VALUES (?, ?, ?, 'completion.callback.v1', 'work', ?, ?, ?,
                     40, 40, ?)""",
        (
            f"outbox-{label}",
            callback,
            delivery_key,
            work,
            callback_state,
            attempts,
            delivered_at,
        ),
    )
    if attempts:
        connection.execute(
            """INSERT INTO callback_delivery_attempts(
                   id, callback_id, attempt_number, delivery_key, state,
                   started_at_us, finished_at_us
               ) VALUES (?, ?, 1, ?, ?, 40, ?)""",
            (
                f"callback-attempt-{label}",
                callback,
                delivery_key,
                callback_state,
                delivered_at,
            ),
        )


def _insert_milestone_seven_recovery(connection: sqlite3.Connection) -> None:
    connection.execute(
        """INSERT INTO recovery_targets(
               target_id, work_id, generation, phase, productive,
               current_timer_id, episode_id, circuit_state,
               last_observed_at_us, updated_at_us
           ) VALUES ('target-upgrade', 'work-inflight', 1, 'active', 0,
                     NULL, 'episode-upgrade', 'closed', 100, 100)"""
    )
    connection.execute(
        """INSERT INTO recovery_episodes(
               id, target_id, work_id, generation, state, reason, attempts,
               opened_at_us
           ) VALUES ('episode-upgrade', 'target-upgrade', 'work-inflight', 1,
                     'open', 'zero_output', 1, 100)"""
    )
    connection.execute(
        """INSERT INTO recovery_timers(
               id, target_id, generation, episode_id, kind, reason,
               attempt_number, state, clock_epoch, scheduled_wall_us,
               scheduled_mono_ns, due_wall_us, due_mono_ns, fired_at_us
           ) VALUES ('timer-upgrade', 'target-upgrade', 1, 'episode-upgrade',
                     'recovery', 'zero_output', 1, 'fired', 'legacy', 100,
                     100, 200, 200, 200)"""
    )
    connection.execute(
        """INSERT INTO recovery_attempts(
               id, episode_id, timer_id, attempt_number, tier, state, reason,
               due_at_us
           ) VALUES ('attempt-upgrade', 'episode-upgrade', 'timer-upgrade', 1,
                     'fast', 'due', 'zero_output', 200)"""
    )


class StoreTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.approved_root = Path(self.temporary_directory.name).resolve() / "approved"
        self.approved_root.mkdir()
        self.runtime_path = self.approved_root / "private-state"
        self.store = self.reopen_store()

    def reopen_store(self) -> RigStore:
        store = RigStore(
            PrivateRuntimeDirectory(self.runtime_path, self.approved_root)
        )
        store.initialize()
        return store

    def snapshot(self):
        return ReadOnlySnapshot(self.store).capture()

    def create_operation(self, operation_id: str) -> None:
        self.store.create_operation(operation_id, OperationKind.DISPATCH)


class StoreSchemaTests(StoreTestCase):
    def test_private_runtime_and_database_permissions(self) -> None:
        self.assertEqual(stat.S_IMODE(self.runtime_path.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.store.path.stat().st_mode), 0o600)

    def test_runtime_requires_containment_in_explicit_approved_root(self) -> None:
        outside = self.approved_root.parent / "outside"
        with self.assertRaisesRegex(ValueError, "outside approved root"):
            PrivateRuntimeDirectory(outside, self.approved_root).prepare()
        self.assertFalse(outside.exists())

    def test_runtime_rejects_symlink_in_existing_ancestor(self) -> None:
        real = self.approved_root / "real"
        real.mkdir()
        linked = self.approved_root / "linked"
        linked.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "traverse a symlink"):
            PrivateRuntimeDirectory(linked / "state", self.approved_root).prepare()
        self.assertFalse((real / "state").exists())

    def test_runtime_rejects_symlinked_database(self) -> None:
        runtime = self.approved_root / "symlink-db"
        runtime.mkdir()
        destination = self.approved_root / "elsewhere.sqlite3"
        destination.touch()
        (runtime / "rig.sqlite3").symlink_to(destination)
        with self.assertRaisesRegex(ValueError, "regular file"):
            PrivateRuntimeDirectory(runtime, self.approved_root).prepare()

    def test_runtime_rejects_database_hardlinked_to_external_sqlite(self) -> None:
        external = self.approved_root / "external.sqlite3"
        with closing(sqlite3.connect(external)) as connection, connection:
            connection.execute("CREATE TABLE external_marker(value TEXT)")
            connection.execute("INSERT INTO external_marker VALUES ('unchanged')")
        external.chmod(0o600)
        runtime = self.approved_root / "hardlinked-db"
        runtime.mkdir(mode=0o700)
        (runtime / "rig.sqlite3").hardlink_to(external)

        with self.assertRaisesRegex(ValueError, "one link"):
            PrivateRuntimeDirectory(runtime, self.approved_root).prepare()

        with closing(sqlite3.connect(external)) as connection, connection:
            self.assertEqual(
                connection.execute("SELECT value FROM external_marker").fetchall(),
                [("unchanged",)],
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name = 'schema_migrations'"
                ).fetchone()
            )

    def test_runtime_rejects_unexpected_preexisting_sidecar(self) -> None:
        unexpected = self.runtime_path / "rig.sqlite3-unexpected"
        unexpected.write_text("not sqlite", encoding="utf-8")
        unexpected.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "unexpected entry"):
            self.store.configuration()

    def test_runtime_rejects_unknown_entry_before_database_creation(self) -> None:
        runtime = self.approved_root / "unexpected-initial"
        runtime.mkdir(mode=0o700)
        unexpected = runtime / "rig.sqlite3-backup"
        unexpected.write_bytes(b"external")
        unexpected.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "unexpected entry"):
            PrivateRuntimeDirectory(runtime, self.approved_root).prepare()
        self.assertFalse((runtime / "rig.sqlite3").exists())

    def test_runtime_rejects_database_with_non_private_mode(self) -> None:
        self.store.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "mode 0600"):
            self.store.configuration()

    def test_runtime_rejects_hardlinked_sqlite_sidecar(self) -> None:
        external = self.approved_root / "external-sidecar"
        external.write_bytes(b"external")
        external.chmod(0o600)
        (self.runtime_path / "rig.sqlite3-journal").hardlink_to(external)
        with self.assertRaisesRegex(ValueError, "one link"):
            self.store.configuration()

    def test_store_fails_closed_if_database_inode_is_replaced_between_opens(self) -> None:
        replacement = self.approved_root / "replacement.sqlite3"
        with closing(sqlite3.connect(replacement)) as connection, connection:
            connection.execute("CREATE TABLE replacement_marker(value TEXT)")
        replacement.chmod(0o600)
        replacement.replace(self.store.path)
        with self.assertRaisesRegex(ValueError, "inode changed"):
            self.store.configuration()

    def test_store_detects_hardlink_replacement_across_guarded_open(self) -> None:
        external = self.approved_root / "race.sqlite3"
        with closing(sqlite3.connect(external)) as connection, connection:
            connection.execute("CREATE TABLE external_marker(value TEXT)")
            connection.execute("INSERT INTO external_marker VALUES ('unchanged')")
        external.chmod(0o600)
        real_connect = sqlite3.connect

        def replace_then_connect(*args, **kwargs):
            self.store.path.unlink()
            self.store.path.hardlink_to(external)
            return real_connect(*args, **kwargs)

        with patch("oc_rig.store.database.sqlite3.connect", replace_then_connect):
            with self.assertRaisesRegex(ValueError, "one link"):
                self.store.configuration()
        with closing(sqlite3.connect(external)) as connection, connection:
            self.assertEqual(
                connection.execute("SELECT value FROM external_marker").fetchall(),
                [("unchanged",)],
            )

    def test_required_sqlite_safety_configuration(self) -> None:
        self.assertEqual(
            self.store.configuration(),
            {
                "foreign_keys": 1,
                "journal_mode": "wal",
                "synchronous": 2,
                "busy_timeout": 5000,
            },
        )

    def test_schema_is_complete_and_migrations_are_idempotent(self) -> None:
        self.store.initialize()
        expected = {
            "settings",
            "controller_runs",
            "operations",
            "session_bindings",
            "scope_claims",
            "dispatches",
            "transport_attempts",
            "transport_deliveries",
            "transport_completion_registrations",
            "transport_callback_registrations",
            "daemon_outcome_reservations",
            "completion_events",
            "completion_child_barriers",
            "completion_child_sessions",
            "callbacks",
            "return_routes",
            "outbox",
            "callback_delivery_attempts",
            "callback_delivery_reconciliations",
            "recovery_episodes",
            "recovery_targets",
            "recovery_timers",
            "recovery_attempts",
            "recovery_clock_state",
            "pane_bindings",
            "work_queue",
            "events",
        }
        self.assertEqual(set(self.snapshot().tables), expected)
        with closing(sqlite3.connect(self.store.path)) as connection, connection:
            migrations = connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        self.assertEqual(
            migrations,
            [
                ("001_initial.sql",),
                ("002_queue_and_fences.sql",),
                ("003_scheduler.sql",),
                ("004_scheduler_authority.sql",),
                ("005_transport.sql",),
                ("006_completion_recovery.sql",),
                ("007_disabled_callback_recovery.sql",),
                ("008_opencode_delivery.sql",),
                ("009_transport_adapter_selection.sql",),
                ("010_local_codex_callbacks.sql",),
                ("011_isolated_review_sessions.sql",),
                ("012_isolated_session_cleanup.sql",),
                ("013_provisional_review_sessions.sql",),
                ("014_durable_completion_results.sql",),
                ("015_agent_lifecycle.sql",),
                ("016_cancelled_session_cleanup.sql",),
                ("017_child_completion_barrier.sql",),
                ("018_llm_behaviour.sql",),
                ("019_control_pool_expansion.sql",),
                ("020_codex_source_routes.sql",),
                ("021_slot_session_rebind.sql",),
                ("022_child_barrier_generation.sql",),
                ("023_descendant_budget.sql",),
                ("024_completed_transcript_archive.sql",),
                ("025_callback_delivery_reconciliation.sql",),
                ("026_source_inbox_read_indexes.sql",),
                ("027_persistent_session_close.sql",),
            ],
        )
        with closing(sqlite3.connect(self.store.path)) as connection:
            topology = connection.execute(
                "SELECT id, lane, position FROM scheduler_slots ORDER BY id"
            ).fetchall()
            barrier_schema = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' "
                "AND name = 'completion_child_barriers'"
            ).fetchone()
            foreign_key_violations = connection.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()
            source_route_index = tuple(
                row[2] for row in connection.execute(
                    "PRAGMA index_info(ix_local_codex_return_routes_thread_route)"
                ).fetchall()
            )
            completion_result_index = tuple(
                row[2] for row in connection.execute(
                    "PRAGMA index_info(ix_completion_results_work_generation)"
                ).fetchall()
            )
        self.assertEqual(source_route_index, ("thread_id", "return_route_id"))
        self.assertEqual(completion_result_index, ("work_id", "generation"))
        self.assertEqual(len(topology), 13)
        self.assertIn(("control-1", "control", 1), topology)
        self.assertIn(("control-2", "control", 2), topology)
        self.assertIn(("control-3", "control", 3), topology)
        self.assertIsNotNone(barrier_schema)
        assert barrier_schema is not None
        self.assertIn("child_count BETWEEN 0 AND 12", barrier_schema[0])
        self.assertIn("child_count BETWEEN 1 AND 12", barrier_schema[0])
        self.assertEqual(foreign_key_violations, [])

    def test_descendant_budget_migration_preserves_open_barrier_authority(self) -> None:
        migration_root = resources.files("oc_rig.store.migrations")
        with closing(sqlite3.connect(":memory:")) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.executescript(
                """
                CREATE TABLE scheduler_admission_decisions(
                    id TEXT PRIMARY KEY, allow_child_agents INTEGER
                );
                CREATE TABLE transport_deliveries(
                    id TEXT PRIMARY KEY, admission_decision_id TEXT, created_at TEXT
                );
                CREATE TABLE transport_completion_registrations(
                    id TEXT PRIMARY KEY, transport_id TEXT, work_id TEXT,
                    assignment_attempt INTEGER
                );
                CREATE TABLE completion_events(
                    transport_id TEXT, completion_registration_id TEXT,
                    work_id TEXT, generation INTEGER
                );
                CREATE TABLE completion_results(
                    transport_id TEXT, completion_registration_id TEXT,
                    work_id TEXT, generation INTEGER, session_id TEXT,
                    assistant_message_id TEXT
                );
                INSERT INTO scheduler_admission_decisions VALUES ('decision-1', 1);
                INSERT INTO transport_deliveries VALUES (
                    'transport-1', 'decision-1', 't1'
                );
                INSERT INTO transport_completion_registrations VALUES (
                    'completion-1', 'transport-1', 'work-1', 4
                );
                """
            )
            for name in (
                "017_child_completion_barrier.sql",
                "022_child_barrier_generation.sql",
            ):
                connection.executescript(
                    migration_root.joinpath(name).read_text(encoding="utf-8")
                )
            connection.execute(
                """INSERT INTO completion_child_barriers(
                       transport_id, completion_registration_id, work_id,
                       generation, root_session_id, turn_started_at_ms,
                       child_set_sha256, child_count, state, created_at, updated_at
                   ) VALUES (
                       'transport-1', 'completion-1', 'work-1', 4,
                       'root-1', 1, ?, 1, 'waiting', 't1', 't1'
                   )""",
                ("a" * 64,),
            )
            connection.execute(
                """INSERT INTO completion_child_sessions(
                       transport_id, child_session_id, parent_session_id,
                       created_at_ms, state, updated_at
                   ) VALUES (
                       'transport-1', 'child-1', 'root-1', 2, 'waiting', 't1'
                   )"""
            )

            connection.executescript(
                migration_root.joinpath("023_descendant_budget.sql").read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(
                connection.execute(
                    "SELECT generation, child_count, state "
                    "FROM completion_child_barriers WHERE transport_id = 'transport-1'"
                ).fetchone(),
                (4, 1, "waiting"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT parent_session_id, state FROM completion_child_sessions "
                    "WHERE child_session_id = 'child-1'"
                ).fetchone(),
                ("root-1", "waiting"),
            )
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            with self.assertRaisesRegex(sqlite3.IntegrityError, "insert is not initial"):
                connection.execute(
                    """INSERT INTO completion_child_sessions(
                           transport_id, child_session_id, parent_session_id,
                           created_at_ms, state, terminal_assistant_message_id,
                           updated_at
                       ) VALUES (
                           'transport-1', 'forged-terminal', 'root-1', 3,
                           'terminal', 'forged-final', 't2'
                       )"""
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "invalid.*transition"):
                connection.execute(
                    """UPDATE completion_child_barriers
                       SET state = 'consolidation_prepared',
                           consolidation_message_id = 'consolidate-1',
                           consolidation_idempotency_key = 'key-1'
                       WHERE transport_id = 'transport-1'"""
                )

    def test_control_pool_expansion_requires_a_quiescent_legacy_topology(self) -> None:
        migration_root = resources.files("oc_rig.store.migrations")
        with closing(sqlite3.connect(":memory:", isolation_level=None)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(
                """CREATE TABLE schema_migrations (
                       version TEXT PRIMARY KEY,
                       checksum TEXT NOT NULL,
                       applied_at TEXT NOT NULL
                   ) STRICT"""
            )
            for index in range(1, 19):
                migration = next(
                    item for item in migration_root.iterdir()
                    if item.name.startswith(f"{index:03d}_")
                )
                script = migration.read_text(encoding="utf-8")
                connection.execute("BEGIN IMMEDIATE")
                for statement in _split_sql(script):
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO schema_migrations VALUES (?, ?, 'test')",
                    (migration.name, hashlib.sha256(script.encode()).hexdigest()),
                )
                connection.commit()
            connection.execute(
                """UPDATE scheduler_slots
                   SET state = 'assigned', active_assignment_id = 'assignment',
                       active_work_id = 'work', owner_id = 'owner', attempt = 1,
                       fence_token = 'fence'
                   WHERE id = 'control-1'"""
            )
            migration = migration_root.joinpath("019_control_pool_expansion.sql")
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaises(sqlite3.IntegrityError):
                for statement in _split_sql(migration.read_text(encoding="utf-8")):
                    connection.execute(statement)
            connection.rollback()
            self.assertEqual(
                connection.execute("SELECT count(*) FROM scheduler_slots").fetchone(),
                (11,),
            )

    def test_agent_lifecycle_migration_has_safe_historical_defaults(self) -> None:
        migration = (
            resources.files("oc_rig.store.migrations")
            .joinpath("015_agent_lifecycle.sql")
            .read_text(encoding="utf-8")
        )
        with closing(sqlite3.connect(":memory:")) as connection:
            connection.execute(
                "CREATE TABLE scheduler_admission_decisions(id TEXT PRIMARY KEY)"
            )
            connection.execute(
                """CREATE TRIGGER scheduler_admission_decisions_are_immutable_update
                   BEFORE UPDATE ON scheduler_admission_decisions BEGIN
                       SELECT RAISE(ABORT, 'scheduler admission decision is immutable');
                   END"""
            )
            connection.execute(
                """CREATE TABLE transport_deliveries(
                       admission_decision_id TEXT NOT NULL,
                       payload_json TEXT NOT NULL
                   )"""
            )
            connection.execute(
                """CREATE TABLE opencode_deliveries(
                       id INTEGER PRIMARY KEY,
                       transport_id TEXT,
                       isolated_session_id TEXT,
                       cleanup_state TEXT DEFAULT 'none',
                       lease_state TEXT DEFAULT 'active'
                   )"""
            )
            connection.execute(
                """CREATE UNIQUE INDEX opencode_isolated_session_is_single_use
                   ON opencode_deliveries(isolated_session_id)
                   WHERE isolated_session_id IS NOT NULL"""
            )
            connection.execute(
                """CREATE TRIGGER opencode_cleanup_requires_isolated_session
                   BEFORE UPDATE OF cleanup_state ON opencode_deliveries BEGIN
                       SELECT 1;
                   END"""
            )
            connection.execute(
                """CREATE TRIGGER opencode_cleanup_enqueue_after_release
                   AFTER UPDATE OF lease_state ON opencode_deliveries BEGIN
                       SELECT 1;
                   END"""
            )
            connection.execute(
                "INSERT INTO scheduler_admission_decisions(id) VALUES ('legacy')"
            )
            connection.execute(
                "INSERT INTO scheduler_admission_decisions(id) VALUES ('capsule')"
            )
            connection.execute(
                """INSERT INTO transport_deliveries(
                       admission_decision_id, payload_json
                   ) VALUES ('capsule', ?)""",
                (json.dumps({"prompt": "RIG_READ_ONLY_REVIEW_V1\nbounded"}),),
            )
            connection.executescript(migration)
            connection.execute(
                """INSERT INTO opencode_deliveries(
                       transport_id, isolated_session_id, cleanup_state,
                       lease_state, agent_lifecycle
                   ) VALUES ('persistent-turn', 'retained-root', 'none',
                             'active', 'persistent')"""
            )
            connection.execute(
                """UPDATE opencode_deliveries SET lease_state = 'released'
                   WHERE transport_id = 'persistent-turn'"""
            )
            self.assertEqual(
                connection.execute(
                    """SELECT cleanup_state FROM opencode_deliveries
                       WHERE transport_id = 'persistent-turn'"""
                ).fetchone(),
                ("none",),
            )
            self.assertEqual(
                connection.execute(
                    """SELECT agent_lifecycle, allow_child_agents
                       FROM scheduler_admission_decisions WHERE id = 'legacy'"""
                ).fetchone(),
                ("persistent", 0),
            )
            self.assertEqual(
                connection.execute(
                    """SELECT agent_lifecycle, allow_child_agents
                       FROM scheduler_admission_decisions WHERE id = 'capsule'"""
                ).fetchone(),
                ("disposable", 0),
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "scheduler admission decision is immutable"
            ):
                connection.execute(
                    """UPDATE scheduler_admission_decisions
                       SET agent_lifecycle = 'persistent' WHERE id = 'capsule'"""
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """INSERT INTO scheduler_admission_decisions(
                           id, agent_lifecycle, allow_child_agents
                       ) VALUES ('bad-lifecycle', 'ephemeral', 0)"""
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """INSERT INTO scheduler_admission_decisions(
                           id, agent_lifecycle, allow_child_agents
                       ) VALUES ('bad-child-flag', 'persistent', 2)"""
                )

    def test_exact_milestone_seven_store_upgrades_without_data_loss(self) -> None:
        upgrade_root = self.approved_root / "milestone-seven-upgrade"
        upgrade_root.mkdir()
        store = RigStore(
            PrivateRuntimeDirectory(upgrade_root / "state", upgrade_root)
        )
        _initialize_milestone_seven(store)
        preserved_tables = (
            "completion_events",
            "return_routes",
            "transport_callback_registrations",
            "callbacks",
            "outbox",
            "callback_delivery_attempts",
            "recovery_targets",
            "recovery_episodes",
            "recovery_timers",
            "recovery_attempts",
        )
        with closing(sqlite3.connect(store.path)) as connection, connection:
            connection.execute("PRAGMA foreign_keys = ON")
            _insert_milestone_seven_completion(connection, "pending", "pending")
            _insert_milestone_seven_completion(
                connection, "inflight", "delivering"
            )
            _insert_milestone_seven_recovery(connection)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            before = {
                table: tuple(
                    row[0]
                    for row in connection.execute(
                        f'SELECT id FROM "{table}" ORDER BY id'
                        if table != "recovery_targets"
                        else "SELECT target_id FROM recovery_targets ORDER BY target_id"
                    )
                )
                for table in preserved_tables
            }

        store.initialize()
        store.initialize()

        with closing(sqlite3.connect(store.path)) as connection, connection:
            connection.execute("PRAGMA foreign_keys = ON")
            after = {
                table: tuple(
                    row[0]
                    for row in connection.execute(
                        f'SELECT id FROM "{table}" ORDER BY id'
                        if table != "recovery_targets"
                        else "SELECT target_id FROM recovery_targets ORDER BY target_id"
                    )
                )
                for table in preserved_tables
            }
            self.assertEqual(after, before)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(
                connection.execute(
                    "SELECT checksum FROM schema_migrations WHERE version = ?",
                    (_MILESTONE_SEVEN_MIGRATION,),
                ).fetchone(),
                (_MILESTONE_SEVEN_CHECKSUM,),
            )
            self.assertIn(
                ("007_disabled_callback_recovery.sql",),
                connection.execute(
                    "SELECT version FROM schema_migrations"
                ).fetchall(),
            )
            self.assertEqual(
                connection.execute(
                    """SELECT state, attention_reason FROM callbacks
                       WHERE id = 'callback-pending'"""
                ).fetchone(),
                ("blocked", "callback_adapter_disabled"),
            )
            self.assertEqual(
                connection.execute(
                    """SELECT state, disabled_reason FROM outbox
                       WHERE id = 'outbox-pending'"""
                ).fetchone(),
                ("blocked", "callback_adapter_disabled"),
            )
            self.assertEqual(
                connection.execute(
                    """SELECT callback.state, outbox.state, attempt.state,
                              outbox.disabled_reason
                       FROM callbacks AS callback
                       JOIN outbox ON outbox.callback_id = callback.id
                       JOIN callback_delivery_attempts AS attempt
                         ON attempt.callback_id = callback.id
                       WHERE callback.id = 'callback-inflight'"""
                ).fetchone(),
                ("delivering", "delivering", "delivering", None),
            )
            self.assertEqual(
                connection.execute(
                    """SELECT episode_id, timer_id, state
                       FROM recovery_attempts
                       WHERE id = 'attempt-upgrade'"""
                ).fetchone(),
                ("episode-upgrade", "timer-upgrade", "due"),
            )
            connection.execute(
                """UPDATE recovery_attempts
                   SET state = 'cancelled', finished_at_us = 201
                   WHERE id = 'attempt-upgrade'"""
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM recovery_attempts WHERE id = 'attempt-upgrade'"
                ).fetchone(),
                ("cancelled",),
            )

        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "blocked callback requires disabled reason"
        ):
            with closing(sqlite3.connect(store.path)) as connection, connection:
                connection.execute(
                    """UPDATE callbacks SET attention_reason = NULL
                       WHERE id = 'callback-pending'"""
                )

    def test_exact_35c3c625_store_upgrades_forward_without_data_loss(self) -> None:
        upgrade_root = self.approved_root / "commit-35c3c625-upgrade"
        upgrade_root.mkdir()
        store = RigStore(
            PrivateRuntimeDirectory(upgrade_root / "state", upgrade_root)
        )
        _initialize_commit_35c3c625(store)
        with closing(sqlite3.connect(store.path)) as connection, connection:
            connection.execute(
                """INSERT INTO operations(id, kind, state, created_at, updated_at)
                   VALUES ('preserved-35c3c625', 'dispatch', 'pending',
                           'legacy', 'legacy')"""
            )
        store.initialize()
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM operations WHERE id = 'preserved-35c3c625'"
                ).fetchone(),
                ("pending",),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT checksum FROM schema_migrations WHERE version = ?",
                    (_COMMIT_35C3C625_MIGRATION,),
                ).fetchone(),
                (_COMMIT_35C3C625_CHECKSUM,),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1"
                ).fetchone(),
                ("027_persistent_session_close.sql",),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
                    ("transport_adapter_selections",),
                ).fetchone(),
                ("transport_adapter_selections",),
            )

    def test_milestone_seven_upgrade_fails_closed_on_delivered_callback(self) -> None:
        upgrade_root = self.approved_root / "milestone-seven-incompatible"
        upgrade_root.mkdir()
        store = RigStore(
            PrivateRuntimeDirectory(upgrade_root / "state", upgrade_root)
        )
        _initialize_milestone_seven(store)
        with closing(sqlite3.connect(store.path)) as connection, connection:
            connection.execute("PRAGMA foreign_keys = ON")
            _insert_milestone_seven_completion(connection, "delivered", "delivered")
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

        with self.assertRaises(sqlite3.IntegrityError):
            store.initialize()

        with closing(sqlite3.connect(store.path)) as connection:
            self.assertNotIn(
                ("007_disabled_callback_recovery.sql",),
                connection.execute(
                    "SELECT version FROM schema_migrations"
                ).fetchall(),
            )
            self.assertNotIn(
                "disabled_reason",
                {
                    row[1]
                    for row in connection.execute("PRAGMA table_info(outbox)")
                },
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state, delivered_at_us FROM callbacks"
                ).fetchall(),
                [("delivered", 50)],
            )

    def test_foreign_keys_reject_orphaned_rows(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store._transaction() as connection:
                connection.execute(
                    """INSERT INTO scope_claims(
                           id, scope_key, owner_operation_id, state, claimed_at,
                           attempt, fence_token, idempotency_key
                       ) VALUES ('c', 'scope', 'missing', 'active', 'now',
                                 1, 'fence-1', 'idem-1')"""
                )


class StoreJournalAndValidationTests(StoreTestCase):
    def test_event_wait_wakes_only_after_a_committed_event(self) -> None:
        with ThreadPoolExecutor(max_workers=1) as executor:
            waiting = executor.submit(self.store._wait_for_event_sequence, 0)
            self.assertFalse(waiting.done())
            self.store.create_operation("watch-operation", OperationKind.DISPATCH)
            self.assertEqual(waiting.result(timeout=1), 1)

    def test_event_wait_rejects_invalid_sequences_and_wakes_on_close(self) -> None:
        for invalid in (-1, True, 2**63):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.store._wait_for_event_sequence(invalid)

        with ThreadPoolExecutor(max_workers=1) as executor:
            waiting = executor.submit(self.store._wait_for_event_sequence, 0)
            self.store._close_event_feed()
            with self.assertRaisesRegex(RuntimeError, "event feed is closed"):
                waiting.result(timeout=1)

    def test_same_database_instances_share_weakly_registered_lock(self) -> None:
        second = RigStore(
            PrivateRuntimeDirectory(self.runtime_path, self.approved_root)
        )
        self.assertIs(second._serialization_lock, self.store._serialization_lock)

        weak_lock = weakref.ref(second._serialization_lock)
        other_root = self.approved_root / "weak-registry"
        temporary_store = RigStore(
            PrivateRuntimeDirectory(other_root, self.approved_root)
        )
        temporary_store.initialize()
        temporary_ref = weakref.ref(temporary_store._serialization_lock)
        del temporary_store
        gc.collect()
        self.assertIsNone(temporary_ref())
        self.assertIsNotNone(weak_lock())

    def test_five_hundred_two_store_mutations_have_no_wal_or_shm_errors(self) -> None:
        stores = (
            self.store,
            RigStore(PrivateRuntimeDirectory(self.runtime_path, self.approved_root)),
        )

        def create(index: int) -> None:
            stores[index % 2].create_operation(
                f"registry-operation-{index}", OperationKind.DISPATCH
            )

        with ThreadPoolExecutor(max_workers=24) as executor:
            list(executor.map(create, range(512)))
        with closing(sqlite3.connect(self.store.path)) as verifier:
            self.assertEqual(
                verifier.execute(
                    "SELECT count(*) FROM operations WHERE id LIKE 'registry-operation-%'"
                ).fetchone(),
                (512,),
            )
        wal_path = self.runtime_path / "rig.sqlite3-wal"
        self.assertTrue(not wal_path.exists() or wal_path.stat().st_size == 0)

    def test_snapshot_configuration_and_scheduler_reads_share_database_lock(self) -> None:
        second = RigStore(
            PrivateRuntimeDirectory(self.runtime_path, self.approved_root)
        )
        scheduler = object.__new__(_Scheduler)
        scheduler.store = second
        started = threading.Barrier(4)
        finished = [threading.Event() for _ in range(3)]
        failures: list[BaseException] = []

        def read(index: int) -> None:
            started.wait()
            try:
                if index == 0:
                    second.configuration()
                elif index == 1:
                    ReadOnlySnapshot(second).capture()
                else:
                    scheduler.snapshot()
            except BaseException as error:
                failures.append(error)
            finally:
                finished[index].set()

        threads = [threading.Thread(target=read, args=(index,)) for index in range(3)]
        with self.store._serialization_lock:
            for thread in threads:
                thread.start()
            started.wait()
            self.assertTrue(all(not event.wait(timeout=0.05) for event in finished))
        for thread in threads:
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
        self.assertFalse(failures)

    def test_different_database_locks_are_independent(self) -> None:
        second_root = self.approved_root / "independent-state"
        second = RigStore(PrivateRuntimeDirectory(second_root, self.approved_root))
        second.initialize()
        completed = threading.Event()

        def mutate_second() -> None:
            second.create_operation("independent", OperationKind.DISPATCH)
            completed.set()

        thread = threading.Thread(target=mutate_second)
        with self.store._serialization_lock:
            thread.start()
            self.assertTrue(completed.wait(timeout=0.5))
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_lock_registry_rejects_identity_replacement_during_creation(self) -> None:
        replacement = self.approved_root / "registry-replacement.sqlite3"
        with closing(sqlite3.connect(replacement)) as connection:
            connection.execute("CREATE TABLE replacement(value TEXT)")
        replacement.chmod(0o600)
        original_identity = store_database._path_identity
        calls = 0

        def replace_after_canonical_check(path: Path):
            nonlocal calls
            identity = original_identity(path)
            calls += 1
            if calls == 2:
                replacement.replace(self.store.path)
            return identity

        with patch.object(
            store_database,
            "_path_identity",
            side_effect=replace_after_canonical_check,
        ):
            with self.assertRaises(RuntimeContainmentError):
                store_database._database_serialization_lock(
                    self.store.path, self.store._database_identity
                )

    def test_store_serialization_lock_is_reentrant_without_deadlock(self) -> None:
        with self.store._serialization_lock:
            self.store.create_operation("op-reentrant", OperationKind.DISPATCH)
        self.assertEqual(
            self.snapshot().rows("operations")[0]["id"],
            "op-reentrant",
        )

    def test_restart_recovers_committed_crash_wal_to_quiescent_baseline(self) -> None:
        script = """
import os
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1], isolation_level=None)
connection.execute("PRAGMA journal_mode = WAL")
connection.execute("BEGIN IMMEDIATE")
connection.execute(
    "INSERT INTO operations(id, kind, state, created_at, updated_at) "
    "VALUES ('crash-owner', 'dispatch', 'pending', 'crash', 'crash')"
)
connection.commit()
os._exit(0)
"""
        subprocess.run(
            [sys.executable, "-c", script, str(self.store.path)],
            check=True,
        )
        wal_path = self.runtime_path / "rig.sqlite3-wal"
        self.assertGreater(wal_path.stat().st_size, 0)

        restarted = self.reopen_store()
        self.assertTrue(not wal_path.exists() or wal_path.stat().st_size == 0)
        with closing(sqlite3.connect(restarted.path)) as verifier:
            self.assertEqual(
                verifier.execute(
                    "SELECT state FROM operations WHERE id = 'crash-owner'"
                ).fetchone(),
                ("pending",),
            )

    def test_busy_checkpoint_fails_fast_without_rolling_back_commit_or_reader(self) -> None:
        with closing(sqlite3.connect(self.store.path, isolation_level=None)) as reader:
            reader.execute("BEGIN")
            self.assertEqual(
                reader.execute("SELECT count(*) FROM operations").fetchone(), (0,)
            )
            started = time.monotonic()
            with self.assertRaises(StoreQuiescenceError):
                self.store.create_operation("op-busy", OperationKind.DISPATCH)
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertEqual(
                reader.execute("SELECT count(*) FROM operations").fetchone(), (0,)
            )
            reader.rollback()

        with closing(sqlite3.connect(self.store.path)) as verifier:
            self.assertEqual(
                verifier.execute(
                    "SELECT kind FROM operations WHERE id = 'op-busy'"
                ).fetchone(),
                ("dispatch",),
            )
        self.store.create_operation("op-after-reader", OperationKind.DISPATCH)
        wal_path = self.runtime_path / "rig.sqlite3-wal"
        self.assertTrue(not wal_path.exists() or wal_path.stat().st_size == 0)

    def test_checkpoint_failure_surfaces_after_committed_mutation(self) -> None:
        failure = StoreQuiescenceError("injected checkpoint failure")
        with patch.object(self.store, "_checkpoint_wal", side_effect=failure):
            with self.assertRaises(StoreQuiescenceError):
                self.store.create_operation("op-checkpoint", OperationKind.DISPATCH)
        with closing(sqlite3.connect(self.store.path)) as verifier:
            self.assertEqual(
                verifier.execute(
                    "SELECT kind FROM operations WHERE id = 'op-checkpoint'"
                ).fetchone(),
                ("dispatch",),
            )
        self.store.create_operation("op-checkpoint-retry", OperationKind.DISPATCH)

    def test_operation_and_event_are_committed_together(self) -> None:
        self.create_operation("op-1")
        self.store.transition_operation("op-1", OperationState.RUNNING)
        snapshot = self.snapshot()
        self.assertEqual(snapshot.rows("operations")[0]["state"], "running")
        self.assertEqual(
            [row["event_type"] for row in snapshot.rows("events")],
            ["operation.created", "operation.state_changed"],
        )

    def test_invalid_transition_rolls_back_without_event(self) -> None:
        self.create_operation("op-1")
        with self.assertRaises(ValueError):
            self.store.transition_operation("op-1", OperationState.SUCCEEDED)
        snapshot = self.snapshot()
        self.assertEqual(snapshot.rows("operations")[0]["state"], "pending")
        self.assertEqual(len(snapshot.rows("events")), 1)

    def test_database_trigger_rejects_bypassed_invalid_transition(self) -> None:
        self.create_operation("op-1")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "invalid operation"):
            with self.store._transaction() as connection:
                connection.execute(
                    "UPDATE operations SET state = 'succeeded' WHERE id = 'op-1'"
                )

    def test_event_log_cannot_be_updated_or_deleted(self) -> None:
        self.create_operation("op-1")
        for statement in (
            "UPDATE events SET event_type = 'changed'",
            "DELETE FROM events",
        ):
            with self.subTest(statement=statement):
                with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                    with self.store._transaction() as connection:
                        connection.execute(statement)

    def test_public_api_exposes_no_raw_write_or_arbitrary_event_method(self) -> None:
        self.assertFalse(hasattr(self.store, "transaction"))
        self.assertFalse(hasattr(self.store, "append_event"))

    def test_settings_are_typed_and_allowlisted(self) -> None:
        self.store.set_setting(SettingKey.CONTROLLER_ENABLED, True)
        self.store.set_setting(SettingKey.MAX_CONCURRENT_WORKERS, 5)
        with self.assertRaises(TypeError):
            self.store.set_setting("backend", "token=synthetic-marker")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            self.store.set_setting(SettingKey.MAX_CONCURRENT_WORKERS, True)
        self.assertEqual(len(self.snapshot().rows("settings")), 2)

    def test_credential_like_free_text_cannot_enter_ordinary_api_values(self) -> None:
        self.create_operation("op-1")
        with self.assertRaises(CredentialDataError):
            self.store.transition_operation(
                "op-1",
                OperationState.FAILED,
                error_summary="transport failed token=synthetic-marker",
            )
        with self.assertRaises(CredentialDataError):
            self.store.enqueue_work(
                "token=synthetic-marker",
                WorkKind.DISPATCH,
                idempotency_key="idem-1",
            )
        snapshot = self.snapshot()
        self.assertEqual(snapshot.rows("operations")[0]["state"], "pending")
        self.assertEqual(snapshot.rows("work_queue"), ())


class DurableQueueTests(StoreTestCase):
    def test_fifo_order_survives_reopen(self) -> None:
        for label in ("a", "b", "c"):
            self.store.enqueue_work(
                f"work-{label}", WorkKind.DISPATCH, idempotency_key=f"enqueue-{label}"
            )
        self.store = self.reopen_store()

        claimed = []
        for number in range(1, 4):
            reservation = self.store.reserve_work(
                "worker-1", fence_token=f"queue-fence-{number}"
            )
            self.assertIsNotNone(reservation)
            assert reservation is not None
            claimed.append(reservation.id)
            self.assertTrue(
                self.store.complete_work(
                    reservation.id,
                    reservation.owner_id,
                    attempt=reservation.attempt,
                    fence_token=reservation.fence_token,
                )
            )
        self.assertEqual(claimed, ["work-a", "work-b", "work-c"])

    def test_priority_precedes_fifo_and_fifo_breaks_priority_ties(self) -> None:
        self.store.enqueue_work(
            "work-a", WorkKind.DISPATCH, idempotency_key="enqueue-a", priority=0
        )
        self.store.enqueue_work(
            "work-b", WorkKind.DISPATCH, idempotency_key="enqueue-b", priority=5
        )
        self.store.enqueue_work(
            "work-c", WorkKind.DISPATCH, idempotency_key="enqueue-c", priority=0
        )
        order = []
        for number in range(3):
            reservation = self.store.reserve_work(
                "worker-1", fence_token=f"fence-{number}"
            )
            assert reservation is not None
            order.append(reservation.id)
            self.store.complete_work(
                reservation.id,
                reservation.owner_id,
                attempt=reservation.attempt,
                fence_token=reservation.fence_token,
            )
        self.assertEqual(order, ["work-b", "work-a", "work-c"])

    def test_enqueue_idempotency_returns_original_without_duplicate_event(self) -> None:
        first = self.store.enqueue_work(
            "work-a", WorkKind.DISPATCH, idempotency_key="enqueue-a"
        )
        second = self.store.enqueue_work(
            "work-a", WorkKind.DISPATCH, idempotency_key="enqueue-a"
        )
        self.assertEqual(first, second)
        self.assertEqual(len(self.snapshot().rows("work_queue")), 1)
        self.assertEqual(len(self.snapshot().rows("events")), 1)
        with self.assertRaises(IdempotencyConflict):
            self.store.enqueue_work(
                "work-b", WorkKind.DISPATCH, idempotency_key="enqueue-a"
            )

    def test_concurrent_reserve_has_exactly_one_winner(self) -> None:
        self.store.enqueue_work(
            "work-a", WorkKind.DISPATCH, idempotency_key="enqueue-a"
        )
        stores = (self.reopen_store(), self.reopen_store())
        barrier = threading.Barrier(2)

        def reserve(number: int):
            barrier.wait()
            return stores[number - 1].reserve_work(
                f"worker-{number}", fence_token=f"fence-{number}"
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(reserve, (1, 2)))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(
            [row["state"] for row in self.snapshot().rows("work_queue")],
            ["claimed"],
        )

    def test_enqueue_crash_rolls_back_item_and_event(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            with self.store._transaction() as connection:
                self.store._enqueue_work(
                    connection,
                    "work-a",
                    WorkKind.DISPATCH,
                    idempotency_key="enqueue-a",
                    operation_id=None,
                    priority=0,
                    now="2026-01-01T00:00:00Z",
                )
                raise RuntimeError("simulated crash")
        snapshot = self.snapshot()
        self.assertEqual(snapshot.rows("work_queue"), ())
        self.assertEqual(snapshot.rows("events"), ())

    def test_claim_survives_crash_and_exact_reopen_recovers_once(self) -> None:
        self.store.enqueue_work(
            "work-a", WorkKind.DISPATCH, idempotency_key="enqueue-a"
        )
        reservation = self.store.reserve_work("worker-1", fence_token="fence-1")
        assert reservation is not None
        self.store = self.reopen_store()

        self.assertFalse(
            self.store.reopen_work(
                "work-a", "worker-foreign", attempt=1, fence_token="fence-1"
            )
        )
        self.assertFalse(
            self.store.reopen_work(
                "work-a", "worker-1", attempt=2, fence_token="fence-1"
            )
        )
        self.assertTrue(
            self.store.reopen_work(
                "work-a", "worker-1", attempt=1, fence_token="fence-1"
            )
        )
        self.assertFalse(
            self.store.reopen_work(
                "work-a", "worker-1", attempt=1, fence_token="fence-1"
            )
        )
        recovered = self.store.reserve_work("worker-2", fence_token="fence-2")
        assert recovered is not None
        self.assertEqual((recovered.id, recovered.attempt), ("work-a", 2))


class FencedOwnershipTests(StoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.create_operation("op-1")
        self.create_operation("op-2")

    def test_scope_claim_public_api_requires_rigd(self) -> None:
        with self.assertRaises(DaemonAuthorityError):
            self.store.claim_scope(
                "claim-1",
                "repo:/one",
                "op-1",
                attempt=1,
                fence_token="scope-fence-1",
                idempotency_key="claim-idem",
            )
        with self.assertRaises(DaemonAuthorityError):
            self.store.release_scope(
                "claim-1", "op-1", attempt=1, fence_token="scope-fence-1"
            )

    def test_session_binding_and_release_are_fenced_and_journaled(self) -> None:
        receipt = self.store.bind_session(
            "binding-1",
            "op-1",
            "session-1",
            attempt=3,
            fence_token="session-fence-3",
            idempotency_key="binding-idem",
        )
        duplicate = self.store.bind_session(
            "binding-retry",
            "op-1",
            "session-1",
            attempt=3,
            fence_token="session-fence-3",
            idempotency_key="binding-idem",
        )
        self.assertEqual(receipt, duplicate)
        self.assertFalse(
            self.store.release_session(
                "binding-1", "op-1", attempt=2, fence_token="session-fence-3"
            )
        )
        self.assertTrue(
            self.store.release_session(
                "binding-1", "op-1", attempt=3, fence_token="session-fence-3"
            )
        )
        lifecycle = [
            row["event_type"] for row in self.snapshot().rows("events")
            if row["aggregate_type"] == "session_binding"
        ]
        self.assertEqual(lifecycle, ["session.bound", "session.released"])

class ReadOnlySnapshotTests(StoreTestCase):
    def test_snapshot_is_immutable_and_has_no_write_interface(self) -> None:
        self.create_operation("op-1")
        with self.assertRaisesRegex(TypeError, "live RigStore"):
            ReadOnlySnapshot(self.store.path)  # type: ignore[arg-type]
        reader = ReadOnlySnapshot(self.store)
        snapshot = reader.capture()
        self.assertFalse(hasattr(reader, "execute"))
        with self.assertRaises(TypeError):
            snapshot.tables["new"] = ()  # type: ignore[index]
        with self.assertRaises(TypeError):
            snapshot.rows("operations")[0]["state"] = "failed"  # type: ignore[index]
        self.assertEqual(
            ReadOnlySnapshot(self.store).capture().rows("operations")[0]["state"],
            "pending",
        )

    def test_path_replacement_while_waiting_fails_before_sqlite_open(self) -> None:
        reader = ReadOnlySnapshot(self.store)
        replacement = self.approved_root / "snapshot-replacement.sqlite3"
        replacement.write_bytes(self.store.path.read_bytes())
        replacement.chmod(0o600)
        started = threading.Event()
        results: list[object] = []
        failures: list[BaseException] = []

        def capture() -> None:
            started.set()
            try:
                results.append(reader.capture())
            except BaseException as error:
                failures.append(error)

        real_connect = sqlite3.connect
        with patch(
            "oc_rig.store.snapshot.sqlite3.connect", wraps=real_connect
        ) as connect:
            with reader._serialization_lock:
                thread = threading.Thread(target=capture)
                thread.start()
                self.assertTrue(started.wait(timeout=1))
                replacement.replace(self.store.path)
            thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(results, [])
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], RuntimeContainmentError)
        connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
