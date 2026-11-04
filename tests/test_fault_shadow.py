from __future__ import annotations

import copy
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from oc_rig.cockpit import normalize_snapshot, render_terminal
from oc_rig.domain.models import WorkKind
from oc_rig.store import PrivateRuntimeDirectory, RigStore
from oc_rig.store.snapshot import _CockpitSnapshotProjection
from tests import test_transport_delivery as transport_tests
from tests.fixtures.fault_shadow import (
    EXPECTED_SLOT_TOPOLOGY,
    apply_migrations_with_restarts,
    hard_crash,
    process_is_gone,
)


class FaultShadowDaemonExercises(unittest.TestCase):
    """Cross-process exercises that use only the isolated disabled transport."""

    def setUp(self) -> None:
        self.harness = transport_tests.TransportDaemonTests(methodName="runTest")
        self.addCleanup(self._cleanup_harness)
        self.harness.setUp()

    def _cleanup_harness(self) -> None:
        daemon = getattr(self.harness, "daemon", None)
        try:
            if daemon is not None:
                daemon.shutdown()
        finally:
            self.harness.doCleanups()

    def test_hard_crash_replaces_process_and_socket_without_losing_state(self) -> None:
        created = self.harness.call(
            "operation.create.v1",
            {"operation_id": "fault-shadow-owner", "kind": "dispatch"},
            idempotency_id="fault-shadow-create",
        )
        assert self.harness.daemon is not None
        first_pid = self.harness.daemon.child_pid
        self.assertIsNotNone(first_pid)
        first_socket = self.harness.socket.lstat()

        crashed_pid = hard_crash(self.harness.daemon)
        self.assertEqual(crashed_pid, first_pid)
        self.assertTrue(process_is_gone(crashed_pid))
        self.assertTrue(self.harness.socket.exists())

        self.harness.restart_daemon()
        assert self.harness.daemon is not None
        second_pid = self.harness.daemon.child_pid
        second_socket = self.harness.socket.lstat()
        self.assertIsNotNone(second_pid)
        self.assertNotEqual(second_pid, first_pid)
        self.assertNotEqual(
            (second_socket.st_dev, second_socket.st_ino),
            (first_socket.st_dev, first_socket.st_ino),
        )
        retried = self.harness.call(
            "operation.create.v1",
            {"operation_id": "fault-shadow-owner", "kind": "dispatch"},
            request_id="fault-shadow-create-after-restart",
            idempotency_id="fault-shadow-create",
        )
        self.assertEqual(retried, created)
        self.assertEqual(
            [row["id"] for row in self.harness.rows("operations")],
            ["fault-shadow-owner"],
        )
        self.assertEqual(
            tuple(
                (str(row["id"]), str(row["lane"]), int(row["position"]))
                for row in self.harness.rows("scheduler_slots")
            ),
            EXPECTED_SLOT_TOPOLOGY,
        )


class NestedHarnessCleanupExercises(unittest.TestCase):
    def _exercise_setup_failure(self, target: str) -> None:
        observed: dict[str, object] = {}

        class SetupFailureProbe(unittest.TestCase):
            def setUp(inner_self) -> None:
                inner_self.harness = transport_tests.TransportDaemonTests(
                    methodName="runTest"
                )
                inner_self.addCleanup(inner_self._cleanup_harness)

                def reject_setup(*args: object, **kwargs: object) -> None:
                    if target.endswith("_read_child_status"):
                        process = args[0]
                        observed["pid"] = int(getattr(process, "pid"))
                    else:
                        observed["pid"] = int(kwargs["child_pid"])
                    raise RuntimeError("synthetic post-spawn setup failure")

                with patch(
                    target,
                    side_effect=reject_setup,
                ):
                    inner_self.harness.setUp()

            def _cleanup_harness(inner_self) -> None:
                root = inner_self.harness.root
                observed["root_before_stop"] = root.exists()
                daemon = getattr(inner_self.harness, "daemon", None)
                observed["process_retained_before_cleanup"] = (
                    None if daemon is None else daemon.process
                )
                try:
                    if daemon is not None:
                        daemon.shutdown()
                finally:
                    observed["root_after_stop"] = root.exists()
                    inner_self.harness.doCleanups()
                    observed["root_after_cleanup"] = root.exists()

            def runTest(inner_self) -> None:
                inner_self.fail("forced setup failure should prevent test execution")

        result = unittest.TestResult()
        SetupFailureProbe().run(result)
        if result.skipped:
            self.skipTest(result.skipped[0][1])
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.failures, [])
        self.assertTrue(observed["root_before_stop"])
        self.assertTrue(observed["root_after_stop"])
        self.assertFalse(observed["root_after_cleanup"])
        self.assertIsNone(observed["process_retained_before_cleanup"])
        self.assertTrue(process_is_gone(int(observed["pid"])))

    def test_status_read_failure_clears_child_before_temp_cleanup(self) -> None:
        self._exercise_setup_failure(
            "tests.fixtures.durable_daemon._read_child_status"
        )

    def test_post_readiness_failure_stops_child_before_removing_temp_root(self) -> None:
        self._exercise_setup_failure(
            "tests.fixtures.durable_daemon._verify_ready_socket"
        )


class SameDatabaseRestartExercises(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.runtime = PrivateRuntimeDirectory(self.root / "state", self.root)
        self.store = RigStore(self.runtime)
        self.store.initialize()

    def test_concurrent_claim_then_restart_preserves_one_fenced_owner(self) -> None:
        self.store.enqueue_work(
            "fault-shadow-work",
            WorkKind.DISPATCH,
            idempotency_key="fault-shadow-enqueue",
        )
        stores = (RigStore(self.runtime), RigStore(self.runtime))
        barrier = threading.Barrier(2)

        def reserve(index: int):
            barrier.wait()
            return stores[index].reserve_work(
                f"fault-shadow-worker-{index}",
                fence_token=f"fault-shadow-fence-{index}",
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            reservations = list(executor.map(reserve, range(2)))
        winners = [reservation for reservation in reservations if reservation is not None]
        self.assertEqual(len(winners), 1)
        winner = winners[0]

        restarted = RigStore(self.runtime)
        restarted.initialize()
        self.assertFalse(
            restarted.reopen_work(
                winner.id,
                winner.owner_id,
                attempt=winner.attempt + 1,
                fence_token=winner.fence_token,
            )
        )
        self.assertFalse(
            restarted.reopen_work(
                winner.id,
                winner.owner_id,
                attempt=winner.attempt,
                fence_token="fault-shadow-stale-fence",
            )
        )
        self.assertTrue(
            restarted.reopen_work(
                winner.id,
                winner.owner_id,
                attempt=winner.attempt,
                fence_token=winner.fence_token,
            )
        )
        self.assertFalse(
            restarted.reopen_work(
                winner.id,
                winner.owner_id,
                attempt=winner.attempt,
                fence_token=winner.fence_token,
            )
        )


class MigrationRestartExercises(unittest.TestCase):
    def test_migrations_001_through_009_restart_cleanly_and_preserve_state(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        runtime = PrivateRuntimeDirectory(root / "state", root)

        def seed_and_verify(version: str, database: Path) -> None:
            with closing(sqlite3.connect(database)) as connection:
                if version == "001_initial.sql":
                    connection.execute(
                        """INSERT INTO operations(
                               id, kind, state, created_at, updated_at
                           ) VALUES (
                               'synthetic-shadow-owner', 'dispatch', 'pending',
                               'synthetic', 'synthetic'
                           )"""
                    )
                    connection.commit()
                self.assertEqual(
                    connection.execute(
                        "SELECT state FROM operations WHERE id = 'synthetic-shadow-owner'"
                    ).fetchone(),
                    ("pending",),
                )

        applied = apply_migrations_with_restarts(
            runtime,
            after_migration=seed_and_verify,
        )
        self.assertEqual(
            applied,
            (
                "001_initial.sql",
                "002_queue_and_fences.sql",
                "003_scheduler.sql",
                "004_scheduler_authority.sql",
                "005_transport.sql",
                "006_completion_recovery.sql",
                "007_disabled_callback_recovery.sql",
                "008_opencode_delivery.sql",
                "009_transport_adapter_selection.sql",
                "010_local_codex_callbacks.sql",
                "011_isolated_review_sessions.sql",
                "012_isolated_session_cleanup.sql",
                "013_provisional_review_sessions.sql",
                "014_durable_completion_results.sql",
                "015_agent_lifecycle.sql",
                "016_cancelled_session_cleanup.sql",
                "017_child_completion_barrier.sql",
                "018_llm_behaviour.sql",
                "019_control_pool_expansion.sql",
                "020_codex_source_routes.sql",
                "021_slot_session_rebind.sql",
                "022_child_barrier_generation.sql",
                "023_descendant_budget.sql",
                "024_completed_transcript_archive.sql",
                "025_callback_delivery_reconciliation.sql",
                "026_source_inbox_read_indexes.sql",
                "027_persistent_session_close.sql",
            ),
        )
        restarted = RigStore(runtime)
        restarted.initialize()
        with closing(sqlite3.connect(restarted.path)) as connection:
            self.assertEqual(
                tuple(
                    (str(row[0]), str(row[1]), int(row[2]))
                    for row in connection.execute(
                        """SELECT id, lane, position FROM scheduler_slots
                           ORDER BY rowid"""
                    )
                ),
                EXPECTED_SLOT_TOPOLOGY,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM operations WHERE id = 'synthetic-shadow-owner'"
                ).fetchone(),
                ("pending",),
            )


class CorruptedSnapshotExercises(unittest.TestCase):
    def test_missing_and_corrupted_sections_degrade_visibly_with_exact_topology(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        store = RigStore(PrivateRuntimeDirectory(root / "state", root))
        store.initialize()
        with closing(sqlite3.connect(store.path, isolation_level=None)) as connection:
            connection.execute("BEGIN")
            snapshot = dict(_CockpitSnapshotProjection().capture(connection))
            connection.rollback()

        exercises = []
        for section in ("queue", "attention", "metrics", "recent_turns"):
            missing = copy.deepcopy(snapshot)
            del missing[section]
            exercises.append((f"missing {section}", missing))
        corrupted = copy.deepcopy(snapshot)
        corrupted["snapshot_version"]["event_sequence"] = 2**1000
        corrupted["worker_graph"]["workers"][0]["transport"] = {"state": object()}
        exercises.append(("corrupted durable values", corrupted))

        for label, exercise in exercises:
            with self.subTest(label=label):
                normalized = normalize_snapshot(exercise)
                self.assertIn(
                    normalized["availability"]["status"],
                    {"degraded", "unavailable"},
                )
                self.assertEqual(len(normalized["lanes"]), 5)
                self.assertEqual(
                    sum(len(lane["slots"]) for lane in normalized["lanes"]),
                    13,
                )
                terminal = render_terminal(exercise, width=80)
                self.assertIn("Warnings", terminal)
                self.assertNotIn("<object object", terminal)


if __name__ == "__main__":
    unittest.main()
