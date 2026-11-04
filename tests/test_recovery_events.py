from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from oc_rig.completion.service import _create_completion
from oc_rig.adapters import DisabledAdapter
from oc_rig.daemon.controller import OperationRejected, _RigController
from oc_rig.recovery import (
    CORPSE_SECONDS,
    PRODUCTIVE_ACTIVE_SECONDS,
    STALE_THINKING_SECONDS,
    STALLED_SECONDS,
    UNANSWERED_SECONDS,
    ZERO_OUTPUT_SECONDS,
    ClockReading,
    ClockRollbackError,
    RecoveryPhase,
    threshold_seconds,
)
from oc_rig.recovery.service import _create_recovery
from oc_rig.scheduler.service import _Scheduler
from oc_rig.store import DaemonAuthorityError, PrivateRuntimeDirectory, RigStore
from oc_rig.store.database import _DaemonAuthority, _utc_now
from oc_rig.transport.service import _create_transport


class ManualTrustedClock:
    def __init__(self) -> None:
        self.epoch = "manual-epoch-1"
        self.wall_us = 1_000_000
        self.monotonic_ns = 1_000_000_000

    def read(self) -> ClockReading:
        return ClockReading(self.epoch, self.wall_us, self.monotonic_ns)

    def advance(self, seconds: float) -> None:
        microseconds = int(seconds * 1_000_000)
        self.wall_us += microseconds
        self.monotonic_ns += microseconds * 1_000

    def restart(self) -> None:
        self.epoch = "manual-epoch-2"
        self.monotonic_ns = 10_000


class RecoveryEventTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.store = RigStore(
            PrivateRuntimeDirectory(self.root / "state", self.root)
        )
        lock_path = self.store.path.parent / "rigd.lock"
        lock_path.touch(mode=0o600)
        lock_path.chmod(0o600)
        self.store.initialize()
        descriptor = os.open(lock_path, os.O_RDWR)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        authority = object.__new__(_DaemonAuthority)
        authority._store = self.store
        authority._closed = False
        authority._descriptor = descriptor
        authority._path = lock_path
        linked = lock_path.lstat()
        authority._identity = (linked.st_dev, linked.st_ino)
        authority._activate_usage_guard()
        self.authority = authority
        self.addCleanup(authority.close)
        self.capability = object()
        self.clock = ManualTrustedClock()
        completion = _create_completion(self.store, authority, self.capability)
        recovery = _create_recovery(
            self.store,
            authority,
            self.capability,
            clock=self.clock,
        )
        transport = _create_transport(
            self.store,
            authority,
            self.capability,
            completion,
            DisabledAdapter(),
        )
        scheduler = object.__new__(_Scheduler)
        scheduler.store = self.store
        scheduler._authority = authority
        scheduler._clock = _utc_now
        controller = object.__new__(_RigController)
        controller.store = self.store
        controller.max_idempotency_entries = 4096
        controller._authority = authority
        controller._scheduler = scheduler
        controller._transport = transport
        controller._completion = completion
        controller._recovery = recovery
        self.controller = controller
        self.recovery = recovery

    def call(
        self,
        operation: str,
        params: dict[str, object],
        *,
        idempotency_id: str,
    ) -> dict[str, object]:
        material = json.dumps(
            {"operation": operation, "params": params},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return dict(
            self.controller.execute_durable(
                self.capability,
                idempotency_id,
                hashlib.sha256(material).hexdigest(),
                operation,
                params,
            )
        )

    def observe(
        self,
        label: str,
        phase: str,
        *,
        productive: bool = False,
        evidence: str = "none",
        generation: int = 1,
        work_id: str | None = None,
        request: str | None = None,
    ) -> dict[str, object]:
        return self.call(
            "recovery.observe.v1",
            {
                "target_id": f"target-{label}",
                "work_id": work_id or f"work-{label}",
                "generation": generation,
                "phase": phase,
                "productive": productive,
                "evidence": evidence,
            },
            idempotency_id=request or f"observe-{label}-{self.clock.wall_us}",
        )

    def fire(self, timer_id: str, request: str) -> dict[str, object]:
        return self.call(
            "recovery.timer.fire.v1",
            {"timer_id": timer_id},
            idempotency_id=request,
        )

    def rows(self, table: str) -> list[sqlite3.Row]:
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.row_factory = sqlite3.Row
            return list(connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid'))

    def open_episode(self, label: str) -> dict[str, object]:
        observed = self.observe(label, "corpse")
        self.clock.advance(CORPSE_SECONDS)
        return self.fire(str(observed["timer_id"]), f"open-episode-{label}")

    def test_all_thresholds_are_explicit_and_inclusive(self) -> None:
        cases = (
            (RecoveryPhase.ACTIVE, True, PRODUCTIVE_ACTIVE_SECONDS),
            (RecoveryPhase.ACTIVE, False, ZERO_OUTPUT_SECONDS),
            (RecoveryPhase.HANDED_OFF, False, UNANSWERED_SECONDS),
            (RecoveryPhase.TOOL_FLOW, False, STALLED_SECONDS),
            (RecoveryPhase.BUSY, False, STALLED_SECONDS),
            (RecoveryPhase.THINKING, False, STALE_THINKING_SECONDS),
            (RecoveryPhase.CORPSE, False, CORPSE_SECONDS),
        )
        for index, (phase, productive, threshold) in enumerate(cases):
            with self.subTest(phase=phase, productive=productive):
                self.assertEqual(
                    threshold_seconds(phase, productive=productive), threshold
                )
                observed = self.observe(
                    f"threshold-{index}", phase.value, productive=productive
                )
                timer = str(observed["timer_id"])
                self.clock.advance(threshold - 0.000001)
                early = self.fire(timer, f"early-{index}")
                self.assertFalse(early["due"])
                self.assertEqual(early["state"], "scheduled")
                self.clock.advance(0.000001)
                exact = self.fire(timer, f"exact-{index}")
                self.assertTrue(exact["due"])
                self.assertEqual(exact["state"], "fired")

    def test_queued_is_not_timed_and_productive_progress_resets_due_event(self) -> None:
        queued = self.observe("queued", "queued")
        self.assertIsNone(queued["timer_id"])
        first = self.observe("reset", "active", productive=True)
        self.clock.advance(30)
        second = self.observe(
            "reset", "active", productive=True, request="observe-reset-again"
        )
        self.assertNotEqual(first["timer_id"], second["timer_id"])
        old = self.fire(str(first["timer_id"]), "fire-cancelled-reset")
        self.assertEqual(old["state"], "cancelled")
        self.clock.advance(30)
        not_yet = self.fire(str(second["timer_id"]), "fire-reset-not-yet")
        self.assertFalse(not_yet["due"])
        self.clock.advance(30)
        self.assertTrue(
            self.fire(str(second["timer_id"]), "fire-reset-exact")["due"]
        )

    def test_queued_observation_closes_episode_and_late_tick_is_inert(self) -> None:
        opened = self.open_episode("queued-tick")
        recovery_timer = str(opened["next_timer_id"])
        queued = self.observe(
            "queued-tick", "queued", request="observe-queued-after-open"
        )
        self.assertIsNone(queued["timer_id"])
        self.assertEqual(self.rows("recovery_episodes")[0]["state"], "recovered")
        self.clock.advance(60)
        late = self.fire(recovery_timer, "late-queued-tick")
        self.assertEqual(late["state"], "cancelled")
        self.assertFalse(late["due"])
        self.assertEqual(len(self.rows("recovery_episodes")), 1)

    def test_handed_off_resets_episode_then_schedules_unanswered_timer(self) -> None:
        opened = self.open_episode("handed-reset")
        old_timer = str(opened["next_timer_id"])
        handed = self.observe(
            "handed-reset", "handed_off", request="observe-handed-after-open"
        )
        self.assertEqual(handed["threshold_seconds"], UNANSWERED_SECONDS)
        self.assertNotEqual(handed["timer_id"], old_timer)
        self.assertEqual(self.rows("recovery_episodes")[0]["state"], "recovered")
        self.assertEqual(
            next(row for row in self.rows("recovery_timers") if row["id"] == old_timer)[
                "state"
            ],
            "cancelled",
        )
        target = self.rows("recovery_targets")[0]
        self.assertIsNone(target["episode_id"])
        self.assertEqual(target["current_timer_id"], handed["timer_id"])

    def test_nonproductive_tool_flow_preserves_valid_episode_timer(self) -> None:
        opened = self.open_episode("tool-preserve")
        episode = str(opened["episode_id"])
        recovery_timer = str(opened["next_timer_id"])
        tool = self.observe(
            "tool-preserve", "tool_flow", request="observe-tool-flow-open"
        )
        self.assertEqual(tool["timer_id"], recovery_timer)
        self.assertIsNone(tool["threshold_seconds"])
        target = self.rows("recovery_targets")[0]
        self.assertEqual(target["episode_id"], episode)
        self.assertEqual(target["current_timer_id"], recovery_timer)
        self.assertEqual(self.rows("recovery_episodes")[0]["state"], "open")

    def test_productive_tool_flow_resets_episode_to_fresh_stall_timer(self) -> None:
        opened = self.open_episode("tool-reset")
        old_timer = str(opened["next_timer_id"])
        tool = self.observe(
            "tool-reset",
            "tool_flow",
            productive=True,
            request="observe-productive-tool-flow",
        )
        self.assertEqual(tool["threshold_seconds"], STALLED_SECONDS)
        self.assertNotEqual(tool["timer_id"], old_timer)
        self.assertEqual(self.rows("recovery_episodes")[0]["state"], "recovered")
        target = self.rows("recovery_targets")[0]
        self.assertIsNone(target["episode_id"])
        self.assertEqual(target["current_timer_id"], tool["timer_id"])

    def test_active_nonproductive_preserves_same_episode_and_timer(self) -> None:
        opened = self.open_episode("active-preserve")
        episode = str(opened["episode_id"])
        recovery_timer = str(opened["next_timer_id"])
        active = self.observe(
            "active-preserve", "active", request="observe-active-nonproductive"
        )
        self.assertEqual(active["timer_id"], recovery_timer)
        self.assertIsNone(active["threshold_seconds"])
        self.clock.advance(60)
        due = self.fire(recovery_timer, "fire-preserved-active-timer")
        self.assertEqual(due["episode_id"], episode)
        self.assertEqual(due["attempt"], 1)
        while_due = self.observe(
            "active-preserve",
            "active",
            request="observe-active-with-due-attempt",
        )
        self.assertIsNone(while_due["timer_id"])
        self.assertEqual(self.rows("recovery_targets")[0]["episode_id"], episode)
        self.assertEqual(self.rows("recovery_attempts")[0]["state"], "due")
        self.assertEqual(len(self.rows("recovery_episodes")), 1)

    def test_unverified_callback_evidence_cannot_override_heuristics(self) -> None:
        observed = self.observe("evidence", "corpse")
        self.clock.advance(CORPSE_SECONDS)
        opened = self.fire(str(observed["timer_id"]), "open-evidence-episode")
        self.assertIsNotNone(opened["episode_id"])
        with self.assertRaises(OperationRejected) as unverified:
            self.observe(
                "evidence",
                "corpse",
                evidence="callback",
                request="callback-evidence",
            )
        self.assertEqual(unverified.exception.code, "ownership_conflict")
        self.assertEqual(self.rows("recovery_episodes")[0]["state"], "open")

    def test_fast_then_normal_schedule_opens_no_progress_circuit(self) -> None:
        observed = self.observe("schedule", "corpse")
        self.clock.advance(CORPSE_SECONDS)
        detected = self.fire(str(observed["timer_id"]), "detect-schedule")
        episode = str(detected["episode_id"])
        timer = str(detected["next_timer_id"])
        delays = (60, 60, 60, 180, 300, 600)
        tiers = ("fast", "fast", "fast", "normal", "normal", "normal")
        for attempt, (delay, tier) in enumerate(zip(delays, tiers, strict=True), 1):
            self.clock.advance(delay)
            due = self.fire(timer, f"fire-recovery-{attempt}")
            self.assertEqual(due["attempt"], attempt)
            self.assertEqual(due["tier"], tier)
            result = self.call(
                "recovery.attempt.record.v1",
                {
                    "episode_id": episode,
                    "attempt": attempt,
                    "result": "no_progress",
                    "failure_class": None,
                    "reason": "same_state",
                },
                idempotency_id=f"result-recovery-{attempt}",
            )
            if attempt < 6:
                self.assertEqual(result["circuit_state"], "closed")
                timer = str(result["next_timer_id"])
            else:
                self.assertEqual(result["circuit_state"], "open")
                self.assertIsNone(result["next_timer_id"])
        self.assertEqual(self.rows("recovery_episodes")[0]["state"], "attention")
        self.assertEqual(len(self.rows("recovery_attempts")), 6)

    def test_permission_and_delivery_unknown_are_terminal_without_retry(self) -> None:
        for index, failure in enumerate(("permission", "delivery_unknown")):
            observed = self.observe(f"terminal-{index}", "corpse")
            self.clock.advance(CORPSE_SECONDS)
            detected = self.fire(
                str(observed["timer_id"]), f"detect-terminal-{index}"
            )
            self.clock.advance(60)
            due = self.fire(
                str(detected["next_timer_id"]), f"fire-terminal-{index}"
            )
            result = self.call(
                "recovery.attempt.record.v1",
                {
                    "episode_id": due["episode_id"],
                    "attempt": 1,
                    "result": "terminal_failure",
                    "failure_class": failure,
                    "reason": f"terminal_{failure}",
                },
                idempotency_id=f"result-terminal-{index}",
            )
            self.assertEqual(result["circuit_state"], "open")
            self.assertIsNone(result["next_timer_id"])

    def test_new_generation_cancels_old_timer_and_rejects_late_event(self) -> None:
        first = self.observe("generation-one", "thinking", work_id="shared-work")
        second = self.observe(
            "generation-two",
            "thinking",
            generation=2,
            work_id="shared-work",
        )
        self.assertNotEqual(first["timer_id"], second["timer_id"])
        self.assertEqual(self.rows("recovery_timers")[0]["state"], "cancelled")
        with self.assertRaises(OperationRejected) as stale:
            self.observe(
                "late-generation-one",
                "thinking",
                generation=1,
                work_id="shared-work",
            )
        self.assertEqual(stale.exception.code, "ownership_conflict")

    def test_same_epoch_wall_rollback_and_forward_do_not_fire_timer(self) -> None:
        observed = self.observe("clock", "active")
        timer = str(observed["timer_id"])
        original_wall = self.clock.wall_us
        self.clock.wall_us += 10_000_000_000
        self.assertFalse(self.fire(timer, "clock-forward")["due"])
        self.clock.wall_us = max(0, original_wall - 500_000)
        self.assertFalse(self.fire(timer, "clock-backward")["due"])
        self.clock.monotonic_ns += ZERO_OUTPUT_SECONDS * 1_000_000_000
        self.assertTrue(self.fire(timer, "clock-monotonic-due")["due"])
        self.clock.monotonic_ns -= 1
        with self.assertRaises(ClockRollbackError):
            self.observe("clock-rollback", "active")

    def test_restart_uses_trusted_wall_and_persisted_timer(self) -> None:
        observed = self.observe("restart", "corpse")
        self.clock.advance(CORPSE_SECONDS)
        self.clock.restart()
        restarted = _create_recovery(
            self.store,
            self.authority,
            self.capability,
            clock=self.clock,
        )
        self.controller._recovery = restarted
        fired = self.fire(str(observed["timer_id"]), "fire-after-restart")
        self.assertTrue(fired["due"])
        self.assertEqual(fired["state"], "fired")

    def test_repeated_concurrent_double_fire_creates_one_episode_each(self) -> None:
        with ThreadPoolExecutor(max_workers=2) as executor:
            for repetition in range(64):
                observed = self.observe(f"concurrent-{repetition}", "corpse")
                self.clock.advance(CORPSE_SECONDS)
                timer = str(observed["timer_id"])

                def invoke(index: int) -> dict[str, object]:
                    return self.fire(
                        timer, f"concurrent-fire-{repetition}-{index}"
                    )

                results = list(executor.map(invoke, range(2)))
                self.assertEqual(
                    {result["state"] for result in results}, {"fired"}
                )
        self.assertEqual(len(self.rows("recovery_episodes")), 64)
        self.assertEqual(
            len([row for row in self.rows("recovery_timers") if row["kind"] == "recovery"]),
            64,
        )

    def test_recovery_service_starts_no_polling_thread(self) -> None:
        before = {thread.ident for thread in threading.enumerate()}
        self.observe("threads", "handed_off")
        after = {thread.ident for thread in threading.enumerate()}
        self.assertEqual(after, before)

    def test_blocked_persistent_open_is_refused_after_authority_close_starts(self) -> None:
        open_started = threading.Event()
        open_errors: list[BaseException] = []
        close_errors: list[BaseException] = []

        def open_connection() -> None:
            open_started.set()
            try:
                self.store._open_daemon_connection(self.authority)
            except BaseException as error:
                open_errors.append(error)

        def close_authority() -> None:
            try:
                self.authority.close()
            except BaseException as error:
                close_errors.append(error)

        opener = threading.Thread(target=open_connection)
        closer = threading.Thread(target=close_authority)
        with self.store._serialization_lock:
            opener.start()
            self.assertTrue(open_started.wait(timeout=2))
            closer.start()
            with self.authority._usage_condition:
                self.assertTrue(
                    self.authority._usage_condition.wait_for(
                        lambda: self.authority._closing,
                        timeout=2,
                    )
                )
        opener.join(timeout=2)
        closer.join(timeout=2)
        self.assertFalse(opener.is_alive())
        self.assertFalse(closer.is_alive())
        self.assertEqual(len(open_errors), 1)
        self.assertIsInstance(open_errors[0], DaemonAuthorityError)
        self.assertFalse(close_errors)
        self.assertIsNone(self.store._daemon_connection)
        self.assertEqual(self.authority._active_leases, 0)

    def test_persistent_connection_lease_releases_on_close_and_open_failure(self) -> None:
        self.store._open_daemon_connection(self.authority)
        self.assertEqual(self.authority._active_leases, 1)
        self.store._close_daemon_connection()
        self.assertEqual(self.authority._active_leases, 0)

        with patch.object(
            self.store,
            "_connect",
            side_effect=sqlite3.OperationalError("injected open failure"),
        ):
            with self.assertRaises(sqlite3.OperationalError):
                self.store._open_daemon_connection(self.authority)
        self.assertIsNone(self.store._daemon_connection)
        self.assertIsNone(self.store._daemon_connection_lease)
        self.assertEqual(self.authority._active_leases, 0)

    def test_reentrant_close_refuses_active_lease_without_releasing_authority(self) -> None:
        with self.store._serialization_lock:
            lease = self.authority._acquire_lease_locked(self.store)
            with self.assertRaisesRegex(DaemonAuthorityError, "leases remain"):
                self.authority.close()
            self.assertFalse(self.authority._closed)
            self.assertFalse(self.authority._closing)
            lease.close()
        self.authority.close()
        self.assertTrue(self.authority._closed)

    def test_close_waits_while_existing_lease_finishes_validation(self) -> None:
        close_errors: list[BaseException] = []

        def close_authority() -> None:
            try:
                self.authority.close()
            except BaseException as error:
                close_errors.append(error)

        closer = threading.Thread(target=close_authority)
        with self.store._serialization_lock:
            lease = self.authority._acquire_lease_locked(self.store)
            closer.start()
            with self.authority._usage_condition:
                self.assertTrue(
                    self.authority._usage_condition.wait_for(
                        lambda: self.authority._closing,
                        timeout=2,
                    )
                )
            self.authority._assert_for(self.store)
            lease.close()
        closer.join(timeout=2)
        self.assertFalse(closer.is_alive())
        self.assertFalse(close_errors)
        self.assertTrue(self.authority._closed)


if __name__ == "__main__":
    unittest.main()
