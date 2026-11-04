from __future__ import annotations

import sqlite3
import unittest
from contextlib import closing

from oc_rig.completion.service import _CompletionService
from oc_rig.protocol.client import RigClientError
from oc_rig.store import ReadOnlySnapshot
from tests import test_transport_delivery as transport_tests


class CompletionJoinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = transport_tests.TransportDaemonTests(methodName="runTest")
        self.harness.setUp()
        self.addCleanup(self.harness.tearDown)
        self.addCleanup(self.harness.doCleanups)

    def _rows(self, table: str) -> list[sqlite3.Row]:
        return self.harness.rows(table)

    def _prepare(self, label: str) -> tuple[dict[str, object], sqlite3.Row]:
        self.harness.ready(label)
        self.harness.restart_daemon(mode="accepted")
        transport = self.harness.dispatch(label)
        self.assertEqual(transport["state"], "accepted")
        registration = self._rows("transport_completion_registrations")[0]
        return transport, registration

    def _accept(
        self,
        label: str,
        registration: sqlite3.Row,
        *,
        request: str,
        generation: int | None = None,
    ) -> dict[str, object]:
        return self.harness.call(
            "completion.accept.v1",
            {
                "completion_key": f"completion-key-{label}",
                "registration_id": registration["id"],
                "work_id": f"work-{label}",
                "generation": generation or int(registration["assignment_attempt"]),
                "outcome": "succeeded",
            },
            idempotency_id=request,
        )

    def _release_scope(self, label: str) -> None:
        claim = self.harness.claims[label]
        self.harness.call(
            "scope.release.v1",
            {
                "claim_id": claim["claim_id"],
                "owner_id": claim["owner_id"],
                "attempt": claim["attempt"],
                "fence_token": claim["fence_token"],
            },
            idempotency_id=f"scope-release-{label}",
        )

    def _release_assignment(self, label: str) -> None:
        assignment = self._rows("scheduler_assignments")[0]
        self.harness.call(
            "scheduler.release.v1",
            {
                "reservation_id": assignment["id"],
                "work_id": assignment["work_id"],
                "owner_id": assignment["owner_id"],
                "attempt": assignment["attempt"],
                "fence_token": assignment["fence_token"],
                "outcome": "completed",
            },
            idempotency_id=f"assignment-release-{label}",
        )

    def test_route_registration_precedes_transport_send_intent(self) -> None:
        self._prepare("ordered-route")
        events = self._rows("events")
        names = [row["event_type"] for row in events]
        self.assertLess(
            names.index("completion.route.registered"),
            names.index("transport.prepared"),
        )
        route = self._rows("return_routes")[0]
        callback = self._rows("transport_callback_registrations")[0]
        self.assertEqual(route["state"], "registered")
        self.assertEqual(callback["return_route_id"], route["id"])
        self.assertEqual(callback["generation"], route["generation"])

    def test_completion_atomically_releases_both_exact_fences(self) -> None:
        _, registration = self._prepare("completion-first")
        accepted = self._accept(
            "completion-first", registration, request="accept-completion-first"
        )
        self.assertEqual(accepted["route_state"], "ready")
        self.assertEqual(accepted["delivery_state"], "blocked")
        self.assertEqual(self._rows("scheduler_assignments")[0]["state"], "released")
        self.assertEqual(self._rows("scope_claims")[0]["state"], "released")
        self.assertEqual(self._rows("scheduler_work")[0]["state"], "completed")
        self.assertEqual(
            self._rows("outbox")[0]["disabled_reason"],
            "local_codex_route_missing",
        )

    def test_release_before_completion_joins_and_duplicate_is_exactly_once(self) -> None:
        _, registration = self._prepare("release-first")
        self._release_scope("release-first")
        self._release_assignment("release-first")
        first = self._accept("release-first", registration, request="accept-first")
        duplicate = self._accept("release-first", registration, request="accept-duplicate")
        self.assertEqual(duplicate, first)
        self.assertEqual(len(self._rows("completion_events")), 1)
        self.assertEqual(len(self._rows("callbacks")), 1)
        self.assertEqual(len(self._rows("outbox")), 1)
        self.assertEqual(first["route_state"], "ready")
        self.assertEqual(first["delivery_state"], "blocked")

    def test_local_route_is_promoted_once_by_atomic_completion(self) -> None:
        label = "local-completion"
        self.harness.ready(label)
        self.harness.restart_daemon(mode="accepted")
        transport = self.harness.call(
            "transport.dispatch.v1",
            {
                "work_id": f"work-{label}",
                "pool": "tensorhost",
                "payload": {"prompt": "safe work"},
                "return_route": {
                    "kind": "local_codex",
                    "thread_id": "00000000-0000-7000-8000-abcdef000002",
                },
            },
            idempotency_id=f"dispatch-{label}",
        )
        self.assertEqual(transport["state"], "accepted")
        registration = self._rows("transport_completion_registrations")[0]
        with self.assertRaises(RigClientError) as rejected:
            self._accept(label, registration, request="accept-local-without-result")
        self.assertEqual(rejected.exception.code, "ownership_conflict")
        self.assertEqual(self._rows("completion_events"), [])
        self.assertEqual(self._rows("callbacks"), [])
        self.assertEqual(self._rows("outbox"), [])

    def test_stale_generation_cannot_consume_newer_or_older_route(self) -> None:
        _, registration = self._prepare("generation")
        with self.assertRaises(RigClientError) as stale:
            self._accept(
                "generation",
                registration,
                request="accept-wrong-generation",
                generation=int(registration["assignment_attempt"]) + 1,
            )
        self.assertEqual(stale.exception.code, "ownership_conflict")
        self.assertEqual(len(self._rows("completion_events")), 0)
        self.assertEqual(self._rows("return_routes")[0]["state"], "registered")

    def test_child_enabled_completion_requires_daemon_barrier(self) -> None:
        label = "child-barrier-required"
        _, registration = self._prepare(label)
        with closing(sqlite3.connect(self.harness.store.path)) as connection, connection:
            connection.execute(
                "DROP TRIGGER scheduler_admission_decisions_are_immutable_update"
            )
            connection.execute(
                "UPDATE scheduler_admission_decisions SET allow_child_agents = 1"
            )
            connection.execute(
                """CREATE TRIGGER scheduler_admission_decisions_are_immutable_update
                   BEFORE UPDATE ON scheduler_admission_decisions BEGIN
                       SELECT RAISE(ABORT, 'scheduler admission decision is immutable');
                   END"""
            )

        with self.assertRaises(RigClientError):
            self._accept(label, registration, request="accept-without-child-barrier")

        self.assertEqual(self._rows("completion_events"), [])
        self.assertEqual(self._rows("completion_child_barriers"), [])

    def test_definite_failed_transport_cannot_later_complete(self) -> None:
        label = "failed-cannot-complete"
        self.harness.ready(label)
        self.harness.restart_daemon(mode="review_agent_invalid")
        transport = self.harness.dispatch(label)
        self.assertEqual(transport["state"], "definite_failed")
        registration = self._rows("transport_completion_registrations")[0]
        with self.assertRaises(RigClientError) as rejected:
            self._accept(
                label, registration, request="accept-definite-failed-transport"
            )
        self.assertEqual(rejected.exception.code, "ownership_conflict")
        self.assertEqual(self._rows("completion_events"), [])
        self.assertEqual(self._rows("return_routes")[0]["state"], "registered")

    def test_interrupted_delivery_becomes_terminal_unknown_exactly_once(self) -> None:
        _, registration = self._prepare("callback-restart")
        self._release_scope("callback-restart")
        self._release_assignment("callback-restart")
        self._accept("callback-restart", registration, request="accept-callback-restart")
        callback = self._rows("callbacks")[0]
        outbox = self._rows("outbox")[0]
        with closing(sqlite3.connect(self.harness.store.path)) as connection, connection:
            connection.execute(
                """UPDATE callbacks SET state = 'delivering', attempts = 1
                   WHERE id = ? AND state = 'blocked'""",
                (callback["id"],),
            )
            connection.execute(
                """UPDATE outbox SET state = 'delivering', attempts = 1
                   WHERE id = ? AND state = 'blocked'""",
                (outbox["id"],),
            )
            connection.execute(
                """INSERT INTO callback_delivery_attempts(
                       id, callback_id, attempt_number, delivery_key, state,
                       started_at_us
                   ) VALUES ('fixture-interrupted-attempt', ?, 1, ?,
                             'delivering', 1)""",
                (callback["id"], callback["delivery_key"]),
            )
        self.harness.restart_daemon()
        self.assertEqual(self._rows("callbacks")[0]["state"], "attention")
        self.assertEqual(
            self._rows("callbacks")[0]["failure_class"], "delivery_unknown"
        )
        self.assertEqual(self._rows("outbox")[0]["state"], "attention")
        self.assertEqual(
            self._rows("callback_delivery_attempts")[0]["state"], "attention"
        )
        self.assertEqual(len(self._rows("callback_delivery_attempts")), 1)
        events_before = len(self._rows("events"))
        self.harness.restart_daemon()
        self.assertEqual(len(self._rows("callback_delivery_attempts")), 1)
        self.assertEqual(len(self._rows("events")), events_before)

    def test_shipped_protocol_rejects_callback_worker_mutations(self) -> None:
        self.assertFalse(hasattr(_CompletionService, "begin_next"))
        self.assertFalse(hasattr(_CompletionService, "finish"))
        for operation, params in (
            ("callback.begin.v1", {}),
            (
                "callback.finish.v1",
                {
                    "delivery_key": "delivery-disabled",
                    "attempt": 1,
                    "disposition": "delivered",
                    "failure_class": None,
                },
            ),
        ):
            with self.subTest(operation=operation), self.assertRaises(RigClientError) as rejected:
                self.harness.call(
                    operation,
                    params,
                    idempotency_id=f"rejected-{operation}",
                )
            self.assertEqual(rejected.exception.code, "unknown_operation")

    def test_durable_claim_and_completion_evidence_override_recovery(self) -> None:
        _, registration = self._prepare("evidence")
        observed = self.harness.call(
            "recovery.observe.v1",
            {
                "target_id": "target-evidence",
                "work_id": "work-evidence",
                "generation": 1,
                "phase": "thinking",
                "productive": False,
                "evidence": "none",
            },
            idempotency_id="observe-evidence",
        )
        self.assertIsNotNone(observed["timer_id"])
        claimed = self.harness.call(
            "recovery.observe.v1",
            {
                "target_id": "target-evidence",
                "work_id": "work-evidence",
                "generation": 1,
                "phase": "thinking",
                "productive": False,
                "evidence": "claim",
            },
            idempotency_id="recovery-claim-evidence",
        )
        self.assertEqual(claimed["phase"], "completed")
        self._accept("evidence", registration, request="accept-evidence")
        self.assertEqual(self._rows("recovery_targets")[0]["phase"], "completed")
        self._release_scope("evidence")
        self._release_assignment("evidence")
        self.assertEqual(self._rows("outbox")[0]["state"], "blocked")

    def test_public_snapshot_redacts_transport_payload_and_adapter_output(self) -> None:
        self._prepare("private-snapshot")
        snapshot = ReadOnlySnapshot(self.harness.store).capture()
        delivery = snapshot.rows("transport_deliveries")[0]
        attempt = snapshot.rows("transport_attempts")[0]
        self.assertEqual(delivery["payload_json"], "<redacted>")
        if attempt["output_json"] is not None:
            self.assertEqual(attempt["output_json"], "<redacted>")
        for table in ("completion_events", "return_routes", "callbacks", "outbox"):
            for row in snapshot.rows(table):
                self.assertNotIn("payload_json", row)


if __name__ == "__main__":
    unittest.main()
