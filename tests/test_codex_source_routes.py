from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from oc_rig.daemon.controller import OperationRejected, _RigController
from oc_rig.daemon.security import PrivateSocketPath
from oc_rig.daemon.server import RigDaemon
from oc_rig.protocol.client import RigClient, RigClientError


class _Transport:
    def _assert_authority(self, capability: object) -> None:
        if capability != "authority":
            raise PermissionError


class _Store:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    @contextmanager
    def _daemon_transaction(self, _authority: object):
        with self.connection:
            yield self.connection

    @contextmanager
    def _daemon_read_transaction(self, _authority: object):
        yield self.connection


def _controller() -> _RigController:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    migration = Path(__file__).parents[1] / "src/oc_rig/store/migrations/020_codex_source_routes.sql"
    connection.executescript(migration.read_text(encoding="utf-8"))
    connection.executescript(
        """
        CREATE TABLE daemon_request_outcomes(
          idempotency_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
          operation TEXT NOT NULL, ok INTEGER NOT NULL,
          outcome_json TEXT NOT NULL, completed_at TEXT NOT NULL
        );
        CREATE TABLE daemon_outcome_reservations(idempotency_id TEXT PRIMARY KEY);
        CREATE TABLE scheduler_assignments(
          id TEXT PRIMARY KEY, work_id TEXT NOT NULL, slot_id TEXT NOT NULL,
          attempt INTEGER NOT NULL, fence_token TEXT NOT NULL
        );
        CREATE TABLE scope_claims(
          id TEXT PRIMARY KEY, attempt INTEGER NOT NULL, fence_token TEXT NOT NULL
        );
        CREATE TABLE transport_deliveries(
          id TEXT PRIMARY KEY, work_id TEXT NOT NULL, assignment_id TEXT NOT NULL,
          assignment_attempt INTEGER NOT NULL, assignment_fence TEXT NOT NULL,
          scope_claim_id TEXT NOT NULL, scope_claim_attempt INTEGER NOT NULL,
          scope_claim_fence TEXT NOT NULL
        );
        CREATE TABLE transport_completion_registrations(
          id TEXT PRIMARY KEY, transport_id TEXT NOT NULL, work_id TEXT NOT NULL,
          assignment_id TEXT NOT NULL, assignment_attempt INTEGER NOT NULL,
          assignment_fence TEXT NOT NULL
        );
        CREATE TABLE return_routes(
          id TEXT PRIMARY KEY, transport_id TEXT NOT NULL,
          completion_registration_id TEXT NOT NULL, work_id TEXT NOT NULL,
          generation INTEGER NOT NULL, assignment_id TEXT NOT NULL,
          assignment_fence TEXT NOT NULL, scope_claim_id TEXT NOT NULL,
          scope_claim_attempt INTEGER NOT NULL, scope_claim_fence TEXT NOT NULL
        );
        CREATE TABLE local_codex_return_routes(
          return_route_id TEXT PRIMARY KEY, thread_id TEXT NOT NULL
        );
        CREATE TABLE transport_callback_registrations(
          id TEXT PRIMARY KEY, transport_id TEXT NOT NULL,
          completion_registration_id TEXT NOT NULL, return_route_id TEXT NOT NULL,
          work_id TEXT NOT NULL, generation INTEGER NOT NULL
        );
        CREATE TABLE completion_events(
          id TEXT PRIMARY KEY, completion_registration_id TEXT NOT NULL,
          transport_id TEXT NOT NULL, work_id TEXT NOT NULL, generation INTEGER NOT NULL,
          received_at_us INTEGER NOT NULL
        );
        CREATE TABLE callbacks(
          id TEXT PRIMARY KEY, completion_event_id TEXT NOT NULL,
          return_route_id TEXT NOT NULL, delivery_key TEXT NOT NULL,
          state TEXT NOT NULL, created_at_us INTEGER NOT NULL, attention_reason TEXT
        );
        CREATE TABLE outbox(
          callback_id TEXT PRIMARY KEY, delivery_key TEXT NOT NULL, state TEXT NOT NULL,
          topic TEXT NOT NULL, aggregate_type TEXT NOT NULL, aggregate_id TEXT NOT NULL,
          disabled_reason TEXT
        );
        CREATE TABLE completion_results(
          result_ref TEXT PRIMARY KEY, completion_event_id TEXT NOT NULL,
          transport_id TEXT NOT NULL, completion_registration_id TEXT NOT NULL,
          callback_registration_id TEXT NOT NULL, work_id TEXT NOT NULL,
          generation INTEGER NOT NULL, created_at_us INTEGER NOT NULL
        );
        """
    )
    controller = object.__new__(_RigController)
    controller._transport = _Transport()
    controller._authority = object()
    controller.store = _Store(connection)
    controller.max_idempotency_entries = 100
    return controller

THREAD_A = "123e4567-e89b-42d3-a456-426614174000"
THREAD_B = "123e4567-e89b-42d3-a456-426614174001"


def _insert_source_callback(
    controller: _RigController,
    label: str,
    *,
    thread_id: str,
    state: str,
    created_at_us: int,
    slot_id: str = "control-1",
    reason: str | None = None,
    work_id: str | None = None,
) -> None:
    connection = controller.store.connection
    assignment = f"assignment-{label}"
    work = work_id or f"work-{label}"
    route = f"route-{label}"
    callback = f"callback-{label}"
    transport = f"transport-{label}"
    completion_registration = f"completion-registration-{label}"
    callback_registration = f"callback-registration-{label}"
    completion_event = f"completion-event-{label}"
    result_ref = f"result-{label}"
    scope_claim = f"scope-{label}"
    assignment_fence = f"assignment-fence-{label}"
    scope_fence = f"scope-fence-{label}"
    delivery_key = f"delivery-{label}"
    connection.execute(
        "INSERT INTO scheduler_assignments(id, work_id, slot_id, attempt, fence_token) VALUES (?, ?, ?, 1, ?)",
        (assignment, work, slot_id, assignment_fence),
    )
    connection.execute(
        "INSERT INTO scope_claims(id, attempt, fence_token) VALUES (?, 1, ?)",
        (scope_claim, scope_fence),
    )
    connection.execute(
        """INSERT INTO transport_deliveries(
               id, work_id, assignment_id, assignment_attempt, assignment_fence,
               scope_claim_id, scope_claim_attempt, scope_claim_fence
           ) VALUES (?, ?, ?, 1, ?, ?, 1, ?)""",
        (transport, work, assignment, assignment_fence, scope_claim, scope_fence),
    )
    connection.execute(
        """INSERT INTO transport_completion_registrations(
               id, transport_id, work_id, assignment_id, assignment_attempt, assignment_fence
           ) VALUES (?, ?, ?, ?, 1, ?)""",
        (completion_registration, transport, work, assignment, assignment_fence),
    )
    connection.execute(
        """INSERT INTO return_routes(
               id, transport_id, completion_registration_id, work_id, generation,
               assignment_id, assignment_fence, scope_claim_id, scope_claim_attempt,
               scope_claim_fence
           ) VALUES (?, ?, ?, ?, 1, ?, ?, ?, 1, ?)""",
        (
            route, transport, completion_registration, work, assignment,
            assignment_fence, scope_claim, scope_fence,
        ),
    )
    connection.execute(
        "INSERT INTO local_codex_return_routes(return_route_id, thread_id) VALUES (?, ?)",
        (route, thread_id),
    )
    connection.execute(
        """INSERT INTO transport_callback_registrations(
               id, transport_id, completion_registration_id, return_route_id, work_id, generation
           ) VALUES (?, ?, ?, ?, ?, 1)""",
        (callback_registration, transport, completion_registration, route, work),
    )
    connection.execute(
        """INSERT INTO completion_events(
               id, completion_registration_id, transport_id, work_id, generation, received_at_us
           ) VALUES (?, ?, ?, ?, 1, ?)""",
        (completion_event, completion_registration, transport, work, created_at_us),
    )
    connection.execute(
        """INSERT INTO callbacks(
               id, completion_event_id, return_route_id, delivery_key, state,
               created_at_us, attention_reason
           ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (callback, completion_event, route, delivery_key, state, created_at_us, reason),
    )
    connection.execute(
        """INSERT INTO outbox(
               callback_id, delivery_key, state, topic, aggregate_type, aggregate_id, disabled_reason
           ) VALUES (?, ?, ?, 'completion.callback.v1', 'work', ?, ?)""",
        (callback, delivery_key, state, work, reason),
    )
    connection.execute(
        """INSERT INTO completion_results(
               result_ref, completion_event_id, transport_id, completion_registration_id,
               callback_registration_id, work_id, generation, created_at_us
           ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)""",
        (result_ref, completion_event, transport, completion_registration, callback_registration, work, created_at_us),
    )
    connection.commit()



class CodexSourceRouteTests(unittest.TestCase):
    def test_commits_one_exact_immutable_thread_message_route(self) -> None:
        controller = _controller()
        self.addCleanup(controller.store.connection.close)
        message_id = "123e4567-e89b-42d3-a456-426614174000"
        result = controller.execute_durable(
            "authority", message_id, "f" * 64,
            "codex.source.route.commit.v1",
            {"thread_id": "thread-1", "message_id": message_id},
        )
        self.assertEqual(result, {
            "message_id": message_id,
            "route_id": f"codex-route-{message_id}",
            "state": "committed",
            "thread_id": "thread-1",
        })
        row = controller.store.connection.execute(
            "SELECT message_id, thread_id, state FROM codex_source_routes"
        ).fetchone()
        self.assertEqual(tuple(row), (message_id, "thread-1", "committed"))
        with self.assertRaises(sqlite3.IntegrityError):
            controller.store.connection.execute(
                "UPDATE codex_source_routes SET thread_id = 'thread-2'"
            )

    def test_source_inbox_is_exact_per_thread_and_maps_delivery_conservatively(self) -> None:
        controller = _controller()
        self.addCleanup(controller.store.connection.close)
        _insert_source_callback(
            controller, "pending", thread_id=THREAD_A, state="pending",
            created_at_us=1_000_000, slot_id="control-1",
        )
        _insert_source_callback(
            controller, "delivering", thread_id=THREAD_A, state="delivering",
            created_at_us=2_000_000, slot_id="control-2",
        )
        _insert_source_callback(
            controller, "delivered", thread_id=THREAD_A, state="delivered",
            created_at_us=3_000_000, slot_id="control-3",
        )
        _insert_source_callback(
            controller, "attention", thread_id=THREAD_A, state="attention",
            created_at_us=4_000_000, slot_id="control-1", reason="delivery_unknown",
        )
        _insert_source_callback(
            controller, "other", thread_id=THREAD_B, state="delivered",
            created_at_us=5_000_000, slot_id="control-2",
        )

        before = controller.store.connection.execute(
            "SELECT count(*) FROM daemon_request_outcomes"
        ).fetchone()[0]
        result = controller.source_inbox("authority", THREAD_A)
        after = controller.store.connection.execute(
            "SELECT count(*) FROM daemon_request_outcomes"
        ).fetchone()[0]

        self.assertEqual(before, after)
        self.assertEqual(result["source_id"], THREAD_A)
        self.assertEqual(
            [item["state"] for item in result["items"]],
            ["attention", "accepted", "delivering", "queued"],
        )
        self.assertEqual(
            [item["origin"] for item in result["items"]],
            ["control-1", "control-3", "control-2", "control-1"],
        )
        self.assertEqual(result["items"][0]["reason"], "delivery_unknown")
        self.assertTrue(all(
            item["kind"] == "completion_nudge"
            and "delivery_key" not in item
            and "result" not in item
            for item in result["items"]
        ))
        self.assertEqual(result["items"][-1]["queued_at"], "1970-01-01T00:00:01.000000Z")
        self.assertEqual(result["total"], 4)
        self.assertEqual(result["total_status"], "exact")
        self.assertEqual(result["lower_bound"], 4)
        self.assertFalse(result["truncated"] )

    def test_source_inbox_preserves_full_durable_work_identifier_grammar(self) -> None:
        controller = _controller()
        self.addCleanup(controller.store.connection.close)
        work_id = "team/job+1@example?x*"
        _insert_source_callback(
            controller, "grammar", thread_id=THREAD_A, state="delivered",
            created_at_us=1_000_000, work_id=work_id,
        )

        result = controller.source_inbox("authority", THREAD_A)

        self.assertEqual(result["items"][0]["work_id"], work_id)

    def test_source_inbox_rejects_incomplete_durable_join(self) -> None:
        controller = _controller()
        self.addCleanup(controller.store.connection.close)
        _insert_source_callback(
            controller, "missing-outbox", thread_id=THREAD_A, state="delivered",
            created_at_us=1_000_000,
        )
        controller.store.connection.execute(
            "DELETE FROM outbox WHERE callback_id = 'callback-missing-outbox'"
        )
        controller.store.connection.commit()
        with self.assertRaisesRegex(OperationRejected, "durable join is incomplete"):
            controller.source_inbox("authority", THREAD_A)

    def test_source_inbox_rejects_missing_callback_chain_before_empty_projection(self) -> None:
        controller = _controller()
        self.addCleanup(controller.store.connection.close)
        _insert_source_callback(
            controller, "missing-callback", thread_id=THREAD_A, state="delivered",
            created_at_us=1_000_000,
        )
        controller.store.connection.execute(
            "DELETE FROM callbacks WHERE id = 'callback-missing-callback'"
        )
        controller.store.connection.commit()
        with self.assertRaisesRegex(OperationRejected, "durable join is incomplete"):
            controller.source_inbox("authority", THREAD_A)

    def test_source_inbox_rejects_cross_linked_durable_ownership(self) -> None:
        corruptions = (
            "UPDATE completion_events SET transport_id = 'transport-cross-linked'",
            "UPDATE scheduler_assignments SET fence_token = 'wrong-fence'",
            "UPDATE transport_callback_registrations SET return_route_id = 'route-cross-linked'",
            "UPDATE completion_results SET callback_registration_id = 'callback-registration-cross-linked'",
        )
        for statement in corruptions:
            with self.subTest(statement=statement):
                controller = _controller()
                _insert_source_callback(
                    controller, "integrity", thread_id=THREAD_A, state="delivered",
                    created_at_us=1_000_000,
                )
                try:
                    controller.store.connection.execute(statement)
                    controller.store.connection.commit()
                    with self.assertRaisesRegex(OperationRejected, "durable join is incomplete"):
                        controller.source_inbox("authority", THREAD_A)
                finally:
                    controller.store.connection.close()

    def test_source_inbox_validates_the_hidden_cap_sentinel(self) -> None:
        controller = _controller()
        self.addCleanup(controller.store.connection.close)
        for index in range(13):
            _insert_source_callback(
                controller, str(index), thread_id=THREAD_A, state="delivered",
                created_at_us=1_000_000 + index,
            )
        # label 0 is the oldest row and therefore the thirteenth/cap sentinel.
        controller.store.connection.execute(
            "DELETE FROM completion_results WHERE result_ref = 'result-0'"
        )
        controller.store.connection.commit()
        with self.assertRaisesRegex(OperationRejected, "durable join is incomplete"):
            controller.source_inbox("authority", THREAD_A)

    def test_source_inbox_rejects_callback_outbox_state_mismatch(self) -> None:
        controller = _controller()
        self.addCleanup(controller.store.connection.close)
        _insert_source_callback(
            controller, "mismatch", thread_id=THREAD_A, state="delivered",
            created_at_us=1_000_000,
        )
        controller.store.connection.execute(
            "UPDATE outbox SET state = 'pending' WHERE callback_id = 'callback-mismatch'"
        )
        controller.store.connection.commit()
        with self.assertRaisesRegex(OperationRejected, "states disagree"):
            controller.source_inbox("authority", THREAD_A)

    def test_source_inbox_caps_at_twelve_and_rejects_noncanonical_thread(self) -> None:
        controller = _controller()
        self.addCleanup(controller.store.connection.close)
        for index in range(13):
            _insert_source_callback(
                controller, str(index), thread_id=THREAD_A, state="delivered",
                created_at_us=1_000_000 + index,
            )
        result = controller.source_inbox("authority", THREAD_A)
        self.assertEqual(len(result["items"]), 12)
        self.assertIsNone(result["total"] )
        self.assertEqual(result["total_status"], "capped")
        self.assertEqual(result["lower_bound"], 13)
        self.assertTrue(result["truncated"] )
        with self.assertRaisesRegex(OperationRejected, "canonical lowercase UUID"):
            controller.source_inbox("authority", "thread-1")

    def test_authenticated_socket_source_inbox_is_read_only_and_exactly_parameterized(self) -> None:
        class RecordingController:
            def __init__(self) -> None:
                self.calls = 0

            def execute(self, _operation: str, _params: object) -> dict[str, object]:
                self.calls += 1
                raise AssertionError("source inbox reached mutation dispatch")

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        socket_path = root / "socket" / "rig.sock"
        controller = RecordingController()
        provider_calls: list[object] = []

        def read_source_inbox(thread_id: object) -> dict[str, object]:
            provider_calls.append(thread_id)
            return {
                "source_id": thread_id,
                "items": [],
                "total": 0,
                "total_status": "exact",
                "lower_bound": 0,
                "truncated": False,
            }

        daemon = RigDaemon(
            PrivateSocketPath(socket_path, root),
            controller=controller,
            read_source_inbox_provider=read_source_inbox,
        )
        thread = daemon.start_background()
        self.addCleanup(daemon.shutdown)
        self.addCleanup(lambda: thread.join(timeout=2))
        client = RigClient(
            socket_path, approved_root=root, identity_profile="local-user"
        )
        result = client.call("codex.source.inbox.v1", {"thread_id": THREAD_A})
        self.assertEqual(result["source_id"], THREAD_A)
        self.assertEqual(provider_calls, [THREAD_A])
        self.assertEqual(controller.calls, 0)
        self.assertEqual(len(daemon._idempotency), 0)
        with self.assertRaises(RigClientError) as caught:
            client.call(
                "codex.source.inbox.v1",
                {"thread_id": THREAD_A, "unexpected": True},
            )
        self.assertEqual(caught.exception.code, "invalid_params")
        self.assertEqual(provider_calls, [THREAD_A])
        self.assertEqual(controller.calls, 0)

    def test_rejects_route_when_message_and_idempotency_differ(self) -> None:
        controller = _controller()
        self.addCleanup(controller.store.connection.close)
        with self.assertRaisesRegex(OperationRejected, "idempotency must equal"):
            controller.execute_durable(
                "authority", "123e4567-e89b-42d3-a456-426614174001", "e" * 64,
                "codex.source.route.commit.v1",
                {"thread_id": "thread-1", "message_id": "123e4567-e89b-42d3-a456-426614174000"},
            )


if __name__ == "__main__":
    unittest.main()
