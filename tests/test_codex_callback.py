from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import stat
import tempfile
import threading
import time
import unittest
from contextlib import closing, contextmanager
from pathlib import Path
from unittest.mock import patch

from oc_rig.completion.codex_callback import (
    CallbackDeliveryProof,
    CallbackDisposition,
    CallbackResult,
    CodexCallbackRequest,
    CodexQueueConfig,
    LocalCodexQueueAdapter,
    parse_local_codex_return_route,
    validate_codex_thread_id,
)
from oc_rig.completion.models import CompletionFinalResult, CompletionOutcome
from oc_rig.completion.service import CallbackDelivery, _create_completion
from oc_rig.completion.daemon_callback import _DaemonLocalCodexCallbackPump
from oc_rig.daemon.controller import OperationRejected, _RigController
from oc_rig.store import PrivateRuntimeDirectory, RigStore
from oc_rig.store.database import OwnershipConflict, _DaemonAuthority, _split_sql
from tests.test_store_sqlite import _insert_milestone_seven_completion


THREAD_ID = "00000000-0000-7000-8000-abcdef000002"


class CodexQueueAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.home = self.root / "home"
        self.codex_home = self.home / ".codex"
        self.codex_home.mkdir(parents=True)
        self.home.chmod(0o700)
        self.codex_home.chmod(0o700)
        self.output = self.root / "invocation.json"

    def executable(self, body: str) -> Path:
        executable = self.root / "codex-fixture"
        executable.write_text(f"#!/usr/bin/python3\n{body}", encoding="utf-8")
        executable.chmod(0o700)
        return executable

    def adapter(self, executable: Path, timeout: float = 2) -> LocalCodexQueueAdapter:
        return LocalCodexQueueAdapter(
            CodexQueueConfig(executable, self.home, self.codex_home, timeout)
        )

    def request(self) -> CodexCallbackRequest:
        return CodexCallbackRequest(
            "delivery-one", THREAD_ID, "work-one", "succeeded",
            "completion-result-" + "a" * 64,
        )

    def write_history(
        self,
        request: CodexCallbackRequest,
        *,
        thread_id: str | None = None,
        message: str | None = None,
        duplicate: bool = False,
    ) -> Path:
        history = self.codex_home / "thread_history_1.sqlite"
        connection = sqlite3.connect(history)
        try:
            connection.executescript(
                """
                CREATE TABLE thread_items(
                    thread_id TEXT, turn_id TEXT, item_id TEXT, rollout_ordinal INTEGER,
                    created_at_ms INTEGER, item_json TEXT, item_type TEXT, updated_at_ordinal INTEGER
                );
                CREATE TABLE thread_turns(
                    thread_id TEXT, turn_id TEXT, rollout_ordinal INTEGER, status TEXT,
                    error_json TEXT, started_at INTEGER, completed_at INTEGER, duration_ms INTEGER,
                    first_user_item_id TEXT, final_agent_item_id TEXT, rollout_byte_offset INTEGER,
                    rollout_end_ordinal INTEGER, rollout_end_byte_offset INTEGER
                );
                """
            )
            target = thread_id or request.thread_id
            text = request.message() if message is None else message
            count = 2 if duplicate else 1
            for index in range(count):
                item_id = f"item-{index}"
                turn_id = f"turn-{index}"
                item = {
                    "type": "userMessage",
                    "id": item_id,
                    "clientId": f"client-{index}",
                    "content": [{"type": "text", "text": text, "text_elements": []}],
                }
                connection.execute(
                    "INSERT INTO thread_items VALUES(?,?,?,?,?,?,?,?)",
                    (target, turn_id, item_id, index + 1, 1000 + index, json.dumps(item),
                     "userMessage", index + 1),
                )
                connection.execute(
                    "INSERT INTO thread_turns VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (target, turn_id, index + 1, "completed", None, 1000 + index,
                     1100 + index, 100, item_id, f"agent-{index}", 0, index + 1, 0),
                )
            connection.commit()
        finally:
            connection.close()
        history.chmod(0o600)
        return history

    def test_durable_history_proves_only_exact_bound_callback(self) -> None:
        executable = self.executable("raise SystemExit(0)")
        request = self.request()
        self.write_history(request)
        proof = self.adapter(executable).prove_delivery(request)
        self.assertEqual(
            proof, CallbackDeliveryProof(True, "codex_history_exact_message")
        )

    def test_durable_history_wrong_thread_message_and_duplicates_fail_closed(self) -> None:
        executable = self.executable("raise SystemExit(0)")
        request = self.request()
        self.write_history(request, thread_id="00000000-0000-7000-8000-abcdef000003")
        self.assertEqual(
            self.adapter(executable).prove_delivery(request).reason,
            "codex_history_proof_not_found",
        )
        (self.codex_home / "thread_history_1.sqlite").unlink()
        self.write_history(request, message=request.message() + " changed")
        self.assertEqual(
            self.adapter(executable).prove_delivery(request).reason,
            "codex_history_proof_not_found",
        )
        (self.codex_home / "thread_history_1.sqlite").unlink()
        self.write_history(request, duplicate=True)
        self.assertEqual(
            self.adapter(executable).prove_delivery(request).reason,
            "codex_history_proof_ambiguous",
        )

    def test_durable_history_schema_mode_and_executable_identity_fail_closed(self) -> None:
        executable = self.executable("raise SystemExit(0)")
        request = self.request()
        history = self.codex_home / "thread_history_1.sqlite"
        with closing(sqlite3.connect(history)) as connection, connection:
            connection.execute("CREATE TABLE wrong(value TEXT)")
        history.chmod(0o600)
        adapter = self.adapter(executable)
        self.assertEqual(
            adapter.prove_delivery(request).reason, "codex_history_schema_invalid"
        )
        history.chmod(0o622)
        self.assertEqual(
            adapter.prove_delivery(request).reason, "codex_history_unavailable"
        )
        history.chmod(0o600)
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)
        self.assertEqual(
            adapter.prove_delivery(request).reason, "codex_executable_identity_changed"
        )

    def test_exact_local_queue_argv_and_sanitized_environment(self) -> None:
        executable = self.executable(
            """
import json, os, pathlib, sys
pathlib.Path(%r).write_text(json.dumps({
    'argv': sys.argv[1:],
    'environment': dict(os.environ),
}), encoding='utf-8')
raise SystemExit(0)
""" % str(self.output)
        )
        prior = os.environ.get("SECRET_SHOULD_NOT_CROSS")
        os.environ["SECRET_SHOULD_NOT_CROSS"] = "private"
        self.addCleanup(
            lambda: (
                os.environ.pop("SECRET_SHOULD_NOT_CROSS", None)
                if prior is None
                else os.environ.__setitem__("SECRET_SHOULD_NOT_CROSS", prior)
            )
        )
        result = self.adapter(executable).deliver(self.request())
        self.assertEqual(result.disposition, CallbackDisposition.DELIVERED)
        invoked = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(invoked["argv"][:3], ["queue", "--thread", THREAD_ID])
        self.assertEqual(invoked["argv"][3], "--message")
        self.assertIn("[delivery:delivery-one]", invoked["argv"][4])
        self.assertIn("completion-result-" + "a" * 64, invoked["argv"][4])
        self.assertEqual(
            {key: invoked["environment"][key] for key in ("CODEX_HOME", "HOME", "LANG", "PATH")},
            {
                "CODEX_HOME": str(self.codex_home),
                "HOME": str(self.home),
                "LANG": "C.UTF-8",
                "PATH": "/usr/bin:/bin",
            },
        )
        self.assertNotIn("SECRET_SHOULD_NOT_CROSS", invoked["environment"])

    def test_post_spawn_timeout_and_nonzero_are_delivery_unknown(self) -> None:
        timeout = self.adapter(
            self.executable("import time\ntime.sleep(30)"), timeout=0.05
        ).deliver(self.request())
        self.assertEqual(timeout.disposition, CallbackDisposition.DELIVERY_UNKNOWN)
        self.assertEqual(timeout.reason, "codex_timeout")
        nonzero = self.adapter(
            self.executable("raise SystemExit(7)")
        ).deliver(self.request())
        self.assertEqual(nonzero.disposition, CallbackDisposition.DELIVERY_UNKNOWN)
        self.assertEqual(nonzero.reason, "codex_nonzero_exit_7")

    def test_executable_change_and_unsafe_mode_fail_before_delivery(self) -> None:
        executable = self.executable("raise SystemExit(0)")
        adapter = self.adapter(executable)
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        changed = adapter.deliver(self.request())
        self.assertEqual(changed.disposition, CallbackDisposition.POLICY)
        executable.chmod(0o722)
        with self.assertRaises(PermissionError):
            self.adapter(executable)

    def test_callback_identifiers_reject_controls_and_message_delimiters(self) -> None:
        valid = self.request()
        self.assertIn("delivery-one", valid.message())
        canonical_work = "model/run@v1+test" + "x" * (256 - len("model/run@v1+test"))
        accepted = CodexCallbackRequest(
            valid.delivery_key,
            valid.thread_id,
            canonical_work,
            valid.outcome,
            valid.result_ref,
        )
        self.assertEqual(accepted.work_id, canonical_work)
        for field, value in (
            ("delivery_key", "delivery]\nforged"),
            ("work_id", "--work"),
            ("result_ref", "result with space"),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                values = {
                    "delivery_key": valid.delivery_key,
                    "thread_id": valid.thread_id,
                    "work_id": valid.work_id,
                    "outcome": valid.outcome,
                    "result_ref": valid.result_ref,
                }
                values[field] = value
                CodexCallbackRequest(**values)

    def test_callback_directories_reject_symlink_and_writable_leaf(self) -> None:
        executable = self.executable("raise SystemExit(0)")
        linked_home = self.root / "linked-home"
        linked_home.symlink_to(self.home, target_is_directory=True)
        with self.assertRaises(PermissionError):
            LocalCodexQueueAdapter(
                CodexQueueConfig(
                    executable, linked_home, self.codex_home, 2
                )
            )

        self.codex_home.chmod(0o720)
        self.addCleanup(lambda: self.codex_home.chmod(0o700))
        with self.assertRaises(PermissionError):
            self.adapter(executable)

    def test_executable_identity_os_error_is_transient(self) -> None:
        adapter = self.adapter(self.executable("raise SystemExit(0)"))
        with patch(
            "oc_rig.completion.codex_callback._executable_identity",
            side_effect=OSError("temporary read failure"),
        ):
            result = adapter.deliver(self.request())
        self.assertEqual(result.disposition, CallbackDisposition.TRANSIENT)
        self.assertEqual(result.reason, "codex_identity_check_failed")

    def test_thread_route_is_canonical_uuid_only(self) -> None:
        self.assertEqual(validate_codex_thread_id(THREAD_ID), THREAD_ID)
        for invalid in ("", "control", THREAD_ID.upper(), f"{THREAD_ID} extra", None):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_codex_thread_id(invalid)
        self.assertEqual(
            parse_local_codex_return_route(
                {"kind": "local_codex", "thread_id": THREAD_ID}
            ),
            THREAD_ID,
        )
        self.assertIsNone(parse_local_codex_return_route(None))
        for invalid in (
            {},
            {"kind": "local_codex"},
            {"kind": "remote", "thread_id": THREAD_ID},
            {"kind": "local_codex", "thread_id": THREAD_ID, "extra": True},
        ):
            with self.subTest(route=invalid), self.assertRaises(ValueError):
                parse_local_codex_return_route(invalid)


class CallbackReconciliationControllerTests(unittest.TestCase):
    class Transport:
        @staticmethod
        def _assert_authority(capability: object) -> None:
            if capability != "authority":
                raise PermissionError

    class Store:
        def __init__(self) -> None:
            self.connection = sqlite3.connect(":memory:")
            self.connection.executescript(
                """
                CREATE TABLE daemon_request_outcomes(
                    idempotency_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                    operation TEXT NOT NULL, ok INTEGER NOT NULL,
                    outcome_json TEXT NOT NULL, completed_at TEXT NOT NULL
                );
                """
            )
            self.in_transaction = False

        @contextmanager
        def _daemon_transaction(self, _authority: object):
            self.in_transaction = True
            try:
                with self.connection:
                    yield self.connection
            finally:
                self.in_transaction = False

    class Completion:
        def __init__(self, store: "CallbackReconciliationControllerTests.Store") -> None:
            self.store = store
            self.delivery = CallbackDelivery(
                "callback-one", "outbox-one", "route-one", "delivery-one",
                THREAD_ID, "work-one", "succeeded",
                "completion-result-" + "a" * 64, 1,
            )
            self.reject_binding = False
            self.reject_mutation = False
            self.reconciled = 0

        def local_codex_attention_delivery(
            self, _capability: object, _connection: sqlite3.Connection, callback_id: str
        ) -> CallbackDelivery:
            if self.reject_binding or callback_id != self.delivery.callback_id:
                raise OwnershipConflict("callback is not an exact ambiguous local Codex delivery")
            return self.delivery

        def reconcile_local_codex_delivery(
            self, _capability: object, _connection: sqlite3.Connection,
            delivery: CallbackDelivery, *, proof_kind: str
        ) -> None:
            if self.store.in_transaction is not True:
                raise AssertionError("durable reconciliation must run inside final transaction")
            if self.reject_mutation:
                raise OwnershipConflict("callback reconciliation authority changed after proof")
            if delivery != self.delivery or proof_kind != "codex_history_exact_message":
                raise AssertionError("unexpected reconciliation authority")
            self.reconciled += 1

    def controller(self):
        store = self.Store()
        completion = self.Completion(store)
        controller = object.__new__(_RigController)
        controller._transport = self.Transport()
        controller._authority = object()
        controller._completion = completion
        controller.store = store
        controller.max_idempotency_entries = 100
        self.addCleanup(store.connection.close)
        return controller, store, completion

    def test_negative_proof_is_journaled_without_mutation(self) -> None:
        controller, store, completion = self.controller()

        def verifier(request: CodexCallbackRequest) -> CallbackDeliveryProof:
            self.assertFalse(store.in_transaction)
            self.assertEqual(request, completion.delivery.request())
            return CallbackDeliveryProof(False, "codex_history_proof_not_found")

        result = controller.reconcile_callback_delivery(
            "authority", "reconcile-negative", "f" * 64,
            {"callback_id": "callback-one"}, verifier,
        )
        self.assertEqual(result["reconciled"], False)
        self.assertEqual(result["state"], "attention")
        self.assertEqual(completion.reconciled, 0)
        row = store.connection.execute(
            "SELECT operation, ok, outcome_json FROM daemon_request_outcomes"
        ).fetchone()
        self.assertEqual(row[0:2], ("callback.delivery.reconcile.v1", 1))
        self.assertEqual(json.loads(row[2]), result)

    def test_positive_proof_with_unknown_kind_fails_closed_without_mutation(self) -> None:
        controller, _store, completion = self.controller()
        result = controller.reconcile_callback_delivery(
            "authority", "reconcile-invalid-proof", "b" * 64,
            {"callback_id": "callback-one"},
            lambda _request: CallbackDeliveryProof(True, "unexpected_proof_kind"),
        )
        self.assertEqual(
            result,
            {
                "callback_id": "callback-one",
                "reconciled": False,
                "state": "attention",
                "proof": "callback_proof_invalid",
            },
        )
        self.assertEqual(completion.reconciled, 0)

    def test_positive_proof_reconciles_once_and_is_idempotent(self) -> None:
        controller, store, completion = self.controller()
        calls = 0

        def verifier(request: CodexCallbackRequest) -> CallbackDeliveryProof:
            nonlocal calls
            calls += 1
            self.assertFalse(store.in_transaction)
            self.assertEqual(request, completion.delivery.request())
            return CallbackDeliveryProof(True, "codex_history_exact_message")

        first = controller.reconcile_callback_delivery(
            "authority", "reconcile-positive", "e" * 64,
            {"callback_id": "callback-one"}, verifier,
        )
        duplicate = controller.reconcile_callback_delivery(
            "authority", "reconcile-positive", "e" * 64,
            {"callback_id": "callback-one"}, verifier,
        )
        self.assertEqual(first, duplicate)
        self.assertEqual(first["reconciled"], True)
        self.assertEqual(first["state"], "delivered")
        self.assertEqual(completion.reconciled, 1)
        self.assertEqual(calls, 1)

    def test_binding_and_post_proof_authority_failures_are_durably_rejected(self) -> None:
        controller, store, completion = self.controller()
        completion.reject_binding = True
        with self.assertRaisesRegex(OperationRejected, "not an exact ambiguous"):
            controller.reconcile_callback_delivery(
                "authority", "reconcile-binding-reject", "d" * 64,
                {"callback_id": "callback-one"},
                lambda _request: CallbackDeliveryProof(True, "codex_history_exact_message"),
            )
        first = store.connection.execute(
            "SELECT ok FROM daemon_request_outcomes WHERE idempotency_id = ?",
            ("reconcile-binding-reject",),
        ).fetchone()
        self.assertEqual(first, (0,))

        completion.reject_binding = False
        completion.reject_mutation = True
        with self.assertRaisesRegex(OperationRejected, "authority changed after proof"):
            controller.reconcile_callback_delivery(
                "authority", "reconcile-race-reject", "c" * 64,
                {"callback_id": "callback-one"},
                lambda _request: CallbackDeliveryProof(True, "codex_history_exact_message"),
            )
        second = store.connection.execute(
            "SELECT ok FROM daemon_request_outcomes WHERE idempotency_id = ?",
            ("reconcile-race-reject",),
        ).fetchone()
        self.assertEqual(second, (0,))


class CodexCallbackOutboxTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.store = RigStore(PrivateRuntimeDirectory(self.root / "state", self.root))
        lock_path = self.store.path.parent / "rigd.lock"
        lock_path.touch(mode=0o600)
        self.store.initialize()
        descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        facts = os.fstat(descriptor)
        authority = object.__new__(_DaemonAuthority)
        authority._store = self.store
        authority._closed = False
        authority._descriptor = descriptor
        authority._path = lock_path
        authority._identity = (facts.st_dev, facts.st_ino)
        authority._activate_usage_guard()
        self.authority = authority
        self.addCleanup(authority.close)
        self.capability = object()
        self.completion = _create_completion(self.store, authority, self.capability)
        with self.store._daemon_transaction(authority) as connection:
            _insert_milestone_seven_completion(connection, "local", "pending")
            connection.execute(
                """INSERT INTO opencode_slot_generations(
                       slot_id, session_id, worker, generation, updated_at
                   ) VALUES ('slot-local', 'session-local', 'secure-worker', 1,
                             'legacy')"""
            )
            connection.execute(
                """INSERT INTO opencode_deliveries(
                       transport_id, request_fingerprint, work_id, pool,
                       completion_registration_id, callback_registration_id,
                       slot_id, session_id, worker, assignment_generation,
                       prompt_message_id, delivery_capability, delivery_state,
                       acknowledgement_id, error_code, lease_state, abort_state,
                       created_at, updated_at, finished_at
                   ) VALUES ('transport-local', ?, 'work-local', 'control',
                             'registration-local', 'transport-callback-local',
                             'slot-local', 'session-local', 'secure-worker', 1,
                             'prompt-local', ?, 'accepted', 'ack-local', NULL,
                             'active', 'none', 'legacy', 'legacy', 'legacy')""",
                ("4" * 64, "5" * 64),
            )
            receipt = self.completion.accept(
                self.capability,
                connection,
                completion_key="completion-key-local",
                registration_id="registration-local",
                work_id="work-local",
                generation=1,
                outcome=CompletionOutcome.SUCCEEDED,
                final_result=CompletionFinalResult(
                    "transport-local", "work-local", "registration-local",
                    "transport-callback-local", "session-local", 1,
                    "prompt-local", "assistant-local",
                    CompletionOutcome.SUCCEEDED, "Durable review text.",
                ),
            )
            self.result_ref = receipt.result_ref
            assert self.result_ref is not None
            connection.execute(
                """INSERT INTO local_codex_return_routes(
                       return_route_id, thread_id, created_at_us
                   ) VALUES ('route-local', ?, 30)""",
                (THREAD_ID,),
            )

    def rows(self, table: str) -> list[tuple[object, ...]]:
        with closing(__import__("sqlite3").connect(self.store.path)) as connection:
            return list(connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid'))

    def begin(self):
        with self.store._daemon_transaction(self.authority) as connection:
            return self.completion.begin_local_codex_delivery(
                self.capability, connection
            )

    def finish(self, delivery, result: CallbackResult) -> None:
        with self.store._daemon_transaction(self.authority) as connection:
            self.completion.finish_local_codex_delivery(
                self.capability, connection, delivery, result
            )

    def pump(self) -> _DaemonLocalCodexCallbackPump:
        home = self.root / "home"
        codex_home = home / ".codex"
        codex_home.mkdir(parents=True, exist_ok=True)
        home.chmod(0o700)
        codex_home.chmod(0o700)
        executable = self.root / "codex-fixture"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)
        return _DaemonLocalCodexCallbackPump(
            self.store,
            self.authority,
            self.capability,
            self.completion,
            LocalCodexQueueAdapter(CodexQueueConfig(executable, home, codex_home, 2)),
        )

    def wait_callback_state(self, state: str, timeout: float = 1.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.rows("callbacks")[0][4] == state:
                return
            time.sleep(0.01)
        self.fail(f"callback did not reach {state}")

    def test_delivered_attempt_consumes_exact_route_once(self) -> None:
        delivery = self.begin()
        self.assertIsNotNone(delivery)
        assert delivery is not None
        self.assertEqual(delivery.thread_id, THREAD_ID)
        self.assertEqual(delivery.result_ref, self.result_ref)
        self.assertIn(self.result_ref, delivery.request().message())
        self.assertIsNone(self.begin())
        result = CallbackResult(CallbackDisposition.DELIVERED, "codex_acknowledged")
        self.finish(delivery, result)
        self.finish(delivery, result)
        callback = self.rows("callbacks")[0]
        route = self.rows("return_routes")[0]
        registration = self.rows("transport_callback_registrations")[0]
        self.assertEqual(callback[4], "delivered")
        self.assertEqual(route[12], "consumed")
        self.assertEqual(registration[7], "consumed")
        event_types = [str(row[4]) for row in self.rows("events")]
        self.assertIn("callback.queued_for_codex", event_types)
        self.assertNotIn("callback.delivered", event_types)
        self.assertIsNone(self.begin())

    def test_ambiguous_delivery_reconciles_only_after_immutable_positive_proof(self) -> None:
        delivery = self.begin()
        self.assertIsNotNone(delivery)
        assert delivery is not None
        self.finish(
            delivery,
            CallbackResult(CallbackDisposition.DELIVERY_UNKNOWN, "codex_nonzero_exit_7"),
        )
        self.assertEqual(self.rows("callbacks")[0][4], "attention")
        with self.store._daemon_transaction(self.authority) as connection:
            candidate = self.completion.local_codex_attention_delivery(
                self.capability, connection, delivery.callback_id
            )
        self.assertEqual(candidate, delivery)
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store._daemon_transaction(self.authority) as connection:
                connection.execute(
                    """UPDATE callback_delivery_attempts SET state = 'delivered'
                       WHERE callback_id = ?""",
                    (delivery.callback_id,),
                )
        with self.store._daemon_transaction(self.authority) as connection:
            self.completion.reconcile_local_codex_delivery(
                self.capability,
                connection,
                candidate,
                proof_kind="codex_thread_history_exact_message",
            )
        self.assertEqual(self.rows("callbacks")[0][4], "delivered")
        self.assertEqual(self.rows("outbox")[0][6], "delivered")
        self.assertEqual(self.rows("return_routes")[0][12], "consumed")
        self.assertEqual(self.rows("transport_callback_registrations")[0][7], "consumed")
        attempt = self.rows("callback_delivery_attempts")[0]
        self.assertEqual(attempt[4], "delivered")
        self.assertIsNone(attempt[5])
        reconciliation = self.rows("callback_delivery_reconciliations")[0]
        self.assertEqual(reconciliation[0], delivery.callback_id)
        self.assertEqual(reconciliation[1], delivery.attempt)
        self.assertEqual(reconciliation[2], delivery.delivery_key)
        self.assertEqual(reconciliation[3], "codex_thread_history_exact_message")
        event_types = [str(row[4]) for row in self.rows("events")]
        self.assertIn("callback.delivery_reconciled", event_types)

    def test_nonambiguous_attention_is_not_reconcilable(self) -> None:
        delivery = self.begin()
        self.assertIsNotNone(delivery)
        assert delivery is not None
        self.finish(
            delivery,
            CallbackResult(CallbackDisposition.POLICY, "codex_executable_identity_changed"),
        )
        with self.store._daemon_transaction(self.authority) as connection:
            with self.assertRaisesRegex(OwnershipConflict, "not an exact ambiguous"):
                self.completion.local_codex_attention_delivery(
                    self.capability, connection, delivery.callback_id
                )
        self.assertEqual(self.rows("callback_delivery_reconciliations"), [])

    def test_durable_result_read_verifies_exact_text_and_bindings(self) -> None:
        with self.store._daemon_transaction(self.authority) as connection:
            result = self.completion.read_final_result(
                self.capability, connection, self.result_ref
            )
        self.assertEqual(result["result_ref"], self.result_ref)
        self.assertEqual(result["transport_id"], "transport-local")
        self.assertEqual(result["work_id"], "work-local")
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["assistant_message_id"], "assistant-local")
        self.assertEqual(result["content_state"], "available")
        self.assertEqual(result["text"], "Durable review text.")
        self.assertRegex(str(result["text_sha256"]), r"[0-9a-f]{64}\Z")
        self.assertRegex(str(result["binding_sha256"]), r"[0-9a-f]{64}\Z")

    def test_durable_result_tamper_is_immutable_and_read_fails_closed(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store._daemon_transaction(self.authority) as connection:
                connection.execute(
                    "UPDATE completion_results SET final_text = 'changed'"
                )
        with self.store._daemon_transaction(self.authority) as connection:
            connection.execute("DROP TRIGGER completion_results_are_immutable_update")
            connection.execute(
                "UPDATE completion_results SET binding_sha256 = ?",
                ("0" * 64,),
            )
        with self.store._daemon_transaction(self.authority) as connection:
            with self.assertRaisesRegex(OwnershipConflict, "integrity"):
                self.completion.read_final_result(
                    self.capability, connection, self.result_ref
                )

    def test_callback_result_tamper_enters_attention_without_send_or_spin(self) -> None:
        with self.store._daemon_transaction(self.authority) as connection:
            connection.execute("DROP TRIGGER completion_results_are_immutable_update")
            connection.execute(
                "UPDATE completion_results SET binding_sha256 = ?",
                ("0" * 64,),
            )
        pump = self.pump()
        self.addCleanup(pump.close)
        with patch.object(
            LocalCodexQueueAdapter,
            "deliver",
            side_effect=AssertionError("tampered result must not be sent"),
        ) as deliver:
            self.assertFalse(pump.run_once())
        deliver.assert_not_called()
        self.assertEqual(self.rows("callbacks")[0][4], "attention")
        self.assertEqual(self.rows("callbacks")[0][9], "deterministic")
        self.assertEqual(
            self.rows("callbacks")[0][10], "completion_result_integrity_failed"
        )
        self.assertEqual(self.rows("outbox")[0][6], "attention")
        with self.store._daemon_transaction(self.authority) as connection:
            self.assertIsNone(
                self.completion.next_local_codex_available_at(
                    self.capability, connection
                )
            )

    def test_callback_registration_binding_tamper_sends_nothing(self) -> None:
        with closing(sqlite3.connect(self.store.path, isolation_level=None)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute("DROP TRIGGER completion_results_are_immutable_update")
            connection.execute(
                """UPDATE completion_results
                   SET callback_registration_id = 'callback-forged'"""
            )
        pump = self.pump()
        self.addCleanup(pump.close)
        with patch.object(
            LocalCodexQueueAdapter,
            "deliver",
            side_effect=AssertionError("mismatched callback must not be sent"),
        ) as deliver:
            self.assertFalse(pump.run_once())
        deliver.assert_not_called()
        self.assertEqual(self.rows("callbacks")[0][4], "attention")
        self.assertEqual(
            self.rows("callbacks")[0][10], "completion_result_integrity_failed"
        )

    def test_migration_backfills_explicit_historical_unavailable_result(self) -> None:
        migration = Path(__file__).parents[1].joinpath(
            "src/oc_rig/store/migrations/014_durable_completion_results.sql"
        ).read_text(encoding="utf-8")
        with self.store._daemon_transaction(self.authority) as connection:
            connection.execute("DROP TRIGGER completion_results_are_immutable_update")
            connection.execute("DROP TRIGGER completion_results_are_immutable_delete")
            connection.execute("DROP TABLE completion_results")
            for statement in _split_sql(migration):
                connection.execute(statement)
            result = connection.execute(
                """SELECT result_ref, content_state, final_text, binding_sha256
                   FROM completion_results WHERE transport_id = 'transport-local'"""
            ).fetchone()
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result[1:], ("historical_unavailable", None, None))
        self.assertTrue(str(result[0]).startswith("completion-result-historical-"))

    def test_ambiguous_attempt_is_attention_and_never_retried(self) -> None:
        delivery = self.begin()
        assert delivery is not None
        self.finish(
            delivery,
            CallbackResult(CallbackDisposition.DELIVERY_UNKNOWN, "codex_timeout"),
        )
        self.assertEqual(self.rows("callbacks")[0][4], "attention")
        self.assertEqual(self.rows("outbox")[0][6], "attention")
        self.assertIsNone(self.begin())

    def test_restart_after_send_start_is_delivery_unknown_without_resend(self) -> None:
        self.assertIsNotNone(self.begin())
        with self.store._daemon_transaction(self.authority) as connection:
            self.assertEqual(
                self.completion.reconcile_startup(self.capability, connection), 1
            )
        self.assertEqual(self.rows("callbacks")[0][4], "attention")
        self.assertEqual(self.rows("callback_delivery_attempts")[0][4], "attention")
        self.assertIsNone(self.begin())

    def test_startup_promotes_only_ready_unsent_local_callback_once(self) -> None:
        with self.store._daemon_transaction(self.authority) as connection:
            connection.execute(
                """UPDATE callbacks SET state = 'blocked', attempts = 0,
                          attention_reason = 'awaiting_exact_release'"""
            )
            connection.execute(
                """UPDATE outbox SET state = 'blocked', attempts = 0,
                          disabled_reason = 'awaiting_exact_release'"""
            )
            self.assertEqual(
                self.completion.reconcile_startup(self.capability, connection), 1
            )
        events = len(self.rows("events"))
        with self.store._daemon_transaction(self.authority) as connection:
            self.assertEqual(
                self.completion.reconcile_startup(self.capability, connection), 0
            )
        self.assertEqual(self.rows("callbacks")[0][4], "pending")
        self.assertEqual(self.rows("outbox")[0][6], "pending")
        self.assertEqual(len(self.rows("events")), events)

    def test_startup_does_not_promote_historical_missing_route(self) -> None:
        with self.store._daemon_transaction(self.authority) as connection:
            _insert_milestone_seven_completion(connection, "missing", "pending")
            connection.execute(
                """UPDATE callbacks SET state = 'blocked', attempts = 0,
                          attention_reason = 'local_codex_route_missing'
                   WHERE id = 'callback-missing'"""
            )
            connection.execute(
                """UPDATE outbox SET state = 'blocked', attempts = 0,
                          disabled_reason = 'local_codex_route_missing'
                   WHERE id = 'outbox-missing'"""
            )
            self.assertEqual(
                self.completion.reconcile_startup(self.capability, connection), 0
            )
        missing_callback = next(
            row for row in self.rows("callbacks") if row[0] == "callback-missing"
        )
        missing_outbox = next(
            row for row in self.rows("outbox") if row[0] == "outbox-missing"
        )
        self.assertEqual(missing_callback[4], "blocked")
        self.assertEqual(missing_outbox[6], "blocked")

    def test_daemon_pump_journals_before_local_delivery_and_consumes_ack(self) -> None:
        pump = self.pump()
        self.addCleanup(pump.close)
        self.assertTrue(pump.run_once())
        self.assertFalse(pump.run_once())
        self.assertEqual(self.rows("callbacks")[0][4], "delivered")

    def test_transient_retries_wake_at_one_and_two_seconds_without_traffic(self) -> None:
        pump = self.pump()
        self.addCleanup(pump.close)
        completed = threading.Event()
        calls = 0

        def deliver(_adapter, _request):
            nonlocal calls
            calls += 1
            if calls < 3:
                return CallbackResult(CallbackDisposition.TRANSIENT, "spawn_failed")
            completed.set()
            return CallbackResult(CallbackDisposition.DELIVERED, "acknowledged")

        with patch.object(LocalCodexQueueAdapter, "deliver", deliver):
            self.assertEqual(pump.drain_ready(), 1)
            self.assertTrue(completed.wait(4.5))
            self.wait_callback_state("delivered")
        self.assertEqual(calls, 3)
        self.assertEqual(self.rows("callbacks")[0][4], "delivered")
        self.assertEqual(
            [row[4] for row in self.rows("callback_delivery_attempts")],
            ["retry_scheduled", "retry_scheduled", "delivered"],
        )

    def test_pending_transient_retry_rearms_after_daemon_restart(self) -> None:
        first = self.pump()
        with patch.object(
            LocalCodexQueueAdapter,
            "deliver",
            return_value=CallbackResult(CallbackDisposition.TRANSIENT, "spawn_failed"),
        ):
            self.assertEqual(first.drain_ready(), 1)
        first.close()

        second = self.pump()
        self.addCleanup(second.close)
        completed = threading.Event()

        def deliver(_adapter, _request):
            completed.set()
            return CallbackResult(CallbackDisposition.DELIVERED, "acknowledged")

        with patch.object(LocalCodexQueueAdapter, "deliver", deliver):
            self.assertEqual(second.drain_ready(), 0)
            self.assertTrue(completed.wait(2.5))
            self.wait_callback_state("delivered")
        self.assertEqual(self.rows("callbacks")[0][4], "delivered")
        self.assertEqual(len(self.rows("callback_delivery_attempts")), 2)


if __name__ == "__main__":
    unittest.main()
