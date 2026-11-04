from __future__ import annotations

import concurrent.futures
import inspect
import json
import os
import pwd
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import oc_rig.adapters as adapter_package
from oc_rig.adapters.opencode_client import MAX_PROMPT_BYTES
from oc_rig.cli import main as cli_main
from oc_rig.daemon import identity as service_identity
from oc_rig.daemon.identity import ServiceIdentityPolicy
from oc_rig.daemon.security import PrivateSocketPath
from oc_rig.daemon.server import RigDaemon
from oc_rig.protocol.client import RigClient, RigClientError
from oc_rig.protocol.framing import IncompleteFrame
from oc_rig.policy.capsule import (
    capsule_document,
    capture_scope_capsule,
    render_capsule_prompt,
)
from oc_rig.store import PrivateRuntimeDirectory, RigStore
from oc_rig.transport.service import _TransportService
from tests.fixtures.durable_daemon import ModeledDurableDaemon


class ModeledIdentityProbe:
    def __init__(self, service_uid: int, client_uid: int, client_gid: int):
        self.service_uid = service_uid
        self.client_uid = client_uid
        self.client_gid = client_gid
        self.os_probe = service_identity.OsIdentityProbe()

    def effective_uid(self) -> int:
        return self.service_uid

    def effective_gid(self) -> int:
        return self.client_gid

    def inspect(self, path: Path) -> service_identity.FileFacts:
        return self.os_probe.inspect(path)

    def groups_for_uid(self, uid: int) -> frozenset[int]:
        if uid == self.client_uid:
            return frozenset({self.client_gid})
        raise KeyError(uid)


class TransportDaemonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o710)
        self.service_uid = os.geteuid()
        self.client_gid = os.getegid()
        clients: list[int] = []
        for account in pwd.getpwall():
            if account.pw_uid <= 0 or account.pw_uid == self.service_uid:
                continue
            try:
                groups = os.getgrouplist(account.pw_name, account.pw_gid)
            except (KeyError, OverflowError):
                continue
            if self.client_gid in groups:
                clients.append(account.pw_uid)
        if not clients:
            self.skipTest("no distinct local client in the service client group")
        self.client_uid = min(clients)
        self.policy = ServiceIdentityPolicy(
            self.service_uid,
            frozenset({self.client_uid}),
            self.client_gid,
        )
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.state = self.root / "state"
        self.store = RigStore(PrivateRuntimeDirectory(self.state, self.root))
        self.state.joinpath("rigd.lock").touch(mode=0o600)
        self.state.joinpath("rigd.lock").chmod(0o600)
        self.socket = self.root / "socket" / "rig.sock"
        self.socket.parent.mkdir(mode=0o710)
        self.socket.parent.chmod(0o710)
        self.daemon: ModeledDurableDaemon | None = None
        self.client: RigClient | None = None
        self.claims: dict[str, dict[str, object]] = {}
        self.start_daemon()

    def tearDown(self) -> None:
        if self.daemon is not None:
            self.daemon.shutdown()

    def start_daemon(self, *, max_entries: int = 4096, mode: str = "normal") -> None:
        self.daemon = ModeledDurableDaemon(
            PrivateSocketPath(self.socket, self.root),
            runtime=self.store.runtime,
            identity_policy=self.policy,
            max_idempotency_entries=max_entries,
            mode=mode,
        )
        self.daemon.start()
        self.client = RigClient(
            self.socket,
            approved_root=self.root,
            service_uid=self.service_uid,
            client_gid=self.client_gid,
        )

    def restart_daemon(
        self,
        *,
        max_entries: int = 4096,
        mode: str = "normal",
    ) -> None:
        assert self.daemon is not None
        self.daemon.shutdown()
        self.store = RigStore(PrivateRuntimeDirectory(self.state, self.root))
        self.start_daemon(max_entries=max_entries, mode=mode)

    def call(
        self,
        operation: str,
        params: dict[str, object] | None = None,
        *,
        idempotency_id: str,
        request_id: str | None = None,
    ) -> dict[str, object]:
        assert self.client is not None
        return dict(
            self.client.call(
                operation,
                params or {},
                request_id=request_id or f"request-{idempotency_id}",
                idempotency_id=idempotency_id,
            )
        )

    def ready(
        self,
        label: str,
        pool: str = "tensorhost",
        *,
        content: str = "safe work",
        classification: str = "PUBLIC",
    ) -> None:
        relative = f"{label}.txt"
        self.repository.joinpath(relative).write_text("bounded", encoding="utf-8")
        operation_id = f"owner-{label}"
        self.call(
            "operation.create.v1",
            {"operation_id": operation_id, "kind": "dispatch"},
            idempotency_id=f"operation-{label}",
        )
        claim = self.call(
            "scope.claim.v1",
            {
                "owner_operation_id": operation_id,
                "repository": str(self.repository),
                "scope": [relative],
            },
            idempotency_id=f"claim-{label}",
        )
        self.claims[label] = claim
        self.call(
            "scheduler.enqueue.v1",
            {"work_id": f"work-{label}", "lane": pool},
            idempotency_id=f"enqueue-{label}",
        )
        decision = self.call(
            "scheduler.admit.v1",
            {
                "work_id": f"work-{label}",
                "claim_id": claim["claim_id"],
                "repository": str(self.repository),
                "scope": [relative],
                "content": content,
                "dispatch_kind": "automated",
                "trust": "secure",
                "classification": classification,
                "risk_categories": [],
            },
            idempotency_id=f"admit-{label}",
        )
        if decision["allowed"]:
            reservation = self.call(
                "scheduler.reserve.v1", idempotency_id=f"reserve-{label}"
            )["reservation"]
            self.assertIsNotNone(reservation)

    def dispatch(self, label: str, *, idempotency_id: str | None = None) -> dict[str, object]:
        return self.call(
            "transport.dispatch.v1",
            {
                "work_id": f"work-{label}",
                "pool": "tensorhost",
                "payload": {"prompt": "safe work"},
            },
            idempotency_id=idempotency_id or f"dispatch-{label}",
        )

    def rows(self, table: str) -> list[sqlite3.Row]:
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.row_factory = sqlite3.Row
            return list(connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid'))

    def test_claim_and_registrations_are_committed_before_disabled_send(self) -> None:
        self.ready("ordered")
        self.restart_daemon(mode="assert_registration_before_send")
        result = self.dispatch("ordered")
        self.assertEqual(result["state"], "definite_failed")
        events = [
            row["event_type"]
            for row in self.rows("events")
            if row["aggregate_type"] == "transport"
        ]
        self.assertEqual(
            events,
            [
                "transport.reserved",
                "transport.registrations.persisted",
                "transport.prepared",
                "transport.sending",
                "transport.definite_failed",
            ],
        )

    def test_gui_submission_is_fixed_secure_idempotent_and_releases_failed_scope(self) -> None:
        self.repository.joinpath("gui.txt").write_text("bounded\n", encoding="utf-8")
        submission_id = "123e4567-e89b-12d3-a456-426614174000"
        params = {
            "submission_id": submission_id,
            "lane": "homelab",
            "repository": str(self.repository),
            "scope": ["gui.txt"],
            "objective": "Review the bounded controller behavior",
            "agent_lifecycle": "disposable",
            "allow_child_agents": True,
            "classification": "PUBLIC",
            "trust": "secure",
            "reservation_attempt": 1,
        }
        first = self.call(
            "submission.submit.v1",
            params,
            idempotency_id=f"gui-submit-{submission_id}-attempt-1",
        )
        self.repository.joinpath("gui.txt").unlink()
        second = self.call(
            "submission.submit.v1",
            params,
            idempotency_id=f"gui-submit-{submission_id}-attempt-1",
        )
        self.assertEqual(first, second)
        self.assertEqual(first["state"], "rejected")
        self.assertEqual(first["agent_lifecycle"], "disposable")
        self.assertEqual(first["child_agents"], "allowed")
        self.assertEqual(self.rows("scope_claims")[0]["state"], "released")
        self.assertEqual(self.rows("operations")[0]["state"], "failed")
        outcomes_before_read = len(self.rows("daemon_request_outcomes"))
        task_result = self.call(
            "submission.result.v1",
            {"submission_id": submission_id, "reservation_attempt": 1},
            idempotency_id=f"gui-result-{submission_id}-attempt-1",
        )
        self.assertEqual(
            task_result,
            {
                "submission_id": submission_id,
                "reservation_attempt": 1,
                "state": "not_started",
                "outcome": None,
                "result_ref": None,
                "text": None,
                "persistent_session_state": None,
            },
        )
        self.assertEqual(
            len(self.rows("daemon_request_outcomes")), outcomes_before_read
        )
        with self.assertRaises(RigClientError) as changed:
            self.call(
                "submission.submit.v1",
                {**params, "objective": "Changed after completion"},
                idempotency_id=f"gui-submit-{submission_id}-attempt-1",
            )
        self.assertEqual(changed.exception.code, "idempotency_conflict")
        with self.assertRaises(RigClientError) as close_error:
            self.call(
                "submission.close.v1",
                {"submission_id": submission_id, "reservation_attempt": 1},
                idempotency_id=f"gui-close-{submission_id}-attempt-1",
            )
        self.assertEqual(close_error.exception.code, "invalid_state")
        self.assertFalse(
            any(
                row["operation"] == "submission.close.v1"
                for row in self.rows("daemon_request_outcomes")
            )
        )

    def test_persistent_close_replays_terminal_authority_without_backend_mutation(self) -> None:
        self.repository.joinpath("retained.txt").write_text("bounded\n", encoding="utf-8")
        self.restart_daemon(mode="accepted")
        submission_id = "123e4567-e89b-12d3-a456-426614174099"
        submitted = self.call(
            "submission.submit.v1",
            {
                "submission_id": submission_id,
                "lane": "homelab",
                "repository": str(self.repository),
                "scope": ["retained.txt"],
                "objective": "Retain one bounded conversation",
                "agent_lifecycle": "persistent",
                "allow_child_agents": True,
                "classification": "PUBLIC",
                "trust": "secure",
                "reservation_attempt": 1,
            },
            idempotency_id=f"gui-submit-{submission_id}-attempt-1",
        )
        self.assertEqual(submitted["state"], "accepted")
        row = self.rows("gui_task_submissions")[0]
        canonical = json.loads(row["canonical_json"])
        envelope = json.loads(canonical["envelope"])
        scope_hash = envelope["claim_scope_hash"]
        self.assertIsInstance(scope_hash, str)
        with sqlite3.connect(self.store.path) as connection:
            connection.execute(
                """INSERT INTO opencode_persistent_sessions(
                       scope_hash, pool, worker, title, session_id, state,
                       error, claim_token, claim_started_at, created_at, updated_at
                   ) VALUES (?, 'homelab', 'secure-worker', ?,
                             'retained-terminal-session', 'closed',
                             NULL, NULL, NULL, 't1', 't1')""",
                (scope_hash, f"fugue-persistent-{scope_hash}"),
            )

        params = {"submission_id": submission_id, "reservation_attempt": 1}
        key = f"gui-close-{submission_id}-attempt-1"
        first = self.call("submission.close.v1", params, idempotency_id=key)
        second = self.call("submission.close.v1", params, idempotency_id=key)
        self.assertEqual(first, second)
        self.assertEqual(
            first,
            {
                "submission_id": submission_id,
                "reservation_attempt": 1,
                "state": "closed",
                "reason": None,
            },
        )
        outcomes = [
            item for item in self.rows("daemon_request_outcomes")
            if item["operation"] == "submission.close.v1"
        ]
        self.assertEqual(len(outcomes), 1)
        self.assertFalse(
            any(
                item["operation"] == "submission.close.v1"
                for item in self.rows("daemon_outcome_reservations")
            )
        )
        read = self.call(
            "submission.result.v1",
            params,
            idempotency_id=f"gui-result-{submission_id}-attempt-1",
        )
        self.assertEqual(read["persistent_session_state"], "closed")

    def test_gui_submission_binds_private_codex_callback_outside_payload(self) -> None:
        self.repository.joinpath("callback.txt").write_text("bounded\n", encoding="utf-8")
        submission_id = "123e4567-e89b-12d3-a456-426614174021"
        thread_id = "00000000-0000-7000-8000-abcdef000001"
        result = self.call(
            "submission.submit.v1",
            {
                "submission_id": submission_id,
                "lane": "control",
                "repository": str(self.repository),
                "scope": ["callback.txt"],
                "objective": "Return one bounded proposal",
                "agent_lifecycle": "persistent",
                "allow_child_agents": True,
                "classification": "PUBLIC",
                "trust": "secure",
                "reservation_attempt": 1,
                "return_route": {"kind": "local_codex", "thread_id": thread_id},
            },
            idempotency_id=f"gui-submit-{submission_id}-attempt-1",
        )

        self.assertEqual(result["state"], "rejected")
        routes = self.rows("local_codex_return_routes")
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0]["thread_id"], thread_id)
        payload = self.rows("transport_deliveries")[0]["payload_json"]
        self.assertNotIn(thread_id, payload)
        for event in self.rows("events"):
            self.assertNotIn(thread_id, event["payload_json"])

    def test_workspace_submission_binds_edit_mode_without_disclosing_repository(self) -> None:
        self.repository.joinpath("workspace.txt").write_text(
            "before\n", encoding="utf-8"
        )
        submission_id = "123e4567-e89b-12d3-a456-426614174023"
        result = self.call(
            "submission.submit.v1",
            {
                "submission_id": submission_id,
                "lane": "control",
                "repository": str(self.repository),
                "scope": ["workspace.txt"],
                "objective": "Replace the bounded text.",
                "agent_lifecycle": "disposable",
                "allow_child_agents": True,
                "classification": "PUBLIC",
                "trust": "secure",
                "reservation_attempt": 1,
                "workspace_edit": True,
            },
            idempotency_id=f"gui-submit-{submission_id}-attempt-1",
        )

        self.assertEqual(result["state"], "rejected")
        payload = json.loads(self.rows("transport_deliveries")[0]["payload_json"])
        envelope = json.loads(payload["prompt"])
        self.assertEqual(envelope["task_mode"], "workspace_edit")
        self.assertNotIn(str(self.repository), payload["prompt"])

    def test_workspace_patch_discloses_only_requested_lines(self) -> None:
        lines = [f"ordinary line {index}\n" for index in range(1, 1201)]
        self.repository.joinpath("large.txt").write_text("".join(lines), encoding="utf-8")
        submission_id = "123e4567-e89b-12d3-a456-426614174025"
        result = self.call(
            "submission.submit.v1",
            {
                "submission_id": submission_id,
                "lane": "personal",
                "repository": str(self.repository),
                "scope": ["large.txt"],
                "objective": "Replace the bounded section.",
                "agent_lifecycle": "disposable",
                "allow_child_agents": True,
                "classification": "PUBLIC",
                "trust": "secure",
                "reservation_attempt": 1,
                "workspace_patch": {"line_start": 500, "line_end": 510},
            },
            idempotency_id=f"gui-submit-{submission_id}-attempt-1",
        )

        self.assertEqual(result["state"], "rejected")
        payload = json.loads(self.rows("transport_deliveries")[0]["payload_json"])
        envelope = json.loads(payload["prompt"])
        self.assertEqual(envelope["task_mode"], "workspace_patch")
        disclosed = envelope["scope_capsule"]["files"][0]["content"]
        self.assertIn("ordinary line 500", disclosed)
        self.assertNotIn("ordinary line 499", disclosed)
        self.assertNotIn("ordinary line 511", disclosed)
        self.assertNotIn(str(self.repository), payload["prompt"])
        canonical = json.loads(self.rows("gui_task_submissions")[0]["canonical_json"])
        self.assertIn("ordinary line 499", canonical["patch_authority"]["content"])

    def test_workspace_submission_rejects_multi_file_scope_before_state(self) -> None:
        self.repository.joinpath("workspace-a.txt").write_text("a\n", encoding="utf-8")
        self.repository.joinpath("workspace-b.txt").write_text("b\n", encoding="utf-8")
        submission_id = "123e4567-e89b-12d3-a456-426614174024"
        with self.assertRaises(RigClientError) as rejected:
            self.call(
                "submission.submit.v1",
                {
                    "submission_id": submission_id,
                    "lane": "control",
                    "repository": str(self.repository),
                    "scope": ["workspace-a.txt", "workspace-b.txt"],
                    "objective": "Replace both files.",
                    "agent_lifecycle": "disposable",
                    "allow_child_agents": True,
                    "classification": "PUBLIC",
                    "trust": "secure",
                    "reservation_attempt": 1,
                    "workspace_edit": True,
                },
                idempotency_id=f"gui-submit-{submission_id}-attempt-1",
            )

        self.assertEqual(rejected.exception.code, "invalid_scope")
        self.assertEqual(self.rows("gui_task_submissions"), [])

    def test_gui_submission_rejects_malformed_callback_before_task_state(self) -> None:
        self.repository.joinpath("bad-callback.txt").write_text("bounded\n", encoding="utf-8")
        submission_id = "123e4567-e89b-12d3-a456-426614174022"
        with self.assertRaises(RigClientError) as rejected:
            self.call(
                "submission.submit.v1",
                {
                    "submission_id": submission_id,
                    "lane": "control",
                    "repository": str(self.repository),
                    "scope": ["bad-callback.txt"],
                    "objective": "Return one bounded proposal",
                    "agent_lifecycle": "persistent",
                    "allow_child_agents": True,
                    "classification": "PUBLIC",
                    "trust": "secure",
                    "reservation_attempt": 1,
                    "return_route": {"kind": "local_codex", "thread_id": "invalid"},
                },
                idempotency_id=f"gui-submit-{submission_id}-attempt-1",
            )

        self.assertEqual(rejected.exception.code, "invalid_params")
        self.assertEqual(self.rows("gui_task_submissions"), [])
        self.assertEqual(self.rows("local_codex_return_routes"), [])

    def test_gui_submission_uses_one_journal_entry_and_capacity_fails_atomically(self) -> None:
        self.restart_daemon(max_entries=1)
        self.repository.joinpath("one.txt").write_text("one\n", encoding="utf-8")
        first_id = "123e4567-e89b-12d3-a456-426614174010"
        base = {
            "submission_id": first_id,
            "lane": "homelab",
            "repository": str(self.repository),
            "scope": ["one.txt"],
            "objective": "One bounded task",
            "agent_lifecycle": "disposable",
            "allow_child_agents": True,
            "classification": "PUBLIC",
            "trust": "secure",
            "reservation_attempt": 1,
        }
        first = self.call(
            "submission.submit.v1", base,
            idempotency_id=f"gui-submit-{first_id}-attempt-1",
        )
        self.assertEqual(first["state"], "rejected")
        self.assertEqual(len(self.rows("daemon_request_outcomes")), 1)
        self.assertEqual(self.rows("daemon_outcome_reservations"), [])

        before = {
            table: len(self.rows(table))
            for table in ("operations", "scope_claims", "scheduler_work")
        }
        self.repository.joinpath("two.txt").write_text("two\n", encoding="utf-8")
        second_id = "123e4567-e89b-12d3-a456-426614174011"
        with self.assertRaises(RigClientError) as full:
            self.call(
                "submission.submit.v1",
                {
                    **base,
                    "submission_id": second_id,
                    "scope": ["two.txt"],
                    "objective": "Another bounded task",
                },
                idempotency_id=f"gui-submit-{second_id}-attempt-1",
            )
        self.assertEqual(full.exception.code, "idempotency_capacity")
        self.assertEqual(
            before,
            {
                table: len(self.rows(table))
                for table in ("operations", "scope_claims", "scheduler_work")
            },
        )
        self.assertEqual(len(self.rows("gui_task_submissions")), 1)

    def test_gui_prepared_retry_uses_durable_capsule_after_scope_becomes_symlink(self) -> None:
        relative = "prepared.txt"
        scoped = self.repository / relative
        scoped.write_text("original bounded body\n", encoding="utf-8")
        submission_id = "123e4567-e89b-12d3-a456-426614174012"
        params = {
            "submission_id": submission_id,
            "lane": "homelab",
            "repository": str(self.repository),
            "scope": [relative],
            "objective": "Exercise exact prepared replay",
            "agent_lifecycle": "disposable",
            "allow_child_agents": True,
            "classification": "PUBLIC",
            "trust": "secure",
            "reservation_attempt": 1,
        }
        key = f"gui-submit-{submission_id}-attempt-1"
        self.restart_daemon(mode="crash_after_prepare")
        with self.assertRaises(IncompleteFrame):
            self.call("submission.submit.v1", params, idempotency_id=key)
        self.assertEqual(self.rows("gui_task_submissions")[0]["state"], "prepared")
        self.assertEqual(self.rows("scope_claims")[0]["state"], "active")

        scoped.unlink()
        replacement = self.repository / "replacement.txt"
        replacement.write_text("changed after durable prepare\n", encoding="utf-8")
        scoped.symlink_to(replacement)
        self.restart_daemon()
        replayed = self.call("submission.submit.v1", params, idempotency_id=key)

        self.assertEqual(replayed["state"], "rejected")
        self.assertEqual(self.rows("gui_task_submissions")[0]["state"], "completed")
        self.assertEqual(self.rows("scope_claims")[0]["state"], "released")
        payload = json.loads(self.rows("transport_deliveries")[0]["payload_json"])
        self.assertIn("original bounded body", payload["prompt"])
        self.assertNotIn("changed after durable prepare", payload["prompt"])

    def test_gui_retry_finalizes_stored_transport_rejection(self) -> None:
        self.repository.joinpath("stored-failure.txt").write_text(
            "bounded\n", encoding="utf-8"
        )
        submission_id = "123e4567-e89b-12d3-a456-426614174014"
        params = {
            "submission_id": submission_id,
            "lane": "homelab",
            "repository": str(self.repository),
            "scope": ["stored-failure.txt"],
            "objective": "Recover a stored transport rejection",
            "agent_lifecycle": "persistent",
            "allow_child_agents": True,
            "classification": "PUBLIC",
            "trust": "secure",
            "reservation_attempt": 1,
        }
        key = f"gui-submit-{submission_id}-attempt-1"
        self.restart_daemon(mode="crash_after_prepare")
        with self.assertRaises(IncompleteFrame):
            self.call("submission.submit.v1", params, idempotency_id=key)
        with closing(sqlite3.connect(self.store.path)) as connection, connection:
            reserved = connection.execute(
                """SELECT idempotency_id, fingerprint, operation
                   FROM daemon_outcome_reservations"""
            ).fetchone()
            assert reserved is not None
            connection.execute(
                "DELETE FROM daemon_outcome_reservations WHERE idempotency_id = ?",
                (reserved[0],),
            )
            connection.execute(
                """INSERT INTO daemon_request_outcomes(
                       idempotency_id, fingerprint, operation, ok,
                       outcome_json, completed_at
                   ) VALUES (?, ?, ?, 0, ?, 't1')""",
                (
                    reserved[0], reserved[1], reserved[2],
                    json.dumps(
                        {"code": "adapter_failure", "message": "stored failure"},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
        self.restart_daemon()

        replayed = self.call("submission.submit.v1", params, idempotency_id=key)

        self.assertEqual(replayed["state"], "rejected")
        self.assertEqual(self.rows("gui_task_submissions")[0]["state"], "completed")
        self.assertEqual(self.rows("scheduler_assignments")[0]["state"], "released")
        self.assertEqual(self.rows("scope_claims")[0]["state"], "released")
        result = self.call(
            "submission.result.v1",
            {"submission_id": submission_id, "reservation_attempt": 1},
            idempotency_id=f"gui-result-{submission_id}-attempt-1",
        )
        self.assertEqual(result["state"], "not_started")

    def test_gui_busy_submission_leaves_no_new_authority_and_can_retry(self) -> None:
        for label in ("full-one", "full-two", "full-three"):
            self.ready(label, "homelab")
        self.repository.joinpath("queued.txt").write_text("bounded\n", encoding="utf-8")
        submission_id = "123e4567-e89b-12d3-a456-426614174001"
        params = {
            "submission_id": submission_id,
            "lane": "homelab",
            "repository": str(self.repository),
            "scope": ["queued.txt"],
            "objective": "Review the queued boundary",
            "agent_lifecycle": "persistent",
            "allow_child_agents": True,
            "classification": "PUBLIC",
            "trust": "secure",
            "reservation_attempt": 1,
        }
        first = self.call(
            "submission.submit.v1", params,
            idempotency_id=f"gui-submit-{submission_id}-attempt-1",
        )
        retry = {**params, "reservation_attempt": 2}
        second = self.call(
            "submission.submit.v1", retry,
            idempotency_id=f"gui-submit-{submission_id}-attempt-2",
        )
        self.assertEqual(first["state"], "busy")
        self.assertEqual(second["state"], "busy")
        self.assertEqual(first["reservation_attempt"], 1)
        self.assertEqual(second["reservation_attempt"], 2)
        self.assertEqual(len(self.rows("scope_claims")), 3)
        self.assertEqual(len(self.rows("operations")), 3)

    def test_gui_submission_registry_is_bounded_by_controller_capacity(self) -> None:
        self.restart_daemon(max_entries=1)
        with closing(sqlite3.connect(self.store.path)) as connection, connection:
            connection.execute(
                """INSERT INTO gui_task_submissions(
                       submission_key, request_fingerprint, canonical_json,
                       state, outcome_json, created_at, completed_at
                   ) VALUES ('existing-submission', ?, '{}', 'completed',
                             '{}', 't0', 't1')""",
                ("a" * 64,),
            )
        self.repository.joinpath("bounded-registry.txt").write_text(
            "bounded\n", encoding="utf-8"
        )
        submission_id = "123e4567-e89b-12d3-a456-426614174013"
        params = {
            "submission_id": submission_id,
            "lane": "homelab",
            "repository": str(self.repository),
            "scope": ["bounded-registry.txt"],
            "objective": "Bound the GUI registry",
            "agent_lifecycle": "persistent",
            "allow_child_agents": True,
            "classification": "PUBLIC",
            "trust": "secure",
            "reservation_attempt": 1,
        }
        with self.assertRaises(RigClientError) as bounded:
            self.call(
                "submission.submit.v1",
                params,
                idempotency_id=f"gui-submit-{submission_id}-attempt-1",
            )
        self.assertEqual(bounded.exception.code, "idempotency_capacity")
        self.assertEqual(len(self.rows("gui_task_submissions")), 1)

    def test_submission_rejection_is_atomic_fenced_and_idempotent(self) -> None:
        operation_id = "owner-atomic-reject"
        self.call(
            "operation.create.v1",
            {"operation_id": operation_id, "kind": "dispatch"},
            idempotency_id="atomic-reject-op",
        )
        self.repository.joinpath("reject.txt").write_text("bounded", encoding="utf-8")
        claim = self.call(
            "scope.claim.v1",
            {"owner_operation_id": operation_id, "repository": str(self.repository), "scope": ["reject.txt"]},
            idempotency_id="atomic-reject-claim",
        )
        params = {
            "operation_id": operation_id,
            "claim_id": claim["claim_id"],
            "owner_id": claim["owner_id"],
            "attempt": claim["attempt"],
            "fence_token": claim["fence_token"],
        }
        with self.assertRaises(RigClientError):
            self.call(
                "submission.reject.v1",
                {**params, "fence_token": "wrong-fence"},
                idempotency_id="atomic-reject-wrong",
            )
        self.assertEqual(self.rows("operations")[0]["state"], "pending")
        self.assertEqual(self.rows("scope_claims")[0]["state"], "active")

        first = self.call("submission.reject.v1", params, idempotency_id="atomic-reject")
        second = self.call("submission.reject.v1", params, idempotency_id="atomic-reject")
        repaired = self.call(
            "submission.reject.v1", params, idempotency_id="atomic-reject-retry"
        )
        self.assertEqual(first, second)
        self.assertEqual(first, repaired)
        self.assertEqual(self.rows("operations")[0]["state"], "failed")
        self.assertEqual(self.rows("scope_claims")[0]["state"], "released")

    def test_submit_preflight_rejects_unsupported_trust_and_oversized_envelope_without_leaks(self) -> None:
        relative = "preflight.txt"
        self.repository.joinpath(relative).write_text("bounded", encoding="utf-8")
        base = [
            "--socket",
            str(self.socket),
            "--approved-root",
            str(self.root),
            "--service-uid",
            str(self.service_uid),
            "--client-gid",
            str(self.client_gid),
        ]

        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as insecure:
            cli_main(
                [
                    *base,
                    "--idempotency-id",
                    "preflight-insecure",
                    "submit",
                    "tensorhost",
                    str(self.repository),
                    "--scope",
                    relative,
                    "--prompt",
                    "bounded task",
                    "--classification",
                    "PUBLIC",
                    "--trust",
                    "insecure",
                ]
            )
        self.assertEqual(insecure.exception.code, 2)

        stderr = StringIO()
        with patch.dict(os.environ, {}, clear=True), redirect_stderr(stderr):
            oversized = cli_main(
                [
                    *base,
                    "--idempotency-id",
                    "preflight-oversized",
                    "submit",
                    "tensorhost",
                    str(self.repository),
                    "--scope",
                    relative,
                    "--prompt",
                    "a" * MAX_PROMPT_BYTES,
                    "--classification",
                    "PUBLIC",
                    "--trust",
                    "secure",
                ]
            )
        self.assertEqual(oversized, 1)
        self.assertIn("canonical worker envelope exceeds", stderr.getvalue())

        stderr = StringIO()
        with patch.dict(os.environ, {}, clear=True), redirect_stderr(stderr):
            rejected_capsule = cli_main(
                [
                    *base,
                    "--idempotency-id",
                    "preflight-capsule-sanitized",
                    "submit",
                    "tensorhost",
                    str(self.repository),
                    "--scope",
                    relative,
                    "--include-scope",
                    "--review-profile",
                    "security",
                    "--classification",
                    "SANITIZED",
                    "--trust",
                    "secure",
                ]
            )
        self.assertEqual(rejected_capsule, 1)
        self.assertIn("requires --classification PUBLIC", stderr.getvalue())
        for table in (
            "operations",
            "scope_claims",
            "scheduler_work",
            "scheduler_assignments",
        ):
            self.assertEqual(self.rows(table), [], table)
    def test_private_local_codex_return_route_is_bound_beside_payload(self) -> None:
        self.ready("local-route")
        thread_id = "00000000-0000-7000-8000-abcdef000001"
        result = self.call(
            "transport.dispatch.v1",
            {
                "work_id": "work-local-route",
                "pool": "tensorhost",
                "payload": {"prompt": "safe work"},
                "return_route": {"kind": "local_codex", "thread_id": thread_id},
            },
            idempotency_id="dispatch-local-route",
        )
        self.assertEqual(result["state"], "definite_failed")
        routes = self.rows("local_codex_return_routes")
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0]["thread_id"], thread_id)
        deliveries = self.rows("transport_deliveries")
        self.assertEqual(len(deliveries), 1)
        self.assertNotIn(thread_id, deliveries[0]["payload_json"])
        for event in self.rows("events"):
            self.assertNotIn(thread_id, event["payload_json"])

    def test_malformed_local_codex_return_route_fails_before_side_effects(self) -> None:
        self.ready("bad-local-route")
        before_deliveries = len(self.rows("transport_deliveries"))
        with self.assertRaises(RigClientError) as rejected:
            self.call(
                "transport.dispatch.v1",
                {
                    "work_id": "work-bad-local-route",
                    "pool": "tensorhost",
                    "payload": {"prompt": "safe work"},
                    "return_route": {"kind": "local_codex", "thread_id": "control"},
                },
                idempotency_id="dispatch-bad-local-route",
            )
        self.assertEqual(rejected.exception.code, "invalid_params")
        self.assertEqual(len(self.rows("transport_deliveries")), before_deliveries)
        self.assertEqual(self.rows("local_codex_return_routes"), [])

    def test_duplicate_and_concurrent_dispatch_calls_disabled_adapter_once(self) -> None:
        self.ready("duplicate")
        def invoke(index: int) -> dict[str, object]:
            return self.call(
                "transport.dispatch.v1",
                {
                    "work_id": "work-duplicate",
                    "pool": "tensorhost",
                    "payload": {"prompt": "safe work"},
                },
                idempotency_id="dispatch-duplicate",
                request_id=f"concurrent-{index}",
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(invoke, range(16)))
        self.assertEqual(len(self.rows("transport_attempts")), 1)
        self.assertEqual({result["transport_id"] for result in results}, {results[0]["transport_id"]})

    def test_post_intent_disconnect_is_unknown_and_never_retried(self) -> None:
        self.ready("unknown")
        self.restart_daemon(mode="disconnect")
        first = self.dispatch("unknown")
        second = self.dispatch("unknown")
        self.assertEqual(first["state"], "delivery_unknown")
        self.assertEqual(first["error_code"], "adapter_exception_after_send_intent")
        self.assertEqual(second, first)
        self.assertEqual(len(self.rows("transport_attempts")), 1)

    def test_prompt_must_match_the_exact_admitted_worker_instructions(self) -> None:
        self.ready("instruction-fence", content="admitted instructions")
        with self.assertRaises(RigClientError) as caught:
            self.call(
                "transport.dispatch.v1",
                {
                    "work_id": "work-instruction-fence",
                    "pool": "tensorhost",
                    "payload": {"prompt": "different delivered instructions"},
                },
                idempotency_id="dispatch-instruction-fence",
            )
        self.assertEqual(caught.exception.code, "ownership_conflict")
        self.assertEqual(self.rows("transport_deliveries"), [])

    def test_transport_caller_cannot_override_admitted_agent_policy(self) -> None:
        self.ready("agent-policy-override")
        before = len(self.rows("transport_deliveries"))
        for field, value in (
            ("agent_lifecycle", "disposable"),
            ("allow_child_agents", True),
        ):
            with self.subTest(field=field), self.assertRaises(RigClientError) as caught:
                self.call(
                    "transport.dispatch.v1",
                    {
                        "work_id": "work-agent-policy-override",
                        "pool": "tensorhost",
                        "payload": {"prompt": "safe work", field: value},
                    },
                    idempotency_id=f"dispatch-agent-policy-override-{field}",
                )
            self.assertEqual(caught.exception.code, "invalid_params")
        self.assertEqual(len(self.rows("transport_deliveries")), before)

    def test_transport_revalidates_scope_capsule_and_claim_hash(self) -> None:
        relative = "capsule-valid.txt"
        self.repository.joinpath(relative).write_text("bounded", encoding="utf-8")
        capsule = capture_scope_capsule(str(self.repository), [relative])
        envelope = render_capsule_prompt(
            {
                "claim_scope_hash": capsule.claim_scope_hash,
                "review_profiles": ["correctness"],
                "scope": [relative],
                "scope_capsule": capsule_document(capsule),
                "task_mode": "read_only_review",
                "version": 2,
            },
        )
        self.ready(
            "capsule-valid",
            content=envelope,
            classification="PUBLIC",
        )
        accepted = self.call(
            "transport.dispatch.v1",
            {
                "work_id": "work-capsule-valid",
                "pool": "tensorhost",
                "payload": {
                    "prompt": envelope,
                    "classification": "PUBLIC",
                    "trust": "secure",
                },
            },
            idempotency_id="dispatch-capsule-valid",
        )
        self.assertEqual(accepted["state"], "definite_failed")
        self.assertEqual(len(self.rows("transport_deliveries")), 1)

        mismatch_relative = "capsule-mismatch.txt"
        self.repository.joinpath(mismatch_relative).write_text("bounded", encoding="utf-8")
        mismatch_capsule = capture_scope_capsule(
            str(self.repository), [mismatch_relative]
        )
        mismatch_envelope = render_capsule_prompt(
            {
                "claim_scope_hash": "0" * 64,
                "review_profiles": ["correctness"],
                "scope": [mismatch_relative],
                "scope_capsule": capsule_document(mismatch_capsule),
                "task_mode": "read_only_review",
                "version": 2,
            },
        )
        self.ready(
            "capsule-mismatch",
            content=mismatch_envelope,
            classification="PUBLIC",
        )
        before = len(self.rows("transport_deliveries"))
        with self.assertRaises(RigClientError) as rejected:
            self.call(
                "transport.dispatch.v1",
                {
                    "work_id": "work-capsule-mismatch",
                    "pool": "tensorhost",
                    "payload": {
                        "prompt": mismatch_envelope,
                        "classification": "PUBLIC",
                        "trust": "secure",
                    },
                },
                idempotency_id="dispatch-capsule-mismatch",
            )
        self.assertEqual(rejected.exception.code, "ownership_conflict")
        self.assertEqual(len(self.rows("transport_deliveries")), before)

    def test_confirmed_no_capacity_can_reserve_and_dispatch_next_generation(self) -> None:
        self.ready("capacity-retry")
        first_reservation = dict(self.rows("scheduler_assignments")[0])
        self.restart_daemon(mode="no_capacity_once")

        first = self.call(
            "transport.dispatch.v1",
            {
                "work_id": "work-capacity-retry",
                "pool": "tensorhost",
                "reservation_id": first_reservation["id"],
                "reservation_attempt": first_reservation["attempt"],
                "reservation_fence": first_reservation["fence_token"],
                "payload": {"prompt": "safe work"},
            },
            idempotency_id="dispatch-capacity-retry-1",
        )
        self.assertEqual(first["state"], "definite_failed")
        self.assertEqual(first["error_code"], "no_capacity")
        released = dict(self.rows("scheduler_assignments")[0])
        self.assertEqual(released["state"], "released")
        self.assertEqual(released["release_outcome"], "requeued")
        work = dict(self.rows("scheduler_work")[0])
        self.assertEqual(work["state"], "queued")
        self.assertIsNone(work["active_assignment_id"])
        second_reservation = self.call(
            "scheduler.reserve.v1",
            {"work_id": "work-capacity-retry"},
            idempotency_id="reserve-capacity-retry-2",
        )["reservation"]
        self.assertEqual(second_reservation["attempt"], 2)

        with self.assertRaises(RigClientError) as stale:
            self.call(
                "transport.dispatch.v1",
                {
                    "work_id": "work-capacity-retry",
                    "pool": "tensorhost",
                    "reservation_id": first_reservation["id"],
                    "reservation_attempt": first_reservation["attempt"],
                    "reservation_fence": first_reservation["fence_token"],
                    "payload": {"prompt": "safe work"},
                },
                idempotency_id="dispatch-capacity-retry-stale",
            )
        self.assertEqual(stale.exception.code, "ownership_conflict")

        second = self.call(
            "transport.dispatch.v1",
            {
                "work_id": "work-capacity-retry",
                "pool": "tensorhost",
                "reservation_id": second_reservation["id"],
                "reservation_attempt": second_reservation["attempt"],
                "reservation_fence": second_reservation["fence_token"],
                "payload": {"prompt": "safe work"},
            },
            idempotency_id="dispatch-capacity-retry-2",
        )
        self.assertEqual(second["state"], "accepted")
        self.assertEqual(len(self.rows("transport_deliveries")), 2)

    def test_definite_review_failure_cancels_exact_assignment_idempotently(self) -> None:
        self.ready("review-invalid")
        self.restart_daemon(mode="review_agent_invalid")
        first = self.dispatch(
            "review-invalid", idempotency_id="dispatch-review-invalid"
        )
        retry = self.dispatch(
            "review-invalid", idempotency_id="dispatch-review-invalid"
        )
        self.assertEqual(first, retry)
        self.assertEqual(first["state"], "definite_failed")
        self.assertEqual(first["error_code"], "review_agent_invalid")
        assignment = dict(self.rows("scheduler_assignments")[0])
        self.assertEqual(assignment["state"], "released")
        self.assertEqual(assignment["release_outcome"], "cancelled")
        work = dict(self.rows("scheduler_work")[0])
        self.assertEqual(work["state"], "cancelled")
        self.assertIsNone(work["active_assignment_id"])
        slot = next(
            row for row in self.rows("scheduler_slots")
            if row["id"] == assignment["slot_id"]
        )
        self.assertEqual(slot["state"], "clear")
        self.assertIsNone(slot["active_assignment_id"])
        releases = [
            row for row in self.rows("events")
            if row["event_type"] == "scheduler.assignment.released"
        ]
        self.assertEqual(len(releases), 1)

    def test_cancelled_dispatch_cancels_exact_assignment(self) -> None:
        self.ready("transport-cancelled")
        self.restart_daemon(mode="cancelled")
        result = self.dispatch("transport-cancelled")
        self.assertEqual(result["state"], "cancelled")
        assignment = dict(self.rows("scheduler_assignments")[0])
        self.assertEqual(assignment["release_outcome"], "cancelled")
        self.assertEqual(self.rows("scheduler_work")[0]["state"], "cancelled")

    def test_accepted_and_unknown_dispatches_retain_assignment_authority(self) -> None:
        for mode, state in (("accepted", "accepted"), ("delivery_unknown", "delivery_unknown")):
            with self.subTest(mode=mode):
                label = f"retained-{mode}"
                self.ready(label)
                self.restart_daemon(mode=mode)
                result = self.dispatch(label)
                self.assertEqual(result["state"], state)
                assignment = dict(self.rows("scheduler_assignments")[-1])
                self.assertEqual(assignment["state"], "active")
                self.assertIsNone(assignment["release_outcome"])
                work = next(
                    row for row in self.rows("scheduler_work")
                    if row["id"] == f"work-{label}"
                )
                self.assertEqual(work["state"], "assigned")

    def test_terminal_release_mismatch_is_reported_and_retained_as_attention(self) -> None:
        self.ready("release-mismatch")
        self.restart_daemon(mode="terminal_release_mismatch")
        with self.assertRaises(RigClientError) as rejected:
            self.dispatch("release-mismatch")
        self.assertEqual(rejected.exception.code, "ownership_conflict")
        delivery = dict(self.rows("transport_deliveries")[0])
        self.assertEqual(delivery["state"], "definite_failed")
        self.assertEqual(self.rows("scheduler_assignments")[0]["state"], "active")
        snapshot = self.call(
            "cockpit.snapshot.v1", idempotency_id="snapshot-release-mismatch"
        )["snapshot"]
        reasons = {
            item["reason"]
            for item in snapshot["attention"]["operator_required"]["items"]
        }
        self.assertEqual(reasons, {"ownership_conflict"})
        release_attention = next(
            item for item in snapshot["attention"]["operator_required"]["items"]
            if item["kind"] == "transport_release_attention"
        )
        self.assertEqual(release_attention["id"], delivery["id"])
        self.assertEqual(release_attention["work_id"], "work-release-mismatch")
        self.assertEqual(release_attention["generation"], 1)

    def test_restart_reconciles_committed_send_intent_without_resend_or_pid_signal(self) -> None:
        self.ready("restart")

        self.restart_daemon(mode="crash_after_intent")
        with self.assertRaises(IncompleteFrame):
            self.call(
                "transport.dispatch.v1",
                {
                    "work_id": "work-restart",
                    "pool": "tensorhost",
                    "payload": {"prompt": "safe work"},
                },
                request_id="crash-after-intent",
                idempotency_id="dispatch-restart",
            )
        self.assertEqual(self.rows("transport_deliveries")[0]["state"], "sending")
        self.restart_daemon()
        recovered = self.call(
            "transport.dispatch.v1",
            {
                "work_id": "work-restart",
                "pool": "tensorhost",
                "payload": {"prompt": "safe work"},
            },
            request_id="retry-after-intent",
            idempotency_id="dispatch-restart",
        )
        self.assertEqual(recovered["state"], "delivery_unknown")
        self.assertEqual(len(self.rows("transport_attempts")), 1)

    def test_restart_cancel_prepared_transport_atomically_clears_assignment(self) -> None:
        self.ready("cancel-prepared")
        self.restart_daemon(mode="crash_after_prepare")
        with self.assertRaises(IncompleteFrame):
            self.dispatch("cancel-prepared")
        self.assertEqual(self.rows("transport_deliveries")[0]["state"], "prepared")
        self.assertEqual(self.rows("scheduler_assignments")[0]["state"], "active")

        self.restart_daemon()
        params = {"work_id": "work-cancel-prepared", "pool": "tensorhost"}
        first = self.call(
            "transport.cancel.v1", params,
            idempotency_id="cancel-prepared-after-restart",
        )
        retry = self.call(
            "transport.cancel.v1", params,
            idempotency_id="cancel-prepared-after-restart",
        )
        verified = self.call(
            "transport.cancel.v1", params,
            idempotency_id="cancel-prepared-terminal-verify",
        )
        self.assertEqual(first, retry)
        self.assertEqual(first, verified)
        self.assertEqual(first["transport"]["state"], "cancelled")
        assignment = dict(self.rows("scheduler_assignments")[0])
        self.assertEqual(assignment["state"], "released")
        self.assertEqual(assignment["release_outcome"], "cancelled")
        self.assertEqual(self.rows("scheduler_work")[0]["state"], "cancelled")
        slot = next(
            row for row in self.rows("scheduler_slots")
            if row["id"] == assignment["slot_id"]
        )
        self.assertEqual(slot["state"], "clear")
        self.assertEqual(
            self.rows("transport_completion_registrations")[0]["state"],
            "cancelled",
        )
        self.assertEqual(
            self.rows("transport_callback_registrations")[0]["state"],
            "cancelled",
        )
        self.assertEqual(self.rows("return_routes")[0]["state"], "cancelled")

    def test_cancel_accepted_transport_releases_all_exact_authority(self) -> None:
        self.ready("cancel-accepted")
        self.restart_daemon(mode="accepted_abort_cancelled")
        accepted = self.dispatch("cancel-accepted")
        self.assertEqual(accepted["state"], "accepted")

        params = {"work_id": "work-cancel-accepted", "pool": "tensorhost"}
        first = self.call(
            "transport.cancel.v1", params,
            idempotency_id="cancel-accepted-terminal",
        )
        retry = self.call(
            "transport.cancel.v1", params,
            idempotency_id="cancel-accepted-terminal",
        )

        self.assertEqual(first, retry)
        self.assertEqual(first["abort"]["disposition"], "cancelled")
        assignment = self.rows("scheduler_assignments")[0]
        self.assertEqual(
            (assignment["state"], assignment["release_outcome"]),
            ("released", "cancelled"),
        )
        self.assertEqual(self.rows("scheduler_work")[0]["state"], "cancelled")
        self.assertEqual(self.rows("scope_claims")[0]["state"], "released")
        self.assertEqual(
            self.rows("transport_completion_registrations")[0]["state"],
            "cancelled",
        )
        self.assertEqual(
            self.rows("transport_callback_registrations")[0]["state"],
            "cancelled",
        )
        self.assertEqual(self.rows("return_routes")[0]["state"], "cancelled")
        self.assertEqual(self.rows("completion_events"), [])
        slot = next(
            row for row in self.rows("scheduler_slots")
            if row["id"] == assignment["slot_id"]
        )
        self.assertEqual(slot["state"], "clear")

    def test_cancel_accepted_transport_finishes_prior_exact_release(self) -> None:
        self.ready("cancel-pre-released")
        self.restart_daemon(mode="accepted_abort_cancelled")
        accepted = self.dispatch("cancel-pre-released")
        self.assertEqual(accepted["state"], "accepted")
        delivery = self.rows("transport_deliveries")[0]
        assignment = self.rows("scheduler_assignments")[0]
        claim = self.claims["cancel-pre-released"]
        released = self.call(
            "scheduler.release.v1",
            {
                "reservation_id": assignment["id"],
                "work_id": "work-cancel-pre-released",
                "owner_id": assignment["owner_id"],
                "attempt": assignment["attempt"],
                "fence_token": assignment["fence_token"],
                "outcome": "cancelled",
            },
            idempotency_id="pre-release-assignment",
        )
        self.assertTrue(released["released"])
        scope = self.call(
            "scope.release.v1",
            {
                "claim_id": claim["claim_id"],
                "owner_id": claim["owner_id"],
                "attempt": claim["attempt"],
                "fence_token": claim["fence_token"],
            },
            idempotency_id="pre-release-scope",
        )
        self.assertTrue(scope["released"])

        cancelled = self.call(
            "transport.cancel.v1",
            {"work_id": "work-cancel-pre-released", "pool": "tensorhost"},
            idempotency_id="finish-pre-released-transport",
        )

        self.assertEqual(cancelled["abort"]["disposition"], "cancelled")
        self.assertEqual(delivery["state"], "accepted")
        self.assertEqual(
            self.rows("transport_completion_registrations")[0]["state"],
            "cancelled",
        )
        self.assertEqual(
            self.rows("transport_callback_registrations")[0]["state"],
            "cancelled",
        )
        self.assertEqual(self.rows("return_routes")[0]["state"], "cancelled")
        self.assertEqual(self.rows("completion_events"), [])

    def test_reconcile_legacy_cancelled_transport_releases_lease_and_route(self) -> None:
        self.ready("reconcile-legacy-cancel")
        self.restart_daemon(mode="accepted")
        accepted = self.dispatch("reconcile-legacy-cancel")
        self.assertEqual(accepted["state"], "accepted")
        delivery = self.rows("transport_deliveries")[0]
        completion = self.rows("transport_completion_registrations")[0]
        callback = self.rows("transport_callback_registrations")[0]
        assignment = self.rows("scheduler_assignments")[0]
        claim = self.claims["reconcile-legacy-cancel"]
        now = "2026-09-06T00:00:00Z"
        with sqlite3.connect(self.store.path) as connection:
            connection.execute(
                """INSERT INTO opencode_slot_generations(
                       slot_id, session_id, worker, generation, updated_at
                   ) VALUES ('tensorhost-1', 'session-base',
                             'rig-read-only-review', 1, ?)""",
                (now,),
            )
            connection.execute(
                """INSERT INTO opencode_deliveries(
                       transport_id, request_fingerprint, work_id, pool,
                       completion_registration_id, callback_registration_id,
                       slot_id, session_id, worker, assignment_generation,
                       prompt_message_id, delivery_capability, delivery_state,
                       acknowledgement_id, error_code, lease_state, abort_state,
                       abort_capability, abort_disposition, abort_error_code,
                       created_at, updated_at, finished_at, abort_started_at,
                       abort_finished_at, isolated_session_id, cleanup_state,
                       cleanup_attempts, cleanup_error, agent_lifecycle
                   ) VALUES (?, ?, ?, 'tensorhost', ?, ?, 'tensorhost-1',
                             'session-base', 'rig-read-only-review', 1,
                             'message-legacy', ?, 'accepted',
                             'acknowledgement-legacy', NULL, 'active', 'terminal',
                             ?, 'definite_failed', 'abort_backend_not_active',
                             ?, ?, ?, ?, ?, 'session-isolated', 'none', 0, NULL,
                             'disposable')""",
                (
                    delivery["id"], "a" * 64, delivery["work_id"],
                    completion["id"], callback["id"], "b" * 64, "c" * 64,
                    now, now, now, now, now,
                ),
            )
        released = self.call(
            "scheduler.release.v1",
            {
                "reservation_id": assignment["id"],
                "work_id": delivery["work_id"],
                "owner_id": assignment["owner_id"],
                "attempt": assignment["attempt"],
                "fence_token": assignment["fence_token"],
                "outcome": "cancelled",
            },
            idempotency_id="legacy-release-assignment",
        )
        self.assertTrue(released["released"])
        scope = self.call(
            "scope.release.v1",
            {
                "claim_id": claim["claim_id"],
                "owner_id": claim["owner_id"],
                "attempt": claim["attempt"],
                "fence_token": claim["fence_token"],
            },
            idempotency_id="legacy-release-scope",
        )
        self.assertTrue(scope["released"])

        result = self.call(
            "transport.reconcilecancelled.v1",
            {"work_id": delivery["work_id"], "pool": "tensorhost"},
            idempotency_id="reconcile-legacy-cancel",
        )

        self.assertTrue(result["reconciled"])
        opencode = self.rows("opencode_deliveries")[0]
        self.assertEqual(opencode["lease_state"], "released")
        self.assertEqual(opencode["cleanup_state"], "pending")
        self.assertEqual(
            self.rows("transport_completion_registrations")[0]["state"],
            "cancelled",
        )
        self.assertEqual(self.rows("return_routes")[0]["state"], "cancelled")
        self.assertEqual(self.rows("completion_events"), [])

    def test_reconcile_idle_disposable_abort_releases_exact_authority(self) -> None:
        self.ready("reconcile-idle-disposable")
        self.restart_daemon(mode="accepted")
        accepted = self.dispatch("reconcile-idle-disposable")
        self.assertEqual(accepted["state"], "accepted")
        delivery = self.rows("transport_deliveries")[0]
        completion = self.rows("transport_completion_registrations")[0]
        callback = self.rows("transport_callback_registrations")[0]
        assignment = self.rows("scheduler_assignments")[0]
        now = "2026-09-07T00:00:00Z"
        with sqlite3.connect(self.store.path) as connection:
            connection.execute(
                """INSERT INTO opencode_slot_generations(
                       slot_id, session_id, worker, generation, updated_at
                   ) VALUES ('tensorhost-1', 'session-base',
                             'rig-read-only-review', 1, ?)""",
                (now,),
            )
            connection.execute(
                """INSERT INTO opencode_deliveries(
                       transport_id, request_fingerprint, work_id, pool,
                       completion_registration_id, callback_registration_id,
                       slot_id, session_id, worker, assignment_generation,
                       prompt_message_id, delivery_capability, delivery_state,
                       acknowledgement_id, error_code, lease_state, abort_state,
                       abort_capability, abort_disposition, abort_error_code,
                       created_at, updated_at, finished_at, abort_started_at,
                       abort_finished_at, isolated_session_id, cleanup_state,
                       cleanup_attempts, cleanup_error, agent_lifecycle
                   ) VALUES (?, ?, ?, 'tensorhost', ?, ?, 'tensorhost-1',
                             'session-base', 'rig-read-only-review', 1,
                             'message-idle-disposable', ?, 'accepted',
                             'acknowledgement-idle-disposable', NULL, 'aborting',
                             'in_flight', ?, NULL, NULL, ?, ?, ?, ?, NULL,
                             'session-isolated-idle', 'none', 0, NULL,
                             'disposable')""",
                (
                    delivery["id"], "d" * 64, delivery["work_id"],
                    completion["id"], callback["id"], "e" * 64, "f" * 64,
                    now, now, now, now,
                ),
            )

        result = self.call(
            "transport.reconcilecancelled.v1",
            {"work_id": delivery["work_id"], "pool": "tensorhost"},
            idempotency_id="reconcile-idle-disposable",
        )

        self.assertTrue(result["reconciled"])
        opencode = self.rows("opencode_deliveries")[0]
        self.assertEqual(opencode["abort_state"], "terminal")
        self.assertEqual(opencode["abort_disposition"], "cancelled")
        self.assertEqual(opencode["lease_state"], "released")
        self.assertEqual(opencode["cleanup_state"], "pending")
        assignment = self.rows("scheduler_assignments")[0]
        self.assertEqual(
            (assignment["state"], assignment["release_outcome"]),
            ("released", "cancelled"),
        )
        self.assertEqual(self.rows("scheduler_work")[0]["state"], "cancelled")
        self.assertEqual(self.rows("scope_claims")[0]["state"], "released")
        self.assertEqual(
            self.rows("transport_completion_registrations")[0]["state"],
            "cancelled",
        )
        self.assertEqual(
            self.rows("transport_callback_registrations")[0]["state"],
            "cancelled",
        )
        self.assertEqual(self.rows("return_routes")[0]["state"], "cancelled")
        self.assertEqual(self.rows("completion_events"), [])
        slot = next(
            row for row in self.rows("scheduler_slots")
            if row["id"] == assignment["slot_id"]
        )
        self.assertEqual(slot["state"], "clear")

    def test_prepared_cancel_release_mismatch_rolls_back_and_records_attention(self) -> None:
        self.ready("cancel-mismatch")
        self.restart_daemon(mode="crash_after_prepare")
        with self.assertRaises(IncompleteFrame):
            self.dispatch("cancel-mismatch")
        self.restart_daemon(mode="terminal_release_mismatch")
        with self.assertRaises(RigClientError) as rejected:
            self.call(
                "transport.cancel.v1",
                {"work_id": "work-cancel-mismatch", "pool": "tensorhost"},
                idempotency_id="cancel-prepared-mismatch",
            )
        self.assertEqual(rejected.exception.code, "ownership_conflict")
        self.assertEqual(self.rows("transport_deliveries")[0]["state"], "prepared")
        self.assertEqual(
            self.rows("transport_completion_registrations")[0]["state"],
            "pending",
        )
        self.assertEqual(self.rows("return_routes")[0]["state"], "registered")
        self.assertEqual(self.rows("scheduler_assignments")[0]["state"], "active")
        snapshot = self.call(
            "cockpit.snapshot.v1", idempotency_id="snapshot-cancel-mismatch"
        )["snapshot"]
        attention = [
            item for item in snapshot["attention"]["operator_required"]["items"]
            if item["kind"] == "transport_release_attention"
        ]
        self.assertEqual(len(attention), 1)
        self.assertEqual(attention[0]["reason"], "ownership_conflict")
        self.assertEqual(attention[0]["work_id"], "work-cancel-mismatch")

    def test_stale_fence_policy_denial_and_slot_injection_never_send(self) -> None:
        self.ready("stale")
        claim = self.claims["stale"]
        self.call(
            "scope.release.v1",
            {
                "claim_id": claim["claim_id"],
                "owner_id": claim["owner_id"],
                "attempt": claim["attempt"],
                "fence_token": claim["fence_token"],
            },
            idempotency_id="release-stale",
        )
        self.restart_daemon(mode="forbid_send")
        with self.assertRaises(RigClientError) as stale:
            self.dispatch("stale")
        self.assertEqual(stale.exception.code, "ownership_conflict")
        with self.assertRaises(RigClientError) as injected:
            self.call(
                "transport.dispatch.v1",
                {
                    "work_id": "work-stale",
                    "pool": "tensorhost",
                    "slot_id": "tensorhost-1",
                    "payload": {},
                },
                idempotency_id="slot-injection",
            )
        self.assertEqual(injected.exception.code, "invalid_params")

    def test_production_endpoint_exposes_no_transport_authority_or_arming_surface(self) -> None:
        production = RigDaemon(
            PrivateSocketPath(self.socket, self.root),
            runtime=self.store.runtime,
            identity_policy=self.policy,
        )
        resources = production._RigDaemonBase__resources
        self.assertIsNone(resources.controller)
        self.assertIsNone(resources.controller_close)
        for attribute in (
            "_transport",
            "_authority",
            "prepare",
            "begin_attempt",
            "record_process_identity",
            "finalize",
            "execute_durable",
        ):
            self.assertFalse(hasattr(production, attribute))
        self.assertFalse(hasattr(adapter_package, "SyntheticProcessAdapter"))
        with self.assertRaises(ImportError):
            exec("from oc_rig.adapters import SyntheticProcessAdapter", {})
        for method in ("prepare", "begin_attempt", "record_process_identity", "finalize"):
            parameters = inspect.signature(getattr(_TransportService, method)).parameters
            self.assertIn("capability", parameters)
        schema = self.rows("sqlite_master")
        deliveries = next(row for row in schema if row["name"] == "transport_deliveries")
        self.assertIn("adapter_kind TEXT NOT NULL CHECK(adapter_kind = 'disabled')", deliveries["sql"])
        with self.assertRaises(RigClientError) as armed:
            self.call(
                "transport.dispatch.v1",
                {
                    "work_id": "work-unconfigured",
                    "pool": "tensorhost",
                    "payload": {},
                    "adapter_kind": "synthetic-process",
                },
                idempotency_id="synthetic-adapter-arming",
            )
        self.assertEqual(armed.exception.code, "invalid_params")

    def test_reserved_capacity_survives_transport_commit_before_outcome(self) -> None:
        self.ready("capacity")
        baseline = len(self.rows("daemon_request_outcomes"))
        self.restart_daemon(max_entries=baseline + 1)
        params = {
            "work_id": "work-capacity",
            "pool": "tensorhost",
            "payload": {"prompt": "safe work"},
        }
        self.restart_daemon(max_entries=baseline + 1, mode="crash_after_transport")
        with self.assertRaises(RigClientError) as failed:
            self.call(
                "transport.dispatch.v1",
                params,
                request_id="crash-before-outcome",
                idempotency_id="capacity-retry",
            )
        self.assertEqual(failed.exception.code, "internal_error")
        delivery = dict(self.rows("transport_deliveries")[0])
        self.assertEqual(delivery["state"], "definite_failed")
        self.assertEqual(len(self.rows("daemon_outcome_reservations")), 1)
        self.assertEqual(
            len(self.rows("daemon_request_outcomes"))
            + len(self.rows("daemon_outcome_reservations")),
            baseline + 1,
        )
        self.restart_daemon(max_entries=baseline + 1)
        recovered = self.call(
            "transport.dispatch.v1",
            params,
            request_id="capacity-retry",
            idempotency_id="capacity-retry",
        )
        self.assertEqual(recovered["transport_id"], delivery["id"])
        self.assertEqual(len(self.rows("transport_attempts")), 1)
        self.assertEqual(self.rows("daemon_outcome_reservations"), [])

    def test_database_guards_transport_state_and_process_identity(self) -> None:
        self.ready("guarded")
        result = self.dispatch("guarded")
        with self.assertRaises(sqlite3.IntegrityError):
            with closing(sqlite3.connect(self.store.path)) as connection:
                connection.execute(
                    "UPDATE transport_deliveries SET state = 'sending' WHERE id = ?",
                    (result["transport_id"],),
                )
        attempt = self.rows("transport_attempts")[0]
        self.assertIsNone(attempt["supervisor_pid"])
        self.assertIsNone(attempt["target_pid"])
        self.assertIsNone(attempt["process_token"])


if __name__ == "__main__":
    unittest.main()
