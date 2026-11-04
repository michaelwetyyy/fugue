from __future__ import annotations

import json
import hashlib
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from oc_rig.cli import _resolve_codex_thread_id, main
from oc_rig.daemon.controller import InMemoryController
from oc_rig.daemon.security import PrivateSocketPath
from oc_rig.daemon.server import RigDaemon
from oc_rig.protocol.client import RigClientError
from oc_rig.policy.capsule import claim_scope_hash, parse_capsule_prompt


class CliProtocolTests(unittest.TestCase):
    THREAD_ID = "123e4567-e89b-12d3-a456-426614174000"

    def test_callback_delivery_reconciliation_maps_exact_callback_id(self) -> None:
        calls: list[tuple[str, dict[str, object]]] = []

        class RecordingClient:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def call(
                self, operation: str, params: dict[str, object], **_kwargs: object
            ) -> dict[str, object]:
                calls.append((operation, params))
                return {
                    "callback_id": "callback-one",
                    "reconciled": False,
                    "state": "attention",
                    "proof": "codex_history_proof_not_found",
                }

        output = StringIO()
        with patch.dict(os.environ, {}, clear=True), patch(
            "oc_rig.cli.RigClient", RecordingClient
        ), redirect_stdout(output):
            status = main([
                "--socket", "/unused/rig.sock",
                "--identity-profile", "local-user",
                "reconcile-callback-delivery", "callback-one",
            ])
        self.assertEqual(status, 0)
        self.assertEqual(
            calls,
            [("callback.delivery.reconcile.v1", {"callback_id": "callback-one"})],
        )
        self.assertEqual(json.loads(output.getvalue())["state"], "attention")

    def test_completion_result_reads_exact_durable_reference(self) -> None:
        calls: list[tuple[str, dict[str, object]]] = []
        result_ref = "completion-result-" + "a" * 64

        class RecordingClient:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def call(
                self, operation: str, params: dict[str, object], **_kwargs: object
            ) -> dict[str, object]:
                calls.append((operation, params))
                return {
                    "result_ref": result_ref,
                    "content_state": "available",
                    "text": "Durable review.",
                }

        output = StringIO()
        with patch.dict(os.environ, {}, clear=True), patch(
            "oc_rig.cli.RigClient", RecordingClient
        ), redirect_stdout(output):
            status = main([
                "--socket", "/unused/rig.sock",
                "--identity-profile", "local-user",
                "completion-result", result_ref,
            ])
        self.assertEqual(status, 0)
        self.assertEqual(
            calls, [("completion.result.v1", {"result_ref": result_ref})]
        )
        self.assertEqual(json.loads(output.getvalue())["text"], "Durable review.")

    def test_proposal_submit_uses_fixed_security_and_private_callback_route(self) -> None:
        calls: list[tuple[str, dict[str, object], str | None]] = []

        class RecordingClient:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def call(
                self,
                operation: str,
                params: dict[str, object],
                *,
                idempotency_id: str | None = None,
            ) -> dict[str, object]:
                calls.append((operation, params, idempotency_id))
                return {
                    "submission_id": "proposal-fixed-1",
                    "work_id": "work-proposal-fixed-1",
                    "lane": "control",
                    "state": "accepted",
                    "agent_lifecycle": "persistent",
                    "child_agents": "allowed",
                    "reservation_attempt": 1,
                }

        output = StringIO()
        with patch.dict(os.environ, {}, clear=True), patch(
            "oc_rig.cli.RigClient", RecordingClient
        ), redirect_stdout(output):
            status = main(
                [
                    "--socket", "/unused/rig.sock",
                    "--identity-profile", "local-user",
                    "proposal-submit", "control", "/private/repository",
                    "--scope", "src/app.tsx",
                    "--objective", "Return a bounded implementation proposal.",
                    "--submission-id", "proposal-fixed-1",
                    "--agent-lifecycle", "persistent",
                    "--codex-thread-id", self.THREAD_ID,
                ]
            )

        self.assertEqual(status, 0)
        self.assertEqual(len(calls), 1)
        operation, params, idempotency_id = calls[0]
        self.assertEqual(operation, "submission.submit.v1")
        self.assertEqual(idempotency_id, "gui-submit-proposal-fixed-1-attempt-1")
        self.assertEqual(params["classification"], "PUBLIC")
        self.assertEqual(params["trust"], "secure")
        self.assertIs(params["allow_child_agents"], True)
        self.assertNotIn("workspace_edit", params)
        self.assertEqual(params["agent_lifecycle"], "persistent")
        self.assertEqual(
            params["return_route"],
            {"kind": "local_codex", "thread_id": self.THREAD_ID},
        )
        self.assertNotIn(self.THREAD_ID, output.getvalue())

    def test_workspace_submit_sets_only_the_fixed_local_edit_mode(self) -> None:
        calls: list[tuple[str, dict[str, object], str | None]] = []

        class RecordingClient:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def call(
                self,
                operation: str,
                params: dict[str, object],
                *,
                idempotency_id: str | None = None,
            ) -> dict[str, object]:
                calls.append((operation, params, idempotency_id))
                return {"state": "accepted"}

        with patch.dict(os.environ, {}, clear=True), patch(
            "oc_rig.cli.RigClient", RecordingClient
        ), redirect_stdout(StringIO()):
            status = main(
                [
                    "--socket", "/unused/rig.sock",
                    "--identity-profile", "local-user",
                    "proposal-submit", "control", "/private/repository",
                    "--scope", "src/app.tsx",
                    "--objective", "Implement the bounded change.",
                    "--submission-id", "workspace-fixed-1",
                    "--agent-lifecycle", "disposable",
                    "--workspace-edit",
                ]
            )

        self.assertEqual(status, 0)
        self.assertEqual(calls[0][0], "submission.submit.v1")
        self.assertIs(calls[0][1]["workspace_edit"], True)

    def test_workspace_patch_submit_sends_only_exact_range_authority(self) -> None:
        calls: list[tuple[str, dict[str, object], str | None]] = []

        class RecordingClient:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def call(
                self,
                operation: str,
                params: dict[str, object],
                *,
                idempotency_id: str | None = None,
            ) -> dict[str, object]:
                calls.append((operation, params, idempotency_id))
                return {"state": "accepted"}

        with patch.dict(os.environ, {}, clear=True), patch(
            "oc_rig.cli.RigClient", RecordingClient
        ), redirect_stdout(StringIO()):
            status = main(
                [
                    "--socket", "/unused/rig.sock",
                    "--identity-profile", "local-user",
                    "proposal-submit", "personal", "/private/repository",
                    "--scope", "src/large.tsx",
                    "--objective", "Change the selected renderer.",
                    "--submission-id", "patch-fixed-1",
                    "--agent-lifecycle", "disposable",
                    "--workspace-patch", "220:280",
                ]
            )

        self.assertEqual(status, 0)
        self.assertEqual(
            calls[0][1]["workspace_patch"],
            {"line_start": 220, "line_end": 280},
        )
        self.assertNotIn("workspace_edit", calls[0][1])

    @staticmethod
    def _successful_submit_result(
        operation: str,
        params: dict[str, object],
    ) -> dict[str, object]:
        if operation == "scope.claim.v1":
            scope = list(params["scope"])
            repository = str(params["repository"])
            return {
                "claim_id": "claim-capsule",
                "owner_id": "owner-capsule",
                "attempt": 1,
                "fence_token": "fence-capsule",
                "repository": repository,
                "scope": scope,
                "scope_hash": claim_scope_hash(repository, tuple(scope)),
            }
        if operation == "scheduler.enqueue.v1":
            return {"sequence": 1}
        if operation == "scheduler.admit.v1":
            return {"allowed": True, "reason_codes": ["allowed"]}
        if operation == "scheduler.reserve.v1":
            return {
                "reservation": {
                    "id": "reservation-capsule",
                    "work_id": params["work_id"],
                    "lane": "tensorhost",
                    "attempt": 1,
                    "fence_token": "reservation-fence-capsule",
                }
            }
        if operation == "transport.dispatch.v1":
            return {"state": "accepted", "transport_id": "transport-capsule"}
        return {"operation_id": params["operation_id"]}

    def test_submit_runs_guarded_workflow_with_stable_stage_identities(self) -> None:
        calls: list[tuple[str, dict[str, object], str | None]] = []

        class RecordingClient:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def call(
                self,
                operation: str,
                params: dict[str, object],
                *,
                idempotency_id: str | None = None,
            ) -> dict[str, object]:
                calls.append((operation, params, idempotency_id))
                if operation == "scope.claim.v1":
                    return {
                        "claim_id": "claim-1",
                        "owner_id": "owner-1",
                        "attempt": 1,
                        "fence_token": "fence-1",
                        "repository": params["repository"],
                        "scope": params["scope"],
                        "scope_hash": "scope-hash-1",
                    }
                if operation == "scheduler.enqueue.v1":
                    return {"sequence": 1}
                if operation == "scheduler.admit.v1":
                    return {"allowed": True, "reason_codes": ["allowed"]}
                if operation == "scheduler.reserve.v1":
                    work_id = calls[2][1]["work_id"]
                    return {
                        "reservation": {
                            "id": "reservation-1",
                            "work_id": work_id,
                            "lane": "tensorhost",
                            "attempt": 1,
                            "fence_token": "reservation-fence-1",
                        }
                    }
                if operation == "transport.dispatch.v1":
                    return {"state": "accepted", "transport_id": "transport-1"}
                return {"operation_id": params["operation_id"]}

        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            (repository / "one.txt").write_text("one", encoding="utf-8")
            (repository / "subdirectory").mkdir()
            stdout = StringIO()
            with patch.dict(
                os.environ, {"CODEX_THREAD_ID": self.THREAD_ID}, clear=True
            ), patch("oc_rig.cli.RigClient", RecordingClient), redirect_stdout(stdout):
                status = main(
                    [
                        "--socket",
                        "/unused/rig.sock",
                        "--identity-profile",
                        "local-user",
                        "--idempotency-id",
                        "submission-1",
                        "submit",
                        "tensorhost",
                        str(repository),
                        "--scope",
                        "one.txt",
                        "--scope",
                        "subdirectory",
                        "--prompt",
                        "bounded task",
                        "--codex-thread-id",
                        self.THREAD_ID,
                        "--classification",
                        "PUBLIC",
                        "--trust",
                        "secure",
                    ]
                )

        self.assertEqual(status, 0)
        self.assertEqual(
            [call[0] for call in calls],
            [
                "operation.create.v1",
                "scope.claim.v1",
                "scheduler.enqueue.v1",
                "scheduler.admit.v1",
                "scheduler.reserve.v1",
                "transport.dispatch.v1",
            ],
        )
        self.assertEqual(len({call[2] for call in calls}), len(calls))
        self.assertTrue(all((call[2] or "").startswith("submit-") for call in calls))
        self.assertEqual(calls[1][1]["scope"], ["one.txt", "subdirectory"])
        envelope = calls[3][1]["content"]
        self.assertEqual(
            json.loads(envelope),
            {
                "prompt": "bounded task",
                "repository": str(repository),
                "scope": ["one.txt", "subdirectory"],
                "version": 1,
            },
        )
        self.assertEqual(calls[4][1], {"work_id": calls[2][1]["work_id"]})
        self.assertEqual(calls[5][1]["payload"]["prompt"], envelope)
        self.assertEqual(calls[5][1]["reservation_id"], "reservation-1")
        self.assertEqual(calls[5][1]["reservation_attempt"], 1)
        self.assertEqual(
            calls[5][1]["return_route"],
            {"kind": "local_codex", "thread_id": self.THREAD_ID},
        )
        self.assertNotIn("return_route", calls[5][1]["payload"])
        output = json.loads(stdout.getvalue())
        self.assertEqual(output["state"], "accepted")
        self.assertNotIn("claim", output)
        self.assertNotIn("reservation", output)
        self.assertNotIn("owner-1", stdout.getvalue())
        self.assertNotIn("fence-1", stdout.getvalue())
        self.assertNotIn("reservation-fence-1", stdout.getvalue())
        self.assertNotIn(self.THREAD_ID, stdout.getvalue())

    def test_submit_defaults_to_validated_codex_thread_environment(self) -> None:
        with patch.dict(
            os.environ, {"CODEX_THREAD_ID": self.THREAD_ID}, clear=True
        ):
            self.assertEqual(_resolve_codex_thread_id(None), self.THREAD_ID)
        with patch.dict(os.environ, {"CODEX_THREAD_ID": "NOT-A-UUID"}, clear=True):
            with self.assertRaisesRegex(RigClientError, "canonical lowercase UUID"):
                _resolve_codex_thread_id(None)

    def test_include_scope_embeds_sanitized_exact_files_without_source_root(self) -> None:
        calls: list[tuple[str, dict[str, object], str | None]] = []

        class RecordingClient:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def call(
                self,
                operation: str,
                params: dict[str, object],
                *,
                idempotency_id: str | None = None,
            ) -> dict[str, object]:
                calls.append((operation, params, idempotency_id))
                return CliProtocolTests._successful_submit_result(operation, params)

        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve() / "undisclosed-source-root"
            repository.mkdir()
            source = repository / "review.py"
            original = b"def add(left, right):\n    return left + right\n"
            source.write_bytes(original)
            with patch.dict(os.environ, {}, clear=True), patch(
                "oc_rig.cli.RigClient", RecordingClient
            ), redirect_stdout(StringIO()):
                status = main(
                    [
                        "--socket",
                        "/unused/rig.sock",
                        "--identity-profile",
                        "local-user",
                        "--idempotency-id",
                        "scope-capsule-success",
                        "submit",
                        "tensorhost",
                        str(repository),
                        "--scope",
                        "review.py",
                        "--include-scope",
                        "--review-profile",
                        "correctness",
                        "--classification",
                        "PUBLIC",
                        "--trust",
                        "secure",
                    ]
                )
            self.assertEqual(status, 0)
            envelope = parse_capsule_prompt(calls[3][1]["content"])
            self.assertIsNotNone(envelope)
            assert envelope is not None
            self.assertEqual(envelope["version"], 2)
            self.assertEqual(envelope["task_mode"], "read_only_review")
            self.assertNotIn("repository", envelope)
            self.assertNotIn(str(repository), calls[3][1]["content"])
            block = envelope["scope_capsule"]["files"][0]
            self.assertEqual(block["path"], "review.py")
            self.assertEqual((block["line_start"], block["line_end"]), (1, 2))
            self.assertEqual(block["content"].encode("utf-8"), original)
            self.assertEqual(source.read_bytes(), original)

    def test_include_scope_local_rejections_create_no_controller_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            source = repository / "review.txt"
            cases = (
                (b"token=synthetic-secret", "scope_file_sensitive"),
                (b"safe line\n" * 5000, "canonical worker envelope exceeds"),
            )
            for index, (content, message) in enumerate(cases):
                with self.subTest(message=message):
                    source.write_bytes(content)
                    stderr = StringIO()
                    with patch.dict(os.environ, {}, clear=True), patch(
                        "oc_rig.cli.RigClient"
                    ) as client_type, redirect_stderr(stderr):
                        status = main(
                            [
                                "--socket",
                                "/unused/rig.sock",
                                "--identity-profile",
                                "local-user",
                                "--idempotency-id",
                                f"scope-capsule-reject-{index}",
                                "submit",
                                "tensorhost",
                                str(repository),
                                "--scope",
                                "review.txt",
                                "--include-scope",
                                "--review-profile",
                                "correctness",
                                "--classification",
                                "PUBLIC",
                                "--trust",
                                "secure",
                            ]
                        )
                    self.assertEqual(status, 1)
                    self.assertIn(message, stderr.getvalue())
                    client_type.return_value.call.assert_not_called()

            source.write_text("safe review material\n", encoding="utf-8")
            stderr = StringIO()
            with patch.dict(os.environ, {}, clear=True), patch(
                "oc_rig.cli.RigClient"
            ) as client_type, redirect_stderr(stderr):
                status = main(
                    [
                        "--socket",
                        "/unused/rig.sock",
                        "--identity-profile",
                        "local-user",
                        "--idempotency-id",
                        "scope-capsule-mutation-intent",
                        "submit",
                        "tensorhost",
                        str(repository),
                        "--scope",
                        "review.txt",
                        "--prompt",
                        "Review the file and implement the fix.",
                        "--include-scope",
                        "--classification",
                        "PUBLIC",
                        "--trust",
                        "secure",
                    ]
                )
            self.assertEqual(status, 1)
            self.assertIn("does not accept --prompt", stderr.getvalue())
            client_type.return_value.call.assert_not_called()

            for classification in ("SANITIZED", "SENSITIVE"):
                stderr = StringIO()
                with patch.dict(os.environ, {}, clear=True), patch(
                    "oc_rig.cli.RigClient"
                ) as client_type, redirect_stderr(stderr):
                    status = main(
                        [
                            "--socket", "/unused/rig.sock",
                            "--identity-profile", "local-user",
                            "--idempotency-id", f"capsule-{classification.lower()}",
                            "submit", "tensorhost", str(repository),
                            "--scope", "review.txt",
                            "--include-scope",
                            "--review-profile", "security",
                            "--classification", classification,
                            "--trust", "secure",
                        ]
                    )
                self.assertEqual(status, 1)
                self.assertIn("requires --classification PUBLIC", stderr.getvalue())
                client_type.return_value.call.assert_not_called()

    def test_include_scope_claim_mismatch_releases_exact_claim_before_error(self) -> None:
        calls: list[tuple[str, dict[str, object]]] = []

        class MismatchClient:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def call(
                self,
                operation: str,
                params: dict[str, object],
                *,
                idempotency_id: str | None = None,
            ) -> dict[str, object]:
                del idempotency_id
                calls.append((operation, params))
                if operation == "scope.claim.v1":
                    return {
                        "claim_id": "claim-mismatch",
                        "owner_id": "owner-mismatch",
                        "attempt": 7,
                        "fence_token": "fence-mismatch",
                        "repository": str(params["repository"]),
                        "scope": ["wrong.txt"],
                        "scope_hash": "0" * 64,
                    }
                if operation == "submission.reject.v1":
                    return {
                        "operation_id": params["operation_id"],
                        "claim_id": params["claim_id"],
                        "operation_state": "failed",
                        "claim_state": "released",
                    }
                return {"operation_id": params["operation_id"]}

        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            repository.joinpath("review.txt").write_text("bounded\n", encoding="utf-8")
            stderr = StringIO()
            with patch.dict(os.environ, {}, clear=True), patch(
                "oc_rig.cli.RigClient", MismatchClient
            ), redirect_stderr(stderr):
                status = main(
                    [
                        "--socket", "/unused/rig.sock",
                        "--identity-profile", "local-user",
                        "--idempotency-id", "capsule-mismatch-release",
                        "submit", "tensorhost", str(repository),
                        "--scope", "review.txt",
                        "--include-scope",
                        "--review-profile", "correctness",
                        "--classification", "PUBLIC",
                        "--trust", "secure",
                    ]
                )
        self.assertEqual(status, 1)
        self.assertEqual(
            [operation for operation, _ in calls],
            [
                "operation.create.v1",
                "scope.claim.v1",
                "submission.reject.v1",
            ],
        )
        self.assertEqual(
            calls[-1][1],
            {
                "operation_id": "submit-operation-" + hashlib.sha256(
                    b"capsule-mismatch-release"
                ).hexdigest(),
                "claim_id": "claim-mismatch",
                "owner_id": "owner-mismatch",
                "attempt": 7,
                "fence_token": "fence-mismatch",
            },
        )

    def test_include_scope_same_retry_replays_but_changed_content_stops_before_dispatch(self) -> None:
        class IdempotentClient:
            cached: dict[str, tuple[str, str, dict[str, object]]] = {}
            operations: list[str] = []

            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def call(
                self,
                operation: str,
                params: dict[str, object],
                *,
                idempotency_id: str | None = None,
            ) -> dict[str, object]:
                assert idempotency_id is not None
                self.operations.append(operation)
                fingerprint = json.dumps(params, sort_keys=True, separators=(",", ":"))
                existing = self.cached.get(idempotency_id)
                if existing is not None:
                    if existing[:2] != (operation, fingerprint):
                        raise RigClientError(
                            "idempotency_conflict",
                            "idempotency ID was reused for different content",
                        )
                    return dict(existing[2])
                result = CliProtocolTests._successful_submit_result(operation, params)
                self.cached[idempotency_id] = (operation, fingerprint, dict(result))
                return result

        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            source = repository / "review.txt"
            source.write_text("stable first content\n", encoding="utf-8")
            argv = [
                "--socket",
                "/unused/rig.sock",
                "--identity-profile",
                "local-user",
                "--idempotency-id",
                "scope-capsule-replay",
                "submit",
                "tensorhost",
                str(repository),
                "--scope",
                "review.txt",
                "--include-scope",
                "--review-profile",
                "correctness",
                "--classification",
                "PUBLIC",
                "--trust",
                "secure",
            ]
            with patch.dict(os.environ, {}, clear=True), patch(
                "oc_rig.cli.RigClient", IdempotentClient
            ), redirect_stdout(StringIO()):
                self.assertEqual(main(argv), 0)
                self.assertEqual(main(argv), 0)
                before_changed = len(IdempotentClient.operations)
                source.write_text("changed second content\n", encoding="utf-8")
                stderr = StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(main(argv), 1)

        changed_operations = IdempotentClient.operations[before_changed:]
        self.assertEqual(
            changed_operations,
            [
                "operation.create.v1",
                "scope.claim.v1",
                "scheduler.enqueue.v1",
                "scheduler.admit.v1",
            ],
        )
        self.assertIn("idempotency ID was reused for different content", stderr.getvalue())

    def test_submit_rejects_codex_thread_source_mismatch_before_protocol_calls(self) -> None:
        other = "123e4567-e89b-12d3-a456-426614174001"
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            (repository / "one.txt").write_text("one", encoding="utf-8")
            stderr = StringIO()
            with patch.dict(
                os.environ, {"CODEX_THREAD_ID": self.THREAD_ID}, clear=True
            ), patch("oc_rig.cli.RigClient") as client_type, redirect_stderr(stderr):
                status = main(
                    [
                        "--socket",
                        "/unused/rig.sock",
                        "--identity-profile",
                        "local-user",
                        "--idempotency-id",
                        "submission-route-mismatch",
                        "submit",
                        "tensorhost",
                        str(repository),
                        "--scope",
                        "one.txt",
                        "--prompt",
                        "bounded task",
                        "--codex-thread-id",
                        other,
                        "--classification",
                        "PUBLIC",
                        "--trust",
                        "secure",
                    ]
                )
        self.assertEqual(status, 1)
        self.assertIn("does not match CODEX_THREAD_ID", stderr.getvalue())
        client_type.return_value.call.assert_not_called()

    def test_submit_stops_before_reservation_when_policy_rejects(self) -> None:
        operations: list[str] = []

        class RejectingClient:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def call(
                self,
                operation: str,
                params: dict[str, object],
                *,
                idempotency_id: str | None = None,
            ) -> dict[str, object]:
                del idempotency_id
                operations.append(operation)
                if operation == "scope.claim.v1":
                    return {
                        "claim_id": "claim-1",
                        "owner_id": "owner-1",
                        "attempt": 1,
                        "fence_token": "fence-1",
                        "repository": params["repository"],
                        "scope": params["scope"],
                        "scope_hash": "scope-hash-1",
                    }
                if operation == "scheduler.enqueue.v1":
                    return {"sequence": 1}
                if operation == "scheduler.admit.v1":
                    return {"allowed": False, "reason_codes": ["sensitive_task"]}
                if operation == "scope.release.v1":
                    return {"released": True}
                return {"operation_id": params["operation_id"]}

        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            (repository / "one.txt").write_text("one", encoding="utf-8")
            with patch.dict(os.environ, {}, clear=True), patch(
                "oc_rig.cli.RigClient", RejectingClient
            ), redirect_stdout(StringIO()):
                status = main(
                    [
                        "--socket",
                        "/unused/rig.sock",
                        "--identity-profile",
                        "local-user",
                        "--idempotency-id",
                        "submission-rejected",
                        "submit",
                        "tensorhost",
                        str(repository),
                        "--scope",
                        "one.txt",
                        "--prompt",
                        "bounded task",
                        "--classification",
                        "SENSITIVE",
                        "--trust",
                        "secure",
                    ]
                )

        self.assertEqual(status, 2)
        self.assertEqual(operations[-2:], ["scheduler.admit.v1", "scope.release.v1"])

    def test_submit_requires_explicit_retry_identity(self) -> None:
        stderr = StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            main(
                [
                    "--socket",
                    "/unused/rig.sock",
                    "--identity-profile",
                    "local-user",
                    "submit",
                    "tensorhost",
                    "/repository",
                    "--scope",
                    "one.txt",
                    "--prompt",
                    "bounded task",
                    "--classification",
                    "PUBLIC",
                    "--trust",
                    "secure",
                ]
            )
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("submit requires --idempotency-id", stderr.getvalue())

    def test_submit_treats_failed_rejected_scope_cleanup_as_an_error(self) -> None:
        class CleanupFailureClient:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def call(
                self,
                operation: str,
                params: dict[str, object],
                *,
                idempotency_id: str | None = None,
            ) -> dict[str, object]:
                del idempotency_id
                if operation == "scope.claim.v1":
                    return {
                        "claim_id": "claim-cleanup",
                        "owner_id": "owner-cleanup",
                        "attempt": 1,
                        "fence_token": "fence-cleanup",
                        "repository": params["repository"],
                        "scope": params["scope"],
                    }
                if operation == "scheduler.enqueue.v1":
                    return {"sequence": 1}
                if operation == "scheduler.admit.v1":
                    return {"allowed": False}
                if operation == "scope.release.v1":
                    return {"released": False}
                return {"operation_id": params["operation_id"]}

        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            (repository / "one.txt").write_text("one", encoding="utf-8")
            stderr = StringIO()
            with patch.dict(os.environ, {}, clear=True), patch(
                "oc_rig.cli.RigClient", CleanupFailureClient
            ), redirect_stderr(stderr):
                status = main(
                    [
                        "--socket",
                        "/unused/rig.sock",
                        "--identity-profile",
                        "local-user",
                        "--idempotency-id",
                        "submission-cleanup-failure",
                        "submit",
                        "tensorhost",
                        str(repository),
                        "--scope",
                        "one.txt",
                        "--prompt",
                        "bounded task",
                        "--classification",
                        "SENSITIVE",
                        "--trust",
                        "secure",
                    ]
                )
        self.assertEqual(status, 1)
        self.assertIn("retained its active scope claim", stderr.getvalue())

    def test_local_user_profile_must_be_explicit(self) -> None:
        stderr = StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            main(["--socket", "/unused/rig.sock", "health"])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("local-user must be selected explicitly", stderr.getvalue())

    def test_cli_is_a_thin_read_only_socket_client(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            path = root / "socket" / "rig.sock"
            controller = InMemoryController()

            class VersionedReadController:
                def execute(
                    self,
                    operation: str,
                    params: dict[str, object],
                ) -> dict[str, object]:
                    aliases = {"health.v1": "health", "version.v1": "version"}
                    return dict(controller.execute(aliases[operation], params))

            daemon = RigDaemon(
                PrivateSocketPath(path, root),
                controller=VersionedReadController(),
            )
            thread = daemon.start_background()
            stdout = StringIO()
            try:
                with redirect_stdout(stdout):
                    self.assertEqual(
                        main(
                            [
                                "--socket",
                                str(path),
                                "--approved-root",
                                str(root),
                                "--identity-profile",
                                "local-user",
                                "health",
                            ]
                        ),
                        0,
                    )
                health = json.loads(stdout.getvalue())
                self.assertEqual(health["status"], "ok")

                stdout = StringIO()
                with redirect_stdout(stdout):
                    result = main(
                        [
                            "--socket",
                            str(path),
                            "--approved-root",
                            str(root),
                            "--identity-profile",
                            "local-user",
                            "server-version",
                        ]
                    )
                self.assertEqual(result, 0)
                self.assertEqual(
                    json.loads(stdout.getvalue())["protocol_version"], 1
                )
            finally:
                daemon.shutdown()
                thread.join(timeout=2)

    def test_cli_reports_connection_failure_without_starting_a_daemon(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            socket_directory = root / "socket"
            socket_directory.mkdir(mode=0o700)
            stderr = StringIO()
            with redirect_stderr(stderr):
                result = main(
                    [
                        "--socket",
                        str(socket_directory / "missing.sock"),
                        "--identity-profile",
                        "local-user",
                        "health",
                    ]
                )
        self.assertEqual(result, 1)
        self.assertIn("rigctl:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
