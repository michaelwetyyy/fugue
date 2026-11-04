from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import pty
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from oc_rig.store import PrivateRuntimeDirectory, RigStore
from oc_rig.store.snapshot import _CockpitSnapshotProjection
from oc_rig import terminal_cli
from oc_rig.adapters.opencode import LiveOpenCodeAdapterConfig
from oc_rig.cockpit import normalize_snapshot
from oc_rig.deployment.user import (
    DeploymentError,
    UserDeployment,
    _LAUNCHER,
    _AUTOMATED_BACKEND_POLICY,
)
from oc_rig.opencode_authority import (
    AUTOMATED_BACKEND_RELATIVE,
    AUTOMATED_BACKEND_TOOL_OUTPUT_SUFFIX,
    CHILD_AGENT_DESCRIPTION as _CHILD_DESCRIPTION,
    CHILD_AGENT_NAME as _CHILD_NAME,
    CHILD_AGENT_PROMPT as _CHILD_PROMPT,
    REVIEW_AGENT_DESCRIPTION as _REVIEW_DESCRIPTION,
    REVIEW_AGENT_PROMPT as _REVIEW_PROMPT,
    SECURE_AGENT_DESCRIPTION as _SECURE_DESCRIPTION,
    SECURE_AGENT_PROMPT as _SECURE_PROMPT,
)
from oc_rig.terminal_lifecycle import (
    ProcessIdentity,
    TerminalLifecycle,
    TerminalLifecycleError,
    _defer_terminal_signals,
    _backend_binding_matches,
    _managed_backend_directory,
    _ProcessGroupParser,
    _process_group_state,
    _process_observation,
    _prepare_backend_work_directory,
    _prepare_private_backend_tree,
    _prepare_runtime_auth,
    snapshot_is_quiescent,
)


class TerminalQuiescenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name).resolve()
        root.chmod(0o700)
        self.root = root
        self.store = RigStore(PrivateRuntimeDirectory(root / "state", root))
        self.store.initialize()
        with closing(
            sqlite3.connect(self.store.path, isolation_level=None)
        ) as connection:
            connection.execute("BEGIN")
            self.snapshot = dict(_CockpitSnapshotProjection().capture(connection))
            connection.rollback()

    def test_exact_empty_snapshot_is_quiescent(self) -> None:
        self.assertEqual(snapshot_is_quiescent(self.snapshot), (True, "quiescent"))

    def test_assigned_worker_fails_closed(self) -> None:
        value = copy.deepcopy(self.snapshot)
        value["slots"][0]["state"] = "assigned"
        worker = value["worker_graph"]["workers"][0]
        worker["slot_state"] = "assigned"
        worker["work_id"] = "work-1"
        worker["owner_id"] = "owner-1"
        worker["assignment_id"] = "assignment-1"
        worker["attempt"] = 1
        self.assertEqual(snapshot_is_quiescent(value)[0], False)

    def test_queued_work_fails_closed(self) -> None:
        value = copy.deepcopy(self.snapshot)
        value["queue"] = {
            "items": [{"attempt": 0, "enqueued_at": "2026-08-30T00:00:00Z", "lane": "tensorhost", "policy": "allowed", "queue_order": 1, "sequence": 1, "state": "queued", "work_id": "work-1"}],
            "lower_bound": 1,
            "status": "available",
            "total": 1,
            "total_status": "exact",
            "truncated": False,
        }
        self.assertEqual(snapshot_is_quiescent(value)[0], False)

    def test_terminal_operator_attention_does_not_block_quiescence(self) -> None:
        value = copy.deepcopy(self.snapshot)
        value["attention"]["operator_required"] = {
            "items": [
                {
                    "generation": 1,
                    "id": "transport-1",
                    "kind": "transport_attention",
                    "reason": "review_agent_invalid",
                    "state": "definite_failed",
                    "work_id": "work-1",
                },
                {
                    "generation": 1,
                    "id": "transport-2",
                    "kind": "transport_attention",
                    "reason": "no_capacity",
                    "state": "definite_failed",
                    "work_id": "work-2",
                },
            ],
            "lower_bound": 2,
            "status": "available",
            "total": 2,
            "total_status": "exact",
            "truncated": False,
        }
        durable = copy.deepcopy(value)

        self.assertEqual(snapshot_is_quiescent(value), (True, "quiescent"))
        self.assertEqual(value, durable)

    def test_operator_attention_projection_must_remain_exact(self) -> None:
        value = copy.deepcopy(self.snapshot)
        value["attention"]["operator_required"].update(
            {
                "status": "unavailable",
                "total": None,
                "total_status": "unknown",
            }
        )
        self.assertEqual(
            snapshot_is_quiescent(value),
            (False, "operator_required attention count is not exact"),
        )

    def test_automatic_recovery_attention_still_blocks_quiescence(self) -> None:
        value = copy.deepcopy(self.snapshot)
        value["attention"]["automatic_recovery"] = {
            "items": [
                {
                    "attempts": 1,
                    "generation": 1,
                    "id": "recovery-1",
                    "kind": "recovery_episode",
                    "reason": "no_progress",
                    "state": "open",
                    "target_id": "target-1",
                    "work_id": "work-1",
                }
            ],
            "lower_bound": 1,
            "status": "available",
            "total": 1,
            "total_status": "exact",
            "truncated": False,
        }
        self.assertEqual(
            snapshot_is_quiescent(value),
            (False, "automatic_recovery attention is not empty"),
        )

    def test_terminal_attention_persists_across_safe_stop_and_reopen(self) -> None:
        with closing(sqlite3.connect(self.store.path)) as connection:
            for index, reason in enumerate(
                ("review_agent_invalid", "no_capacity", "no_capacity"), start=1
            ):
                connection.execute(
                    """INSERT INTO opencode_provisional_sessions(
                           transport_id, work_id, pool, request_fingerprint,
                           completion_registration_id, callback_registration_id,
                           title, session_id, state, error, claim_token,
                           claim_started_at, created_at, updated_at
                       ) VALUES (?, ?, 'tensorhost', ?, ?, ?, ?, NULL,
                                 'attention', ?, NULL, NULL, 't0', 't0')""",
                    (
                        f"transport-{index}",
                        f"work-{index}",
                        f"{index:064x}",
                        f"completion-{index}",
                        f"callback-{index}",
                        f"review-title-{index}",
                        reason,
                    ),
                )
            connection.commit()

        with closing(
            sqlite3.connect(self.store.path, isolation_level=None)
        ) as connection:
            connection.execute("BEGIN")
            before = dict(_CockpitSnapshotProjection().capture(connection))
            connection.rollback()
        self.assertEqual(before["attention"]["operator_required"]["total"], 3)
        self.assertEqual(snapshot_is_quiescent(before), (True, "quiescent"))

        lifecycle = TerminalLifecycle(
            deployment=object(),
            opencode=Path("/bin/echo"),
            ownership_path=self.root / "ownership.json",
            backend_directory=self.root,
        )
        lifecycle.refresh = unittest.mock.Mock(return_value=before)
        lifecycle._acquire_lock()
        self.assertEqual(
            lifecycle.close(terminal_lost=False),
            (True, "stopped invocation-owned resources"),
        )

        with closing(
            sqlite3.connect(self.store.path, isolation_level=None)
        ) as restarted:
            restarted.execute("BEGIN")
            after = dict(_CockpitSnapshotProjection().capture(restarted))
            restarted.rollback()
        self.assertEqual(
            after["attention"]["operator_required"],
            before["attention"]["operator_required"],
        )
        self.assertEqual(snapshot_is_quiescent(after), (True, "quiescent"))

    def test_degraded_projection_fails_closed(self) -> None:
        value = copy.deepcopy(self.snapshot)
        value["availability"] = {"status": "degraded", "errors": ["bounded"]}
        self.assertEqual(snapshot_is_quiescent(value)[0], False)


class OwnershipPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.path = self.root / "ownership.json"
        self.lifecycle = TerminalLifecycle(
            deployment=object(),  # publication does not consult deployment
            opencode=Path("/bin/echo"),
            ownership_path=self.path,
            backend_directory=self.root,
        )

    @staticmethod
    def _cutover_proof(release: str, config: str, receipt: str) -> dict[str, object]:
        return {"format": 2, "material": {"destination": {"release_id": release, "config_id": config}, "intent": {"legacy": {"label": "legacy"}}}, "receipt_id": receipt}

    def test_short_writes_are_completed_and_read_back(self) -> None:
        real_write = os.write

        def short_write(descriptor: int, data: bytes) -> int:
            return real_write(descriptor, data[: max(1, len(data) // 3)])

        with patch("oc_rig.terminal_lifecycle.os.write", side_effect=short_write):
            self.lifecycle._write_record("starting", "short writes")
        value = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(value["phase"], "starting")
        self.assertFalse(self.lifecycle._pending_path().exists())

    def test_backend_binding_ignores_only_positive_private_root_link_counts(self) -> None:
        backend = self.root / "backend"
        before = {
            "config_id": "a" * 64,
            "private_roots": _prepare_private_backend_tree(backend),
            "provider_auth": {"directory": [1, 2, 3, 4]},
            "working_directory": {
                "ancestors": [["/Users", [5, 6, 7, 8, 2]]],
                "leaf": [9, 10, 11, 12, 2],
                "path": "/Users/work",
            },
        }
        (backend / "data" / "opencode").mkdir()
        after = {
            "config_id": "a" * 64,
            "private_roots": _prepare_private_backend_tree(backend),
            "provider_auth": {"directory": [1, 2, 3, 4]},
            "working_directory": {
                "ancestors": [["/Users", [5, 6, 7, 8, 3]]],
                "leaf": [9, 10, 11, 12, 2],
                "path": "/Users/work",
            },
        }

        self.assertNotEqual(before, after)
        self.assertTrue(_backend_binding_matches(before, after))

        changed_work_ancestor = copy.deepcopy(after)
        changed_work_ancestor["working_directory"]["ancestors"][0][1][1] += 1
        self.assertFalse(_backend_binding_matches(before, changed_work_ancestor))

        changed_work_leaf = copy.deepcopy(after)
        changed_work_leaf["working_directory"]["leaf"][4] += 1
        self.assertFalse(_backend_binding_matches(before, changed_work_leaf))

        legacy = copy.deepcopy(before)
        legacy["private_roots"] = {
            name: identity[:4]
            for name, identity in legacy["private_roots"].items()
        }
        self.assertTrue(_backend_binding_matches(legacy, after))
        self.assertTrue(_backend_binding_matches(after, legacy))

        for label, index in (("device", 0), ("inode", 1), ("mode", 2), ("owner", 3)):
            with self.subTest(label=label):
                changed = copy.deepcopy(after)
                changed["private_roots"]["data"][index] += 1
                self.assertFalse(_backend_binding_matches(before, changed))

        changed_config = copy.deepcopy(after)
        changed_config["config_id"] = "b" * 64
        self.assertFalse(_backend_binding_matches(before, changed_config))

        for field in ("provider_auth", "working_directory"):
            with self.subTest(field=field):
                changed = copy.deepcopy(after)
                changed[field] = {"changed": True}
                self.assertFalse(_backend_binding_matches(before, changed))

        for links in (0, -1, True, "1"):
            with self.subTest(links=links):
                invalid = copy.deepcopy(after)
                invalid["private_roots"]["data"][4] = links
                self.assertFalse(_backend_binding_matches(before, invalid))

        malformed = copy.deepcopy(after)
        malformed["private_roots"]["data"] = [1, 2, 3]
        self.assertFalse(_backend_binding_matches(before, malformed))

    def test_cleanup_reauthenticates_retained_historical_configuration(self) -> None:
        historical_auth = self.root / "historical-auth.json"
        historical_auth.write_text(
            json.dumps(
                {"type": "basic", "username": "opencode", "password": "secret"}
            ),
            encoding="utf-8",
        )
        base_binding = {
            "private_roots": {"root": [1, 2, 3, 4, 1]},
            "provider_auth": {},
            "working_directory": [],
        }
        old = {
            **base_binding,
            "config_id": "a" * 64,
            "environment_sha256": "old",
        }
        current = {
            **base_binding,
            "config_id": "b" * 64,
            "environment_sha256": "current",
        }
        status = lambda: {
                "opencode": {
                    "config_id": "b" * 64,
                    "endpoint": "http://127.0.0.1:4096",
                }
            }
        deployment = SimpleNamespace(
            root=self.root,
            status=status,
            stop_status=status,
        )
        self.lifecycle.deployment = deployment

        with patch.object(
            self.lifecycle, "_expected_backend_binding", return_value=current
        ), patch(
            "oc_rig.terminal_lifecycle.validated_historical_opencode_configuration",
            return_value=SimpleNamespace(auth=historical_auth),
        ) as validate, patch.object(
            self.lifecycle, "_automated_backend_binding", return_value=old
        ) as rebuild:
            self.assertEqual(
                self.lifecycle._expected_retained_backend_binding_for_cleanup(old),
                old,
            )

        validate.assert_called_once_with(
            self.root,
            config_id="a" * 64,
            endpoint="http://127.0.0.1:4096",
        )
        rebuild.assert_called_once_with("a" * 64, "opencode", "secret")

        with patch.object(
            self.lifecycle, "_expected_backend_binding", return_value=current
        ), patch(
            "oc_rig.terminal_lifecycle.validated_historical_opencode_configuration",
            return_value=SimpleNamespace(auth=historical_auth),
        ), patch.object(
            self.lifecycle,
            "_automated_backend_binding",
            return_value={
                **base_binding,
                "config_id": "a" * 64,
                "environment_sha256": "changed",
            },
        ), self.assertRaisesRegex(TerminalLifecycleError, "binding changed"):
            self.lifecycle._expected_retained_backend_binding_for_cleanup(old)

    def test_zero_progress_removes_pending_publication(self) -> None:
        with patch("oc_rig.terminal_lifecycle.os.write", return_value=0):
            with self.assertRaises(TerminalLifecycleError):
                self.lifecycle._write_record("starting", "zero")
        self.assertFalse(self.lifecycle._pending_path().exists())

    def test_complete_crash_left_pending_record_is_promoted(self) -> None:
        value = {
            "backend": None,
            "backend_owned": False,
            "controller_owned": False,
            "controller_pid": None,
            "format": 1,
            "invocation_id": "prior",
            "phase": "running",
            "reason": "published",
        }
        pending = self.lifecycle._pending_path()
        pending.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        pending.chmod(0o600)
        self.lifecycle._recover_pending()
        self.assertEqual(json.loads(self.path.read_text()), value)
        self.assertFalse(pending.exists())

    def test_partial_crash_left_pending_record_is_removed(self) -> None:
        pending = self.lifecycle._pending_path()
        pending.write_bytes(b'{"format":1')
        pending.chmod(0o600)
        self.lifecycle._recover_pending()
        self.assertFalse(pending.exists())
        self.assertFalse(self.path.exists())

    def test_completed_cutover_adoption_is_persisted_before_start(self) -> None:
        prior = {
            "backend_owned": False,
            "controller_owned": False,
            "controller_pid": None,
            "controller_starting": False,
            "cutover_intent": {"legacy": {"label": "legacy"}},
            "format": 1,
            "phase": "stopped",
        }
        self.path.write_text(json.dumps(prior), encoding="utf-8")
        self.path.chmod(0o600)
        proof = self._cutover_proof("0.1.0.dev0-aaaaaaaaaaaaaaaa", "a" * 64, "a" * 32)
        self.lifecycle.adopt_completed_cutover(
            proof=proof,
            expected_existing=prior,
        )
        adopted = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(adopted["phase"], "migrated")
        self.assertEqual(adopted["completed_cutover"], proof)
        self.assertEqual(adopted["cutover_intent"], prior["cutover_intent"])
        self.assertTrue(self.lifecycle._receipt_path(proof).exists())
        self.lifecycle._release_lock()

    def test_stale_stopped_backend_recovery_publishes_canonical_record(self) -> None:
        old_proof = self._cutover_proof(
            "0.1.0.dev0-aaaaaaaaaaaaaaaa", "c" * 64, "a" * 32
        )
        proof = self._cutover_proof(
            "0.1.0.dev1-bbbbbbbbbbbbbbbb", "d" * 64, "d" * 32
        )
        identity = ProcessIdentity(28637, 28637, "started", ("opencode", "serve"))
        binding = {"config_id": "d" * 64, "environment_sha256": "e" * 64}
        record = {
            "backend": identity.as_json(),
            "backend_binding": binding,
            "backend_owned": False,
            "completed_cutover": old_proof,
            "controller_owned": False,
            "controller_pid": None,
            "controller_starting": False,
            "cutover_intent": old_proof["material"]["intent"],
            "format": 1,
            "invocation_id": "b" * 32,
            "phase": "stopped",
            "reason": "startup failed before controller start",
            "tmux_nonce": None,
            "tmux_session_id": None,
        }
        self.path.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        self.path.chmod(0o600)
        with patch(
            "oc_rig.terminal_lifecycle._process_state",
            side_effect=("absent", "absent"),
        ), patch(
            "oc_rig.terminal_lifecycle._process_group_state",
            side_effect=("empty", "empty"),
        ), patch.object(
            self.lifecycle,
            "_prior_backend_binding_from_completed_proof",
            return_value=binding,
        ):
            recovered = self.lifecycle.recover_stale_stopped_backend(
                proof=proof,
                selected_config_id="d" * 64,
                expected_existing=record,
            )
        self.assertEqual(recovered["phase"], "stopped")
        self.assertIsNone(recovered["backend"])
        self.assertFalse(recovered["backend_owned"])
        self.assertNotIn("backend_binding", recovered)
        self.assertIsNone(recovered["tmux_nonce"])
        self.assertIsNone(recovered["tmux_session_id"])
        self.assertEqual(recovered["completed_cutover"], old_proof)
        self.assertFalse(self.lifecycle._receipt_path(proof).exists())
        self.assertIsNone(self.lifecycle._load_retained())
        self.lifecycle.adopt_completed_cutover(
            proof=proof, expected_existing=recovered
        )
        adopted = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(adopted["completed_cutover"], proof)
        self.assertEqual(adopted["phase"], "migrated")
        self.assertTrue(self.lifecycle._receipt_path(proof).is_file())
        self.lifecycle._release_lock()

        class Deployment:
            running = False

            def status(self) -> dict[str, object]:
                return {
                    "job": {
                        "running": self.running,
                        "pid": 42 if self.running else None,
                    }
                }

            def start(self) -> None:
                self.running = True

        class RestartLifecycle(TerminalLifecycle):
            def _configuration(self) -> tuple[str, str, str, int]:
                return "http://127.0.0.1:4096", "user", "password", 4096

            def _start_backend(self, *_args: object) -> None:
                self.backend_owned = True
                self.backend_identity = ProcessIdentity(
                    43, 43, "started", ("opencode", "serve")
                )
                self.backend_binding = {"config_id": "d" * 64}

            def refresh(self) -> object:
                return {"status": "ready"}

        restarted = RestartLifecycle(
            deployment=Deployment(),
            opencode=Path("/bin/echo"),
            ownership_path=self.path,
            backend_directory=self.root,
        )
        self.assertEqual(restarted.start(), {"status": "ready"})
        running = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(running["phase"], "running")
        self.assertEqual(running["completed_cutover"], proof)

    def test_stale_stopped_backend_recovery_preserves_uncertain_evidence(self) -> None:
        old_proof = self._cutover_proof(
            "0.1.0.dev0-aaaaaaaaaaaaaaaa", "c" * 64, "a" * 32
        )
        proof = self._cutover_proof(
            "0.1.0.dev1-bbbbbbbbbbbbbbbb", "d" * 64, "d" * 32
        )
        identity = ProcessIdentity(28637, 28637, "started", ("opencode", "serve"))
        binding = {"config_id": "d" * 64}
        record = {
            "backend": identity.as_json(), "backend_binding": binding,
            "backend_owned": False, "completed_cutover": old_proof,
            "controller_owned": False, "controller_pid": None,
            "controller_starting": False,
            "cutover_intent": old_proof["material"]["intent"], "format": 1,
            "invocation_id": "b" * 32, "phase": "stopped", "reason": "failed",
            "tmux_nonce": None, "tmux_session_id": None,
        }
        original = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        for process_state, group_state in (
            ("exact", "empty"),
            ("mismatch", "empty"),
            ("error", "empty"),
            ("absent", "unanchored_live"),
            ("terminated", "mismatch"),
            ("terminated", "error"),
        ):
            with self.subTest(process=process_state, group=group_state):
                self.path.write_text(original, encoding="utf-8")
                self.path.chmod(0o600)
                with patch(
                    "oc_rig.terminal_lifecycle._process_state",
                    return_value=process_state,
                ), patch(
                    "oc_rig.terminal_lifecycle._process_group_state",
                    return_value=group_state,
                ), patch.object(
                    self.lifecycle,
                    "_prior_backend_binding_from_completed_proof",
                    return_value=binding,
                ), self.assertRaises(TerminalLifecycleError):
                    self.lifecycle.recover_stale_stopped_backend(
                        proof=proof,
                        selected_config_id="d" * 64,
                        expected_existing=record,
                    )
                self.assertEqual(self.path.read_text(encoding="utf-8"), original)
        self.path.write_text(original, encoding="utf-8")
        self.path.chmod(0o600)
        with patch(
            "oc_rig.terminal_lifecycle._process_state", return_value="absent"
        ), patch(
            "oc_rig.terminal_lifecycle._process_group_state", return_value="empty"
        ), patch.object(
            self.lifecycle,
            "_prior_backend_binding_from_completed_proof",
            return_value={"changed": True},
        ), self.assertRaisesRegex(TerminalLifecycleError, "binding changed"):
            self.lifecycle.recover_stale_stopped_backend(
                proof=proof,
                selected_config_id="d" * 64,
                expected_existing=record,
            )
        self.assertEqual(self.path.read_text(encoding="utf-8"), original)

    def test_prior_completed_binding_requires_retained_release_config_and_receipt(self) -> None:
        release_id = "0.1.0.dev0-aaaaaaaaaaaaaaaa"
        config_id = "c" * 64
        release = self.root / "releases" / release_id
        release.mkdir(parents=True, mode=0o700)
        pin = release / "release-pin.json"
        pin.write_bytes(b"retained release pin\n")
        pin.chmod(0o400)
        release.chmod(0o500)
        proof = {
            "format": 2,
            "material": {
                "destination": {
                    "config_id": config_id,
                    "release_id": release_id,
                    "release_pin_sha256": hashlib.sha256(pin.read_bytes()).hexdigest(),
                    "root": str(self.root),
                    "state_sha256": "e" * 64,
                },
                "intent": {"endpoint": "http://127.0.0.1:4096"},
            },
            "receipt_id": "a" * 32,
        }
        receipt = self.lifecycle._receipt_path(proof)
        receipt.write_text(
            json.dumps(proof, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        receipt.chmod(0o600)
        auth = self.root / "historical-auth.json"
        auth.write_text(
            '{"type":"basic","username":"opencode","password":"password"}\n',
            encoding="utf-8",
        )
        auth.chmod(0o600)
        deployment = unittest.mock.Mock(root=self.root)
        deployment.status.return_value = {"installed": True}
        self.lifecycle.deployment = deployment
        binding = {"config_id": config_id, "environment_sha256": "f" * 64}
        historical = SimpleNamespace(auth=auth)
        with patch(
            "oc_rig.terminal_lifecycle.validated_historical_opencode_configuration",
            return_value=historical,
        ) as validate, patch.object(
            self.lifecycle,
            "_backend_binding_for_generation",
            return_value=binding,
        ) as expected_binding:
            self.assertEqual(
                self.lifecycle._prior_backend_binding_from_completed_proof(proof),
                binding,
            )
        validate.assert_called_once_with(
            self.root, config_id=config_id, endpoint="http://127.0.0.1:4096"
        )
        expected_binding.assert_called_once_with(config_id, "opencode", "password")

        with patch(
            "oc_rig.terminal_lifecycle.validated_historical_opencode_configuration",
            side_effect=DeploymentError("canonical mode mismatch"),
        ), patch(
            "oc_rig.terminal_lifecycle.validated_failed_start_historical_opencode_configuration",
            return_value=historical,
        ) as failed_start, patch.object(
            self.lifecycle,
            "_backend_binding_for_generation",
            return_value=binding,
        ):
            self.assertEqual(
                self.lifecycle._prior_backend_binding_from_completed_proof(proof),
                binding,
            )
        failed_start.assert_called_once_with(
            self.root, config_id=config_id, endpoint="http://127.0.0.1:4096"
        )
        with patch(
            "oc_rig.terminal_lifecycle.validated_historical_opencode_configuration",
            side_effect=DeploymentError("canonical mismatch"),
        ), patch(
            "oc_rig.terminal_lifecycle.validated_failed_start_historical_opencode_configuration",
            side_effect=DeploymentError("small failed-start mismatch"),
        ), patch(
            "oc_rig.terminal_lifecycle.validated_polluted_historical_opencode_configuration",
            return_value=historical,
        ) as polluted, patch.object(
            self.lifecycle,
            "_backend_binding_for_generation",
            return_value=binding,
        ):
            self.assertEqual(
                self.lifecycle._prior_backend_binding_from_completed_proof(proof),
                binding,
            )
        polluted.assert_called_once_with(
            self.root, config_id=config_id, endpoint="http://127.0.0.1:4096"
        )

        pin.chmod(0o600)
        with self.assertRaisesRegex(TerminalLifecycleError, "prior release changed"):
            self.lifecycle._prior_backend_binding_from_completed_proof(proof)
        pin.chmod(0o400)
        receipt.write_text("{}\n", encoding="utf-8")
        receipt.chmod(0o600)
        with self.assertRaisesRegex(TerminalLifecycleError, "receipt anchor changed"):
            self.lifecycle._prior_backend_binding_from_completed_proof(proof)

    def test_completed_proof_advancement_retries_after_receipt_before_record_crash(self) -> None:
        old_proof = self._cutover_proof(
            "0.1.0.dev0-aaaaaaaaaaaaaaaa", "c" * 64, "a" * 32
        )
        new_proof = self._cutover_proof(
            "0.1.0.dev1-bbbbbbbbbbbbbbbb", "d" * 64, "d" * 32
        )
        old_receipt = self.lifecycle._receipt_path(old_proof)
        old_receipt.write_text(
            json.dumps(old_proof, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        old_receipt.chmod(0o600)
        recovered = {
            "backend": None,
            "backend_owned": False,
            "completed_cutover": old_proof,
            "controller_owned": False,
            "controller_pid": None,
            "controller_starting": False,
            "cutover_intent": old_proof["material"]["intent"],
            "format": 1,
            "invocation_id": "b" * 32,
            "phase": "stopped",
            "reason": "recovered conclusively terminated startup backend",
            "tmux_nonce": None,
            "tmux_session_id": None,
        }
        original = json.dumps(
            recovered, sort_keys=True, separators=(",", ":")
        ) + "\n"
        self.path.write_text(original, encoding="utf-8")
        self.path.chmod(0o600)
        with patch.object(
            self.lifecycle,
            "_write_record",
            side_effect=RuntimeError("crash after receipt publication"),
        ), self.assertRaisesRegex(RuntimeError, "crash after receipt"):
            self.lifecycle.adopt_completed_cutover(
                proof=new_proof, expected_existing=recovered
            )
        new_receipt = self.lifecycle._receipt_path(new_proof)
        self.assertTrue(new_receipt.is_file())
        self.assertEqual(self.path.read_text(encoding="utf-8"), original)

        self.lifecycle.adopt_completed_cutover(
            proof=new_proof, expected_existing=recovered
        )
        adopted = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(adopted["completed_cutover"], new_proof)
        self.assertEqual(adopted["phase"], "migrated")
        self.lifecycle._release_lock()

    def test_dead_running_record_recovers_only_after_double_absence(self) -> None:
        old_proof = self._cutover_proof(
            "0.1.0.dev0-aaaaaaaaaaaaaaaa", "c" * 64, "a" * 32
        )
        new_proof = self._cutover_proof(
            "0.1.0.dev1-bbbbbbbbbbbbbbbb", "d" * 64, "d" * 32
        )
        identity = ProcessIdentity(28637, 28637, "started", ("opencode", "serve"))
        binding = {"config_id": "c" * 64}
        record = {
            "backend": identity.as_json(), "backend_binding": binding,
            "backend_owned": True, "completed_cutover": old_proof,
            "controller_owned": True, "controller_pid": 28638,
            "controller_starting": False,
            "cutover_intent": old_proof["material"]["intent"], "format": 1,
            "invocation_id": "b" * 32, "phase": "running", "reason": "attached",
            "tmux_nonce": "nonce", "tmux_session_id": "$0",
        }
        original = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        self.path.write_text(original, encoding="utf-8")
        self.path.chmod(0o600)
        deployment = unittest.mock.Mock()
        deployment.status.return_value = {
            "job": {"running": False, "pid": None, "loaded": False}
        }
        self.lifecycle.deployment = deployment
        with patch.object(
            self.lifecycle, "_prior_backend_binding_from_completed_proof",
            return_value=binding,
        ), patch(
            "oc_rig.terminal_lifecycle._process_state",
            side_effect=("absent", "absent"),
        ), patch(
            "oc_rig.terminal_lifecycle._process_group_state",
            side_effect=("empty", "empty"),
        ), patch(
            "oc_rig.terminal_lifecycle._listener_pid", side_effect=(None, None)
        ):
            recovered = self.lifecycle.recover_conclusively_dead_running_record(
                proof=new_proof, selected_config_id="d" * 64,
                expected_existing=record, port=4096, tmux_absent=True,
            )
        self.assertEqual(recovered["phase"], "stopped")
        self.assertIsNone(recovered["backend"])
        self.assertEqual(recovered["completed_cutover"], old_proof)

        self.path.write_text(original, encoding="utf-8")
        self.path.chmod(0o600)
        with patch.object(
            self.lifecycle, "_prior_backend_binding_from_completed_proof",
            return_value=binding,
        ), patch(
            "oc_rig.terminal_lifecycle._process_state", return_value="exact"
        ), self.assertRaises(TerminalLifecycleError):
            self.lifecycle.recover_conclusively_dead_running_record(
                proof=new_proof, selected_config_id="d" * 64,
                expected_existing=record, port=4096, tmux_absent=True,
            )
        self.assertEqual(self.path.read_text(encoding="utf-8"), original)

    def test_dead_starting_record_recovers_only_current_legacy_work_binding(self) -> None:
        proof = self._cutover_proof(
            "0.1.0.dev1-bbbbbbbbbbbbbbbb", "d" * 64, "d" * 32
        )
        identity = ProcessIdentity(95528, 95528, "started", ("opencode", "serve"))
        binding = {"config_id": "d" * 64, "working_directory": [1, 2, 3, 4]}
        record = {
            "backend": identity.as_json(), "backend_binding": binding,
            "backend_owned": True, "completed_cutover": proof,
            "controller_owned": False, "controller_pid": None,
            "controller_starting": False,
            "cutover_intent": proof["material"]["intent"], "format": 1,
            "invocation_id": "b" * 32, "phase": "starting", "reason": "backend started",
            "tmux_nonce": None, "tmux_session_id": None,
        }
        original = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        self.path.write_text(original, encoding="utf-8")
        self.path.chmod(0o600)
        deployment = unittest.mock.Mock()
        deployment.status.return_value = {"job": {"running": False, "pid": None}}
        self.lifecycle.deployment = deployment
        with patch.object(
            self.lifecycle, "_validate_current_completed_cutover_proof"
        ), patch.object(
            self.lifecycle, "_prior_policy_backend_binding_from_completed_proof",
            return_value=binding,
        ) as expected, patch(
            "oc_rig.terminal_lifecycle._process_state", side_effect=("absent", "absent")
        ), patch(
            "oc_rig.terminal_lifecycle._process_group_state", side_effect=("empty", "empty")
        ), patch(
            "oc_rig.terminal_lifecycle._listener_pid", side_effect=(None, None)
        ):
            recovered = self.lifecycle.recover_conclusively_dead_starting_record(
                proof=proof, selected_config_id="d" * 64,
                expected_existing=record, port=4096,
            )
        expected.assert_called_once_with(proof)
        self.assertEqual(recovered["phase"], "stopped")
        self.assertIsNone(recovered["backend"])

        self.path.write_text(original, encoding="utf-8")
        self.path.chmod(0o600)
        with patch.object(
            self.lifecycle, "_validate_current_completed_cutover_proof"
        ), patch.object(
            self.lifecycle, "_prior_policy_backend_binding_from_completed_proof",
            return_value={"drift": True},
        ), self.assertRaisesRegex(TerminalLifecycleError, "binding changed"):
            self.lifecycle.recover_conclusively_dead_starting_record(
                proof=proof, selected_config_id="d" * 64,
                expected_existing=record, port=4096,
            )
        self.assertEqual(self.path.read_text(encoding="utf-8"), original)

    def test_dead_starting_upgrade_preserves_old_proof_until_receipt_retry(self) -> None:
        old_proof = self._cutover_proof(
            "0.1.0.dev1-aaaaaaaaaaaaaaaa", "c" * 64, "a" * 32
        )
        new_proof = self._cutover_proof(
            "0.1.0.dev2-bbbbbbbbbbbbbbbb", "d" * 64, "b" * 32
        )
        identity = ProcessIdentity(95528, 95528, "started", ("opencode", "serve"))
        binding = {"config_id": "c" * 64, "working_directory": [1, 2, 3, 4]}
        record = {
            "backend": identity.as_json(), "backend_binding": binding,
            "backend_owned": True, "completed_cutover": old_proof,
            "controller_owned": False, "controller_pid": None,
            "controller_starting": False,
            "cutover_intent": old_proof["material"]["intent"], "format": 1,
            "invocation_id": "b" * 32, "phase": "starting",
            "reason": "backend started", "tmux_nonce": None,
            "tmux_session_id": None,
        }
        self.path.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        self.path.chmod(0o600)
        deployment = unittest.mock.Mock()
        deployment.status.return_value = {"job": {"running": False, "pid": None}}
        self.lifecycle.deployment = deployment
        with patch.object(
            self.lifecycle, "_validate_current_completed_cutover_proof"
        ) as current_authority, patch.object(
            self.lifecycle, "_prior_policy_backend_binding_from_completed_proof",
            return_value=binding,
        ) as old_authority, patch(
            "oc_rig.terminal_lifecycle._process_state", side_effect=("absent", "absent")
        ), patch(
            "oc_rig.terminal_lifecycle._process_group_state", side_effect=("empty", "empty")
        ), patch(
            "oc_rig.terminal_lifecycle._listener_pid", side_effect=(None, None)
        ):
            recovered = self.lifecycle.recover_conclusively_dead_starting_record(
                proof=new_proof, selected_config_id="d" * 64,
                expected_existing=record, port=4096,
            )
        current_authority.assert_called_once_with(new_proof, "d" * 64)
        old_authority.assert_called_once_with(old_proof)
        self.assertEqual(recovered["phase"], "stopped")
        self.assertEqual(recovered["completed_cutover"], old_proof)

        old_receipt = self.lifecycle._receipt_path(old_proof)
        old_bytes = (
            json.dumps(old_proof, sort_keys=True, separators=(",", ":")).encode()
            + b"\n"
        )
        old_receipt.write_bytes(old_bytes)
        old_receipt.chmod(0o600)
        new_receipt = self.lifecycle._receipt_path(new_proof)
        new_receipt.write_bytes(
            json.dumps(new_proof, sort_keys=True, separators=(",", ":")).encode()
            + b"\n"
        )
        new_receipt.chmod(0o600)
        self.lifecycle.adopt_completed_cutover(
            proof=new_proof, expected_existing=recovered
        )
        adopted = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(adopted["phase"], "migrated")
        self.assertEqual(adopted["completed_cutover"], new_proof)
        self.assertEqual(old_receipt.read_bytes(), old_bytes)
        self.lifecycle._release_lock()

    def test_current_starting_recovery_proof_binds_state_and_release_pin(self) -> None:
        deployment_root = self.root / "deployment"
        release_id = "0.1.0.dev2-bbbbbbbbbbbbbbbb"
        config_id = "d" * 64
        release = deployment_root / "releases" / release_id
        release.mkdir(parents=True)
        state_bytes = b'{"current":"bounded"}\n'
        state = deployment_root / "deployment-state.json"
        state.write_bytes(state_bytes)
        state.chmod(0o600)
        pin_bytes = b'{"release":"bounded"}\n'
        pin = release / "release-pin.json"
        pin.write_bytes(pin_bytes)
        pin.chmod(0o400)
        deployment = unittest.mock.Mock(root=deployment_root)
        deployment.status.return_value = {
            "current": release_id, "opencode": {"config_id": config_id}
        }
        self.lifecycle.deployment = deployment
        proof = {
            "format": 2,
            "material": {
                "destination": {
                    "config_id": config_id, "release_id": release_id,
                    "release_pin_sha256": hashlib.sha256(pin_bytes).hexdigest(),
                    "root": str(deployment_root),
                    "state_sha256": hashlib.sha256(state_bytes).hexdigest(),
                },
                "evidence": {}, "intent": {}, "source": {},
            },
            "receipt_id": "b" * 32,
        }
        self.lifecycle._validate_current_completed_cutover_proof(proof, config_id)
        pin.chmod(0o600)
        with self.assertRaisesRegex(TerminalLifecycleError, "destination changed"):
            self.lifecycle._validate_current_completed_cutover_proof(proof, config_id)

    def test_dead_starting_record_rejects_noncanonical_schema(self) -> None:
        proof = self._cutover_proof(
            "0.1.0.dev1-bbbbbbbbbbbbbbbb", "d" * 64, "d" * 32
        )
        identity = ProcessIdentity(95528, 95528, "started", ("opencode", "serve"))
        record = {
            "backend": identity.as_json(), "backend_binding": {"config_id": "d" * 64},
            "backend_owned": True, "completed_cutover": proof,
            "controller_owned": False, "controller_pid": None,
            "controller_starting": False,
            "cutover_intent": proof["material"]["intent"], "format": 1,
            "invocation_id": "b" * 32, "phase": "starting", "reason": "backend started",
            "tmux_nonce": None, "tmux_session_id": None,
        }
        malformed_records = []
        extra = dict(record)
        extra["extra_authority"] = True
        malformed_records.append(extra)
        malformed_records.append({**record, "reason": "arbitrary"})
        malformed_proof = dict(proof)
        malformed_proof["receipt_id"] = "invalid"
        malformed_records.append({**record, "completed_cutover": malformed_proof})
        different_proof = self._cutover_proof(
            "0.1.0.dev1-bbbbbbbbbbbbbbbb", "d" * 64, "e" * 32
        )
        malformed_records.append({**record, "completed_cutover": different_proof})
        malformed_identity = dict(identity.as_json())
        malformed_identity["extra"] = True
        malformed_records.append({**record, "backend": malformed_identity})
        for malformed in malformed_records:
            with self.subTest(malformed=malformed):
                encoded = json.dumps(
                    malformed, sort_keys=True, separators=(",", ":")
                ) + "\n"
                self.path.write_text(encoded, encoding="utf-8")
                self.path.chmod(0o600)
                with self.assertRaises(TerminalLifecycleError):
                    self.lifecycle.recover_conclusively_dead_starting_record(
                        proof=proof, selected_config_id="d" * 64,
                        expected_existing=malformed, port=4096,
                    )
                self.assertEqual(self.path.read_text(encoding="utf-8"), encoded)

    def test_completed_cutover_receipt_cannot_be_replayed_into_fresh_state(self) -> None:
        prior = {"backend_owned": False, "controller_owned": False, "controller_pid": None, "controller_starting": False, "cutover_intent": {"legacy": {"label": "legacy"}}, "format": 1, "phase": "stopped"}
        proof = self._cutover_proof("0.1.0.dev0-aaaaaaaaaaaaaaaa", "a" * 64, "a" * 32)
        self.path.write_text(json.dumps(prior), encoding="utf-8")
        self.path.chmod(0o600)
        self.lifecycle.adopt_completed_cutover(proof=proof, expected_existing=prior)
        self.lifecycle._release_lock()
        self.path.write_text(json.dumps(prior), encoding="utf-8")
        self.path.chmod(0o600)
        with self.assertRaisesRegex(TerminalLifecycleError, "already consumed"):
            self.lifecycle.adopt_completed_cutover(proof=proof, expected_existing=prior)

    def test_distinct_destination_gets_distinct_receipt_without_changing_prior(self) -> None:
        prior = {"backend_owned": False, "controller_owned": False, "controller_pid": None, "controller_starting": False, "cutover_intent": {"legacy": {"label": "legacy"}}, "format": 1, "phase": "stopped"}
        proof_a = self._cutover_proof("0.1.0.dev0-aaaaaaaaaaaaaaaa", "a" * 64, "a" * 32)
        proof_b = self._cutover_proof("0.1.0.dev0-bbbbbbbbbbbbbbbb", "b" * 64, "b" * 32)
        self.path.write_text(json.dumps(prior), encoding="utf-8")
        self.path.chmod(0o600)
        self.lifecycle.adopt_completed_cutover(proof=proof_a, expected_existing=prior)
        self.lifecycle._release_lock()
        receipt_a = self.lifecycle._receipt_path(proof_a)
        original_a = receipt_a.read_bytes()
        stopped_a = dict(prior, completed_cutover=proof_a)
        self.path.write_text(json.dumps(stopped_a), encoding="utf-8")
        self.path.chmod(0o600)
        self.lifecycle.adopt_completed_cutover(proof=proof_b, expected_existing=stopped_a)
        self.lifecycle._release_lock()
        receipt_b = self.lifecycle._receipt_path(proof_b)
        self.assertNotEqual(receipt_a, receipt_b)
        self.assertTrue(receipt_b.exists())
        self.assertEqual(receipt_a.read_bytes(), original_a)
        altered_b = self._cutover_proof("0.1.0.dev0-bbbbbbbbbbbbbbbb", "b" * 64, "c" * 32)
        self.path.write_text(json.dumps(stopped_a), encoding="utf-8")
        self.path.chmod(0o600)
        with self.assertRaisesRegex(TerminalLifecycleError, "already consumed"):
            self.lifecycle.adopt_completed_cutover(proof=altered_b, expected_existing=stopped_a)
        self.assertEqual(receipt_a.read_bytes(), original_a)
        self.assertEqual(json.loads(receipt_b.read_text()), proof_b)

    def test_cleanup_resumes_backend_after_owned_controller_already_exited(self) -> None:
        identity = ProcessIdentity(93678, 93678, "started", ("backend",))
        record = {"backend": identity.as_json(), "backend_owned": True, "completed_cutover": None, "controller_owned": True, "controller_pid": 93500, "controller_starting": False, "cutover_intent": None, "format": 1, "invocation_id": "prior", "phase": "running", "reason": "terminal attached", "tmux_nonce": "nonce", "tmux_session_id": "$1"}
        self.path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        self.path.chmod(0o600)
        self.lifecycle.deployment = unittest.mock.Mock()
        self.lifecycle.deployment.status.return_value = {"job": {"detail": "not", "loaded": True, "running": False, "pid": None}}
        with patch("oc_rig.terminal_lifecycle._process_state", return_value="exact"):
            self.lifecycle.resume_cleanup()
        resumed = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertFalse(resumed["controller_owned"])
        self.assertEqual(resumed["backend"], identity.as_json())
        self.assertTrue(resumed["backend_owned"])
        with patch.object(self.lifecycle, "_stop_backend", side_effect=lambda: setattr(self.lifecycle, "backend_owned", False)):
            self.assertEqual(self.lifecycle.close(terminal_lost=False), (True, "stopped invocation-owned resources"))
        stopped = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(stopped["phase"], "stopped")
        self.assertIsNone(stopped["backend"])

    def test_pending_real_shape_finishes_after_exact_backend_termination(self) -> None:
        identity = ProcessIdentity(93678, 93678, "started", ("backend",))
        record = {"backend": identity.as_json(), "backend_owned": True, "completed_cutover": None, "controller_owned": False, "controller_pid": None, "controller_starting": False, "cutover_intent": None, "format": 1, "invocation_id": "prior", "phase": "starting", "reason": "controller stopped; backend cleanup pending", "tmux_nonce": "nonce", "tmux_session_id": "$0"}
        self.path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        self.path.chmod(0o600)
        deployment = unittest.mock.Mock()
        deployment.status.return_value = {"job": {"detail": "not", "loaded": True, "running": False, "pid": None}}
        lifecycle = TerminalLifecycle(deployment=deployment, opencode=Path("/bin/echo"), ownership_path=self.path, backend_directory=self.root)
        with patch("oc_rig.terminal_lifecycle._process_state", return_value="exact"), patch("oc_rig.terminal_lifecycle._process_group_state", side_effect=("live", "live", "empty")), patch("oc_rig.terminal_lifecycle.os.killpg") as killpg:
            lifecycle.resume_cleanup()
            self.assertEqual(lifecycle.close(terminal_lost=False), (True, "stopped invocation-owned resources"))
        killpg.assert_called_once_with(identity.pgid, signal.SIGTERM)
        stopped = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(stopped["phase"], "stopped")
        self.assertFalse(stopped["backend_owned"])
        self.assertIsNone(stopped["backend"])
        self.assertIsNone(stopped["tmux_session_id"])
        self.assertIsNone(stopped["tmux_nonce"])

    def test_exact_backend_then_same_identity_zombie_completes_stopped_publication(self) -> None:
        identity = ProcessIdentity(59502, 59502, "Sun Aug 30 22:52:42 2026", ("backend",))
        record = {"backend": identity.as_json(), "backend_owned": True, "completed_cutover": None, "controller_owned": False, "controller_pid": None, "controller_starting": False, "cutover_intent": None, "format": 1, "invocation_id": "a" * 32, "phase": "starting", "reason": "controller stopped; backend cleanup pending", "tmux_nonce": "nonce", "tmux_session_id": "$0"}
        original = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        self.path.write_text(original, encoding="utf-8")
        self.path.chmod(0o600)
        deployment = unittest.mock.Mock()
        deployment.status.return_value = {"job": {"detail": "not", "loaded": True, "running": False, "pid": None}}
        lifecycle = TerminalLifecycle(deployment=deployment, opencode=Path("/bin/echo"), ownership_path=self.path, backend_directory=self.root)
        with patch("oc_rig.terminal_lifecycle._process_state", return_value="exact"), patch("oc_rig.terminal_lifecycle._process_group_state", side_effect=("live", "live", "terminated")), patch("oc_rig.terminal_lifecycle.os.killpg") as killpg:
            lifecycle.resume_cleanup()
            self.assertEqual(lifecycle.close(terminal_lost=False), (True, "stopped invocation-owned resources"))
        killpg.assert_called_once_with(identity.pgid, signal.SIGTERM)
        stopped = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(stopped["phase"], "stopped")
        self.assertIsNone(stopped["backend"])
        self.assertFalse(stopped["backend_owned"])
        self.assertIsNone(stopped["tmux_session_id"])

    def test_zombie_with_reused_identity_is_rejected_without_record_change(self) -> None:
        identity = ProcessIdentity(59502, 59502, "Sun Aug 30 22:52:42 2026", ("backend",))
        record = {"backend": identity.as_json(), "backend_owned": True, "completed_cutover": None, "controller_owned": False, "controller_pid": None, "controller_starting": False, "cutover_intent": None, "format": 1, "invocation_id": "a" * 32, "phase": "starting", "reason": "controller stopped; backend cleanup pending", "tmux_nonce": "nonce", "tmux_session_id": "$0"}
        original = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        self.path.write_text(original, encoding="utf-8")
        self.path.chmod(0o600)
        deployment = unittest.mock.Mock()
        deployment.status.return_value = {"job": {"detail": "not", "loaded": True, "running": False, "pid": None}}
        lifecycle = TerminalLifecycle(deployment=deployment, opencode=Path("/bin/echo"), ownership_path=self.path, backend_directory=self.root)
        reused = subprocess.CompletedProcess([], 0, "59502 Mon Aug 31 22:52:42 2026 Z <defunct>\n", "")
        with patch("oc_rig.terminal_lifecycle.subprocess.run", return_value=reused), self.assertRaisesRegex(TerminalLifecycleError, "cannot be authenticated"):
            lifecycle.resume_cleanup()
        self.assertEqual(self.path.read_text(encoding="utf-8"), original)
        deployment.stop.assert_not_called()

    def test_zombie_leader_waits_for_live_same_group_child_after_term(self) -> None:
        identity = ProcessIdentity(59502, 59502, "Sun Aug 30 22:52:42 2026", ("backend",))
        record = {"backend": identity.as_json(), "backend_owned": True, "completed_cutover": None, "controller_owned": False, "controller_pid": None, "controller_starting": False, "cutover_intent": None, "format": 1, "invocation_id": "a" * 32, "phase": "starting", "reason": "controller stopped; backend cleanup pending", "tmux_nonce": "nonce", "tmux_session_id": "$0"}
        self.path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        self.path.chmod(0o600)
        deployment = unittest.mock.Mock()
        deployment.status.return_value = {"job": {"detail": "not", "loaded": True, "running": False, "pid": None}}
        lifecycle = TerminalLifecycle(deployment=deployment, opencode=Path("/bin/echo"), ownership_path=self.path, backend_directory=self.root)
        calls = 0
        def inspect(*_args: object, **_kwargs: object) -> str:
            nonlocal calls
            calls += 1
            if calls in {1, 2, 3, 4}:
                if calls == 4:
                    self.assertNotEqual(json.loads(self.path.read_text())["phase"], "stopped")
                return "live"
            return "terminated"
        with patch("oc_rig.terminal_lifecycle._process_state", return_value="terminated"), patch("oc_rig.terminal_lifecycle._process_group_state", side_effect=inspect), patch("oc_rig.terminal_lifecycle.os.killpg") as killpg, patch("oc_rig.terminal_lifecycle.time.sleep"):
            lifecycle.resume_cleanup()
            self.assertEqual(lifecycle.close(terminal_lost=False), (True, "stopped invocation-owned resources"))
        killpg.assert_called_once_with(identity.pgid, signal.SIGTERM)
        stopped = json.loads(self.path.read_text())
        self.assertEqual(stopped["phase"], "stopped")
        self.assertFalse(stopped["backend_owned"])

    def test_live_group_without_recorded_leader_is_never_signalled_or_published(self) -> None:
        identity = ProcessIdentity(59502, 59502, "Sun Aug 30 22:52:42 2026", ("backend",))
        record = {"backend": identity.as_json(), "backend_owned": True, "completed_cutover": None, "controller_owned": False, "controller_pid": None, "controller_starting": False, "cutover_intent": None, "format": 1, "invocation_id": "a" * 32, "phase": "starting", "reason": "controller stopped; backend cleanup pending", "tmux_nonce": "nonce", "tmux_session_id": "$0"}
        original = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        self.path.write_text(original, encoding="utf-8")
        self.path.chmod(0o600)
        deployment = unittest.mock.Mock()
        deployment.status.return_value = {"job": {"detail": "not", "loaded": True, "running": False, "pid": None}}
        lifecycle = TerminalLifecycle(deployment=deployment, opencode=Path("/bin/echo"), ownership_path=self.path, backend_directory=self.root)
        with patch("oc_rig.terminal_lifecycle._process_state", return_value="absent"), patch("oc_rig.terminal_lifecycle._process_group_state", return_value="unanchored_live"), patch("oc_rig.terminal_lifecycle.os.killpg") as killpg, self.assertRaisesRegex(TerminalLifecycleError, "not anchored"):
            lifecycle.resume_cleanup()
        killpg.assert_not_called()
        deployment.stop.assert_not_called()
        self.assertEqual(self.path.read_text(encoding="utf-8"), original)

    def test_process_table_group_scan_rejects_duplicate_and_unbounded_output(self) -> None:
        identity = ProcessIdentity(59502, 59502, "Sun Aug 30 22:52:42 2026", ("backend",))
        row = b"59502 59502 Sun Aug 30 22:52:42 2026 S backend"
        parser = _ProcessGroupParser(identity)
        parser.consume(row)
        parser.consume(row)
        self.assertEqual(parser.result(), "error")
        oversized = _ProcessGroupParser(identity)
        oversized.consume(b"x" * (1024 * 1024 + 1))
        self.assertEqual(oversized.result(), "error")

    def test_streaming_process_scan_kills_real_producer_at_hard_output_cap(self) -> None:
        pidfile = self.root / "producer.pid"
        completed = self.root / "producer.completed"
        producer = """
import os, pathlib, sys, time
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
line = b'1 1 Mon Aug 31 00:00:00 2026 S ' + (b'x' * 990) + b'\\n'
for _ in range(10000):
    os.write(1, line)
pathlib.Path(sys.argv[2]).write_text('completed')
time.sleep(30)
"""
        identity = ProcessIdentity(59502, 59502, "Sun Aug 30 22:52:42 2026", ("backend",))
        self.assertEqual(
            _process_group_state(
                identity,
                command=(sys.executable, "-c", producer, str(pidfile), str(completed)),
            ),
            "error",
        )
        producer_pid = int(pidfile.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(producer_pid, 0)
        self.assertFalse(completed.exists())

    @unittest.skipUnless(sys.platform == "darwin", "requires native macOS ps process states")
    def test_native_process_group_term_zombie_and_reap_reaches_canonical_stopped(self) -> None:
        helper = """
import os, signal, subprocess, time
stopping = False
def stop(_signum, _frame):
    global stopping
    stopping = True
signal.signal(signal.SIGTERM, stop)
child = subprocess.Popen(['/bin/sleep', '30'])
print(child.pid, flush=True)
while not stopping:
    time.sleep(0.02)
time.sleep(0.6)
os._exit(0)
"""
        leader = subprocess.Popen(
            [sys.executable, "-c", helper],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            assert leader.stdout is not None
            child_pid = int(leader.stdout.readline().strip())
            self.assertGreater(child_pid, 0)
            observation = _process_observation(leader.pid)
            identity = observation.identity
            self.assertEqual(identity.pgid, leader.pid)
            self.assertEqual(_process_group_state(identity), "live")
            lifecycle = TerminalLifecycle(
                deployment=unittest.mock.Mock(),
                opencode=Path("/bin/echo"),
                ownership_path=self.path,
                backend_directory=self.root,
            )
            lifecycle.backend_owned = True
            lifecycle.backend_identity = identity
            lifecycle.tmux_nonce = "nonce"
            lifecycle.tmux_session_id = "$0"
            lifecycle.cleanup_authorized = True
            lifecycle._acquire_lock()
            self.assertEqual(
                lifecycle.close(terminal_lost=False),
                (True, "stopped invocation-owned resources"),
            )
            leader.wait(timeout=5)
            stopped = json.loads(self.path.read_text(encoding="utf-8"))
            self.assertEqual(stopped["phase"], "stopped")
            self.assertIsNone(stopped["backend"])
            self.assertFalse(stopped["backend_owned"])
            self.assertIsNone(stopped["tmux_session_id"])
        finally:
            if leader.poll() is None:
                os.killpg(leader.pid, signal.SIGKILL)
                leader.wait(timeout=5)
            if leader.stdout is not None:
                leader.stdout.close()
            if leader.stderr is not None:
                leader.stderr.close()

    @unittest.skipUnless(sys.platform == "darwin", "requires native macOS ps process states")
    def test_native_group_transient_post_term_error_then_empty_completes(self) -> None:
        helper = """
import os, signal, subprocess, time
stopping = False
def stop(_signum, _frame):
    global stopping
    stopping = True
signal.signal(signal.SIGTERM, stop)
subprocess.Popen(['/bin/sleep', '30'])
print('ready', flush=True)
while not stopping:
    time.sleep(0.02)
time.sleep(0.3)
os._exit(0)
"""
        leader = subprocess.Popen(
            [sys.executable, "-c", helper],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        real_group_state = _process_group_state
        try:
            assert leader.stdout is not None
            self.assertEqual(leader.stdout.readline().strip(), "ready")
            identity = _process_observation(leader.pid).identity
            lifecycle = TerminalLifecycle(
                deployment=unittest.mock.Mock(),
                opencode=Path("/bin/echo"),
                ownership_path=self.path,
                backend_directory=self.root,
            )
            lifecycle.backend_owned = True
            lifecycle.backend_identity = identity
            lifecycle.cleanup_authorized = True
            lifecycle._acquire_lock()
            calls = 0
            def transient(value: ProcessIdentity) -> str:
                nonlocal calls
                calls += 1
                if calls == 3:
                    return "error"
                return real_group_state(value)
            with patch("oc_rig.terminal_lifecycle._process_group_state", side_effect=transient):
                self.assertEqual(
                    lifecycle.close(terminal_lost=False),
                    (True, "stopped invocation-owned resources"),
                )
            self.assertGreaterEqual(calls, 4)
            stopped = json.loads(self.path.read_text())
            self.assertEqual(stopped["phase"], "stopped")
            self.assertFalse(stopped["backend_owned"])
        finally:
            if leader.poll() is None:
                os.killpg(leader.pid, signal.SIGKILL)
                leader.wait(timeout=5)
            if leader.stdout is not None:
                leader.stdout.close()
            if leader.stderr is not None:
                leader.stderr.close()

    def test_snapshot_classifier_failure_is_durable_lifecycle_branch(self) -> None:
        self.lifecycle.deployment = unittest.mock.Mock()
        self.lifecycle.controller_owned = True
        self.lifecycle.controller_pid = 42
        self.lifecycle.backend_owned = True
        self.lifecycle.backend_identity = ProcessIdentity(43, 43, "started", ("backend",))
        self.lifecycle._acquire_lock()
        self.lifecycle.refresh = unittest.mock.Mock(return_value={})
        with patch("oc_rig.terminal_lifecycle.snapshot_is_quiescent", side_effect=KeyError("missing")):
            self.assertEqual(
                self.lifecycle.close(terminal_lost=True),
                (False, "cockpit snapshot validation failed"),
            )
        retained = json.loads(self.path.read_text())
        self.assertEqual(retained["phase"], "retained")
        self.assertEqual(retained["reason"], "cockpit snapshot validation failed")
        self.lifecycle.deployment.stop.assert_not_called()
        self.assertEqual(
            terminal_cli._finalizer_error_code(
                TerminalLifecycleError("cockpit snapshot validation failed")
            ),
            "snapshot_validation",
        )

    def test_controller_stop_exception_after_conclusive_stop_still_publishes_cleanup(self) -> None:
        self.lifecycle.deployment = unittest.mock.Mock()
        self.lifecycle.deployment.status.side_effect = (
            {"job": {"detail": "running", "loaded": True, "running": True, "pid": 42}},
            {"job": {"detail": "not", "loaded": True, "running": False, "pid": None}},
        )
        self.lifecycle.deployment.stop.side_effect = RuntimeError("post-stop local failure")
        self.lifecycle.controller_owned = True
        self.lifecycle.controller_pid = 42
        self.lifecycle.backend_owned = True
        self.lifecycle.backend_identity = ProcessIdentity(43, 43, "started", ("backend",))
        self.lifecycle._acquire_lock()
        self.lifecycle.refresh = unittest.mock.Mock(return_value={})
        with patch("oc_rig.terminal_lifecycle.snapshot_is_quiescent", return_value=(True, "quiescent")), patch.object(self.lifecycle, "_stop_backend", side_effect=lambda: setattr(self.lifecycle, "backend_owned", False)):
            self.assertEqual(
                self.lifecycle.close(terminal_lost=False),
                (True, "stopped invocation-owned resources"),
            )
        stopped = json.loads(self.path.read_text())
        self.assertEqual(stopped["phase"], "stopped")
        self.assertFalse(stopped["controller_owned"])
        self.assertIsNone(stopped["controller_pid"])

    def test_controller_stop_polls_transitional_nonrunning_then_exact_not(self) -> None:
        self.lifecycle.deployment = unittest.mock.Mock()
        self.lifecycle.deployment.status.side_effect = (
            {"job": {"detail": "running", "loaded": True, "running": True, "pid": 42}},
            {"job": {"detail": "unknown", "loaded": True, "running": False, "pid": None}},
            {"job": {"detail": "not", "loaded": True, "running": False, "pid": None}},
        )
        self.lifecycle.controller_owned = True
        self.lifecycle.controller_pid = 42
        self.lifecycle.backend_owned = True
        self.lifecycle.backend_identity = ProcessIdentity(43, 43, "started", ("backend",))
        self.lifecycle._acquire_lock()
        self.lifecycle.refresh = unittest.mock.Mock(return_value={})
        with patch("oc_rig.terminal_lifecycle.snapshot_is_quiescent", return_value=(True, "quiescent")), patch("oc_rig.terminal_lifecycle.time.sleep") as sleep, patch.object(self.lifecycle, "_stop_backend", side_effect=lambda: setattr(self.lifecycle, "backend_owned", False)):
            self.assertTrue(self.lifecycle.close(terminal_lost=False)[0])
        sleep.assert_called_once_with(0.05)
        self.assertEqual(json.loads(self.path.read_text())["phase"], "stopped")

    def test_controller_stop_polls_original_running_pid_then_exact_not(self) -> None:
        self.lifecycle.deployment = unittest.mock.Mock()
        running = {"job": {"detail": "running", "loaded": True, "running": True, "pid": 42}}
        self.lifecycle.deployment.status.side_effect = (
            running,
            running,
            {"job": {"detail": "not", "loaded": True, "running": False, "pid": None}},
        )
        self.lifecycle.controller_owned = True
        self.lifecycle.controller_pid = 42
        self.lifecycle.backend_owned = True
        self.lifecycle.backend_identity = ProcessIdentity(43, 43, "started", ("backend",))
        self.lifecycle._acquire_lock()
        self.lifecycle.refresh = unittest.mock.Mock(return_value={})
        with patch("oc_rig.terminal_lifecycle.snapshot_is_quiescent", return_value=(True, "quiescent")), patch("oc_rig.terminal_lifecycle.time.sleep") as sleep, patch.object(self.lifecycle, "_stop_backend", side_effect=lambda: setattr(self.lifecycle, "backend_owned", False)):
            self.assertTrue(self.lifecycle.close(terminal_lost=False)[0])
        sleep.assert_called_once_with(0.05)

    def test_controller_stop_changed_live_pid_fails_immediately(self) -> None:
        self.lifecycle.deployment = unittest.mock.Mock()
        self.lifecycle.deployment.status.side_effect = (
            {"job": {"detail": "running", "loaded": True, "running": True, "pid": 42}},
            {"job": {"detail": "running", "loaded": True, "running": True, "pid": 99}},
        )
        self.lifecycle.controller_owned = True
        self.lifecycle.controller_pid = 42
        self.lifecycle._acquire_lock()
        self.lifecycle.refresh = unittest.mock.Mock(return_value={})
        with patch("oc_rig.terminal_lifecycle.snapshot_is_quiescent", return_value=(True, "quiescent")), patch("oc_rig.terminal_lifecycle.time.sleep") as sleep, self.assertRaisesRegex(TerminalLifecycleError, "identity changed"):
            self.lifecycle.close(terminal_lost=False)
        sleep.assert_not_called()
        self.lifecycle._release_lock()

    def test_controller_stop_malformed_status_fails_immediately(self) -> None:
        self.lifecycle.deployment = unittest.mock.Mock()
        self.lifecycle.deployment.status.side_effect = (
            {"job": {"detail": "running", "loaded": True, "running": True, "pid": 42}},
            {"job": {"detail": "unknown", "loaded": "true", "running": False, "pid": None}},
        )
        self.lifecycle.controller_owned = True
        self.lifecycle.controller_pid = 42
        self.lifecycle._acquire_lock()
        self.lifecycle.refresh = unittest.mock.Mock(return_value={})
        with patch("oc_rig.terminal_lifecycle.snapshot_is_quiescent", return_value=(True, "quiescent")), patch("oc_rig.terminal_lifecycle.time.sleep") as sleep, self.assertRaisesRegex(TerminalLifecycleError, "status is malformed"):
            self.lifecycle.close(terminal_lost=False)
        sleep.assert_not_called()
        self.lifecycle._release_lock()

    def test_controller_stop_timeout_retry_preserves_identity_until_exact_stopped(self) -> None:
        record = {"backend": None, "backend_owned": False, "completed_cutover": None, "controller_owned": True, "controller_pid": 42, "controller_starting": False, "cutover_intent": None, "format": 1, "invocation_id": "a" * 32, "phase": "running", "reason": "terminal attached", "tmux_nonce": "nonce", "tmux_session_id": "$0"}
        original = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        self.path.write_text(original, encoding="utf-8")
        self.path.chmod(0o600)
        first_deployment = unittest.mock.Mock()
        first_deployment.status.side_effect = (
            {"job": {"detail": "running", "loaded": True, "running": True, "pid": 42}},
            {"job": {"detail": "unknown", "loaded": True, "running": False, "pid": None}},
        )
        first = TerminalLifecycle(deployment=first_deployment, opencode=Path("/bin/echo"), ownership_path=self.path, backend_directory=self.root)
        first.controller_owned = True
        first.controller_pid = 42
        first.tmux_nonce = "nonce"
        first.tmux_session_id = "$0"
        first._acquire_lock()
        first.refresh = unittest.mock.Mock(return_value={})
        with patch("oc_rig.terminal_lifecycle.snapshot_is_quiescent", return_value=(True, "quiescent")), patch("oc_rig.terminal_lifecycle.time.monotonic", side_effect=(0.0, 6.0)), patch("oc_rig.terminal_lifecycle.time.sleep"), self.assertRaisesRegex(TerminalLifecycleError, "controller stop outcome"):
            first.close(terminal_lost=False)
        first._release_lock()
        self.assertEqual(self.path.read_text(), original)

        transitional_deployment = unittest.mock.Mock()
        transitional_deployment.status.return_value = {"job": {"detail": "unknown", "loaded": True, "running": False, "pid": None}}
        transitional = TerminalLifecycle(deployment=transitional_deployment, opencode=Path("/bin/echo"), ownership_path=self.path, backend_directory=self.root)
        with self.assertRaisesRegex(TerminalLifecycleError, "transitional"):
            transitional.resume_cleanup()
        self.assertEqual(self.path.read_text(), original)

        stopped_deployment = unittest.mock.Mock()
        stopped_deployment.status.return_value = {"job": {"detail": "not", "loaded": True, "running": False, "pid": None}}
        resumed = TerminalLifecycle(deployment=stopped_deployment, opencode=Path("/bin/echo"), ownership_path=self.path, backend_directory=self.root)
        resumed.resume_cleanup()
        self.assertTrue(resumed.close(terminal_lost=False)[0])
        stopped = json.loads(self.path.read_text())
        self.assertEqual(stopped["phase"], "stopped")
        self.assertFalse(stopped["controller_owned"])
        self.assertIsNone(stopped["controller_pid"])

    def test_controller_stop_recovery_rejects_other_loaded_details(self) -> None:
        for detail in ("not-running", "unknown", "stopped", "notready"):
            with self.subTest(detail=detail):
                deployment = unittest.mock.Mock()
                deployment.status.side_effect = (
                    {"job": {"detail": "running", "loaded": True, "running": True, "pid": 42}},
                    {"job": {"detail": detail, "loaded": True, "running": False, "pid": None}},
                )
                deployment.stop.side_effect = RuntimeError("post-stop local failure")
                lifecycle = TerminalLifecycle(
                    deployment=deployment,
                    opencode=Path("/bin/echo"),
                    ownership_path=self.root / f"ownership-{detail}.json",
                    backend_directory=self.root,
                )
                lifecycle.controller_owned = True
                lifecycle.controller_pid = 42
                lifecycle.backend_owned = True
                lifecycle.backend_identity = ProcessIdentity(43, 43, "started", ("backend",))
                lifecycle._acquire_lock()
                lifecycle.refresh = unittest.mock.Mock(return_value={})
                with patch("oc_rig.terminal_lifecycle.snapshot_is_quiescent", return_value=(True, "quiescent")), patch("oc_rig.terminal_lifecycle.time.monotonic", side_effect=(0.0, 6.0)), patch("oc_rig.terminal_lifecycle.time.sleep"), self.assertRaisesRegex(TerminalLifecycleError, "controller stop outcome"):
                    lifecycle.close(terminal_lost=False)
                lifecycle._release_lock()
                deployment.stop.assert_called_once()
                self.assertFalse(lifecycle.ownership_path.exists())

    def test_signal_deferral_in_background_context_is_fixed_lifecycle_error(self) -> None:
        observed: list[BaseException] = []
        def run() -> None:
            try:
                with _defer_terminal_signals():
                    pass
            except BaseException as error:
                observed.append(error)
        worker = threading.Thread(target=run)
        worker.start()
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(observed), 1)
        self.assertIsInstance(observed[0], TerminalLifecycleError)
        self.assertEqual(
            terminal_cli._finalizer_error_code(observed[0]), "signal_context"
        )

    def test_deferred_signal_never_replaces_body_security_exception(self) -> None:
        original = TerminalLifecycleError("exact backend identity is ambiguous")
        with self.assertRaises(TerminalLifecycleError) as raised:
            with _defer_terminal_signals():
                os.kill(os.getpid(), signal.SIGTERM)
                raise original
        self.assertIs(raised.exception, original)

    def test_deferred_signal_with_ambiguous_controller_stop_keeps_controller_error(self) -> None:
        self.lifecycle.deployment = unittest.mock.Mock()
        self.lifecycle.deployment.status.side_effect = (
            {"job": {"detail": "running", "loaded": True, "running": True, "pid": 42}},
            {"job": {"detail": "unknown", "loaded": True, "running": False, "pid": None}},
        )
        def uncertain_stop() -> None:
            os.kill(os.getpid(), signal.SIGTERM)
            raise RuntimeError("ambiguous local stop")
        self.lifecycle.deployment.stop.side_effect = uncertain_stop
        self.lifecycle.controller_owned = True
        self.lifecycle.controller_pid = 42
        self.lifecycle.backend_owned = True
        self.lifecycle.backend_identity = ProcessIdentity(43, 43, "started", ("backend",))
        self.lifecycle._acquire_lock()
        self.lifecycle.refresh = unittest.mock.Mock(return_value={})
        with patch("oc_rig.terminal_lifecycle.snapshot_is_quiescent", return_value=(True, "quiescent")), patch("oc_rig.terminal_lifecycle.time.monotonic", side_effect=(0.0, 6.0)), patch("oc_rig.terminal_lifecycle.time.sleep"), self.assertRaisesRegex(TerminalLifecycleError, "controller stop outcome") as raised:
            self.lifecycle.close(terminal_lost=False)
        self.assertNotIn("terminal signal", str(raised.exception))
        self.lifecycle._release_lock()

    def test_deferred_signal_with_backend_ambiguity_keeps_backend_error(self) -> None:
        self.lifecycle.backend_owned = True
        self.lifecycle.backend_identity = ProcessIdentity(43, 43, "started", ("backend",))
        self.lifecycle.cleanup_authorized = True
        self.lifecycle._acquire_lock()
        original = TerminalLifecycleError("owned backend identity changed; left untouched")
        def ambiguous_backend() -> None:
            os.kill(os.getpid(), signal.SIGTERM)
            raise original
        with patch.object(self.lifecycle, "_stop_backend", side_effect=ambiguous_backend), self.assertRaises(TerminalLifecycleError) as raised:
            self.lifecycle.close(terminal_lost=False)
        self.assertIs(raised.exception, original)
        self.lifecycle._release_lock()

    def test_deferred_detach_signal_after_controller_publication_continues_cleanup(self) -> None:
        identity = ProcessIdentity(59502, 59502, "started", ("backend",))
        self.lifecycle.deployment = unittest.mock.Mock()
        self.lifecycle.deployment.status.side_effect = (
            {"job": {"detail": "running", "loaded": True, "running": True, "pid": 59400}},
            {"job": {"detail": "waiting", "loaded": True, "running": False, "pid": None}},
        )
        self.lifecycle.controller_owned = True
        self.lifecycle.controller_pid = 59400
        self.lifecycle.backend_owned = True
        self.lifecycle.backend_identity = identity
        self.lifecycle.tmux_nonce = "nonce"
        self.lifecycle.tmux_session_id = "$0"
        self.lifecycle._acquire_lock()

        from contextlib import contextmanager

        @contextmanager
        def interrupted_after_publication():
            yield
            raise TerminalLifecycleError("terminal signal 1 deferred across ownership publication")

        @contextmanager
        def uninterrupted():
            yield

        self.lifecycle.refresh = unittest.mock.Mock(return_value={})
        with patch("oc_rig.terminal_lifecycle.snapshot_is_quiescent", return_value=(True, "quiescent")), patch("oc_rig.terminal_lifecycle._defer_terminal_signals", side_effect=(interrupted_after_publication(), uninterrupted())), patch.object(self.lifecycle, "_stop_backend", side_effect=lambda: setattr(self.lifecycle, "backend_owned", False)):
            self.assertEqual(self.lifecycle.close(terminal_lost=False), (True, "stopped invocation-owned resources"))
        stopped = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(stopped["phase"], "stopped")
        self.assertIsNone(stopped["backend"])
        self.assertIsNone(stopped["tmux_session_id"])

    def test_failed_start_preserves_live_retained_identity(self) -> None:
        identity = ProcessIdentity(93678, 93678, "started", ("backend",))
        record = {"backend": identity.as_json(), "backend_owned": True, "completed_cutover": None, "controller_owned": True, "controller_pid": 93500, "controller_starting": False, "cutover_intent": None, "format": 1, "invocation_id": "prior", "phase": "running", "reason": "terminal attached", "tmux_nonce": "nonce", "tmux_session_id": "$1"}
        original = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        self.path.write_text(original, encoding="utf-8")
        self.path.chmod(0o600)
        self.lifecycle.deployment = unittest.mock.Mock()
        self.lifecycle.deployment.status.return_value = {"job": {"running": False, "pid": None}}
        with self.assertRaisesRegex(TerminalLifecycleError, "record preserved"):
            self.lifecycle.start()
        self.assertEqual(self.path.read_text(encoding="utf-8"), original)

    def test_cleanup_backend_mismatch_or_error_preserves_record_and_controller(self) -> None:
        identity = ProcessIdentity(93678, 93678, "started", ("backend",))
        record = {"backend": identity.as_json(), "backend_owned": True, "completed_cutover": None, "controller_owned": True, "controller_pid": 93500, "controller_starting": False, "cutover_intent": None, "format": 1, "invocation_id": "prior", "phase": "running", "reason": "terminal attached", "tmux_nonce": "nonce", "tmux_session_id": "$1"}
        original = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        for state in ("mismatch", "error"):
            with self.subTest(state=state):
                self.path.write_text(original, encoding="utf-8")
                self.path.chmod(0o600)
                lifecycle = TerminalLifecycle(deployment=unittest.mock.Mock(), opencode=Path("/bin/echo"), ownership_path=self.path, backend_directory=self.root)
                lifecycle.deployment.status.return_value = {"job": {"running": True, "pid": 93500}}
                with patch("oc_rig.terminal_lifecycle._process_state", return_value=state), self.assertRaisesRegex(TerminalLifecycleError, "cannot be authenticated"):
                    lifecycle.resume_cleanup()
                lifecycle.deployment.stop.assert_not_called()
                self.assertEqual(self.path.read_text(encoding="utf-8"), original)
                self.assertNotEqual(json.loads(original)["phase"], "stopped")

    def test_cleanup_pid_reuse_ambiguous_output_and_inspection_failure_fail_closed(self) -> None:
        identity = ProcessIdentity(93678, 93678, "Sun Aug 30 20:00:00 2026", ("backend",))
        record = {"backend": identity.as_json(), "backend_owned": True, "completed_cutover": None, "controller_owned": True, "controller_pid": 93500, "controller_starting": False, "cutover_intent": None, "format": 1, "invocation_id": "prior", "phase": "running", "reason": "terminal attached", "tmux_nonce": "nonce", "tmux_session_id": "$1"}
        original = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        results = (
            subprocess.CompletedProcess([], 0, "93678 Mon Aug 31 20:00:00 2026 S backend\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 2, "", "permission denied"),
        )
        for result in results:
            with self.subTest(result=result):
                self.path.write_text(original, encoding="utf-8")
                self.path.chmod(0o600)
                deployment = unittest.mock.Mock()
                deployment.status.return_value = {"job": {"running": True, "pid": 93500}}
                lifecycle = TerminalLifecycle(deployment=deployment, opencode=Path("/bin/echo"), ownership_path=self.path, backend_directory=self.root)
                with patch("oc_rig.terminal_lifecycle.subprocess.run", return_value=result), self.assertRaises(TerminalLifecycleError):
                    lifecycle.resume_cleanup()
                deployment.stop.assert_not_called()
                self.assertEqual(self.path.read_text(encoding="utf-8"), original)


class TransactionalStartupTests(unittest.TestCase):
    def test_adopted_record_fresh_backend_attestation_failure_cleans_canonically(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        proof = {
            "format": 2, "material": {"intent": {}}, "receipt_id": "a" * 32,
        }
        retained = {
            "backend": None, "backend_binding": None, "backend_owned": False,
            "completed_cutover": proof, "controller_owned": False,
            "controller_pid": None, "controller_starting": False,
            "cutover_intent": {}, "format": 1, "invocation_id": "b" * 32,
            "phase": "migrated", "reason": "adopted", "tmux_nonce": None,
            "tmux_session_id": None,
        }
        ownership = root / "ownership.json"
        ownership.write_text(json.dumps(retained), encoding="utf-8")
        ownership.chmod(0o600)

        class Deployment:
            @staticmethod
            def status() -> dict[str, object]:
                return {"job": {"running": False, "pid": None}}

        class Lifecycle(TerminalLifecycle):
            def _configuration(self) -> tuple[str, str, str, int]:
                return "http://127.0.0.1:4096", "u", "p", 4096

            def _start_backend(self, *_args: object) -> None:
                self.backend_started_by_invocation = True
                self.backend_owned = False
                self.backend = None
                self.backend_identity = None
                self.backend_binding = None
                raise TerminalLifecycleError("automated backend policy is contaminated")

        lifecycle = Lifecycle(
            deployment=Deployment(), opencode=Path("/bin/echo"),
            ownership_path=ownership, backend_directory=root,
        )
        with self.assertRaises(TerminalLifecycleError):
            lifecycle.start()
        stopped = json.loads(ownership.read_text(encoding="utf-8"))
        self.assertEqual(stopped["phase"], "stopped")
        self.assertIsNone(stopped["backend"])
        self.assertFalse(stopped["backend_owned"])

    def test_readiness_failure_after_confirmed_backend_stop_is_canonical(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)

        class Deployment:
            @staticmethod
            def status() -> dict[str, object]:
                return {"job": {"running": False, "pid": None}}

        class Lifecycle(TerminalLifecycle):
            def _configuration(self) -> tuple[str, str, str, int]:
                return "http://127.0.0.1:4096", "user", "password", 4096

            def _start_backend(self, *_args: object) -> None:
                self.backend_owned = True
                self.backend_identity = ProcessIdentity(
                    28637, 28637, "started", ("opencode", "serve")
                )
                self.backend_binding = {"config_id": "config"}
                self.tmux_nonce = "nonce"
                self.tmux_session_id = "$0"
                self._clear_confirmed_backend()
                raise TerminalLifecycleError("fresh backend lost exact ownership")

        lifecycle = Lifecycle(
            deployment=Deployment(), opencode=Path("/bin/echo"),
            ownership_path=root / "ownership.json", backend_directory=root,
        )
        with self.assertRaises(TerminalLifecycleError):
            lifecycle.start()
        stopped = json.loads((root / "ownership.json").read_text())
        self.assertEqual(stopped["phase"], "stopped")
        self.assertIsNone(stopped["backend"])
        self.assertNotIn("backend_binding", stopped)
        self.assertIsNone(stopped["tmux_nonce"])
        self.assertIsNone(stopped["tmux_session_id"])

    def test_backend_is_rolled_back_when_controller_start_is_interrupted(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)

        class Deployment:
            running = False
            fail_once = True

            def status(self) -> dict[str, object]:
                return {
                    "job": {
                        "running": self.running,
                        "pid": 42 if self.running else None,
                    }
                }

            def start(self) -> None:
                if self.fail_once:
                    self.fail_once = False
                    raise KeyboardInterrupt
                self.running = True

        class Lifecycle(TerminalLifecycle):
            def _configuration(self) -> tuple[str, str, str, int]:
                return "http://127.0.0.1:4096", "user", "password", 4096

            def _start_backend(self, *_args: object) -> None:
                self.backend_owned = True
                self.backend_identity = ProcessIdentity(10, 10, "start", ("backend",))
                self.backend_binding = {"config_id": "config"}
                self.tmux_nonce = "nonce"
                self.tmux_session_id = "$0"

            def _stop_backend(self) -> None:
                self.backend_owned = False

            def refresh(self) -> object:
                return {"status": "ready"}

        deployment = Deployment()
        lifecycle = Lifecycle(
            deployment=deployment,
            opencode=Path("/bin/echo"),
            ownership_path=root / "ownership.json",
            backend_directory=root,
            backend_work_directory=root / "Library/Application Support/oc-rig-v2-backend-work",
        )
        with self.assertRaises(TerminalLifecycleError):
            lifecycle.start()
        self.assertFalse(lifecycle.backend_owned)
        stopped = json.loads((root / "ownership.json").read_text())
        self.assertEqual(stopped["phase"], "stopped")
        self.assertIsNone(stopped["backend"])
        self.assertNotIn("backend_binding", stopped)
        self.assertIsNone(stopped["tmux_nonce"])
        self.assertIsNone(stopped["tmux_session_id"])

        restarted = Lifecycle(
            deployment=deployment,
            opencode=Path("/bin/echo"),
            ownership_path=root / "ownership.json",
            backend_directory=root,
        )
        self.assertEqual(restarted.start(), {"status": "ready"})


class TerminalLayoutTests(unittest.TestCase):
    def arguments(self, root: Path) -> SimpleNamespace:
        return SimpleNamespace(
            backend_directory=root,
            backend_work_directory=(
                root / "Library/Application Support/oc-rig-v2-backend-work"
            ),
            completed_cutover_evidence=None,
            completed_cutover_evidence_sha256=None,
            completed_cutover_source=None,
            completed_cutover_source_config=None,
            completed_cutover_source_release=None,
            completed_cutover_controller_pid=None,
            completed_cutover_legacy_pid=None,
            cutover_existing=True,
            deployment_root=root,
            finalize_interval=2.0,
            finalize_timeout=60.0,
            home=root,
            launchctl=Path("/bin/launchctl"),
            legacy_backend_label="legacy",
            legacy_backend_program=root / "legacy-backend",
            opencode=root / "opencode",
            ownership=root / "ownership.json",
            plist=root / "rig.plist",
            release_id="0.1.0.dev9-fedcba0987654321",
            session="oc-rig-v2-test",
            tmux=root / "tmux",
        )

    def test_terminal_preflight_allows_stale_callback_only_for_cleanup(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        arguments = self.arguments(root)
        arguments.backend_directory = (
            root / ".config/opencode/.rig-v2-automated-backend"
        )
        parser = unittest.mock.Mock()
        parser.parse_args.return_value = arguments

        for mode, allowed in (
            ("open", False),
            ("app", False),
            ("hub", False),
            ("finalize", True),
            ("stop", True),
        ):
            with self.subTest(mode=mode):
                arguments.mode = mode
                target = "open" if mode == "app" else mode
                with patch(
                    "oc_rig.terminal_cli.build_parser", return_value=parser
                ), patch(
                    "oc_rig.terminal_cli._validate_runtime"
                ) as validate, patch(
                    f"oc_rig.terminal_cli._{target}", return_value=0
                ):
                    self.assertEqual(terminal_cli.main([]), 0)
                validate.assert_called_once_with(
                    arguments.deployment_root,
                    require_empty_socket=False,
                    expected_release=arguments.release_id,
                    allow_stale_codex_callback=allowed,
                )

    def test_cleanup_binding_uses_one_authenticated_stop_status(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        home = Path(temporary.name).resolve()
        deployment_root = home / "deployment"
        config_id = "a" * 64
        auth_root = deployment_root / "config" / "opencode" / config_id
        auth_root.mkdir(parents=True)
        (deployment_root / "deployment-state.json").write_text(
            json.dumps(
                {
                    "opencode": {
                        "config_id": config_id,
                        "endpoint": "http://127.0.0.1:4096",
                    }
                }
            ),
            encoding="utf-8",
        )
        (auth_root / "auth.json").write_text(
            json.dumps(
                {"type": "basic", "username": "user", "password": "password"}
            ),
            encoding="utf-8",
        )
        deployment = UserDeployment(
            deployment_root,
            home,
            home / "rig.plist",
            Path("/bin/launchctl"),
            Path(sys.executable),
            dry_run=True,
        )
        lifecycle = TerminalLifecycle(
            deployment=deployment,
            opencode=Path("/bin/echo"),
            ownership_path=home / "ownership.json",
            backend_directory=(
                home / ".config/opencode/.rig-v2-automated-backend"
            ),
        )
        with patch.object(
            deployment,
            "stop_status",
            return_value={
                "socket": str(home / "rig.sock"),
                "opencode": {"config_id": config_id},
            },
        ) as stop_status, patch.object(
            deployment,
            "status",
            side_effect=AssertionError("strict status used during cleanup"),
        ), patch.object(
            lifecycle,
            "_automated_backend_binding",
            return_value={"binding": "exact"},
        ) as binding:
            self.assertEqual(
                lifecycle._expected_backend_binding(for_cleanup=True),
                {"binding": "exact"},
            )
        stop_status.assert_called_once_with()
        binding.assert_called_once_with(config_id, "user", "password")

    def test_installed_launcher_routes_terminal_through_verified_wheel(self) -> None:
        self.assertLess(
            _LAUNCHER.index('sys.path.insert(0, str(wheel))'),
            _LAUNCHER.index('runpy.run_module("oc_rig.terminal_cli"'),
        )

    def test_hub_frame_survives_controller_restart_without_error_disclosure(self) -> None:
        client = unittest.mock.Mock()
        client.refresh.side_effect = terminal_cli.RigClientError(
            "synthetic_secret_code", "customer-specific socket detail"
        )
        frame = terminal_cli._hub_frame(client)
        self.assertIn("temporarily unavailable", frame)
        self.assertIn("retrying automatically", frame)
        self.assertNotIn("synthetic_secret_code", frame)
        self.assertNotIn("customer-specific socket detail", frame)

    def test_hub_frame_returns_normal_render_after_controller_recovers(self) -> None:
        client = unittest.mock.Mock()
        snapshot = {"snapshot": "restored"}
        client.refresh.return_value = snapshot
        with patch.object(terminal_cli, "render_terminal", return_value="ready frame") as render:
            self.assertEqual(terminal_cli._hub_frame(client), "ready frame")
        render.assert_called_once_with(snapshot, width=100, ansi=True)

    def test_verified_terminal_entry_routes_only_the_fixed_codex_marker(self) -> None:
        root = Path("/private/verified/oc-rig-v2")
        thread_id = "123e4567-e89b-12d3-a456-426614174000"
        arguments = [
            "--deployment-root", str(root),
            "--release-id", "0.1.0.dev0-0123456789abcdef",
            "--codex-route", thread_id,
            "status", "--format", "json",
        ]
        with patch.object(terminal_cli, "_validate_runtime") as validate, patch(
            "oc_rig.route_cli.main", return_value=0
        ) as route:
            self.assertEqual(terminal_cli.main(arguments), 0)
        validate.assert_called_once_with(
            root,
            require_empty_socket=False,
            expected_release="0.1.0.dev0-0123456789abcdef",
        )
        route.assert_called_once_with(
            [str(root), thread_id, "status", "--format", "json"]
        )

    def test_backend_root_is_one_lexical_cli_and_lifecycle_authority(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        home = Path(temporary.name).resolve()
        home.chmod(0o700)
        expected = home / AUTOMATED_BACKEND_RELATIVE
        self.assertEqual(_managed_backend_directory(home, expected), expected)
        for alternative in (
            home / ".config/opencode/secure-workspace",
            Path(AUTOMATED_BACKEND_RELATIVE),
            home / ".config/opencode/../opencode/.rig-v2-automated-backend",
        ):
            with self.subTest(alternative=alternative), self.assertRaisesRegex(
                TerminalLifecycleError, "managed path"
            ):
                _managed_backend_directory(home, alternative)

        deployment = UserDeployment(
            home / "deployment", home, home / "rig.plist",
            Path("/bin/launchctl"), Path(sys.executable), dry_run=True,
        )
        with self.assertRaisesRegex(TerminalLifecycleError, "managed path"):
            TerminalLifecycle(
                deployment=deployment,
                opencode=Path("/bin/echo"),
                ownership_path=home / "ownership.json",
                backend_directory=home / ".config/opencode/secure-workspace",
            )
        lifecycle = TerminalLifecycle(
            deployment=deployment,
            opencode=Path("/bin/echo"),
            ownership_path=home / "ownership.json",
            backend_directory=expected,
        )
        self.assertEqual(lifecycle.backend_directory, expected)

    def test_backend_root_cli_admission_precedes_runtime_access(self) -> None:
        arguments = self.arguments(Path("/private/tmp/terminal-cli-root"))
        arguments.backend_directory = arguments.home / "alternative"
        parser = unittest.mock.Mock()
        parser.parse_args.return_value = arguments
        with patch("oc_rig.terminal_cli.build_parser", return_value=parser), patch(
            "oc_rig.terminal_cli._validate_runtime"
        ) as validate, patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(terminal_cli.main([]), 1)
        validate.assert_not_called()
        self.assertIn("automated backend directory", stderr.getvalue())

    def test_backend_root_documentation_and_dispatch_suffix_are_identical(self) -> None:
        expected = "$HOME/" + AUTOMATED_BACKEND_RELATIVE
        documentation = Path(__file__).parents[1].joinpath(
            "docs/local-user-deployment.md"
        ).read_text(encoding="utf-8")
        self.assertNotIn(".config/opencode/secure-workspace", documentation)
        self.assertEqual(documentation.count(expected), 2)
        self.assertEqual(
            AUTOMATED_BACKEND_TOOL_OUTPUT_SUFFIX,
            f"/{AUTOMATED_BACKEND_RELATIVE}/data/opencode/tool-output/*",
        )

    def test_cockpit_only_tmux_preserves_detach_finalizer(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        calls: list[tuple[str, ...]] = []
        session_ids = iter(("$1",))

        def fake_tmux(_arguments: object, *values: str, check: bool = True) -> subprocess.CompletedProcess[str]:
            calls.append(tuple(values))
            if values[0] == "has-session":
                return subprocess.CompletedProcess(values, 1, "", "")
            if values[0] == "show-options":
                return subprocess.CompletedProcess(values, 0, "nonce-1\n", "")
            if values[0] == "display-message":
                return subprocess.CompletedProcess(values, 0, next(session_ids) + "\n", "")
            return subprocess.CompletedProcess(values, 0, "", "")

        topology = [(lane, f"session-{lane}", "secure-worker") for lane in ("control", "tensorhost", "homelab", "personal", "hands-off")]
        arguments = self.arguments(root)
        with patch("oc_rig.terminal_cli._tmux", side_effect=fake_tmux), patch(
            "oc_rig.terminal_cli._topology", return_value=topology
        ) as topology_view:
            terminal_cli._build_tmux(arguments, "nonce-1")
        topology_view.assert_called_once_with(arguments)
        self.assertEqual(sum(call[0] == "new-session" for call in calls), 1)
        self.assertFalse(any(call[0] == "split-window" for call in calls))
        self.assertTrue(any(call[:4] == ("set-hook", "-t", "oc-rig-v2-test", "client-detached") for call in calls))
        creation = next(call for call in calls if call[0] == "new-session")
        self.assertIn(("-n", "cockpit"), tuple(zip(creation, creation[1:])))
        self.assertIn(("@oc_rig_nonce", "nonce-1"), tuple(zip(creation, creation[1:])))

    def test_foreign_legacy_backend_job_is_never_removed(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        arguments = self.arguments(root)
        foreign = subprocess.CompletedProcess(
            [], 0, "program = /foreign\narguments = {\n/foreign\n}\n", ""
        )
        with patch("oc_rig.terminal_cli.subprocess.run", return_value=foreign) as run:
            with self.assertRaises(TerminalLifecycleError):
                terminal_cli._cutover_backend(arguments, 4096, {"foreign": False})
        self.assertEqual(run.call_count, 1)

    def test_absent_legacy_requires_durable_cutover_intent(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        arguments = self.arguments(root)
        absent = subprocess.CompletedProcess([], 113, "", "could not find service")
        with patch("oc_rig.terminal_cli.subprocess.run", return_value=absent):
            with self.assertRaisesRegex(TerminalLifecycleError, "absent"):
                terminal_cli._authenticate_legacy_backend(arguments, 4096)
            arguments.ownership.write_text(
                json.dumps({"cutover_intent": {"legacy": {}}, "format": 1}),
                encoding="utf-8",
            )
            arguments.ownership.chmod(0o600)
            with self.assertRaisesRegex(TerminalLifecycleError, "absent"):
                terminal_cli._authenticate_legacy_backend(arguments, 4096)
            self.assertIsNone(
                terminal_cli._authenticate_legacy_backend(
                    arguments, 4096, allow_absent=True
                )
            )
        denied = subprocess.CompletedProcess([], 5, "", "permission denied")
        with patch("oc_rig.terminal_cli.subprocess.run", return_value=denied):
            with self.assertRaisesRegex(TerminalLifecycleError, "inspected"):
                terminal_cli._authenticate_legacy_backend(
                    arguments, 4096, allow_absent=True
                )

    def _stopped_record(self) -> dict[str, object]:
        return {
            "backend": None,
            "backend_owned": False,
            "controller_owned": False,
            "controller_pid": None,
            "controller_starting": False,
            "cutover_intent": None,
            "format": 1,
            "invocation_id": "stopped-current",
            "phase": "stopped",
            "reason": "operator closed",
            "tmux_nonce": "prior-nonce",
            "tmux_session_id": "$1",
        }

    @staticmethod
    def _canonical(path: Path, value: object, mode: int = 0o600) -> bytes:
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        return data

    def _migration_fixture(self, root: Path) -> tuple[SimpleNamespace, SimpleNamespace, dict[str, object]]:
        destination = root / "destination"
        destination.mkdir(mode=0o700)
        arguments = self.arguments(destination)
        arguments.home = root
        arguments.backend_directory = root
        arguments.ownership = root / "ownership.json"
        arguments.legacy_backend_program = root / "legacy-backend"
        selected = SimpleNamespace(config_id="d" * 64, endpoint="http://127.0.0.1:4096")
        self._canonical(destination / "deployment-state.json", {"current": arguments.release_id, "opencode": {"config_id": selected.config_id}})
        self._canonical(destination / "releases" / arguments.release_id / "release-pin.json", {"release_id": arguments.release_id}, 0o400)

        source = root / "source"
        source.mkdir(mode=0o700)
        source_release, source_config = "0.1.0.dev0-1234567890abcdef", "a" * 64
        config_root = source / "config" / "opencode" / source_config
        pools: dict[str, list[dict[str, object]]] = {}
        counter = 0
        for pool, size in {"tensorhost": 3, "homelab": 3, "personal": 3, "control": 3, "hands-off": 1}.items():
            pools[pool] = []
            for position in range(size):
                counter += 1
                pools[pool].append({"slot_id": f"{pool}-{position + 1}", "session_id": f"session-{counter}", "worker": "secure-worker"})
        values = {"auth.json": {"type": "bearer", "token": "test-token-with-minimum-entropy"}, "topology.json": {"version": 1, "pools": pools}, "trust.json": {"mode": "secure", "secure_worker": "secure-worker"}}
        file_pins: dict[str, object] = {}
        for name, value in values.items():
            data = self._canonical(config_root / name, value)
            details = (config_root / name).stat()
            file_pins[name] = {"device": details.st_dev, "inode": details.st_ino, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        runtime = source / "runtime"
        runtime.mkdir(mode=0o700)
        store = RigStore(PrivateRuntimeDirectory(runtime / "state", runtime))
        store.initialize()
        loaded = LiveOpenCodeAdapterConfig.from_explicit_files(endpoint=selected.endpoint, auth_path=config_root / "auth.json", topology_path=config_root / "topology.json", trust_path=config_root / "trust.json")
        with closing(sqlite3.connect(store.path, isolation_level=None)) as connection:
            connection.execute("BEGIN")
            snapshot = dict(
                _CockpitSnapshotProjection(
                    topology=loaded.topology,
                    include_agent_lifecycle=False,
                ).capture(connection)
            )
            connection.rollback()
        version = normalize_snapshot(snapshot)["snapshot_version"]
        release_root = source / "releases" / source_release
        release_root.mkdir(parents=True)
        release_pin: dict[str, object] = {"format": "oc-rig-local-user-release-pin-v2", "release_id": source_release}
        for name, filename, data in (("wheel", "rig.whl", b"wheel"), ("manifest", "manifest.json", b"{}\n")):
            path = release_root / filename
            path.write_bytes(data)
            path.chmod(0o400)
            release_pin[name] = {"filename": filename, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        self._canonical(release_root / "release-pin.json", release_pin, 0o400)
        release_root.chmod(0o500)
        self._canonical(source / "deployment-state.json", {"format": "oc-rig-local-user-deployment-v1", "current": source_release, "previous": None, "opencode": {"format": "oc-rig-local-user-opencode-v1", "config_id": source_config, "endpoint": selected.endpoint, "files": file_pins}})
        program = str(arguments.legacy_backend_program.resolve())
        evidence = {"backend": {"command": ["backend"], "pgid": 222, "pid": 222, "started": "start"}, "backend_owned": True, "controller_owned": True, "controller_pid": 4321, "controller_starting": False, "cutover_intent": {"config_id": source_config, "controller_pid": 4321, "endpoint": selected.endpoint, "event_sequence": version["event_sequence"], "legacy": {"arguments": [program, "serve", "4096", str(arguments.opencode)], "label": "legacy", "pid": 1234, "program": program, "target": f"gui/{os.geteuid()}/legacy"}, "release_id": source_release, "snapshot_digest": version["digest"]}, "format": 1, "invocation_id": "prior-cutover", "phase": "retained", "reason": "completed", "tmux_nonce": "prior-nonce", "tmux_session_id": "$1"}
        evidence_path = root / "archive" / "ownership.json"
        evidence_data = self._canonical(evidence_path, evidence)
        arguments.completed_cutover_evidence = evidence_path
        arguments.completed_cutover_evidence_sha256 = hashlib.sha256(evidence_data).hexdigest()
        arguments.completed_cutover_source = source
        arguments.completed_cutover_source_release = source_release
        arguments.completed_cutover_source_config = source_config
        arguments.completed_cutover_controller_pid = 4321
        arguments.completed_cutover_legacy_pid = 1234
        return arguments, selected, evidence

    def test_completed_cutover_proof_is_bound_to_retained_source_and_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            arguments, selected, _ = self._migration_fixture(Path(temporary).resolve())
            proof = terminal_cli._completed_cutover_proof(arguments, selected, self._stopped_record())
            self.assertEqual(proof["material"]["source"]["release_id"], arguments.completed_cutover_source_release)
            self.assertEqual(proof["material"]["destination"]["config_id"], selected.config_id)

    def test_prior_destination_receipt_cannot_authorize_new_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            arguments, selected, _ = self._migration_fixture(Path(temporary).resolve())
            proof_a = terminal_cli._completed_cutover_proof(arguments, selected, self._stopped_record())
            arguments.release_id = "0.1.0.dev9-bbbbbbbbbbbbbbbb"
            selected.config_id = "e" * 64
            self._canonical(arguments.deployment_root / "deployment-state.json", {"current": arguments.release_id, "opencode": {"config_id": selected.config_id}})
            self._canonical(arguments.deployment_root / "releases" / arguments.release_id / "release-pin.json", {"release_id": arguments.release_id}, 0o400)
            record = dict(self._stopped_record(), completed_cutover=proof_a)
            proof_b = terminal_cli._completed_cutover_proof(arguments, selected, record)
            self.assertNotEqual(proof_a["receipt_id"], proof_b["receipt_id"])
            self.assertEqual(proof_b["material"]["destination"]["release_id"], arguments.release_id)
            self.assertNotEqual(proof_a["material"]["destination"], proof_b["material"]["destination"])

    def test_receipt_before_record_crash_rederives_stable_proof_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            arguments, selected, _ = self._migration_fixture(root)
            proof_a = terminal_cli._completed_cutover_proof(
                arguments, selected, self._stopped_record()
            )
            receipt_a = arguments.ownership.with_name(
                "completed-cutover-receipt-"
                f"{arguments.release_id}-{selected.config_id}.json"
            )
            self._canonical(receipt_a, proof_a)

            arguments.release_id = "0.1.0.dev9-bbbbbbbbbbbbbbbb"
            selected.config_id = "e" * 64
            self._canonical(
                arguments.deployment_root / "deployment-state.json",
                {"current": arguments.release_id, "opencode": {"config_id": selected.config_id}},
            )
            self._canonical(
                arguments.deployment_root / "releases" / arguments.release_id
                / "release-pin.json",
                {"release_id": arguments.release_id},
                0o400,
            )
            prior = dict(
                self._stopped_record(), completed_cutover=proof_a,
                cutover_intent=proof_a["material"]["intent"],
                tmux_nonce=None, tmux_session_id=None,
            )
            first = terminal_cli._completed_cutover_proof(
                arguments, selected, prior
            )
            receipt_b = arguments.ownership.with_name(
                "completed-cutover-receipt-"
                f"{arguments.release_id}-{selected.config_id}.json"
            )
            receipt_b_bytes = self._canonical(receipt_b, first)

            retry = terminal_cli._completed_cutover_proof(
                arguments, selected, prior
            )
            self.assertEqual(retry, first)

            self._canonical(arguments.ownership, prior)
            lifecycle = TerminalLifecycle(
                deployment=object(), opencode=Path("/bin/echo"),
                ownership_path=arguments.ownership, backend_directory=root,
            )
            receipt_b.write_bytes(b"{}\n")
            receipt_b.chmod(0o600)
            original = arguments.ownership.read_bytes()
            with self.assertRaisesRegex(
                TerminalLifecycleError, "already consumed"
            ):
                lifecycle.adopt_completed_cutover(
                    proof=retry, expected_existing=prior
                )
            self.assertEqual(arguments.ownership.read_bytes(), original)

            receipt_b.write_bytes(receipt_b_bytes)
            receipt_b.chmod(0o600)
            lifecycle.adopt_completed_cutover(
                proof=retry, expected_existing=prior
            )
            adopted = json.loads(arguments.ownership.read_text(encoding="utf-8"))
            self.assertEqual(adopted["completed_cutover"], retry)
            self.assertEqual(adopted["phase"], "migrated")
            lifecycle._release_lock()

    def test_completed_cutover_rejects_invented_pids_and_snapshot(self) -> None:
        for field in ("controller", "legacy", "snapshot"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                arguments, selected, evidence = self._migration_fixture(Path(temporary).resolve())
                changed = copy.deepcopy(evidence)
                if field == "controller":
                    changed["controller_pid"] = changed["cutover_intent"]["controller_pid"] = 9999
                elif field == "legacy":
                    changed["cutover_intent"]["legacy"]["pid"] = 9999
                else:
                    changed["cutover_intent"]["snapshot_digest"] = "f" * 64
                data = self._canonical(arguments.completed_cutover_evidence, changed)
                arguments.completed_cutover_evidence_sha256 = hashlib.sha256(data).hexdigest()
                with self.assertRaises(TerminalLifecycleError):
                    terminal_cli._completed_cutover_proof(arguments, selected, self._stopped_record())

    def test_completed_cutover_rejects_changed_source_or_destination_binding(self) -> None:
        for field in ("source-release", "source-config", "destination-release", "destination-config"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                arguments, selected, _ = self._migration_fixture(Path(temporary).resolve())
                if field == "source-release": arguments.completed_cutover_source_release = "0.1.0.dev0-ffffffffffffffff"
                elif field == "source-config": arguments.completed_cutover_source_config = "f" * 64
                elif field == "destination-release": arguments.release_id = "0.1.0.dev9-aaaaaaaaaaaaaaaa"
                else: selected.config_id = "e" * 64
                with self.assertRaises(TerminalLifecycleError):
                    terminal_cli._completed_cutover_proof(arguments, selected, self._stopped_record())

    def test_completed_cutover_rejects_committed_nonquiescent_wal_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            arguments, selected, _ = self._migration_fixture(Path(temporary).resolve())
            database = arguments.completed_cutover_source / "runtime" / "state" / "rig.sqlite3"
            config_root = arguments.completed_cutover_source / "config" / "opencode" / arguments.completed_cutover_source_config
            loaded = LiveOpenCodeAdapterConfig.from_explicit_files(endpoint=selected.endpoint, auth_path=config_root / "auth.json", topology_path=config_root / "topology.json", trust_path=config_root / "trust.json")
            with closing(sqlite3.connect(database, isolation_level=None)) as writer:
                self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone(), ("wal",))
                writer.execute("PRAGMA wal_autocheckpoint=0")
                writer.execute("INSERT INTO scheduler_work(id,idempotency_key,lane,state,enqueued_at) VALUES ('wal-work','wal-idem','tensorhost','queued','t0')")
                wal = database.with_name(database.name + "-wal")
                self.assertTrue(wal.exists() and wal.stat().st_size > 0)
                with closing(sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True, isolation_level=None)) as main_only:
                    main_only.execute("BEGIN")
                    snapshot = dict(_CockpitSnapshotProjection(topology=loaded.topology).capture(main_only))
                    main_only.rollback()
                self.assertTrue(snapshot_is_quiescent(snapshot)[0])
                self.assertEqual(writer.execute("SELECT state FROM scheduler_work WHERE id='wal-work'").fetchone(), ("queued",))
                with self.assertRaisesRegex(TerminalLifecycleError, "not proven checkpointed"):
                    terminal_cli._completed_cutover_proof(arguments, selected, self._stopped_record())

    def test_fresh_release_adopts_exact_completed_cutover_record(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        arguments = self.arguments(root)
        record = self._stopped_record()
        arguments.ownership.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        arguments.ownership.chmod(0o600)
        selected = SimpleNamespace(
            config_id="d" * 64, endpoint="http://127.0.0.1:4096"
        )
        proof = {
            "format": 2,
            "material": {"intent": {"legacy": {"label": "legacy"}}},
            "receipt_id": "c" * 32,
        }
        lifecycle = unittest.mock.Mock(tmux_nonce=None)
        with patch(
            "oc_rig.terminal_cli._matching_existing_tmux", return_value=False
        ), patch(
            "oc_rig.terminal_cli._selected_configuration", return_value=selected
        ), patch(
            "oc_rig.terminal_cli._authenticate_legacy_backend", return_value=None
        ), patch(
            "oc_rig.terminal_cli._lifecycle", return_value=lifecycle
        ), patch(
            "oc_rig.terminal_cli._job"
        ) as job, patch(
            "oc_rig.terminal_cli._completed_cutover_proof", return_value=proof
        ), patch(
            "oc_rig.terminal_cli._recover_partial_tmux"
        ), patch(
            "oc_rig.terminal_cli._build_tmux", return_value="$new"
        ), patch(
            "oc_rig.terminal_cli._terminal_env", return_value={}
        ), patch(
            "oc_rig.terminal_cli.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ):
            job.return_value.status.return_value = {
                "job": {"running": False, "pid": None}
            }
            self.assertEqual(terminal_cli._open(arguments), 0)
        lifecycle.adopt_completed_cutover.assert_called_once()
        adoption = lifecycle.adopt_completed_cutover.call_args.kwargs
        self.assertEqual(adoption["expected_existing"], record)
        self.assertEqual(adoption["proof"], proof)
        lifecycle.start.assert_called_once()

    def test_migration_replay_without_stopped_destination_record_is_rejected(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        arguments = self.arguments(root)
        selected = SimpleNamespace(
            config_id="d" * 64, endpoint="http://127.0.0.1:4096"
        )
        lifecycle = unittest.mock.Mock(tmux_nonce=None)
        with patch(
            "oc_rig.terminal_cli._matching_existing_tmux", return_value=False
        ), patch(
            "oc_rig.terminal_cli._selected_configuration", return_value=selected
        ), patch(
            "oc_rig.terminal_cli._authenticate_legacy_backend", return_value=None
        ), patch(
            "oc_rig.terminal_cli._lifecycle", return_value=lifecycle
        ), self.assertRaisesRegex(TerminalLifecycleError, "absent before direct cutover"):
            terminal_cli._open(arguments)
        lifecycle.adopt_completed_cutover.assert_not_called()
        lifecycle.start.assert_not_called()

    def test_stored_receipt_rejects_active_ownership_or_stale_tmux_before_start(self) -> None:
        for field, value in (("backend_owned", True), ("controller_owned", True), ("controller_pid", 99), ("tmux_nonce", "stale"), ("tmux_session_id", "$1")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                arguments = self.arguments(root)
                proof = {"format": 2, "material": {"intent": {}}, "receipt_id": "c" * 32}
                record = self._stopped_record()
                record.update({"completed_cutover": proof, "tmux_nonce": None, "tmux_session_id": None})
                record[field] = value
                self._canonical(arguments.ownership, record)
                lifecycle = unittest.mock.Mock(tmux_nonce=None)
                with patch("oc_rig.terminal_cli._matching_existing_tmux", return_value=False), patch("oc_rig.terminal_cli._selected_configuration", return_value=SimpleNamespace(config_id="d" * 64, endpoint="http://127.0.0.1:4096")), patch("oc_rig.terminal_cli._authenticate_legacy_backend", return_value=None), patch("oc_rig.terminal_cli._lifecycle", return_value=lifecycle), patch("oc_rig.terminal_cli._completed_cutover_proof", return_value=proof), self.assertRaisesRegex(TerminalLifecycleError, "stale resource ownership"):
                    terminal_cli._open(arguments)
                lifecycle.start.assert_not_called()

    def test_open_recovers_only_stale_dead_backend_before_cutover_adoption(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        arguments = self.arguments(root)
        selected = SimpleNamespace(
            config_id="d" * 64, endpoint="http://127.0.0.1:4096"
        )
        proof = {
            "format": 2,
            "material": {
                "destination": {"config_id": "d" * 64},
                "intent": {},
            },
            "receipt_id": "c" * 32,
        }
        record = self._stopped_record()
        record.update(
            {
                "backend": ProcessIdentity(
                    28637, 28637, "started", ("opencode", "serve")
                ).as_json(),
                "backend_binding": {"config_id": "d" * 64},
                "completed_cutover": proof,
                "tmux_nonce": None,
                "tmux_session_id": None,
            }
        )
        recovered = dict(record)
        recovered.pop("backend_binding")
        recovered["backend"] = None
        lifecycle = unittest.mock.Mock(tmux_nonce=None)
        lifecycle.recover_stale_stopped_backend.return_value = recovered
        lifecycle.start.side_effect = TerminalLifecycleError("stop after recovery")
        with patch(
            "oc_rig.terminal_cli._matching_existing_tmux", return_value=False
        ), patch(
            "oc_rig.terminal_cli._selected_configuration", return_value=selected
        ), patch(
            "oc_rig.terminal_cli._authenticate_legacy_backend", return_value=None
        ), patch(
            "oc_rig.terminal_cli._ownership_record", return_value=record
        ), patch(
            "oc_rig.terminal_cli._lifecycle", return_value=lifecycle
        ), patch(
            "oc_rig.terminal_cli._completed_cutover_proof", return_value=proof
        ), self.assertRaisesRegex(TerminalLifecycleError, "stop after recovery"):
            terminal_cli._open(arguments)
        lifecycle.recover_stale_stopped_backend.assert_called_once_with(
            proof=proof,
            selected_config_id="d" * 64,
            expected_existing=record,
        )
        lifecycle.adopt_completed_cutover.assert_called_once_with(
            proof=proof, expected_existing=recovered
        )

    def test_missing_legacy_without_completed_proof_stays_fail_closed(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        arguments = self.arguments(Path(temporary.name).resolve())
        selected = SimpleNamespace(
            config_id="d" * 64, endpoint="http://127.0.0.1:4096"
        )
        lifecycle = unittest.mock.Mock()
        with patch(
            "oc_rig.terminal_cli._matching_existing_tmux", return_value=False
        ), patch(
            "oc_rig.terminal_cli._selected_configuration", return_value=selected
        ), patch(
            "oc_rig.terminal_cli._authenticate_legacy_backend", return_value=None
        ), patch(
            "oc_rig.terminal_cli._lifecycle", return_value=lifecycle
        ), self.assertRaisesRegex(TerminalLifecycleError, "absent before direct cutover"):
            terminal_cli._open(arguments)
        lifecycle.start.assert_not_called()

    def test_cutover_intent_survives_crash_after_remove(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        path = root / "ownership.json"
        intent = {
            "config_id": "config-1",
            "controller_pid": 4321,
            "endpoint": "http://127.0.0.1:4096",
            "event_sequence": 7,
            "legacy": {"label": "legacy", "target": "gui/501/legacy"},
            "release_id": "release-1",
            "snapshot_digest": "digest-1",
        }

        def lifecycle() -> TerminalLifecycle:
            return TerminalLifecycle(
                deployment=object(),
                opencode=Path("/bin/echo"),
                ownership_path=path,
                backend_directory=root,
            )

        before_remove = lifecycle()
        before_remove.prepare_cutover(controller_pid=4321, intent=intent)
        published = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(published["phase"], "cutover")
        self.assertEqual(published["cutover_intent"], intent)
        before_remove._release_lock()

        after_crash = lifecycle()
        after_crash.prepare_cutover(controller_pid=4321, intent=intent)
        after_crash._release_lock()

    def test_cutover_health_wait_resume_fails_on_changed_admission_proof(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        path = root / "ownership.json"
        intent = {
            "config_id": "config-1",
            "controller_pid": 4321,
            "endpoint": "http://127.0.0.1:4096",
            "event_sequence": 7,
            "legacy": {"label": "legacy", "target": "gui/501/legacy"},
            "release_id": "release-1",
            "snapshot_digest": "digest-1",
        }
        first = TerminalLifecycle(
            deployment=object(), opencode=Path("/bin/echo"),
            ownership_path=path, backend_directory=root,
        )
        first.prepare_cutover(controller_pid=4321, intent=intent)
        first._release_lock()
        changed = dict(intent, event_sequence=8, snapshot_digest="digest-2")
        resumed = TerminalLifecycle(
            deployment=object(), opencode=Path("/bin/echo"),
            ownership_path=path, backend_directory=root,
        )
        with self.assertRaisesRegex(TerminalLifecycleError, "durable proof"):
            resumed.prepare_cutover(controller_pid=4321, intent=changed)
        resumed._release_lock()

    def test_tmux_nonce_is_durable_before_creation(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        lifecycle = TerminalLifecycle(
            deployment=object(), opencode=Path("/bin/echo"),
            ownership_path=root / "ownership.json", backend_directory=root,
        )
        lifecycle._acquire_lock()
        lifecycle.prepare_tmux("nonce-1")
        record = json.loads((root / "ownership.json").read_text(encoding="utf-8"))
        self.assertEqual(record["phase"], "starting")
        self.assertEqual(record["tmux_nonce"], "nonce-1")
        self.assertIsNone(record["tmux_session_id"])
        lifecycle._release_lock()

    def test_partial_tmux_crash_stages_remove_only_matching_nonce(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        arguments = self.arguments(Path(temporary.name).resolve())
        for stage in ("after-new-session", "after-hooks", "before-bind"):
            with self.subTest(stage=stage):
                calls: list[tuple[str, ...]] = []

                def matching(
                    _arguments: object, *values: str, check: bool = True
                ) -> subprocess.CompletedProcess[str]:
                    calls.append(tuple(values))
                    output = "$1\n" if values[0] == "display-message" else "nonce-1\n"
                    return subprocess.CompletedProcess(values, 0, output, "")

                with patch("oc_rig.terminal_cli._tmux", side_effect=matching):
                    terminal_cli._recover_partial_tmux(arguments, "nonce-1")
                self.assertIn(
                    ("kill-session", "-t", "oc-rig-v2-test"), calls
                )

                calls.clear()

                def foreign(
                    _arguments: object, *values: str, check: bool = True
                ) -> subprocess.CompletedProcess[str]:
                    calls.append(tuple(values))
                    output = "$1\n" if values[0] == "display-message" else "foreign\n"
                    return subprocess.CompletedProcess(values, 0, output, "")

                with patch("oc_rig.terminal_cli._tmux", side_effect=foreign):
                    with self.assertRaisesRegex(TerminalLifecycleError, "nonce"):
                        terminal_cli._recover_partial_tmux(arguments, "nonce-1")
                self.assertNotIn(
                    ("kill-session", "-t", "oc-rig-v2-test"), calls
                )

    def test_backend_child_does_not_inherit_parent_signal_deferral(self) -> None:
        with _defer_terminal_signals():
            child = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        os.killpg(child.pid, signal.SIGTERM)
        self.assertEqual(child.wait(timeout=2.0), -signal.SIGTERM)

    def test_terminal_environment_is_bounded_and_explicit(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        arguments = self.arguments(Path(temporary.name).resolve())
        with patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True):
            self.assertEqual(
                terminal_cli._terminal_env(arguments),
                {"HOME": str(arguments.home), "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin", "TERM": "xterm-256color"},
            )
        with patch.dict(os.environ, {"TERM": "bad term"}, clear=True):
            with self.assertRaises(TerminalLifecycleError):
                terminal_cli._terminal_env(arguments)
        with patch.dict(os.environ, {"TERM": "-V"}, clear=True):
            with self.assertRaises(TerminalLifecycleError):
                terminal_cli._terminal_env(arguments)

    def test_terminal_probe_ignores_ambient_terminfo_paths(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        arguments = self.arguments(Path(temporary.name).resolve())
        with patch.dict(
            os.environ,
            {
                "TERM": "xterm-256color",
                "TERMINFO": "/hostile/terminfo",
                "TERMINFO_DIRS": "/hostile/dirs",
            },
            clear=True,
        ):
            self.assertEqual(
                terminal_cli._terminal_env(arguments)["TERM"],
                "xterm-256color",
            )

    def test_safe_unusable_terminal_values_use_verified_fallback(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        arguments = self.arguments(Path(temporary.name).resolve())
        for term in ("", "dumb", "oc-rig-unsupported-terminal"):
            with self.subTest(term=term), patch.dict(
                os.environ, {"TERM": term}, clear=True
            ):
                self.assertEqual(
                    terminal_cli._terminal_env(arguments)["TERM"],
                    "xterm-256color",
                )

    def test_normalized_dumb_term_builds_and_attaches_real_tmux(self) -> None:
        tmux = shutil.which("tmux")
        if tmux is None:
            self.skipTest("tmux is unavailable")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        arguments = self.arguments(root)
        server = f"oc-rig-term-{os.getpid()}-{root.name}"
        command = [tmux, "-L", server, "-f", "/dev/null"]
        with patch.dict(os.environ, {"TERM": "dumb"}, clear=True):
            environment = terminal_cli._terminal_env(arguments)
        subprocess.run(
            [*command, "new-session", "-d", "-s", arguments.session],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        master, slave = pty.openpty()
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                [*command, "attach-session", "-t", arguments.session],
                stdin=slave,
                stdout=slave,
                stderr=slave,
                env=environment,
            )
            os.close(slave)
            slave = -1
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                attached = subprocess.run(
                    [
                        *command,
                        "display-message",
                        "-p",
                        "-t",
                        arguments.session,
                        "#{session_attached}",
                    ],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=environment,
                ).stdout.strip()
                if attached == "1":
                    break
                time.sleep(0.05)
            else:
                self.fail("real tmux client did not attach")
            os.write(master, b"\x02d")
            self.assertEqual(process.wait(timeout=5.0), 0)
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=5.0)
            subprocess.run(
                [*command, "kill-server"],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
            )
            os.close(master)
            if slave >= 0:
                os.close(slave)

    def test_second_open_attaches_before_lifecycle_mutation(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        arguments = self.arguments(Path(temporary.name).resolve())
        with patch("oc_rig.terminal_cli._matching_existing_tmux", return_value=True), patch(
            "oc_rig.terminal_cli._selected_configuration"
        ) as selected, patch(
            "oc_rig.terminal_cli.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ):
            self.assertEqual(terminal_cli._open(arguments), 0)
        selected.assert_not_called()

    def test_second_app_open_reuses_background_session_without_attaching(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        arguments = self.arguments(Path(temporary.name).resolve())
        with patch(
            "oc_rig.terminal_cli._matching_existing_tmux", return_value=True
        ), patch("oc_rig.terminal_cli._selected_configuration") as selected, patch(
            "oc_rig.terminal_cli.subprocess.run"
        ) as attach:
            self.assertEqual(terminal_cli._open(arguments, attach=False), 0)
        selected.assert_not_called()
        attach.assert_not_called()

    def test_deferred_finalizer_hands_back_on_reattach(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        arguments = self.arguments(Path(temporary.name).resolve())
        lifecycle = unittest.mock.Mock()
        attached = iter(("0", "1"))

        def fake_tmux(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, next(attached) + "\n", "")

        with patch("oc_rig.terminal_cli._tmux", side_effect=fake_tmux), patch(
            "oc_rig.terminal_cli._lifecycle", return_value=lifecycle
        ):
            self.assertEqual(terminal_cli._finalize(arguments), 0)
        lifecycle.resume_cleanup.assert_called_once()
        lifecycle.handoff.assert_called_once()
        lifecycle.close.assert_not_called()

    def test_session_kill_finalizer_stops_resources_before_killing_tmux(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        arguments = self.arguments(Path(temporary.name).resolve())
        lifecycle = unittest.mock.Mock()
        lifecycle.close.return_value = (True, "stopped invocation-owned resources")
        calls: list[tuple[str, ...]] = []
        def fake_tmux(_arguments: object, *values: str, check: bool = True) -> subprocess.CompletedProcess[str]:
            calls.append(tuple(values))
            if values[0] == "display-message":
                return subprocess.CompletedProcess([], 0, "0\n", "")
            return subprocess.CompletedProcess([], 0, "", "")
        with patch("oc_rig.terminal_cli._tmux", side_effect=fake_tmux), patch("oc_rig.terminal_cli._lifecycle", return_value=lifecycle):
            self.assertEqual(terminal_cli._finalize(arguments), 0)
        lifecycle.resume_cleanup.assert_called_once()
        lifecycle.close.assert_called_once()
        self.assertIn(("kill-session", "-t", arguments.session), calls)

    def test_repeated_stop_command_retries_durable_pending_cleanup(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        arguments = self.arguments(Path(temporary.name).resolve())
        pending = {"format": 1, "phase": "starting", "backend_owned": True}
        with patch("oc_rig.terminal_cli._matching_existing_tmux", return_value=False), patch("oc_rig.terminal_cli._ownership_record", return_value=pending), patch("oc_rig.terminal_cli._finalize", side_effect=(TerminalLifecycleError("interrupted after backend TERM"), 0)) as finalize:
            with self.assertRaisesRegex(TerminalLifecycleError, "interrupted"):
                terminal_cli._stop(arguments)
            self.assertEqual(terminal_cli._stop(arguments), 0)
        self.assertEqual(finalize.call_count, 2)

    def test_stop_rejects_each_stale_resource_field_without_action(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        arguments = self.arguments(root)
        canonical = {"backend": None, "backend_owned": False, "completed_cutover": None, "controller_owned": False, "controller_pid": None, "controller_starting": False, "cutover_intent": None, "format": 1, "invocation_id": "a" * 32, "phase": "stopped", "reason": "operator closed", "tmux_nonce": None, "tmux_session_id": None}
        changes = {
            "backend": {"pid": 10},
            "backend_owned": True,
            "controller_owned": True,
            "controller_pid": 10,
            "controller_starting": True,
            "tmux_nonce": "stale-nonce",
            "tmux_session_id": "$0",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                record = dict(canonical)
                record[field] = value
                self._canonical(arguments.ownership, record)
                with patch("oc_rig.terminal_cli._matching_existing_tmux") as matching, patch("oc_rig.terminal_cli._finalize") as finalize, patch("oc_rig.terminal_cli._tmux") as tmux, self.assertRaisesRegex(TerminalLifecycleError, "inconsistent"):
                    terminal_cli._stop(arguments)
                matching.assert_not_called()
                finalize.assert_not_called()
                tmux.assert_not_called()

    def test_stop_accepts_only_exact_canonical_stopped_record(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        arguments = self.arguments(Path(temporary.name).resolve())
        record = {"backend": None, "backend_owned": False, "completed_cutover": None, "controller_owned": False, "controller_pid": None, "controller_starting": False, "cutover_intent": None, "format": 1, "invocation_id": "a" * 32, "phase": "stopped", "reason": "operator closed", "tmux_nonce": None, "tmux_session_id": None}
        self._canonical(arguments.ownership, record)
        with patch("oc_rig.terminal_cli._matching_existing_tmux") as matching, patch("oc_rig.terminal_cli._finalize") as finalize, patch("oc_rig.terminal_cli._tmux") as tmux:
            self.assertEqual(terminal_cli._stop(arguments), 0)
        matching.assert_not_called()
        finalize.assert_not_called()
        tmux.assert_not_called()

    def test_finalizer_failure_is_published_without_exception_text(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        arguments = self.arguments(root)
        error = TerminalLifecycleError("secret path /private/example backend identity changed")
        with patch("oc_rig.terminal_cli._finalize_impl", side_effect=error), self.assertRaises(TerminalLifecycleError):
            terminal_cli._finalize(arguments)
        path = root / "finalizer-error.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        value = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(value["format"], "oc-rig-terminal-finalizer-error-v1")
        self.assertEqual(value["error_category"], "lifecycle")
        self.assertEqual(value["error_code"], "backend_identity")
        self.assertNotIn("secret", path.read_text(encoding="utf-8"))

    def test_finalizer_recorder_failure_never_replaces_original_identity_error(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        arguments = self.arguments(Path(temporary.name).resolve())
        original = TerminalLifecycleError("backend identity changed")
        recorder = OSError("diagnostic disk failure")
        with patch("oc_rig.terminal_cli._finalize_impl", side_effect=original), patch("oc_rig.terminal_cli._record_finalizer_error", side_effect=recorder):
            with self.assertRaises(TerminalLifecycleError) as raised:
                terminal_cli._finalize(arguments)
        self.assertIs(raised.exception, original)

    def test_unexpected_exception_name_is_never_written_to_diagnostic(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        arguments = self.arguments(root)
        sensitive_name = "SensitiveCustomerPath" * 100
        sensitive_type = type(sensitive_name, (Exception,), {})
        error = sensitive_type("more sensitive text")
        with patch("oc_rig.terminal_cli._finalize_impl", side_effect=error), self.assertRaises(sensitive_type):
            terminal_cli._finalize(arguments)
        text = (root / "finalizer-error.json").read_text(encoding="utf-8")
        value = json.loads(text)
        self.assertEqual(value["error_category"], "unexpected")
        self.assertEqual(value["error_code"], "unexpected_error")
        self.assertNotIn("SensitiveCustomerPath", text)
        self.assertNotIn("more sensitive", text)

    def test_active_snapshot_aborts_before_legacy_removal(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        arguments = self.arguments(Path(temporary.name).resolve())
        selected = SimpleNamespace(endpoint="http://127.0.0.1:4096")
        active = TerminalQuiescenceTests("test_exact_empty_snapshot_is_quiescent")
        active.setUp()
        self.addCleanup(active.doCleanups)
        active.snapshot["queue"]["total"] = 1
        active.snapshot["queue"]["lower_bound"] = 1
        with patch("oc_rig.terminal_cli._matching_existing_tmux", return_value=False), patch(
            "oc_rig.terminal_cli._selected_configuration", return_value=selected
        ), patch("oc_rig.terminal_cli._authenticate_legacy_backend", return_value=True), patch(
            "oc_rig.terminal_cli._job"
        ) as job, patch("oc_rig.terminal_cli.CockpitClient") as client, patch(
            "oc_rig.terminal_cli._cutover_backend"
        ) as cutover:
            job.return_value.status.return_value = {"job": {"running": True}}
            client.return_value.refresh.return_value = active.snapshot
            with self.assertRaises(TerminalLifecycleError):
                terminal_cli._open(arguments)
        cutover.assert_not_called()

    def test_provisional_backend_is_killed_on_identity_failure(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        lifecycle = TerminalLifecycle(
            deployment=object(), opencode=Path("/bin/echo"),
            ownership_path=root / "ownership.json", backend_directory=root,
        )
        process = unittest.mock.Mock(pid=43210)
        process.wait.return_value = -signal.SIGTERM
        with patch.dict(os.environ, {"OPENCODE_CONFIG": "/poison", "AWS_SECRET_ACCESS_KEY": "secret"}, clear=False), patch.object(lifecycle, "_health", return_value=False), patch(
            "oc_rig.terminal_lifecycle.subprocess.Popen", return_value=process
        ) as popen, patch(
            "oc_rig.terminal_lifecycle._process_identity",
            side_effect=TerminalLifecycleError("identity failed"),
        ), patch("oc_rig.terminal_lifecycle.os.killpg") as killpg:
            with self.assertRaises(TerminalLifecycleError):
                lifecycle._start_backend("http://127.0.0.1:4096", "u", "p", 4096)
        killpg.assert_called_once_with(43210, signal.SIGTERM)
        self.assertFalse(lifecycle.backend_owned)
        environment = popen.call_args.kwargs["env"]
        self.assertNotIn("OPENCODE_CONFIG", environment)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
        self.assertEqual(environment["HOME"], str(root / "home"))
        self.assertEqual(popen.call_args.kwargs["cwd"], root / "work")

    def test_healthy_unowned_backend_is_never_adopted(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        lifecycle = TerminalLifecycle(
            deployment=object(), opencode=Path("/bin/echo"),
            ownership_path=root / "ownership.json", backend_directory=root,
        )
        with patch.object(lifecycle, "_health", return_value=True), patch(
            "oc_rig.terminal_lifecycle.subprocess.Popen"
        ) as popen, self.assertRaisesRegex(TerminalLifecycleError, "not owned"):
            lifecycle._start_backend("http://127.0.0.1:4096", "u", "p", 4096)
        popen.assert_not_called()

    def test_private_backend_roots_reject_symlink_mode_extra_and_inode_swap(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        parent = Path(temporary.name).resolve()
        parent.chmod(0o700)
        external = parent / "external"
        external.mkdir(mode=0o700)
        linked = parent / "linked"
        linked.symlink_to(external)
        with self.assertRaises(TerminalLifecycleError):
            _prepare_private_backend_tree(linked)

        root = parent / "backend"
        first = _prepare_private_backend_tree(root)
        (root / "cache").chmod(0o755)
        with self.assertRaises(TerminalLifecycleError):
            _prepare_private_backend_tree(root)
        (root / "cache").chmod(0o700)
        (root / "extra").mkdir(mode=0o700)
        with self.assertRaisesRegex(TerminalLifecycleError, "unexpected"):
            _prepare_private_backend_tree(root)
        (root / "extra").rmdir()
        (root / "work").rename(root / "work-old")
        (root / "work").mkdir(mode=0o700)
        with self.assertRaisesRegex(TerminalLifecycleError, "unexpected"):
            _prepare_private_backend_tree(root)
        (root / "work-old").rmdir()
        self.assertNotEqual(first, _prepare_private_backend_tree(root))

    def test_runtime_provider_auth_is_empty_pinned_and_separate_from_config(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        parent = Path(temporary.name).resolve()
        parent.chmod(0o700)
        backend = parent / "backend"
        _prepare_private_backend_tree(backend)
        generation = parent / "generation"
        generation.mkdir(mode=0o700)
        seed = generation / "provider-auth-seed.json"
        seed.write_bytes(b"{}\n")
        seed.chmod(0o600)

        first = _prepare_runtime_auth(generation, backend / "data", create=True)
        auth = backend / "data/opencode/auth.json"
        self.assertEqual(auth.read_bytes(), b"{}\n")
        self.assertEqual(stat.S_IMODE(auth.stat().st_mode), 0o600)
        (backend / "data/opencode/opencode.db").write_bytes(b"runtime")
        (backend / "data/opencode/log").mkdir(mode=0o700)
        (backend / "data/opencode/repos").mkdir(mode=0o700)
        (backend / "data/opencode/opencode.json").write_text(
            '{"plugin":["untrusted"],"mcp":{"unsafe":{}}}', encoding="utf-8"
        )
        self.assertEqual(
            first, _prepare_runtime_auth(generation, backend / "data", create=False)
        )

        auth.write_text('{"provider":"credential"}\n', encoding="utf-8")
        with self.assertRaisesRegex(TerminalLifecycleError, "provider credentials"):
            _prepare_runtime_auth(generation, backend / "data", create=False)
        auth.unlink()
        auth.symlink_to(seed)
        with self.assertRaises(TerminalLifecycleError):
            _prepare_runtime_auth(generation, backend / "data", create=False)
        auth.unlink()
        auth.write_bytes(b"{}\n")
        auth.chmod(0o600)
        seed.write_text('{"provider":"credential"}\n', encoding="utf-8")
        with self.assertRaisesRegex(TerminalLifecycleError, "provider credentials"):
            _prepare_runtime_auth(generation, backend / "data", create=False)

    def test_managed_backend_uses_private_writable_data_home(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        parent = Path(temporary.name).resolve()
        parent.chmod(0o700)
        backend = parent / "backend"
        external_work = parent / "oc-rig-v2-backend-work"
        generation = parent / "deployment/config/opencode/config-id"
        generation.mkdir(parents=True, mode=0o700)
        seed = generation / "provider-auth-seed.json"
        seed.write_bytes(b"{}\n")
        seed.chmod(0o600)
        policy = generation / "automated-backend-policy.json"
        policy.write_text("{}\n", encoding="utf-8")
        policy.chmod(0o400)

        class Deployment:
            root = parent / "deployment"

            @staticmethod
            def status() -> dict[str, object]:
                return {"opencode": {"config_id": "config-id"}}

        lifecycle = TerminalLifecycle(
            deployment=Deployment(), opencode=Path("/bin/echo"),
            ownership_path=parent / "ownership.json", backend_directory=backend,
            backend_work_directory=external_work,
        )
        process = unittest.mock.Mock(pid=43210)
        process.wait.return_value = -signal.SIGTERM
        generation_before = {
            path.relative_to(generation).as_posix(): path.read_bytes()
            for path in generation.rglob("*") if path.is_file()
        }

        def bootstrap_writer(*_args: object, **kwargs: object):
            environment = kwargs["env"]
            runtime_config = Path(environment["XDG_CONFIG_HOME"]) / "opencode"
            runtime_config.mkdir(parents=True, exist_ok=True)
            (runtime_config / "package.json").write_text("{}\n", encoding="utf-8")
            (runtime_config / "node_modules").mkdir(mode=0o755)
            return process

        with patch.object(lifecycle, "_health", return_value=False), patch(
            "oc_rig.terminal_lifecycle.subprocess.Popen", side_effect=bootstrap_writer
        ) as popen, patch(
            "oc_rig.terminal_lifecycle._process_identity",
            side_effect=TerminalLifecycleError("identity failed"),
        ), patch("oc_rig.terminal_lifecycle.os.killpg"):
            with self.assertRaises(TerminalLifecycleError):
                lifecycle._start_backend("http://127.0.0.1:4096", "u", "p", 4096)
        environment = popen.call_args.kwargs["env"]
        self.assertEqual(environment["XDG_CONFIG_HOME"], str(backend / "config"))
        self.assertEqual(environment["OPENCODE_CONFIG"], str(policy))
        self.assertEqual(environment["XDG_DATA_HOME"], str(backend / "data"))
        self.assertNotEqual(environment["XDG_DATA_HOME"], str(generation))
        for name in (
            "OPENCODE_DISABLE_CLAUDE_CODE",
            "OPENCODE_DISABLE_DEFAULT_PLUGINS",
            "OPENCODE_DISABLE_EXTERNAL_SKILLS",
            "OPENCODE_DISABLE_LSP_DOWNLOAD",
            "OPENCODE_DISABLE_PROJECT_CONFIG",
            "OPENCODE_PURE",
        ):
            self.assertEqual(environment[name], "1")
        self.assertIn("--pure", popen.call_args.args[0])
        self.assertEqual(popen.call_args.kwargs["cwd"], external_work)
        self.assertEqual(
            generation_before,
            {
                path.relative_to(generation).as_posix(): path.read_bytes()
                for path in generation.rglob("*") if path.is_file()
            },
        )
        self.assertTrue((backend / "config/opencode/package.json").is_file())
        self.assertTrue((backend / "config/opencode/node_modules").is_dir())

    def test_backend_authority_attestation_rejects_integration_or_agent_drift(self) -> None:
        data_home = Path("/private/oc-rig-backend/data")
        tool_output = str(data_home / "opencode/tool-output/*")
        permission = [
            {"permission": "*", "pattern": "*", "action": "allow"},
            {"permission": "doom_loop", "pattern": "*", "action": "ask"},
            {"permission": "external_directory", "pattern": "*", "action": "ask"},
            {"permission": "external_directory", "pattern": tool_output, "action": "allow"},
            {"permission": "external_directory", "pattern": "/tmp/opencode/*", "action": "allow"},
            {"permission": "question", "pattern": "*", "action": "deny"},
            {"permission": "plan_enter", "pattern": "*", "action": "deny"},
            {"permission": "plan_exit", "pattern": "*", "action": "deny"},
            {"permission": "read", "pattern": "*", "action": "allow"},
            {"permission": "read", "pattern": "*.env", "action": "ask"},
            {"permission": "read", "pattern": "*.env.*", "action": "ask"},
            {"permission": "read", "pattern": "*.env.example", "action": "allow"},
            {"permission": "*", "pattern": "*", "action": "deny"},
            {"permission": "external_directory", "pattern": tool_output, "action": "allow"},
        ]
        model = {
            "providerID": "opencode",
            "modelID": "muse-spark-1.3-contributor-free",
        }
        custom = [
            {
                "color": None, "hidden": None, "native": False,
                "name": "rig-read-only-review", "mode": "primary",
                "description": _REVIEW_DESCRIPTION, "prompt": _REVIEW_PROMPT,
                "permission": permission, "model": model, "variant": "max",
                "options": {}, "steps": None, "temperature": None,
                "topP": None,
            },
            {
                "color": None, "hidden": None, "native": False,
                "name": "secure-worker", "mode": "primary",
                "description": _SECURE_DESCRIPTION, "prompt": _SECURE_PROMPT,
                "permission": [
                    *permission[:-1],
                    {"permission": "task", "pattern": "*", "action": "allow"},
                    permission[-1],
                ],
                "model": model, "variant": "max",
                "options": {}, "steps": None, "temperature": None,
                "topP": None,
            },
            {
                "color": None, "hidden": True, "native": False,
                "name": _CHILD_NAME, "mode": "subagent",
                "description": _CHILD_DESCRIPTION, "prompt": _CHILD_PROMPT,
                "permission": [
                    *permission[:-1],
                    {"permission": "task", "pattern": "*", "action": "allow"},
                    permission[-1],
                ],
                "model": model, "variant": "max",
                "options": {}, "steps": None, "temperature": None,
                "topP": None,
            },
        ]
        native = [
            {
                "name": name, "mode": "primary", "native": True,
                "hidden": True, "permission": permission, "tools": None,
                "options": {}, "prompt": f"native-{name}",
            }
            for name in ("compaction", "summary", "title")
        ]
        agents = [*native, *custom]

        class Response:
            status = 200

            def __init__(self, value: object):
                self.data = json.dumps(value).encode()

            def __enter__(self):
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self, _limit: int) -> bytes:
                return self.data

        resolved_config_agents = {
            "build": {"disable": True, "options": {}, "permission": {}},
            "explore": {"disable": True, "options": {}, "permission": {}},
            "general": {"disable": True, "options": {}, "permission": {}},
            "plan": {"disable": True, "options": {}, "permission": {}},
            "rig-read-only-review": {
                "description": _REVIEW_DESCRIPTION, "mode": "primary",
                "model": "opencode/muse-spark-1.3-contributor-free",
                "options": {}, "permission": {"*": "deny"},
                "prompt": _REVIEW_PROMPT, "variant": "max",
            },
            "secure-worker": {
                "description": _SECURE_DESCRIPTION, "mode": "primary",
                "model": "opencode/muse-spark-1.3-contributor-free",
                "options": {}, "permission": {"*": "deny", "task": "allow"},
                "prompt": _SECURE_PROMPT, "variant": "max",
            },
            _CHILD_NAME: {
                "description": _CHILD_DESCRIPTION, "hidden": True,
                "mode": "subagent",
                "model": "opencode/muse-spark-1.3-contributor-free",
                "options": {}, "permission": {"*": "deny", "task": "allow"},
                "prompt": _CHILD_PROMPT, "variant": "max",
            },
        }
        base_config = {
            "$schema": "https://opencode.ai/config.json",
            "agent": resolved_config_agents, "command": {},
            "mcp": {}, "mode": {}, "plugin": [], "username": "bounded-user",
        }
        with patch(
            "oc_rig.terminal_lifecycle.urllib.request.urlopen",
            side_effect=(
                Response(base_config),
                Response(agents),
            ),
        ):
            self.assertEqual(
                len(TerminalLifecycle._backend_authority(
                    "http://127.0.0.1:4096", "u", "p", data_home
                )),
                64,
            )
        enriched = [{**agents[0], "temperature": 0.1}, *agents[1:]]
        with patch(
            "oc_rig.terminal_lifecycle.urllib.request.urlopen",
            side_effect=(Response(base_config), Response(enriched)),
        ):
            enriched_hash = TerminalLifecycle._backend_authority(
                "http://127.0.0.1:4096", "u", "p", data_home
            )
        with patch(
            "oc_rig.terminal_lifecycle.urllib.request.urlopen",
            side_effect=(
                Response(base_config),
                Response([{**agents[0], "temperature": 0.2}, *agents[1:]]),
            ),
        ):
            self.assertNotEqual(
                enriched_hash,
                TerminalLifecycle._backend_authority(
                    "http://127.0.0.1:4096", "u", "p", data_home
                ),
            )
        for config, changed_agents in (
            ({**base_config, "mcp": {"personal": {}}}, agents),
            ({**base_config, "plugin": ["personal"]}, agents),
            ({**base_config, "command": {"shell": {}}}, agents),
            ({**base_config, "mode": {"write": {}}}, agents),
            ({**base_config, "extra": {}}, agents),
            ({**base_config, "agent": _AUTOMATED_BACKEND_POLICY["agent"]}, agents),
            (
                {
                    **base_config,
                    "agent": {
                        **resolved_config_agents,
                        "build": {"disable": True, "options": {}},
                    },
                },
                agents,
            ),
            (
                {
                    **base_config,
                    "agent": {
                        **resolved_config_agents,
                        "secure-worker": {
                            key: value
                            for key, value in resolved_config_agents["secure-worker"].items()
                            if key != "options"
                        },
                    },
                },
                agents,
            ),
            (
                base_config,
                [*agents[:-1], {**agents[-1], "permission": []}],
            ),
            ({**base_config, "agent": {}}, agents),
            (
                base_config,
                [*agents, {
                    "name": "tool-agent", "mode": "primary",
                    "description": "unsafe", "prompt": "run bash",
                    "permission": [{
                        "permission": "bash", "pattern": "*", "action": "allow",
                    }],
                    "model": model, "variant": "xhigh",
                }],
            ),
            (base_config, [agents[0], dict(agents[0])]),
            (base_config, [*native, {key: value for key, value in custom[0].items() if key != "model"}, custom[1]]),
            (base_config, [*native, {**custom[0], "model": {**model, "modelID": "drift"}}, custom[1]]),
            (base_config, [*native, {**custom[0], "variant": "low"}, custom[1]]),
            (base_config, [*native, {**custom[0], "native": True}, custom[1]]),
            (base_config, [*native, {**custom[0], "tools": None}, custom[1]]),
            (base_config, [{**native[0], "hidden": False}, *native[1:], *custom]),
            (base_config, [{**native[0], "native": False}, *native[1:], *custom]),
            (base_config, [{**native[0], "mode": "subagent"}, *native[1:], *custom]),
            (base_config, [{**native[0], "tools": {"bash": True}}, *native[1:], *custom]),
            (
                base_config,
                [*native, {
                    **custom[0],
                    "permission": [
                        *permission[:3],
                        {"permission": "external_directory", "pattern": "/personal/skills/*", "action": "allow"},
                        *permission[4:],
                    ],
                }, custom[1]],
            ),
        ):
            with self.subTest(config=config), patch(
                "oc_rig.terminal_lifecycle.urllib.request.urlopen",
                side_effect=(Response(config), Response(changed_agents)),
            ), self.assertRaises(TerminalLifecycleError):
                TerminalLifecycle._backend_authority(
                    "http://127.0.0.1:4096", "u", "p", data_home
                )

    def test_backend_work_rejects_personal_config_ancestry(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        personal = root / "personal"
        personal.mkdir(mode=0o700)
        (personal / "opencode.jsonc").write_text(
            '{"mcp":{"personal":{}}}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(TerminalLifecycleError, "contains OpenCode"):
            _prepare_backend_work_directory(personal / "nested-work")
        external = root / "Application Support" / "oc-rig-v2-backend-work"
        external.parent.mkdir(mode=0o700)
        identity = _prepare_backend_work_directory(external)
        self.assertEqual(
            identity["leaf"][:2],
            [external.stat().st_dev, external.stat().st_ino],
        )
        leaf_target = root / "leaf-target"
        leaf_target.mkdir(mode=0o700)
        linked_leaf = root / "linked-leaf"
        linked_leaf.symlink_to(leaf_target)
        with self.assertRaises(TerminalLifecycleError):
            _prepare_backend_work_directory(linked_leaf)
        ancestor_target = root / "ancestor-target"
        ancestor_target.mkdir(mode=0o700)
        ancestor_link = root / "ancestor-link"
        ancestor_link.symlink_to(ancestor_target)
        with self.assertRaises(TerminalLifecycleError):
            _prepare_backend_work_directory(ancestor_link / "work")

        original_fstat = os.fstat
        for race_target in (external, external.parent):
            with self.subTest(race_target=race_target):
                calls = 0
                target_inode = race_target.stat().st_ino

                def racing_fstat(descriptor: int) -> os.stat_result:
                    nonlocal calls
                    details = original_fstat(descriptor)
                    if details.st_ino == target_inode:
                        calls += 1
                        if calls == 2:
                            values = list(details)
                            values[1] += 1
                            return os.stat_result(values)
                    return details

                with patch(
                    "oc_rig.terminal_lifecycle.os.fstat", side_effect=racing_fstat
                ), self.assertRaisesRegex(TerminalLifecycleError, "ancestry changed"):
                    _prepare_backend_work_directory(external)

    def test_healthy_retained_backend_requires_exact_process_and_listener(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        lifecycle = TerminalLifecycle(
            deployment=object(), opencode=Path("/bin/echo"),
            ownership_path=root / "ownership.json", backend_directory=root,
        )
        identity = ProcessIdentity(123, 123, "start", ("backend",))
        lifecycle.backend_owned = True
        lifecycle.backend_identity = identity
        binding = {
            "bound": True,
            "private_roots": {"root": [1, 2, stat.S_IFDIR | 0o700, os.geteuid(), 1]},
        }
        lifecycle.backend_binding = binding
        with patch.object(lifecycle, "_health", return_value=True), patch.object(
            lifecycle, "_expected_backend_binding", return_value=binding
        ), patch("oc_rig.terminal_lifecycle._process_state", return_value="exact"), patch(
            "oc_rig.terminal_lifecycle._listener_pid", return_value=123
        ), patch("oc_rig.terminal_lifecycle.subprocess.Popen") as popen:
            lifecycle._start_backend("http://127.0.0.1:4096", "u", "p", 4096)
        popen.assert_not_called()
        for state, listener in (("absent", 999), ("terminated", 999), ("exact", 999)):
            with self.subTest(state=state, listener=listener), patch.object(
                lifecycle, "_health", return_value=True
            ), patch.object(
                lifecycle, "_expected_backend_binding", return_value=binding
            ), patch("oc_rig.terminal_lifecycle._process_state", return_value=state), patch(
                "oc_rig.terminal_lifecycle._listener_pid", return_value=listener
            ), self.assertRaisesRegex(TerminalLifecycleError, "not owned"):
                lifecycle._start_backend("http://127.0.0.1:4096", "u", "p", 4096)

    def test_fresh_backend_readiness_requires_exact_listener_process_and_binding(self) -> None:
        for label, listener, state, binding_match, succeeds in (
            ("exact", 43210, "exact", True, True),
            ("foreign-listener", 99999, "exact", True, False),
            ("pid-reuse", 43210, "mismatch", True, False),
            ("root-swap", 43210, "exact", False, False),
        ):
            with self.subTest(label=label):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                root = Path(temporary.name).resolve()
                root.chmod(0o700)
                lifecycle = TerminalLifecycle(
                    deployment=object(), opencode=Path("/bin/echo"),
                    ownership_path=root / "ownership.json", backend_directory=root,
                )
                process = unittest.mock.Mock(pid=43210)
                process.poll.return_value = None
                identity = ProcessIdentity(
                    43210, 43210, "start", ("/usr/bin/echo", "serve", "--port", "4096")
                )

                def expected_binding() -> object:
                    return lifecycle.backend_binding if binding_match else {"changed": True}

                with patch.object(
                    lifecycle, "_health", side_effect=[False, True]
                ), patch(
                    "oc_rig.terminal_lifecycle.subprocess.Popen", return_value=process
                ), patch(
                    "oc_rig.terminal_lifecycle._process_identity", return_value=identity
                ), patch(
                    "oc_rig.terminal_lifecycle._listener_pid", return_value=listener
                ), patch(
                    "oc_rig.terminal_lifecycle._process_state", return_value=state
                ), patch.object(
                    lifecycle, "_expected_backend_binding", side_effect=expected_binding
                ), patch.object(lifecycle, "_write_record"), patch.object(
                    lifecycle, "_stop_backend"
                ) as stop:
                    if succeeds:
                        lifecycle._start_backend(
                            "http://127.0.0.1:4096", "u", "p", 4096
                        )
                        stop.assert_not_called()
                    else:
                        with self.assertRaisesRegex(
                            TerminalLifecycleError, "lost exact ownership"
                        ):
                            lifecycle._start_backend(
                                "http://127.0.0.1:4096", "u", "p", 4096
                            )
                        stop.assert_called_once_with()

if __name__ == "__main__":
    unittest.main()
