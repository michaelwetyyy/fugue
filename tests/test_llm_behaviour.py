from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from oc_rig.adapters import DisabledAdapter
from oc_rig.adapters.opencode import LiveOpenCodeAdapter
from oc_rig.completion.service import _create_completion
from oc_rig.daemon.controller import OperationRejected, _RigController
from oc_rig.recovery.service import _create_recovery
from oc_rig.scheduler.service import _Scheduler
from oc_rig.store import PrivateRuntimeDirectory, RigStore
from oc_rig.store.database import _DaemonAuthority, _utc_now
from oc_rig.transport.service import _create_transport


class LlmBehaviourTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        self.store = RigStore(PrivateRuntimeDirectory(root / "state", root))
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
        self.store._open_daemon_connection(authority)
        self.addCleanup(authority.close)
        self.capability = object()
        completion = _create_completion(self.store, authority, self.capability)
        recovery = _create_recovery(self.store, authority, self.capability)
        transport = _create_transport(
            self.store, authority, self.capability, completion, DisabledAdapter()
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

    def call(
        self, operation: str, params: dict[str, object], idempotency_id: str
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

    def test_default_and_closed_roster_preserve_muse_13_max(self) -> None:
        result = self.call("llm.behaviour.status.v1", {}, "llm-status-1")
        self.assertEqual(
            (result["current_model"], result["current_effort"]),
            ("opencode/muse-spark-1.3-contributor-free", "max"),
        )
        self.assertIn(
            "max",
            result["supported_efforts_by_model"][
                "opencode/muse-spark-1.3-contributor-free"
            ],
        )
        self.assertNotIn("opencode/claude-fable-5", result["supported_models"])

    def test_apply_is_durable_idempotent_and_changes_future_prompt_fields(self) -> None:
        params = {"model": "opencode/ling-3.0-flash-fin-free", "effort": "high"}
        first = self.call("llm.behaviour.apply.v1", params, "llm-apply-1")
        second = self.call("llm.behaviour.apply.v1", params, "llm-apply-1")
        self.assertEqual(first, second)
        self.assertEqual(
            (first["effective_model"], first["effective_effort"]),
            (params["model"], params["effort"]),
        )

        adapter = object.__new__(LiveOpenCodeAdapter)
        reservations = type("Reservations", (), {})()
        reservations._store = self.store
        reservations._authority = self.authority
        object.__setattr__(adapter, "_reservations", reservations)
        self.assertEqual(
            adapter._future_dispatch_llm_fields(),
            {
                "model": {
                    "providerID": "opencode",
                    "modelID": "ling-3.0-flash-fin-free",
                },
                "variant": "high",
            },
        )
        with closing(self.store._connect()) as connection:
            row = connection.execute(
                "SELECT revision, applied_idempotency_id FROM llm_behaviour_settings"
            ).fetchone()
        self.assertEqual(tuple(row), (2, "llm-apply-1"))

    def test_apply_rejects_unknown_pair_and_non_idle_scheduler(self) -> None:
        with self.assertRaisesRegex(OperationRejected, "unsupported LLM") as invalid:
            self.call(
                "llm.behaviour.apply.v1",
                {"model": "opencode/claude-fable-5", "effort": "max"},
                "llm-invalid-1",
            )
        self.assertEqual(invalid.exception.code, "invalid_params")

        self.call(
            "scheduler.enqueue.v1",
            {"work_id": "llm-busy-work", "lane": "homelab"},
            "llm-enqueue-1",
        )
        with self.assertRaisesRegex(OperationRejected, "scheduler must be idle") as busy:
            self.call(
                "llm.behaviour.apply.v1",
                {"model": "opencode/muse-spark-1.2-contributor-free", "effort": "xhigh"},
                "llm-busy-1",
            )
        self.assertEqual(busy.exception.code, "scheduler_busy")

    def test_idempotency_id_cannot_be_reused_for_a_different_pair(self) -> None:
        self.call(
            "llm.behaviour.apply.v1",
            {"model": "opencode/muse-spark-1.2-contributor-free", "effort": "xhigh"},
            "llm-conflict-1",
        )
        with self.assertRaises(OperationRejected) as conflict:
            self.call(
                "llm.behaviour.apply.v1",
                {"model": "opencode/ling-3.0-flash-fin-free", "effort": "high"},
                "llm-conflict-1",
            )
        self.assertEqual(conflict.exception.code, "idempotency_conflict")


if __name__ == "__main__":
    unittest.main()
