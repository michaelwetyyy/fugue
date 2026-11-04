from __future__ import annotations

import copy
import gc
import hashlib
import os
import pickle
import pwd
import resource
import signal
import socket as socket_module
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import weakref
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from importlib import resources
from pathlib import Path
from unittest.mock import patch

from oc_rig.daemon.identity import (
    ServiceIdentityError,
    ServiceIdentityPolicy,
    validate_service_topology,
)
from oc_rig.daemon import identity as service_identity
from oc_rig.daemon import server as daemon_server
from oc_rig.daemon.controller import _RigController
from oc_rig.daemon.security import PrivateSocketPath, SocketSecurityError
from oc_rig.daemon.server import RigdChildArtifact, RigDaemon, _RigDaemonBase
from oc_rig.protocol.client import RigClient, RigClientError
from oc_rig.protocol.framing import receive_frame, send_frame
from oc_rig.protocol.messages import Request, Response
from oc_rig.policy import AdmissionRequest, decide_standalone_worker
from oc_rig.scheduler import LANES
from oc_rig.scheduler.service import _AdmissionEvidence, _Scheduler, _evaluate_admission
from oc_rig.store import PrivateRuntimeDirectory, RigStore
from oc_rig.store.database import DaemonAuthorityError, _DaemonAuthority, _split_sql
from tests.fixtures.durable_daemon import (
    ModeledDurableDaemon,
    _NATIVE_BOOTSTRAP_SOURCE,
    descriptor_execution_supported,
    modeled_bootstrap_strategy,
    provision_child_artifact,
)


class ModeledIdentityProbe:
    def __init__(
        self,
        service_uid: int,
        client_uid: int,
        client_gid: int,
    ):
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

class SchedulerDaemonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

        self.root.chmod(0o710)
        self.service_uid = os.geteuid()
        self.client_gid = os.getegid()
        eligible_clients: list[int] = []
        for account in pwd.getpwall():
            if account.pw_uid <= 0 or account.pw_uid == self.service_uid:
                continue
            try:
                groups = os.getgrouplist(account.pw_name, account.pw_gid)
            except (KeyError, OverflowError):
                continue
            if self.client_gid in groups:
                eligible_clients.append(account.pw_uid)
        if not eligible_clients:
            self.skipTest("no distinct non-root local client in the service client group")
        self.client_uid = min(eligible_clients)
        self.identity_policy = ServiceIdentityPolicy(
            self.service_uid,
            frozenset({self.client_uid}),
            self.client_gid,
        )
        self.identity_probe = ModeledIdentityProbe(
            self.service_uid,
            self.client_uid,
            self.client_gid,
        )
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.state = self.root / "state"
        self.store = RigStore(PrivateRuntimeDirectory(self.state, self.root))
        self.state.joinpath("rigd.lock").touch(mode=0o600)
        self.state.joinpath("rigd.lock").chmod(0o600)
        self.max_idempotency_entries = 4096
        self.socket = self.root / "socket" / "rig.sock"
        self.socket.parent.mkdir(mode=0o710)
        self.socket.parent.chmod(0o710)
        self.daemon: ModeledDurableDaemon | None = None
        self.thread: threading.Thread | None = None
        self.client: RigClient | None = None
        self.claims: dict[str, dict[str, object]] = {}
        self.start_daemon()

    def assert_no_launch_artifacts(self, artifact: object) -> None:
        artifact_root = getattr(artifact, "artifact_root")
        self.assertEqual(
            {entry.name for entry in artifact_root.iterdir()},
            {"python", "rigd-child.py", "rigd-native-bootstrap"},
        )
        self.assertFalse((artifact_root.parent / "test-rigd-launch").exists())

    def modeled_root_artifact(
        self,
        approved_root: Path,
    ) -> tuple[RigdChildArtifact, dict[Path, daemon_server._ArtifactFacts]]:
        provisioned = provision_child_artifact(approved_root)
        bootstrap = replace(provisioned.bootstrap, owner_uid=0, mode=0o555)
        helper = replace(provisioned.helper, owner_uid=0, mode=0o555)
        interpreter = replace(provisioned.interpreter, owner_uid=0, mode=0o555)
        artifact = replace(
            provisioned,
            bootstrap=bootstrap,
            helper=helper,
            interpreter=interpreter,
        )
        facts: dict[Path, daemon_server._ArtifactFacts] = {}
        directories = {artifact.artifact_root, *artifact.artifact_root.parents}
        for path in directories:
            details = path.lstat()
            facts[path] = daemon_server._ArtifactFacts(
                path,
                stat.S_IFDIR | 0o755,
                0,
                0,
                details.st_nlink,
                details.st_dev,
                details.st_ino,
                details.st_size,
                False,
            )
        for pinned in (bootstrap, helper, interpreter):
            details = pinned.path.lstat()
            facts[pinned.path] = daemon_server._ArtifactFacts(
                pinned.path,
                stat.S_IFREG | 0o555,
                0,
                0,
                1,
                pinned.device,
                pinned.inode,
                pinned.size,
                False,
            )
        return artifact, facts

    def tearDown(self) -> None:
        self.stop_daemon()

    def start_daemon(self, *, mode: str = "normal") -> None:
        self.daemon = ModeledDurableDaemon(
            PrivateSocketPath(self.socket, self.root),
            runtime=self.store.runtime,
            identity_policy=self.identity_policy,
            max_idempotency_entries=self.max_idempotency_entries,
            mode=mode,
        )
        self.daemon.start()
        self.thread = None
        self.client = RigClient(
            self.socket,
            approved_root=self.root,
            service_uid=self.service_uid,
            client_gid=self.client_gid,
        )

    def stop_daemon(self) -> None:
        if self.daemon is not None:
            self.daemon.shutdown()
        if self.thread is not None:
            self.thread.join(timeout=2)
        self.daemon = None
        self.thread = None
        self.client = None

    def restart_daemon(self, *, mode: str = "normal") -> None:
        self.stop_daemon()
        self.store = RigStore(PrivateRuntimeDirectory(self.state, self.root))
        self.start_daemon(mode=mode)

    def call(
        self,
        operation: str,
        params: dict[str, object] | None = None,
        *,
        idempotency_id: str,
    ) -> dict[str, object]:
        assert self.client is not None
        return dict(
            self.client.call(
                operation,
                params or {},
                request_id=f"request-{idempotency_id}",
                idempotency_id=idempotency_id,
            )
        )

    def prepare_claim(
        self,
        label: str,
    ) -> tuple[dict[str, object], str]:
        relative = f"{label}.txt"
        self.repository.joinpath(relative).write_text("bounded input", encoding="utf-8")
        operation_id = f"owner-{label}"
        self.call(
            "operation.create.v1",
            {"operation_id": operation_id, "kind": "dispatch"},
            idempotency_id=f"operation-{label}",
        )
        receipt = self.call(
            "scope.claim.v1",
            {
                "owner_operation_id": operation_id,
                "repository": str(self.repository),
                "scope": [relative],
            },
            idempotency_id=f"claim-{label}",
        )
        self.claims[label] = receipt
        return receipt, relative

    def enqueue(self, label: str, lane: str = "tensorhost") -> None:
        self.call(
            "scheduler.enqueue.v1",
            {"work_id": f"work-{label}", "lane": lane},
            idempotency_id=f"enqueue-{label}",
        )

    def admit(
        self,
        label: str,
        *,
        content: object = "safe isolated work",
    ) -> dict[str, object]:
        claim, relative = self.prepare_claim(label)
        return self.call(
            "scheduler.admit.v1",
            {
                "work_id": f"work-{label}",
                "claim_id": claim["claim_id"],
                "repository": str(self.repository),
                "scope": [relative],
                "content": content,
                "dispatch_kind": "automated",
                "trust": "secure",
                "classification": "PUBLIC",
                "risk_categories": [],
            },
            idempotency_id=f"admit-{label}",
        )

    def ready(self, label: str, lane: str = "tensorhost") -> None:
        self.enqueue(label, lane)
        result = self.admit(label)
        self.assertTrue(result["allowed"])

    def reserve(self, label: str) -> dict[str, object] | None:
        return self.call(
            "scheduler.reserve.v1", idempotency_id=f"reserve-{label}"
        )["reservation"]  # type: ignore[return-value]

    def release(
        self,
        label: str,
        reservation: dict[str, object],
        outcome: str,
    ) -> bool:
        result = self.call(
            "scheduler.release.v1",
            {
                "reservation_id": reservation["id"],
                "work_id": reservation["work_id"],
                "owner_id": reservation["owner_id"],
                "attempt": reservation["attempt"],
                "fence_token": reservation["fence_token"],
                "outcome": outcome,
            },
            idempotency_id=f"release-{label}",
        )
        return bool(result["released"])

    def rows(self, table: str) -> list[sqlite3.Row]:
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.row_factory = sqlite3.Row
            return list(connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid'))

    def provision_runtime(
        self,
        label: str,
    ) -> tuple[PrivateRuntimeDirectory, PrivateSocketPath]:
        root = self.root / label
        root.mkdir(mode=0o710)
        root.chmod(0o710)
        runtime = PrivateRuntimeDirectory(root / "state", root)
        store = RigStore(runtime)
        store.initialize()
        runtime.root.joinpath("rigd.lock").touch(mode=0o600)
        runtime.root.joinpath("rigd.lock").chmod(0o600)
        socket_directory = root / "socket"
        socket_directory.mkdir(mode=0o710)
        socket_directory.chmod(0o710)
        return runtime, PrivateSocketPath(socket_directory / "rig.sock", root)

    def test_public_scheduler_exports_values_not_mutation_service(self) -> None:
        import oc_rig.scheduler as scheduler

        self.assertFalse(hasattr(scheduler, "Scheduler"))
        self.assertEqual(len(LANES), 5)

    def test_exact_topology_is_verified_and_immutable(self) -> None:
        snapshot = self.call(
            "scheduler.snapshot.v1", idempotency_id="snapshot-topology"
        )["snapshot"]
        lanes = snapshot["lanes"]  # type: ignore[index]
        self.assertEqual([len(lane["slots"]) for lane in lanes], [3, 3, 3, 3, 1])
        statements = (
            "INSERT INTO scheduler_slots(id,lane,position,state) "
            "VALUES ('extra','control',2,'clear')",
            "DELETE FROM scheduler_slots WHERE id = 'control-1'",
            "UPDATE scheduler_slots SET id = 'changed' WHERE id = 'control-1'",
        )
        for statement in statements:
            with self.subTest(statement=statement):
                with self.assertRaises((sqlite3.IntegrityError, sqlite3.OperationalError)):
                    with self.store._transaction() as connection:
                        connection.execute(statement)

    def test_upgrade_fails_closed_with_legacy_active_assignment(self) -> None:
        other_root = self.root / "upgrade"
        other_root.mkdir()
        runtime = PrivateRuntimeDirectory(other_root / "state", other_root)
        store = RigStore(runtime)
        database = store.path
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                """CREATE TABLE schema_migrations (
                       version TEXT PRIMARY KEY, checksum TEXT NOT NULL,
                       applied_at TEXT NOT NULL
                   ) STRICT"""
            )
            migration_root = resources.files("oc_rig.store.migrations")
            for name in ("001_initial.sql", "002_queue_and_fences.sql", "003_scheduler.sql"):
                script = migration_root.joinpath(name).read_text(encoding="utf-8")
                for statement in _split_sql(script):
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO schema_migrations VALUES (?, ?, 'now')",
                    (name, hashlib.sha256(script.encode()).hexdigest()),
                )
            connection.execute(
                """INSERT INTO operations(
                       id, kind, state, created_at, updated_at
                   ) VALUES ('legacy-owner', 'dispatch', 'pending', 'now', 'now')"""
            )
            connection.execute(
                """INSERT INTO scope_claims(
                       id, scope_key, owner_operation_id, state, claimed_at,
                       attempt, fence_token, idempotency_key
                   ) VALUES ('legacy-claim', 'legacy-scope', 'legacy-owner',
                             'active', 'now', 1, 'legacy-claim-fence',
                             'legacy-claim-idem')"""
            )
            connection.execute(
                """INSERT INTO scheduler_work(
                       id, idempotency_key, lane, state, scope_key,
                       scope_owner_id, policy_decision_id, policy_allowed,
                       admission_idempotency_key, enqueued_at
                   ) VALUES ('legacy-work', 'legacy-work-idem', 'control',
                             'queued', 'legacy-scope', 'legacy-owner',
                             'legacy-decision', 1, 'legacy-admit', 'now')"""
            )
            connection.execute(
                """INSERT INTO scheduler_assignments(
                       id, work_id, slot_id, lane, owner_id, attempt,
                       fence_token, state, assigned_at
                   ) VALUES ('legacy-assignment', 'legacy-work', 'control-1',
                             'control', 'legacy-owner', 1,
                             'legacy-assignment-fence', 'active', 'now')"""
            )
            connection.execute(
                """UPDATE scheduler_work SET state = 'assigned',
                          active_assignment_id = 'legacy-assignment',
                          attempt = 1, assigned_at = 'now'
                   WHERE id = 'legacy-work'"""
            )
            connection.execute(
                """UPDATE scheduler_slots SET state = 'assigned',
                          active_assignment_id = 'legacy-assignment',
                          active_work_id = 'legacy-work', owner_id = 'legacy-owner',
                          attempt = 1, fence_token = 'legacy-assignment-fence'
                   WHERE id = 'control-1'"""
            )
            connection.execute(
                """INSERT INTO events(
                       event_id, aggregate_type, aggregate_id, event_type,
                       payload_json, occurred_at
                   ) VALUES ('legacy-event', 'scheduler_assignment',
                             'legacy-assignment', 'scheduler.assignment.created',
                             '{}', 'now')"""
            )
            connection.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            store.initialize()
        with closing(sqlite3.connect(database)) as connection:
            self.assertNotIn(
                ("004_scheduler_authority.sql",),
                connection.execute("SELECT version FROM schema_migrations").fetchall(),
            )

    def test_direct_construction_and_store_mutation_lack_daemon_authority(self) -> None:
        with self.assertRaises(ImportError):
            exec("from oc_rig.daemon.controller import RigController", {})
        assert self.daemon is not None
        self.assertFalse(hasattr(self.daemon, "controller"))
        with self.assertRaises(DaemonAuthorityError):
            _DaemonAuthority(self.store, object())
        with self.assertRaises(PermissionError):
            _Scheduler(self.store, object())  # type: ignore[arg-type]
        inert_controller = object.__new__(_RigController)
        with self.assertRaises(AttributeError):
            inert_controller.execute_durable(
                object(),
                "direct-idempotency",
                "0" * 64,
                "health.v1",
                {},
            )
        with self.assertRaises(DaemonAuthorityError):
            self.store.claim_scope(
                "direct-claim",
                "direct-scope",
                "direct-owner",
                attempt=1,
                fence_token="direct-fence",
                idempotency_key="direct-idem",
            )
        for statement in (
            "from oc_rig.store.database import _issue_daemon_authority",
            "from oc_rig.daemon.controller import _create_rig_controller",
            "from oc_rig.scheduler.service import _create_scheduler",
        ):
            with self.subTest(statement=statement), self.assertRaises(ImportError):
                exec(statement, {})
        topology = validate_service_topology(
            self.store.runtime,
            PrivateSocketPath(self.socket, self.root),
            self.identity_policy,
            self.identity_probe,
        )
        self.assertFalse(topology.database_open_allowed(self.client_uid))
        self.assertTrue(
            topology.socket_connect_allowed(
                self.client_uid,
                frozenset({self.client_gid}),
            )
        )
        self.assertFalse(
            topology.socket_connect_allowed(
                self.client_uid + 1,
                frozenset(),
            )
        )

        def raw_udf_bypass_as_client() -> None:
            if not topology.database_open_allowed(self.client_uid):
                raise PermissionError("client cannot traverse the state directory")
            with sqlite3.connect(self.store.path) as connection:
                connection.create_function("rigd_authorized", 0, lambda: 1)
                connection.execute("DELETE FROM scheduler_work")

        with self.assertRaises(PermissionError):
            raw_udf_bypass_as_client()

    def test_production_state_and_socket_have_separate_exact_permissions(self) -> None:
        facts = {
            "state": self.state.lstat(),
            "database": self.store.path.lstat(),
            "lock": self.state.joinpath("rigd.lock").lstat(),
            "socket_directory": self.socket.parent.lstat(),
            "socket": self.socket.lstat(),
        }
        self.assertEqual(stat.S_IMODE(facts["state"].st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(facts["database"].st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(facts["lock"].st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(facts["socket_directory"].st_mode), 0o710)
        self.assertEqual(stat.S_IMODE(facts["socket"].st_mode), 0o620)
        self.assertTrue(all(item.st_uid == self.service_uid for item in facts.values()))
        self.assertEqual(facts["socket_directory"].st_gid, self.client_gid)
        self.assertEqual(facts["socket"].st_gid, self.client_gid)
        self.assertEqual(facts["database"].st_nlink, 1)
        self.assertEqual(facts["lock"].st_nlink, 1)
        self.assertEqual(facts["socket"].st_nlink, 1)

    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_prestart_gc_has_no_lock_and_context_exit_releases_started_lock(self) -> None:
        runtime, address = self.provision_runtime("prestart-gc")
        artifact = provision_child_artifact(runtime.approved_root)
        abandoned = RigDaemon(
            address,
            runtime=runtime,
            identity_policy=self.identity_policy,
            child_artifact=artifact,
        )
        del abandoned
        gc.collect()
        with RigDaemon(
            address,
            runtime=runtime,
            identity_policy=self.identity_policy,
            child_artifact=artifact,
        ):
            with self.assertRaises(DaemonAuthorityError):
                competing = RigDaemon(
                    address,
                    runtime=runtime,
                    identity_policy=self.identity_policy,
                    child_artifact=artifact,
                )
                competing.start()
        restarted = RigDaemon(
            address,
            runtime=runtime,
            identity_policy=self.identity_policy,
            child_artifact=artifact,
        )
        restarted.start()
        restarted.close()

    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_foreground_started_daemon_gc_releases_all_resources(self) -> None:
        runtime, address = self.provision_runtime("started-gc")
        artifact = provision_child_artifact(runtime.approved_root)
        abandoned = RigDaemon(
            address,
            runtime=runtime,
            identity_policy=self.identity_policy,
            child_artifact=artifact,
        )
        abandoned.start()
        resources = abandoned._RigDaemonBase__resources
        for candidate in (abandoned, resources):
            with self.subTest(type=type(candidate).__name__, operation="copy"):
                with self.assertRaises(TypeError):
                    copy.copy(candidate)
            with self.subTest(type=type(candidate).__name__, operation="deepcopy"):
                with self.assertRaises(TypeError):
                    copy.deepcopy(candidate)
            with self.subTest(type=type(candidate).__name__, operation="pickle"):
                with self.assertRaises(TypeError):
                    pickle.dumps(candidate)
        del resources
        reference = weakref.ref(abandoned)
        del abandoned
        gc.collect()
        self.assertIsNone(reference())
        restarted = RigDaemon(
            address,
            runtime=runtime,
            identity_policy=self.identity_policy,
            child_artifact=artifact,
        )
        restarted.start()
        restarted.close()

    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_durable_launcher_graph_has_only_child_handle_and_kill_releases_state(self) -> None:
        runtime, address = self.provision_runtime("child-boundary")
        artifact = provision_child_artifact(runtime.approved_root)
        daemon = RigDaemon(
            address,
            runtime=runtime,
            identity_policy=self.identity_policy,
            child_artifact=artifact,
        )
        daemon.start()
        resources = daemon._RigDaemonBase__resources
        process = resources.current_process()
        self.assertIsNotNone(process)
        assert process is not None
        self.assertNotEqual(process.pid, os.getpid())
        self.assertEqual(daemon.child_pid, process.pid)
        self.assertIsNone(resources.controller)
        self.assertIsNone(resources.controller_close)
        self.assertIsNone(resources.listener)
        self.assertIsNone(resources.bootstrap)
        self.assertIsNone(daemon._RigDaemonBase__runtime)
        self.assertIsNone(daemon._RigDaemonBase__identity_policy)
        accepted_topology = daemon.topology_hash
        self.assertRegex(accepted_topology or "", r"[0-9a-f]{64}\Z")
        self.assert_no_launch_artifacts(artifact)
        forbidden = {_RigController, _DaemonAuthority}
        pending = [daemon]
        visited: set[int] = set()
        while pending:
            current = pending.pop()
            if id(current) in visited:
                continue
            visited.add(id(current))
            self.assertNotIn(type(current), forbidden)
            if isinstance(current, (type, weakref.ReferenceType)) or callable(current):
                continue
            pending.extend(gc.get_referents(current))
        os.kill(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        daemon.shutdown()
        self.assertEqual(daemon.topology_hash, accepted_topology)
        self.assert_no_launch_artifacts(artifact)
        restarted = RigDaemon(
            address,
            runtime=runtime,
            identity_policy=self.identity_policy,
            child_artifact=artifact,
        )
        restarted.start()
        restarted.shutdown()

    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_repeated_ready_then_sigkill_leaves_bootstrap_root_bounded(self) -> None:
        runtime, address = self.provision_runtime("ready-crash")
        artifact = provision_child_artifact(runtime.approved_root)
        for _ in range(6):
            daemon = RigDaemon(
                address,
                runtime=runtime,
                identity_policy=self.identity_policy,
                child_artifact=artifact,
            )
            daemon.start()
            self.assert_no_launch_artifacts(artifact)
            resources = daemon._RigDaemonBase__resources
            process = resources.current_process()
            assert process is not None
            os.kill(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            daemon.shutdown()
            self.assert_no_launch_artifacts(artifact)

    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_verified_descriptors_survive_provisioned_path_swap(self) -> None:
        for seam in ("before-spawn", "at-posix-spawn"):
            with self.subTest(seam=seam):
                runtime, address = self.provision_runtime(f"descriptor-{seam}")
                marker = runtime.approved_root / "verified-helper"
                artifact = provision_child_artifact(
                    runtime.approved_root,
                    helper_prelude=(
                        "from pathlib import Path\n"
                        f"Path({str(marker)!r}).write_text('verified')"
                    ),
                )
                daemon = RigDaemon(
                    address,
                    runtime=runtime,
                    identity_policy=self.identity_policy,
                    child_artifact=artifact,
                )
                originals: list[tuple[Path, Path]] = []
                captured: list[daemon_server._VerifiedBootstrap] = []
                native_prepare = daemon_server._prepare_bootstrap
                native_spawn = daemon_server._spawn_verified_child
                native_posix_spawn = daemon_server.os.posix_spawn

                def capture_prepare(
                    *args: object,
                    **kwargs: object,
                ) -> daemon_server._VerifiedBootstrap:
                    bootstrap = native_prepare(*args, **kwargs)  # type: ignore[arg-type]
                    captured.append(bootstrap)
                    return bootstrap

                def swap_paths() -> None:
                    for pinned in (
                        artifact.bootstrap,
                        artifact.helper,
                        artifact.interpreter,
                    ):
                        original = pinned.path.with_name(
                            pinned.path.name + ".verified"
                        )
                        pinned.path.rename(original)
                        pinned.path.write_bytes(b"unverified replacement")
                        pinned.path.chmod(0o500)
                        originals.append((pinned.path, original))

                def swap_then_spawn(
                    bootstrap: daemon_server._VerifiedBootstrap,
                ) -> object:
                    swap_paths()
                    return native_spawn(bootstrap)

                def swap_at_posix_spawn(
                    *args: object,
                    **kwargs: object,
                ) -> int:
                    swap_paths()
                    return native_posix_spawn(*args, **kwargs)  # type: ignore[arg-type]

                try:
                    if seam == "before-spawn":
                        with patch.object(
                            daemon_server,
                            "_prepare_bootstrap",
                            capture_prepare,
                        ), patch.object(
                            daemon_server,
                            "_spawn_verified_child",
                            swap_then_spawn,
                        ):
                            daemon.start()
                    else:
                        with patch.object(
                            daemon_server,
                            "_prepare_bootstrap",
                            capture_prepare,
                        ), patch.object(
                            daemon_server.os,
                            "posix_spawn",
                            swap_at_posix_spawn,
                        ):
                            daemon.start()
                    self.assertEqual(
                        marker.read_text(encoding="utf-8"),
                        "verified",
                    )
                    self.assertIsNotNone(daemon.child_pid)
                    self.assertEqual(len(captured), 1)
                    self.assertEqual(captured[0].helper_fd, -1)
                    self.assertEqual(captured[0].interpreter_fd, -1)
                finally:
                    daemon.shutdown()
                    for replacement_path, original in originals:
                        replacement_path.unlink(missing_ok=True)
                        original.rename(replacement_path)
                self.assert_no_launch_artifacts(artifact)

    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_descriptor_substitution_is_rejected_without_launch_artifacts(self) -> None:
        runtime, _ = self.provision_runtime("fd-substitution")
        artifact = provision_child_artifact(runtime.approved_root)
        bootstrap = daemon_server._prepare_bootstrap(
            artifact,
            approved_root=runtime.approved_root,
            service_uid=self.service_uid,
        )
        substitution = os.open(self.root / "substitution", os.O_CREAT | os.O_RDWR, 0o600)
        native_open = daemon_server.os.open

        def substitute(path: object, flags: int, *args: object, **kwargs: object) -> int:
            if isinstance(path, str) and path.startswith("/dev/fd/"):
                return os.dup(substitution)
            return native_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

        try:
            with patch.object(daemon_server.os, "open", substitute), self.assertRaisesRegex(
                DaemonAuthorityError,
                "identity mismatch",
            ):
                daemon_server._spawn_verified_child(bootstrap)
        finally:
            bootstrap.close()
            os.close(substitution)
        self.assert_no_launch_artifacts(artifact)

    @unittest.skipUnless(sys.platform == "darwin", "macOS pathname launcher")
    def test_user_owned_macos_artifact_fails_closed_without_fd_leaks(self) -> None:
        runtime, address = self.provision_runtime("mac-user-owned")
        artifact = provision_child_artifact(runtime.approved_root)
        daemon = RigDaemon(
            address,
            runtime=runtime,
            identity_policy=self.identity_policy,
            child_artifact=artifact,
        )
        with self.assertRaisesRegex(
            DaemonAuthorityError,
            "root-owned and non-writable",
        ):
            daemon.start()
        self.assertIsNone(daemon.child_pid)
        self.assert_no_launch_artifacts(artifact)

    def test_modeled_root_owned_macos_artifact_denies_service_and_client_swap(self) -> None:
        runtime, _ = self.provision_runtime("mac-root-model")
        artifact, facts = self.modeled_root_artifact(runtime.approved_root)
        with patch.object(
            daemon_server,
            "_artifact_facts",
            side_effect=lambda path: facts[path],
        ):
            proof = daemon_server._validate_root_owned_artifact(artifact)
        self.assertTrue(proof)
        for uid in (self.service_uid, self.client_uid):
            for pinned in (
                artifact.bootstrap,
                artifact.helper,
                artifact.interpreter,
            ):
                self.assertFalse(
                    daemon_server._proof_allows_nonroot_replacement(
                        proof,
                        pinned.path,
                        uid=uid,
                        groups=frozenset({self.client_gid}),
                    )
                )

    def test_native_bootstrap_pin_is_required_and_binds_topology_hash(self) -> None:
        runtime, _ = self.provision_runtime("native-pin")
        artifact = provision_child_artifact(runtime.approved_root)
        malformed = replace(artifact, bootstrap=None)  # type: ignore[arg-type]
        with self.assertRaisesRegex(
            DaemonAuthorityError,
            "pinned native bootstrap",
        ):
            daemon_server._prepare_bootstrap(
                malformed,
                approved_root=runtime.approved_root,
                service_uid=self.service_uid,
            )
        changed = replace(
            artifact,
            bootstrap=replace(artifact.bootstrap, digest="0" * 64),
        )
        self.assertNotEqual(
            daemon_server._bootstrap_manifest_hash(artifact),
            daemon_server._bootstrap_manifest_hash(changed),
        )

    def test_macos_artifact_model_rejects_writable_group_acl_and_owner(self) -> None:
        runtime, _ = self.provision_runtime("mac-root-denial")
        artifact, base_facts = self.modeled_root_artifact(runtime.approved_root)
        ancestor = artifact.artifact_root
        cases = {
            "group-writable": replace(
                base_facts[ancestor],
                mode=stat.S_IFDIR | 0o775,
            ),
            "extended-acl": replace(
                base_facts[ancestor],
                has_extended_acl=True,
            ),
            "service-owned": replace(
                base_facts[ancestor],
                uid=self.service_uid,
            ),
        }
        for label, replacement_facts in cases.items():
            with self.subTest(label=label):
                facts = dict(base_facts)
                facts[ancestor] = replacement_facts
                with patch.object(
                    daemon_server,
                    "_artifact_facts",
                    side_effect=lambda path, current=facts: current[path],
                ), self.assertRaisesRegex(
                    DaemonAuthorityError,
                    "root-owned and non-writable",
                ):
                    daemon_server._validate_root_owned_artifact(artifact)
        file_cases = {
            "bootstrap-mode": replace(
                base_facts[artifact.bootstrap.path],
                mode=stat.S_IFREG | 0o500,
            ),
            "bootstrap-acl": replace(
                base_facts[artifact.bootstrap.path],
                has_extended_acl=True,
            ),
            "homebrew-user-owned-interpreter": replace(
                base_facts[artifact.interpreter.path],
                uid=self.service_uid,
            ),
            "group-writable-helper": replace(
                base_facts[artifact.helper.path],
                mode=stat.S_IFREG | 0o575,
            ),
            "helper-acl": replace(
                base_facts[artifact.helper.path],
                has_extended_acl=True,
            ),
        }
        for label, replacement_facts in file_cases.items():
            with self.subTest(label=label):
                facts = dict(base_facts)
                target = (
                    artifact.interpreter.path
                    if "interpreter" in label
                    else (
                        artifact.bootstrap.path
                        if "bootstrap" in label
                        else artifact.helper.path
                    )
                )
                facts[target] = replacement_facts
                with patch.object(
                    daemon_server,
                    "_artifact_facts",
                    side_effect=lambda path, current=facts: current[path],
                ), self.assertRaisesRegex(
                    DaemonAuthorityError,
                    "root-owned mode 0555 and single-link",
                ):
                    daemon_server._validate_root_owned_artifact(artifact)

        bad_digest = replace(
            artifact.bootstrap,
            digest="0" * 64,
            owner_uid=self.service_uid,
            mode=0o500,
        )
        with self.assertRaisesRegex(DaemonAuthorityError, "provenance"):
            daemon_server._open_pinned_executable(
                bad_digest,
                artifact_root=artifact.artifact_root,
                expected_uid=self.service_uid,
                expected_mode=0o500,
            )

    def test_platform_selection_is_sealed_from_runtime_mutation(self) -> None:
        runtime, _ = self.provision_runtime("platform-selection")
        captured = sys.platform
        self.assertIn(captured, {"darwin", "linux"})
        self.assertFalse(hasattr(daemon_server, "_native_platform"))
        self.assertEqual(modeled_bootstrap_strategy("darwin"), "macos-path")
        self.assertEqual(modeled_bootstrap_strategy("linux"), "descriptor")
        for unsupported in ("freebsd", "win32", "linux2", "Darwin"):
            with self.subTest(unsupported=unsupported), self.assertRaisesRegex(
                ValueError,
                "unsupported rigd bootstrap platform",
            ):
                modeled_bootstrap_strategy(unsupported)

        called: list[bool] = []

        def mutable_hook() -> str:
            called.append(True)
            return "linux" if captured == "darwin" else "darwin"

        if captured == "linux":
            artifact = provision_child_artifact(runtime.approved_root)
            with patch.object(
                daemon_server.sys,
                "platform",
                "darwin",
            ), patch.object(
                daemon_server,
                "_native_platform",
                mutable_hook,
                create=True,
            ):
                prepared = daemon_server._prepare_bootstrap(
                    artifact,
                    approved_root=runtime.approved_root,
                    service_uid=self.service_uid,
                )
        else:
            artifact, facts = self.modeled_root_artifact(runtime.approved_root)

            def modeled_open(
                pinned: object,
                **_kwargs: object,
            ) -> tuple[int, os.stat_result]:
                path = getattr(pinned, "path")
                descriptor_fd = os.open(path, os.O_RDONLY)
                return descriptor_fd, os.fstat(descriptor_fd)

            with patch.object(
                daemon_server.sys,
                "platform",
                "linux",
            ), patch.object(
                daemon_server,
                "_native_platform",
                mutable_hook,
                create=True,
            ), patch.object(
                daemon_server,
                "_artifact_facts",
                side_effect=lambda path: facts[path],
            ), patch.object(
                daemon_server,
                "_open_pinned_executable",
                side_effect=modeled_open,
            ), patch.object(
                daemon_server,
                "_revalidate_macos_bootstrap",
            ):
                prepared = daemon_server._prepare_bootstrap(
                    artifact,
                    approved_root=runtime.approved_root,
                    service_uid=self.service_uid,
                )
        try:
            self.assertEqual(
                prepared.launcher,
                modeled_bootstrap_strategy(captured),
            )
            self.assertEqual(called, [])
            with self.assertRaises((AttributeError, TypeError)):
                setattr(artifact, "platform", "linux")
        finally:
            prepared.close()

    def test_production_platform_allowlist_rejects_unsupported_import(self) -> None:
        source = Path(__file__).resolve().parents[1] / "src"
        code = (
            "import pathlib, sys\n"
            "sys.platform = 'freebsd'\n"
            f"sys.path.insert(0, {str(source)!r})\n"
            "from oc_rig.daemon import server\n"
            "try:\n"
            "    server._prepare_bootstrap(None, approved_root=pathlib.Path('/'), service_uid=1)\n"
            "except Exception as error:\n"
            "    assert type(error).__name__ == 'DaemonAuthorityError'\n"
            "    assert str(error) == 'unsupported rigd bootstrap platform'\n"
            "else:\n"
            "    raise AssertionError('unsupported platform accepted')\n"
        )
        subprocess.run(
            [sys.executable, "-I", "-B", "-c", code],
            check=True,
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            capture_output=True,
            text=True,
        )

    def test_python_child_closes_and_asserts_no_unexpected_descriptor(self) -> None:
        source = Path(__file__).resolve().parents[1] / "src"
        code = (
            "import os, sys\n"
            f"sys.path.insert(0, {str(source)!r})\n"
            "fd = os.open('/dev/null', os.O_RDONLY)\n"
            "assert fd >= 3\n"
            "import oc_rig.daemon.child\n"
            "try:\n"
            "    os.fstat(fd)\n"
            "except OSError:\n"
            "    print('sealed', flush=True)\n"
            "else:\n"
            "    raise AssertionError('unexpected fd remained open')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            check=True,
            capture_output=True,
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            text=True,
        )
        self.assertEqual(result.stdout, "sealed\n")

    @unittest.skipUnless(sys.platform == "darwin", "macOS pathname launcher")
    def test_macos_path_spawn_has_isolated_environment_and_no_ambient_fd(self) -> None:
        runtime, _ = self.provision_runtime("mac-env")
        artifact = provision_child_artifact(runtime.approved_root)
        inherited = os.open(self.root / "mac-inherited", os.O_CREAT | os.O_RDWR, 0o600)
        os.set_inheritable(inherited, True)
        helper = artifact.helper.path
        helper.chmod(0o700)
        helper.write_text(
            "import fcntl, os\n"
            "assert os.environ['LANG'] == os.environ['LC_ALL'] == 'C.UTF-8'\n"
            "assert os.environ['PYTHONNOUSERSITE'] == '1'\n"
            "assert not {'HOME', 'PATH', 'PYTHONHOME', 'PYTHONPATH'} & set(os.environ)\n"
            f"\ntry: os.fstat({inherited})\n"
            "except OSError: pass\n"
            "else: raise AssertionError('ambient fd inherited')\n"
            "for name in os.listdir('/dev/fd'):\n"
            "    try: fd = int(name)\n"
            "    except ValueError: continue\n"
            "    if fd < 3: continue\n"
            "    try: fcntl.fcntl(fd, fcntl.F_GETFD)\n"
            "    except OSError: continue\n"
            "    raise AssertionError(f'unexpected fd {fd}')\n"
            "print('isolated-path-spawn', flush=True)\n",
            encoding="utf-8",
        )
        helper.chmod(0o500)
        details = helper.lstat()
        artifact = replace(
            artifact,
            helper=replace(
                artifact.helper,
                digest=hashlib.sha256(helper.read_bytes()).hexdigest(),
                device=details.st_dev,
                inode=details.st_ino,
                size=details.st_size,
            ),
        )
        bootstrap = daemon_server._VerifiedBootstrap(
            os.open(artifact.bootstrap.path, os.O_RDONLY),
            os.open(helper, os.O_RDONLY),
            os.open(artifact.interpreter.path, os.O_RDONLY),
            artifact,
            "macos-path",
        )
        process = None
        raced: list[int] = []
        native_spawn = daemon_server.os.posix_spawn

        def open_during_spawn(*args: object, **kwargs: object) -> int:
            descriptor = os.open(
                self.root / "inside-posix-spawn",
                os.O_CREAT | os.O_RDWR,
                0o600,
            )
            os.set_inheritable(descriptor, True)
            raced.append(descriptor)
            return native_spawn(*args, **kwargs)  # type: ignore[arg-type]

        try:
            with patch.dict(
                os.environ,
                {
                    "HOME": str(self.root),
                    "PATH": str(self.root),
                    "PYTHONHOME": str(self.root),
                    "PYTHONPATH": str(self.root),
                },
            ), patch.object(
                daemon_server,
                "_revalidate_macos_bootstrap",
            ), patch.object(
                daemon_server.os,
                "posix_spawn",
                side_effect=open_during_spawn,
            ):
                process = daemon_server._spawn_verified_child(bootstrap)
            assert process.stdout is not None
            self.assertEqual(process.stdout.readline(), b"isolated-path-spawn\n")
            self.assertEqual(process.wait(timeout=5), 0)
        finally:
            if process is not None:
                if process.stdin is not None:
                    process.stdin.close()
                if process.stdout is not None:
                    process.stdout.close()
            bootstrap.close()
            os.close(inherited)
            for descriptor in raced:
                os.close(descriptor)

    @unittest.skipUnless(
        sys.platform == "darwin" or descriptor_execution_supported(),
        "native bootstrap is not executable on this kernel",
    )
    def test_native_gate_closes_sparse_fds_above_lowered_soft_limit(self) -> None:
        runtime, _ = self.provision_runtime("native-sparse-fds")
        targets = (300, 512, 700)
        prelude = (
            f"targets = {targets!r}\n"
            "for descriptor in targets:\n"
            "    try: os.fstat(descriptor)\n"
            "    except OSError: pass\n"
            "    else: raise AssertionError(f'inherited fd {descriptor}')\n"
            "remaining = []\n"
            "for name in os.listdir('/dev/fd'):\n"
            "    try: descriptor = int(name)\n"
            "    except ValueError: continue\n"
            "    if descriptor <= 5: continue\n"
            "    try: os.fstat(descriptor)\n"
            "    except OSError: continue\n"
            "    remaining.append(descriptor)\n"
            "assert remaining == [], remaining\n"
            "print('sparse-fds-sealed', flush=True)\n"
            "raise SystemExit(0)"
        )
        artifact = provision_child_artifact(
            runtime.approved_root,
            helper_prelude=prelude,
        )
        bootstrap = daemon_server._VerifiedBootstrap(
            os.open(artifact.bootstrap.path, os.O_RDONLY),
            os.open(artifact.helper.path, os.O_RDONLY),
            os.open(artifact.interpreter.path, os.O_RDONLY),
            artifact,
            modeled_bootstrap_strategy(sys.platform),
        )
        original_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        duplicated: list[int] = []
        base = os.open(os.devnull, os.O_RDONLY)
        process = None
        try:
            raised_soft = max(original_limit[0], max(targets) + 32)
            resource.setrlimit(
                resource.RLIMIT_NOFILE,
                (raised_soft, original_limit[1]),
            )
            for target in targets:
                descriptor = daemon_server.fcntl.fcntl(
                    base,
                    daemon_server.fcntl.F_DUPFD,
                    target,
                )
                self.assertEqual(descriptor, target)
                os.set_inheritable(descriptor, True)
                duplicated.append(descriptor)
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, original_limit[1]))
            with patch.object(daemon_server, "_revalidate_macos_bootstrap"):
                process = daemon_server._spawn_verified_child(bootstrap)
            resource.setrlimit(resource.RLIMIT_NOFILE, original_limit)
            assert process.stdout is not None
            self.assertEqual(process.stdout.readline(), b"sparse-fds-sealed\n")
            self.assertEqual(process.wait(timeout=5), 0)
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, original_limit)
            if process is not None:
                if process.stdin is not None:
                    process.stdin.close()
                if process.stdout is not None:
                    process.stdout.close()
            bootstrap.close()
            os.close(base)
            for descriptor in duplicated:
                os.close(descriptor)

    @unittest.skipUnless(
        sys.platform == "darwin" or descriptor_execution_supported(),
        "native bootstrap is not executable on this kernel",
    )
    def test_native_gate_fails_closed_without_descriptor_directory(self) -> None:
        runtime, _ = self.provision_runtime("native-missing-fd-directory")
        missing = str(runtime.approved_root / "missing-fd-directory")
        if sys.platform == "darwin":
            source = _NATIVE_BOOTSTRAP_SOURCE.replace(
                'return opendir("/dev/fd");',
                f'return opendir("{missing}");',
            )
        else:
            source = _NATIVE_BOOTSTRAP_SOURCE.replace(
                'opendir("/proc/self/fd")',
                f'opendir("{missing}")',
            ).replace('opendir("/dev/fd")', f'opendir("{missing}")')
        artifact = provision_child_artifact(
            runtime.approved_root,
            helper_prelude="raise AssertionError('unsealed native gate ran Python')",
            native_bootstrap_source=source,
        )
        bootstrap = daemon_server._VerifiedBootstrap(
            os.open(artifact.bootstrap.path, os.O_RDONLY),
            os.open(artifact.helper.path, os.O_RDONLY),
            os.open(artifact.interpreter.path, os.O_RDONLY),
            artifact,
            modeled_bootstrap_strategy(sys.platform),
        )
        process = None
        try:
            with patch.object(daemon_server, "_revalidate_macos_bootstrap"):
                process = daemon_server._spawn_verified_child(bootstrap)
            assert process.stdout is not None
            self.assertEqual(process.stdout.read(), b"")
            self.assertEqual(process.wait(timeout=5), 120)
        finally:
            if process is not None:
                if process.stdin is not None:
                    process.stdin.close()
                if process.stdout is not None:
                    process.stdout.close()
            bootstrap.close()

    @unittest.skipUnless(sys.platform == "darwin", "macOS pathname launcher")
    def test_macos_post_spawn_identity_mismatch_kills_child(self) -> None:
        runtime, _ = self.provision_runtime("mac-post-spawn")
        artifact = provision_child_artifact(runtime.approved_root)
        helper = artifact.helper.path
        helper.chmod(0o700)
        helper.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
        helper.chmod(0o500)
        bootstrap = daemon_server._VerifiedBootstrap(
            os.open(artifact.bootstrap.path, os.O_RDONLY),
            os.open(helper, os.O_RDONLY),
            os.open(artifact.interpreter.path, os.O_RDONLY),
            artifact,
            "macos-path",
        )
        pids: list[int] = []
        native_spawn = daemon_server.os.posix_spawn

        def capture_spawn(*args: object, **kwargs: object) -> int:
            pid = native_spawn(*args, **kwargs)  # type: ignore[arg-type]
            pids.append(pid)
            return pid

        try:
            with patch.object(
                daemon_server,
                "_revalidate_macos_bootstrap",
                side_effect=(None, DaemonAuthorityError("post-spawn mismatch")),
            ), patch.object(
                daemon_server.os,
                "posix_spawn",
                side_effect=capture_spawn,
            ), self.assertRaisesRegex(
                DaemonAuthorityError,
                "post-spawn mismatch",
            ):
                daemon_server._spawn_verified_child(bootstrap)
            self.assertEqual(len(pids), 1)
            with self.assertRaises(ProcessLookupError):
                os.kill(pids[0], 0)
        finally:
            bootstrap.close()

    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_production_bootstrap_is_pinned_isolated_and_closes_inherited_fds(self) -> None:
        runtime, address = self.provision_runtime("boot-iso")
        inherited = os.open(self.root / "inherited-fd", os.O_CREAT | os.O_RDWR, 0o600)
        os.set_inheritable(inherited, True)
        marker = runtime.approved_root / "ambient-imported"
        malicious = runtime.approved_root / "malicious"
        malicious.mkdir(mode=0o700)
        malicious.joinpath("sitecustomize.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
            encoding="utf-8",
        )
        prelude = (
            "import os\n"
            "assert sys.flags.isolated == 1 and sys.dont_write_bytecode\n"
            "assert 'PATH' not in os.environ\n"
            "assert 'HOME' not in os.environ\n"
            "assert 'PYTHONPATH' not in os.environ\n"
            "assert 'PYTHONHOME' not in os.environ\n"
            f"assert os.getcwd().startswith({str(runtime.approved_root)!r})\n"
            "try:\n"
            f"    os.fstat({inherited})\n"
            "except OSError:\n"
            "    pass\n"
            "else:\n"
            "    raise AssertionError('inherited fd')"
        )
        artifact = provision_child_artifact(
            runtime.approved_root,
            helper_prelude=prelude,
        )
        daemon = RigDaemon(
            address,
            runtime=runtime,
            identity_policy=self.identity_policy,
            child_artifact=artifact,
        )
        try:
            with patch.dict(
                os.environ,
                {
                    "PATH": str(malicious),
                    "PYTHONHOME": str(malicious),
                    "PYTHONPATH": str(malicious),
                },
            ):
                daemon.start()
            self.assertFalse(marker.exists())
        finally:
            daemon.shutdown()
            os.close(inherited)
        self.assert_no_launch_artifacts(artifact)

    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_production_bootstrap_fails_closed_on_missing_or_replaced_artifact(self) -> None:
        missing_runtime, missing_address = self.provision_runtime("boot-miss")
        missing = RigDaemon(
            missing_address,
            runtime=missing_runtime,
            identity_policy=self.identity_policy,
        )
        with self.assertRaisesRegex(DaemonAuthorityError, "artifact is required"):
            missing.start()
        for label, field in (
            ("bootstrap", "bootstrap"),
            ("helper", "helper"),
            ("interpreter", "interpreter"),
        ):
            with self.subTest(field=field):
                runtime, address = self.provision_runtime(f"swap-{label[:3]}")
                artifact = provision_child_artifact(runtime.approved_root)
                pinned = getattr(artifact, field)
                original = pinned.path.with_suffix(pinned.path.suffix + ".original")
                pinned.path.rename(original)
                pinned.path.write_bytes(original.read_bytes() + b"\n")
                pinned.path.chmod(0o500)
                daemon = RigDaemon(
                    address,
                    runtime=runtime,
                    identity_policy=self.identity_policy,
                    child_artifact=artifact,
                )
                with self.assertRaisesRegex(DaemonAuthorityError, "provenance"):
                    daemon.start()
                self.assertIsNone(daemon.child_pid)
                self.assert_no_launch_artifacts(artifact)
                pinned.path.unlink()
                original.rename(pinned.path)
                daemon.start()
                daemon.shutdown()
                self.assert_no_launch_artifacts(artifact)

    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_fake_readiness_without_socket_is_rejected_and_cleaned(self) -> None:
        runtime, address = self.provision_runtime("fake-ready")
        artifact = provision_child_artifact(runtime.approved_root)
        helper = artifact.helper.path
        helper.chmod(0o700)
        helper.write_text(
            "import json, os, sys\n"
            "value = json.loads(sys.stdin.buffer.readline())\n"
            "status = {\n"
            " 'child_pid': os.getpid(),\n"
            " 'configuration_hash': value['configuration_hash'],\n"
            " 'readiness_nonce': value['readiness_nonce'],\n"
            " 'socket_device': 1, 'socket_inode': 1,\n"
            " 'status': 'ready', 'version': 1}\n"
            "print(json.dumps(status, separators=(',', ':')), flush=True)\n"
            "sys.stdin.buffer.read()\n",
            encoding="utf-8",
        )
        helper.chmod(0o500)
        details = helper.lstat()
        artifact = replace(
            artifact,
            helper=replace(
                artifact.helper,
                digest=hashlib.sha256(helper.read_bytes()).hexdigest(),
                device=details.st_dev,
                inode=details.st_ino,
                mode=stat.S_IMODE(details.st_mode),
                size=details.st_size,
            ),
        )
        daemon = RigDaemon(
            address,
            runtime=runtime,
            identity_policy=self.identity_policy,
            child_artifact=artifact,
        )
        with self.assertRaisesRegex(SocketSecurityError, "socket is unavailable"):
            daemon.start()
        self.assertIsNone(daemon.child_pid)
        self.assert_no_launch_artifacts(artifact)

    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_readiness_rejects_socket_replacement_and_peer_mismatch(self) -> None:
        for seam in ("socket", "uid", "pid"):
            with self.subTest(seam=seam):
                runtime, address = self.provision_runtime(f"ready-{seam}")
                artifact = provision_child_artifact(runtime.approved_root)
                daemon = RigDaemon(
                    address,
                    runtime=runtime,
                    identity_policy=self.identity_policy,
                    child_artifact=artifact,
                )
                replacement: socket_module.socket | None = None
                native_read = daemon_server._read_child_status

                def replace_socket(*args: object, **kwargs: object) -> dict[str, object]:
                    nonlocal replacement
                    status = native_read(*args, **kwargs)  # type: ignore[arg-type]
                    address.socket_path.unlink()
                    replacement = socket_module.socket(
                        socket_module.AF_UNIX,
                        socket_module.SOCK_STREAM,
                    )
                    replacement.bind(str(address.socket_path))
                    os.chmod(address.socket_path, 0o620)
                    return status

                context = {
                    "socket": patch.object(
                        daemon_server,
                        "_read_child_status",
                        replace_socket,
                    ),
                    "uid": patch.object(
                        daemon_server,
                        "peer_uid",
                        return_value=self.service_uid + 1,
                    ),
                    "pid": patch.object(
                        daemon_server,
                        "peer_pid",
                        return_value=999_999,
                    ),
                }[seam]
                try:
                    with context, self.assertRaises(SocketSecurityError):
                        daemon.start()
                finally:
                    if replacement is not None:
                        replacement.close()
                    try:
                        address.socket_path.unlink()
                    except FileNotFoundError:
                        pass
                self.assertIsNone(daemon.child_pid)
                self.assert_no_launch_artifacts(artifact)

    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_startup_refuses_same_identity_and_unprovisioned_topology(self) -> None:
        runtime, address = self.provision_runtime("same-identity")
        class WrongEffectiveUidProbe(ModeledIdentityProbe):
            def effective_uid(probe_self) -> int:
                return self.service_uid + 1

        with self.assertRaises(ServiceIdentityError):
            validate_service_topology(
                runtime,
                address,
                self.identity_policy,
                WrongEffectiveUidProbe(
                    self.service_uid,
                    self.client_uid,
                    self.client_gid,
                ),
            )
        with self.assertRaises(ServiceIdentityError):
            validate_service_topology(
                runtime,
                address,
                ServiceIdentityPolicy(
                    self.service_uid,
                    frozenset({self.service_uid}),
                    self.client_gid,
                ),
                self.identity_probe,
            )
        class OutsideClientGroupProbe(ModeledIdentityProbe):
            def groups_for_uid(self, uid: int) -> frozenset[int]:
                if uid == self.client_uid:
                    return frozenset({self.client_gid + 1})
                raise KeyError(uid)

        outside_group = OutsideClientGroupProbe(
            self.service_uid,
            self.client_uid,
            self.client_gid,
        )
        with self.assertRaisesRegex(ServiceIdentityError, "client group"):
            validate_service_topology(
                runtime,
                address,
                self.identity_policy,
                outside_group,
            )

        missing_root = self.root / "unprovisioned"
        missing_root.mkdir(mode=0o710)
        missing_root.chmod(0o710)
        missing_socket = missing_root / "socket"
        missing_socket.mkdir(mode=0o710)
        missing_socket.chmod(0o710)
        unprovisioned = RigDaemon(
            PrivateSocketPath(missing_socket / "rig.sock", missing_root),
            runtime=PrivateRuntimeDirectory(missing_root / "state", missing_root),
            identity_policy=self.identity_policy,
            child_artifact=provision_child_artifact(missing_root),
        )
        with self.assertRaises(ServiceIdentityError):
            unprovisioned.start()

    def test_root_identities_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "service_uid"):
            ServiceIdentityPolicy(0, frozenset({self.client_uid}), self.client_gid)
        with self.assertRaisesRegex(ValueError, "client UIDs"):
            ServiceIdentityPolicy(
                self.service_uid,
                frozenset({0}),
                self.client_gid,
            )
        with self.assertRaisesRegex(ValueError, "client_gid"):
            ServiceIdentityPolicy(self.service_uid, frozenset({self.client_uid}), 0)

    @unittest.skipUnless(sys.platform == "darwin", "macOS ACL regression")
    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_startup_rejects_real_acl_grants_across_service_topology(self) -> None:
        for index, target_name in enumerate(
            ("root", "state", "database", "lock", "sidecar", "socket")
        ):
            with self.subTest(target=target_name):
                runtime, address = self.provision_runtime(f"acl-{index}")
                sidecar = runtime.root / f"{runtime.database_name}-wal"
                sidecar.touch(mode=0o600)
                sidecar.chmod(0o600)
                targets = {
                    "root": address.approved_root,
                    "state": runtime.root,
                    "database": runtime.database,
                    "lock": runtime.root / "rigd.lock",
                    "sidecar": sidecar,
                    "socket": address.socket_path.parent,
                }
                subprocess.run(
                    ["chmod", "+a", "everyone allow read", str(targets[target_name])],
                    check=True,
                )
                daemon = RigDaemon(
                    address,
                    runtime=runtime,
                    identity_policy=self.identity_policy,
                    child_artifact=provision_child_artifact(runtime.approved_root),
                )
                with self.assertRaises(ServiceIdentityError):
                    daemon.start()

    @unittest.skipUnless(sys.platform == "darwin", "macOS ACL regression")
    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_modeled_probe_globals_cannot_hide_unsafe_acl_from_production(self) -> None:
        runtime, address = self.provision_runtime("acl-hidden")
        subprocess.run(
            ["chmod", "+a", "everyone allow read", str(runtime.database)],
            check=True,
        )

        class AclHidingProbe(ModeledIdentityProbe):
            def inspect(self, path: Path) -> service_identity.FileFacts:
                return replace(super().inspect(path), has_extended_acl=False)

        hiding_probe = AclHidingProbe(
            self.service_uid,
            self.client_uid,
            self.client_gid,
        )
        native_probe_type = service_identity.OsIdentityProbe
        native_inspect = native_probe_type.inspect

        def hide_acl(
            _probe: object,
            path: Path,
        ) -> service_identity.FileFacts:
            return replace(
                native_inspect(hiding_probe.os_probe, path),
                has_extended_acl=False,
            )

        with patch.object(
            native_probe_type,
            "inspect",
            hide_acl,
        ), patch.object(
            service_identity,
            "_OS_IDENTITY_PROBE",
            hiding_probe,
        ), patch.object(
            service_identity,
            "OsIdentityProbe",
            return_value=hiding_probe,
        ), patch.object(
            service_identity,
            "validate_service_topology",
            return_value=None,
        ):
            daemon = RigDaemon(
                address,
                runtime=runtime,
                identity_policy=self.identity_policy,
                child_artifact=provision_child_artifact(runtime.approved_root),
            )
            for attribute in (
                "identity_probe",
                "_RigDaemon__identity_probe",
                "_RigDaemonBase__identity_probe",
            ):
                with self.subTest(attribute=attribute), self.assertRaises(AttributeError):
                    setattr(daemon, attribute, hiding_probe)
            with self.assertRaises(ServiceIdentityError):
                daemon.start()

    def test_acl_null_without_explicit_no_data_errno_fails_closed(self) -> None:
        class NativeFunction:
            def __init__(self, result: object):
                self.result = result

            def __call__(self, *_args: object) -> object:
                return self.result

        class NativeAclLibrary:
            acl_get_file = NativeFunction(None)
            acl_get_entry = NativeFunction(0)
            acl_free = NativeFunction(0)
            acl_equiv_mode = NativeFunction(0)

        with patch.object(service_identity.ctypes, "CDLL", return_value=NativeAclLibrary()):
            with self.assertRaisesRegex(ServiceIdentityError, "could not inspect ACLs"):
                service_identity._has_extended_acl(self.store.path)

    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_partial_start_failure_releases_lock_and_controller(self) -> None:
        runtime, address = self.provision_runtime("partial-start")
        failed = ModeledDurableDaemon(
            address,
            runtime=runtime,
            identity_policy=self.identity_policy,
            mode="bind_failure",
        )
        with self.assertRaisesRegex(RuntimeError, "bind preparation"):
            failed.start()
        restarted = RigDaemon(
            address,
            runtime=runtime,
            identity_policy=self.identity_policy,
            child_artifact=provision_child_artifact(runtime.approved_root),
        )
        restarted.start()
        restarted.shutdown()

    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_production_socket_rejects_service_uid_as_client(self) -> None:
        runtime, address = self.provision_runtime("service-peer")
        daemon = RigDaemon(
            address,
            runtime=runtime,
            identity_policy=self.identity_policy,
            child_artifact=provision_child_artifact(runtime.approved_root),
        )
        thread = daemon.start_background()
        try:
            with socket_module.socket(
                socket_module.AF_UNIX,
                socket_module.SOCK_STREAM,
            ) as connection:
                connection.connect(str(address.socket_path))
                response = Response.decode(receive_frame(connection))
            assert response.error is not None
            self.assertEqual(response.error["code"], "peer_uid_mismatch")
        finally:
            daemon.shutdown()
            thread.join(timeout=2)

    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_peer_resolver_is_immutable_after_daemon_construction(self) -> None:
        runtime, address = self.provision_runtime("peer-capture")
        daemon = RigDaemon(
            address,
            runtime=runtime,
            identity_policy=self.identity_policy,
            child_artifact=provision_child_artifact(runtime.approved_root),
        )
        with self.assertRaises(TypeError):
            RigDaemon(
                address,
                runtime=runtime,
                identity_policy=self.identity_policy,
                child_artifact=provision_child_artifact(runtime.approved_root),
                peer_uid_resolver=lambda _connection: self.client_uid,
            )
        for attribute in (
            "peer_uid_resolver",
            "_RigDaemon__peer_uid_resolver",
            "_RigDaemonBase__peer_uid_resolver",
        ):
            with self.subTest(attribute=attribute), self.assertRaises(AttributeError):
                setattr(daemon, attribute, lambda _connection: self.client_uid)
        with self.assertRaisesRegex(TypeError, "sealed"):
            type("ResolverBypassDaemon", (RigDaemon,), {})
        self.assertFalse(hasattr(service_identity, "native_peer_uid"))
        with self.assertRaises(ImportError):
            exec("from oc_rig.daemon.server import _TestRigDaemon", {})
        self.assertFalse(hasattr(daemon_server, "_production_request_handler_method"))
        self.assertFalse(hasattr(daemon, "_start_with_peer_resolver"))

        class ForgedDurableDaemon(_RigDaemonBase):
            __slots__ = ()
            _require_native_peer = False

            def start(self) -> None:
                self._start()

            def _create_request_handler(self) -> object:
                return lambda _connection: None

        with self.assertRaisesRegex(PermissionError, "exact RigDaemon"):
            ForgedDurableDaemon(
                address,
                runtime=runtime,
                identity_policy=self.identity_policy,
            )
        forged = ForgedDurableDaemon(address, controller=object())  # type: ignore[arg-type]
        object.__setattr__(forged, "_RigDaemonBase__durable", True)
        object.__setattr__(forged, "_RigDaemonBase__runtime", runtime)
        object.__setattr__(forged, "_RigDaemonBase__identity_policy", self.identity_policy)
        with self.assertRaisesRegex(PermissionError, "exact RigDaemon"):
            forged.start()
        thread = daemon.start_background()
        with patch(
            "oc_rig.daemon.server.peer_uid",
            return_value=self.client_uid,
        ), patch(
            "oc_rig.daemon.security.peer_uid",
            return_value=self.client_uid,
        ):
            try:
                request = Request(
                    request_id="captured-peer-request",
                    idempotency_id="captured-peer-write",
                    operation="scheduler.enqueue.v1",
                    params={"work_id": "forbidden-write", "lane": "control"},
                )
                with socket_module.socket(
                    socket_module.AF_UNIX,
                    socket_module.SOCK_STREAM,
                ) as connection:
                    connection.connect(str(address.socket_path))
                    send_frame(connection, request.encode())
                    response = Response.decode(receive_frame(connection))
                assert response.error is not None
                self.assertEqual(response.error["code"], "peer_uid_mismatch")
                with closing(sqlite3.connect(runtime.database)) as connection:
                    count = connection.execute(
                        "SELECT count(*) FROM scheduler_work"
                    ).fetchone()
                assert count is not None
                self.assertEqual(count[0], 0)
            finally:
                daemon.shutdown()
                thread.join(timeout=2)

    def test_forged_policy_decision_and_allowed_wire_field_are_rejected(self) -> None:
        relative = "forged.txt"
        self.repository.joinpath(relative).write_text("bounded input", encoding="utf-8")
        denied = decide_standalone_worker(
            AdmissionRequest(
                repository=self.repository,
                scope=[relative],
                content="delete the production database",
                dispatch_kind="automated",
                trust="secure",
                classification="PUBLIC",
                risk_categories=[],
            )
        )
        forged = replace(denied, allowed=True)
        with self.assertRaises(PermissionError):
            _AdmissionEvidence(object(), forged, object())  # type: ignore[arg-type]
        with self.assertRaises(PermissionError):
            _evaluate_admission(
                object(),  # type: ignore[arg-type]
                forged,  # type: ignore[arg-type]
            )
        self.enqueue("forged-wire")
        claim, scoped = self.prepare_claim("forged-wire")
        with self.assertRaises(RigClientError) as rejected:
            self.call(
                "scheduler.admit.v1",
                {
                    "work_id": "work-forged-wire",
                    "claim_id": claim["claim_id"],
                    "repository": str(self.repository),
                    "scope": [scoped],
                    "content": "delete the production database",
                    "dispatch_kind": "automated",
                    "trust": "secure",
                    "classification": "PUBLIC",
                    "risk_categories": [],
                    "allowed": True,
                },
                idempotency_id="forged-wire-admit",
            )
        self.assertEqual(rejected.exception.code, "invalid_params")

    @unittest.skipUnless(
        descriptor_execution_supported(),
        "kernel does not support descriptor execution",
    )
    def test_exclusive_os_lock_survives_crash_and_allows_restart(self) -> None:
        crash_root = self.root / "os-lock"
        crash_root.mkdir(mode=0o710)
        crash_root.chmod(0o710)
        code = """
import os
import sys, time
from pathlib import Path
from oc_rig.daemon.identity import ServiceIdentityPolicy
from oc_rig.daemon.security import PrivateSocketPath
from oc_rig.daemon.server import RigDaemon
from oc_rig.store import PrivateRuntimeDirectory, RigStore
from tests.fixtures.durable_daemon import provision_child_artifact
root = Path(sys.argv[1]).resolve()
runtime = PrivateRuntimeDirectory(root / 'state', root)
store = RigStore(runtime)
store.initialize()
(root / 'state' / 'rigd.lock').touch(mode=0o600)
(root / 'state' / 'rigd.lock').chmod(0o600)
(root / 'socket').mkdir(mode=0o710)
(root / 'socket').chmod(0o710)
client_uid = int(sys.argv[2])
client_gid = os.getegid()
daemon = RigDaemon(
    PrivateSocketPath(root / 'socket' / 'rig.sock', root),
    runtime=runtime,
    identity_policy=ServiceIdentityPolicy(
        os.geteuid(), frozenset({client_uid}), client_gid
    ),
    child_artifact=provision_child_artifact(root),
)
daemon.start_background()
print('ready', flush=True)
time.sleep(60)
"""
        environment = dict(os.environ)
        process = subprocess.Popen(
            [sys.executable, "-c", code, str(crash_root), str(self.client_uid)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        try:
            assert process.stdout is not None
            self.assertEqual(process.stdout.readline().strip(), "ready")
            self.assertFalse((crash_root / "test-rigd-launch").exists())
            store = RigStore(
                PrivateRuntimeDirectory(crash_root / "state", crash_root)
            )
            with self.assertRaises(DaemonAuthorityError):
                competing = RigDaemon(
                    PrivateSocketPath(crash_root / "socket" / "rig.sock", crash_root),
                    runtime=store.runtime,
                    identity_policy=ServiceIdentityPolicy(
                        os.geteuid(),
                        frozenset({self.client_uid}),
                        os.getegid(),
                    ),
                    child_artifact=provision_child_artifact(crash_root),
                )
                competing.start()
            process.kill()
            process.communicate(timeout=5)
            self.assertFalse((crash_root / "test-rigd-launch").exists())
            restarted = RigDaemon(
                PrivateSocketPath(crash_root / "socket" / "rig.sock", crash_root),
                runtime=store.runtime,
                identity_policy=ServiceIdentityPolicy(
                    os.geteuid(),
                    frozenset({self.client_uid}),
                    os.getegid(),
                ),
                child_artifact=provision_child_artifact(crash_root),
            )
            restarted.start()
            restarted.shutdown()
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_admission_is_engine_owned_immutable_and_contains_no_content(self) -> None:
        content = "safe isolated work marker never persisted"
        self.enqueue("admission")
        result = self.admit("admission", content=content)
        self.assertTrue(result["allowed"])
        decision = dict(self.rows("scheduler_admission_decisions")[0])
        self.assertEqual(decision["policy_version"], result["policy_version"])
        self.assertEqual(decision["policy_hash"], result["policy_hash"])
        self.assertEqual(decision["content_hash"], result["content_hash"])
        claim = self.claims["admission"]
        self.assertEqual(decision["scope_claim_id"], claim["claim_id"])
        self.assertEqual(decision["scope_owner_id"], "owner-admission")
        self.assertEqual(decision["scope_claim_attempt"], claim["attempt"])
        self.assertEqual(decision["scope_claim_fence"], claim["fence_token"])
        self.assertEqual(decision["agent_lifecycle"], "persistent")
        self.assertEqual(decision["allow_child_agents"], 0)
        for value in decision.values():
            self.assertNotIn(content, str(value))
        with closing(sqlite3.connect(self.store.path)) as connection:
            self.assertNotIn(content, "\n".join(connection.iterdump()))
        with self.assertRaisesRegex(sqlite3.IntegrityError, "decision is immutable"):
            with self.store._transaction() as connection:
                connection.execute(
                    "UPDATE scheduler_admission_decisions SET allowed = 0"
                )

    def test_fabricated_admission_fields_and_released_claim_cannot_reserve(self) -> None:
        self.enqueue("fabricated")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable decision"):
            with self.store._transaction() as connection:
                connection.execute(
                    """UPDATE scheduler_work SET scope_key = 'fabricated',
                              scope_owner_id = 'owner-fabricated',
                              policy_decision_id = 'decision-fabricated',
                              policy_allowed = 1,
                              admission_idempotency_key = 'admit-fabricated'
                       WHERE id = 'work-fabricated'"""
                )
        self.ready("released")
        claim = self.claims["released"]
        self.assertTrue(
            self.call(
                "scope.release.v1",
                {
                    "claim_id": claim["claim_id"],
                    "owner_id": claim["owner_id"],
                    "attempt": claim["attempt"],
                    "fence_token": claim["fence_token"],
                },
                idempotency_id="release-scope-released",
            )["released"]
        )
        self.assertIsNone(self.reserve("released"))

    def test_reserve_accepts_no_caller_identity_assertions(self) -> None:
        self.ready("strict")
        with self.assertRaises(RigClientError) as caught:
            self.call(
                "scheduler.reserve.v1",
                {"reservation_id": "fabricated", "fence_token": "fabricated"},
                idempotency_id="reserve-strict-invalid",
            )
        self.assertEqual(caught.exception.code, "invalid_params")
        reservation = self.reserve("strict")
        assert reservation is not None
        self.assertTrue(str(reservation["id"]).startswith("reservation-"))
        self.assertEqual(
            reservation["scope_claim_id"], self.claims["strict"]["claim_id"]
        )

    def test_target_bound_reserve_never_assigns_an_older_different_work(self) -> None:
        self.ready("target-first")
        self.ready("target-second")

        blocked = self.call(
            "scheduler.reserve.v1",
            {"work_id": "work-target-second"},
            idempotency_id="reserve-target-second-blocked",
        )["reservation"]
        self.assertIsNone(blocked)
        self.assertEqual(self.rows("scheduler_assignments"), [])

        first = self.call(
            "scheduler.reserve.v1",
            {"work_id": "work-target-first"},
            idempotency_id="reserve-target-first",
        )["reservation"]
        self.assertEqual(first["work_id"], "work-target-first")
        second = self.call(
            "scheduler.reserve.v1",
            {"work_id": "work-target-second"},
            idempotency_id="reserve-target-second",
        )["reservation"]
        self.assertEqual(second["work_id"], "work-target-second")

    def test_denied_policy_is_persisted_and_never_assigns(self) -> None:
        content = "delete the production database"
        self.enqueue("denied", "control")
        result = self.admit("denied", content=content)
        self.assertFalse(result["allowed"])
        self.assertIsNone(self.reserve("denied"))
        decision = dict(self.rows("scheduler_admission_decisions")[0])
        self.assertEqual(decision["allowed"], 0)
        self.assertIn("production_task", decision["reasons_json"])
        self.assertNotIn(content, decision["reasons_json"])

    def test_requeue_gets_new_order_and_later_lane_progresses(self) -> None:
        self.ready("old", "tensorhost")
        first = self.reserve("old-first")
        assert first is not None
        self.ready("later", "homelab")
        self.assertTrue(self.release("old-requeue", first, "requeued"))
        later = self.reserve("later")
        assert later is not None
        self.assertEqual(later["work_id"], "work-later")
        next_old = self.reserve("old-second")
        assert next_old is not None
        self.assertEqual(next_old["work_id"], "work-old")
        work = {row["id"]: row for row in self.rows("scheduler_work")}
        self.assertGreater(work["work-old"]["queue_order"], work["work-later"]["queue_order"])

    def test_pending_admission_does_not_block_admitted_later_lane_work(self) -> None:
        self.enqueue("unaudited-old", "personal")
        self.ready("admitted-later", "personal")
        reservation = self.reserve("hol-regression")
        assert reservation is not None
        self.assertEqual(reservation["work_id"], "work-admitted-later")

    def test_strict_dispatch_scope_claim_admit_reserve_release_end_to_end(self) -> None:
        self.ready("protocol-e2e", "homelab")
        reservation = self.reserve("protocol-e2e")
        assert reservation is not None
        self.assertTrue(self.release("protocol-e2e", reservation, "completed"))
        claim = self.claims["protocol-e2e"]
        released = self.call(
            "scope.release.v1",
            {
                "claim_id": claim["claim_id"],
                "owner_id": claim["owner_id"],
                "attempt": claim["attempt"],
                "fence_token": claim["fence_token"],
            },
            idempotency_id="protocol-e2e-scope-release",
        )
        self.assertTrue(released["released"])

    def test_initial_fifo_and_full_lane_bypass_remain_deterministic(self) -> None:
        self.ready("t1", "tensorhost")
        self.ready("h1", "homelab")
        self.ready("p1", "personal")
        initial = [self.reserve(f"fifo-{number}") for number in range(1, 4)]
        self.assertEqual(
            [reservation["work_id"] for reservation in initial if reservation],
            ["work-t1", "work-h1", "work-p1"],
        )
        for number, reservation in enumerate(initial, start=1):
            assert reservation is not None
            self.assertTrue(self.release(f"fifo-{number}", reservation, "completed"))

        for label in ("t2", "t3", "t4", "t5"):
            self.ready(label, "tensorhost")
        self.ready("h2", "homelab")
        tensorhost = [self.reserve(f"pool-{number}") for number in range(3)]
        self.assertEqual(
            [reservation["work_id"] for reservation in tensorhost if reservation],
            ["work-t2", "work-t3", "work-t4"],
        )
        bypass = self.reserve("pool-bypass")
        assert bypass is not None
        self.assertEqual(bypass["work_id"], "work-h2")

    def test_socket_cancellation_preserves_capacity_and_exact_ownership(self) -> None:
        self.ready("cancel", "control")
        cancelled = self.call(
            "scheduler.cancel.v1",
            {"work_id": "work-cancel"},
            idempotency_id="cancel-work",
        )
        self.assertTrue(cancelled["cancelled"])
        self.ready("after-cancel", "control")
        reservation = self.reserve("after-cancel")
        assert reservation is not None
        self.assertEqual(reservation["work_id"], "work-after-cancel")
        self.assertTrue(self.release("cancel-assigned", reservation, "cancelled"))

    def test_durable_success_and_failure_idempotency_survive_restart(self) -> None:
        first = self.call(
            "scheduler.enqueue.v1",
            {"work_id": "work-restart", "lane": "personal"},
            idempotency_id="restart-success",
        )
        with self.assertRaises(RigClientError) as denied:
            self.call(
                "scheduler.enqueue.v1",
                {"work_id": "work-invalid", "lane": "invalid"},
                idempotency_id="restart-failure",
            )
        self.assertEqual(denied.exception.code, "invalid_params")
        with self.assertRaises(RigClientError) as malformed_admission:
            self.call(
                "scheduler.admit.v1",
                {},
                idempotency_id="restart-malformed-admission",
            )
        self.assertEqual(malformed_admission.exception.code, "invalid_params")
        self.restart_daemon()
        self.assertEqual(
            self.call(
                "scheduler.enqueue.v1",
                {"work_id": "work-restart", "lane": "personal"},
                idempotency_id="restart-success",
            ),
            first,
        )
        with self.assertRaises(RigClientError) as replayed:
            self.call(
                "scheduler.enqueue.v1",
                {"work_id": "work-invalid", "lane": "invalid"},
                idempotency_id="restart-failure",
            )
        self.assertEqual(replayed.exception.code, "invalid_params")
        with self.assertRaises(RigClientError) as replayed_admission:
            self.call(
                "scheduler.admit.v1",
                {},
                idempotency_id="restart-malformed-admission",
            )
        self.assertEqual(replayed_admission.exception.code, "invalid_params")
        with self.assertRaises(RigClientError) as conflict:
            self.call(
                "scheduler.enqueue.v1",
                {"work_id": "work-other", "lane": "personal"},
                idempotency_id="restart-success",
            )
        self.assertEqual(conflict.exception.code, "idempotency_conflict")
        self.assertEqual(len(self.rows("scheduler_work")), 1)

    def test_crash_between_mutation_and_outcome_rolls_back_one_transaction(self) -> None:
        self.restart_daemon(mode="crash_after_enqueue")
        with self.assertRaises(RigClientError) as crashed:
            self.call(
                "scheduler.enqueue.v1",
                {"work_id": "work-atomic", "lane": "control"},
                idempotency_id="atomic-crash",
            )
        self.assertEqual(crashed.exception.code, "internal_error")
        self.assertEqual(self.rows("scheduler_work"), [])
        self.assertEqual(self.rows("daemon_request_outcomes"), [])
        self.restart_daemon()
        recovered = self.call(
            "scheduler.enqueue.v1",
            {"work_id": "work-atomic", "lane": "control"},
            idempotency_id="atomic-crash",
        )
        self.assertEqual(recovered["sequence"], 1)

    def test_durable_idempotency_capacity_is_bounded_across_restart(self) -> None:
        self.stop_daemon()
        self.max_idempotency_entries = 1
        self.start_daemon()
        retained = self.call("health.v1", idempotency_id="retained-capacity")
        with self.assertRaises(RigClientError) as full:
            self.call(
                "scheduler.enqueue.v1",
                {"work_id": "work-over-capacity", "lane": "personal"},
                idempotency_id="over-capacity",
            )
        self.assertEqual(full.exception.code, "idempotency_capacity")
        self.restart_daemon()
        self.assertEqual(
            self.call("health.v1", idempotency_id="retained-capacity"), retained
        )
        with self.assertRaises(RigClientError) as still_full:
            self.call(
                "scheduler.enqueue.v1",
                {"work_id": "work-over-capacity", "lane": "personal"},
                idempotency_id="over-capacity",
            )
        self.assertEqual(still_full.exception.code, "idempotency_capacity")

    def test_concurrent_reserve_commits_one_assignment_and_one_none(self) -> None:
        self.ready("concurrent", "hands-off")
        barrier = threading.Barrier(2)

        def reserve(number: int) -> dict[str, object] | None:
            barrier.wait()
            return self.call(
                "scheduler.reserve.v1",
                idempotency_id=f"concurrent-{number}",
            )["reservation"]  # type: ignore[return-value]

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(reserve, (1, 2)))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(len(self.rows("scheduler_assignments")), 1)

    def test_restart_preserves_fence_retry_and_exact_events(self) -> None:
        self.ready("crash")
        first = self.reserve("crash-first")
        assert first is not None
        self.restart_daemon()
        self.assertTrue(self.release("crash-requeue", first, "requeued"))
        second = self.reserve("crash-second")
        assert second is not None
        self.assertEqual(second["work_id"], first["work_id"])
        self.assertEqual(second["attempt"], int(first["attempt"]) + 1)
        self.assertNotEqual(second["fence_token"], first["fence_token"])
        self.assertFalse(self.release("stale", first, "completed"))
        event_types = [
            row["event_type"]
            for row in self.rows("events")
            if row["aggregate_type"] == "scheduler_assignment"
        ]
        self.assertEqual(
            event_types,
            [
                "scheduler.assignment.created",
                "scheduler.assignment.released",
                "scheduler.assignment.created",
            ],
        )


if __name__ == "__main__":
    unittest.main()
