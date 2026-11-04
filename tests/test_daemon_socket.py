from __future__ import annotations

import concurrent.futures
import os
import socket
import stat
import struct
import tempfile
import threading
import unittest
import weakref
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from unittest.mock import Mock, patch

from oc_rig.daemon.security import (
    DaemonAlreadyRunning,
    DirectoryIdentity,
    PrivateSocketPath,
    SocketSecurityError,
    StaleSocketAmbiguity,
    peer_uid,
)
from oc_rig.daemon.server import RigDaemon, _RigDaemonBase
from oc_rig.daemon.controller import InMemoryController
from oc_rig.protocol.client import RigClient, RigClientError
from oc_rig.protocol.framing import receive_frame, send_frame
from oc_rig.protocol.messages import Request, Response
from oc_rig.store.snapshot import Snapshot


class RunningDaemon:
    def __init__(self, root: Path, **kwargs: object):
        self.path = root / "socket" / "rig.sock"
        self.address = PrivateSocketPath(self.path, root)
        kwargs.setdefault("controller", InMemoryController())
        resolver = kwargs.pop("peer_uid_resolver", None)
        self.daemon = (
            _InjectedPeerDaemon(
                self.address,
                resolver=resolver,
                **kwargs,
            )
            if resolver is not None
            else RigDaemon(self.address, **kwargs)
        )
        self.thread = self.daemon.start_background()

    def close(self) -> None:
        self.daemon.shutdown()
        self.thread.join(timeout=2)


class _InjectedPeerDaemon(_RigDaemonBase):
    """Non-durable socket fault-injection fixture; never owns a runtime store."""

    __slots__ = ("_resolver",)
    _require_native_peer = False

    def __init__(
        self,
        address: PrivateSocketPath,
        *,
        resolver: object,
        controller: object,
        **limits: object,
    ):
        if not callable(resolver):
            raise TypeError("resolver fixture must be callable")
        super().__init__(address, controller=controller, **limits)
        self._resolver: Callable[[socket.socket], int | None] = resolver

    def start(self) -> None:
        self._start()

    def _create_request_handler(self) -> Callable[[socket.socket], None]:
        daemon_reference = weakref.ref(self)
        resolver = self._resolver

        def request_handler(connection: socket.socket) -> None:
            daemon = daemon_reference()
            if daemon is None:
                connection.close()
                return
            daemon._serve_client(connection, resolver)

        return request_handler


def raw_exchange(path: Path, wire: bytes) -> Response:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(str(path))
        connection.sendall(wire)
        return Response.decode(receive_frame(connection))


class DaemonSocketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.running: RunningDaemon | None = None

    def tearDown(self) -> None:
        if self.running is not None:
            self.running.close()
        self.temporary.cleanup()

    def start(self, **kwargs: object) -> RigClient:
        self.running = RunningDaemon(self.root, **kwargs)
        return RigClient(
            self.running.path,
            approved_root=self.root,
            identity_profile="local-user",
        )

    def test_health_version_and_snapshot_have_no_live_dependencies(self) -> None:
        client = self.start()
        health = client.call("health")
        self.assertEqual(health["status"], "ok")
        self.assertFalse(health["external_dependencies"])
        self.assertEqual(client.call("version")["protocol_version"], 1)
        self.assertEqual(client.call("snapshot"), {"snapshot": {"memory": {}}})

    def test_read_only_store_snapshot_is_serialized_without_mutation(self) -> None:
        snapshot = Snapshot(
            MappingProxyType(
                {"events": (MappingProxyType({"sequence": 1, "kind": "created"}),)}
            )
        )
        client = self.start(controller=InMemoryController(lambda: snapshot))
        self.assertEqual(
            client.call("snapshot"),
            {"snapshot": {"tables": {"events": [{"sequence": 1, "kind": "created"}]}}},
        )

    def test_cockpit_watch_blocks_without_timeout_until_change_provider_wakes(self) -> None:
        entered = threading.Event()
        changed = threading.Event()

        def wait_snapshot(after_sequence: int) -> dict[str, object]:
            self.assertEqual(after_sequence, 27)
            entered.set()
            self.assertTrue(changed.wait(timeout=1))
            return {"snapshot_version": {"event_sequence": 28}}

        client = self.start(
            read_snapshot_provider=lambda: {},
            wait_snapshot_provider=wait_snapshot,
            connection_timeout=0.05,
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            waiting = executor.submit(
                client.call,
                "cockpit.watch.v1",
                {"after_event_sequence": 27},
            )
            self.assertTrue(entered.wait(timeout=1))
            self.assertFalse(waiting.done())
            changed.set()
            self.assertEqual(
                waiting.result(timeout=1),
                {"snapshot": {"snapshot_version": {"event_sequence": 28}}},
            )

    def test_cockpit_watch_rejects_invalid_sequence_without_waiting(self) -> None:
        wait_snapshot = Mock()
        client = self.start(
            read_snapshot_provider=lambda: {},
            wait_snapshot_provider=wait_snapshot,
        )
        for invalid in (-1, True, 2**63):
            with self.subTest(invalid=invalid), self.assertRaises(RigClientError) as caught:
                client.call("cockpit.watch.v1", {"after_event_sequence": invalid})
            self.assertEqual(caught.exception.code, "invalid_params")
        wait_snapshot.assert_not_called()

    def test_socket_directory_and_file_are_private(self) -> None:
        self.start()
        assert self.running is not None
        self.assertEqual(stat.S_IMODE(self.running.path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.running.path.lstat().st_mode), 0o600)
        self.assertEqual(self.running.path.lstat().st_uid, os.geteuid())

    def test_idempotent_retry_mutates_once_and_conflict_is_rejected(self) -> None:
        client = self.start()
        first = client.call(
            "memory.increment",
            {"key": "counter", "amount": 1},
            request_id="request-1",
            idempotency_id="same-retry",
        )
        second = client.call(
            "memory.increment",
            {"key": "counter", "amount": 1},
            request_id="request-2",
            idempotency_id="same-retry",
        )
        self.assertEqual(first, second)
        self.assertEqual(client.call("memory.get", {"key": "counter"})["value"], 1)
        with self.assertRaisesRegex(RigClientError, "different request") as caught:
            client.call(
                "memory.increment",
                {"key": "counter", "amount": 2},
                idempotency_id="same-retry",
            )
        self.assertEqual(caught.exception.code, "idempotency_conflict")

    def test_concurrent_clients_are_serialized_without_lost_updates(self) -> None:
        client = self.start()

        def increment(index: int) -> int:
            result = client.call(
                "memory.increment",
                {"key": "counter", "amount": 1},
                idempotency_id=f"increment-{index}",
            )
            return result["value"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            values = list(executor.map(increment, range(40)))
        self.assertEqual(sorted(values), list(range(1, 41)))
        self.assertEqual(client.call("memory.get", {"key": "counter"})["value"], 40)

    def test_concurrent_retry_is_executed_once(self) -> None:
        client = self.start()

        def retry(index: int) -> int:
            return client.call(
                "memory.increment",
                {"key": "counter", "amount": 1},
                request_id=f"request-{index}",
                idempotency_id="one-logical-call",
            )["value"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            values = list(executor.map(retry, range(20)))
        self.assertEqual(values, [1] * 20)

    def test_unknown_malformed_and_oversized_requests_are_rejected(self) -> None:
        client = self.start(max_frame_bytes=1024)
        with self.assertRaises(RigClientError) as caught:
            client.call("backend.start")
        self.assertEqual(caught.exception.code, "unknown_operation")
        assert self.running is not None
        malformed = raw_exchange(
            self.running.path,
            struct.pack("!I", len(b"not-json")) + b"not-json",
        )
        self.assertEqual(malformed.error["code"], "malformed_json")
        oversized = raw_exchange(self.running.path, struct.pack("!I", 1025))
        self.assertEqual(oversized.error["code"], "frame_too_large")

    def test_oversized_response_becomes_a_correlated_error(self) -> None:
        client = self.start(
            max_frame_bytes=1024,
            controller=InMemoryController(lambda: {"large": "x" * 2000}),
        )
        with self.assertRaises(RigClientError) as caught:
            client.call(
                "snapshot",
                request_id="large-response-request",
                idempotency_id="large-response-retry",
            )
        self.assertEqual(caught.exception.code, "response_too_large")

    def test_peer_uid_mismatch_is_rejected_before_dispatch(self) -> None:
        client = self.start(peer_uid_resolver=lambda _connection: os.geteuid() + 1)
        with self.assertRaises(RigClientError) as caught:
            client.call("health")
        self.assertEqual(caught.exception.code, "peer_uid_mismatch")

    def test_unavailable_peer_uid_rejects_before_decode_or_controller_execution(self) -> None:
        class RecordingController:
            def __init__(self) -> None:
                self.calls = 0

            def execute(self, _operation: str, _params: object) -> dict[str, object]:
                self.calls += 1
                return {"unexpected": True}

        controller = RecordingController()
        self.start(
            controller=controller,
            peer_uid_resolver=lambda _connection: None,
        )
        assert self.running is not None
        response = raw_exchange(
            self.running.path,
            struct.pack("!I", len(b"not-json")) + b"not-json",
        )
        self.assertEqual(response.error["code"], "peer_credentials_unavailable")
        self.assertEqual(controller.calls, 0)
        self.assertEqual(len(self.running.daemon._idempotency), 0)

    def test_daemon_refuses_start_when_platform_peer_auth_is_unavailable(self) -> None:
        path = self.root / "socket" / "rig.sock"
        daemon = RigDaemon(
            PrivateSocketPath(path, self.root), controller=InMemoryController()
        )
        with patch("oc_rig.daemon.server.peer_credentials_supported", return_value=False):
            with self.assertRaisesRegex(SocketSecurityError, "authentication is unavailable"):
                daemon.start()
        self.assertFalse(path.exists())

    def test_platform_peer_uid_is_authenticated_when_supported(self) -> None:
        left, right = socket.socketpair()
        try:
            uid = peer_uid(left)
        finally:
            left.close()
            right.close()
        if uid is not None:
            self.assertEqual(uid, os.geteuid())

    def test_idempotency_capacity_preserves_old_retry_guarantee(self) -> None:
        client = self.start(max_idempotency_entries=1)
        original = client.call(
            "memory.increment",
            {"key": "counter", "amount": 1},
            idempotency_id="retained",
        )
        with self.assertRaises(RigClientError) as caught:
            client.call("health", idempotency_id="new-request")
        self.assertEqual(caught.exception.code, "idempotency_capacity")
        retried = client.call(
            "memory.increment",
            {"key": "counter", "amount": 1},
            request_id="retry-request",
            idempotency_id="retained",
        )
        self.assertEqual(retried, original)

    def test_path_escape_and_symlink_are_rejected(self) -> None:
        outside = self.root.parent / "escape.sock"
        with self.assertRaises(SocketSecurityError):
            RigDaemon(
                PrivateSocketPath(outside, self.root), controller=InMemoryController()
            ).start()
        actual = self.root / "actual"
        actual.mkdir()
        link = self.root / "link"
        link.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(SocketSecurityError):
            RigDaemon(
                PrivateSocketPath(link / "rig.sock", self.root),
                controller=InMemoryController(),
            ).start()

    def test_approved_root_with_lexical_symlink_ancestor_is_rejected(self) -> None:
        real = self.root / "real"
        approved = real / "approved"
        approved.mkdir(parents=True, mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(real, target_is_directory=True)
        lexical_approved = alias / "approved"
        lexical_socket = lexical_approved / "socket" / "rig.sock"
        with self.assertRaisesRegex(SocketSecurityError, "traverses a symlink"):
            RigDaemon(
                PrivateSocketPath(lexical_socket, lexical_approved),
                controller=InMemoryController(),
            ).start()
        self.assertFalse(approved.joinpath("socket", "rig.sock").exists())

    def test_concurrent_socket_directory_replacement_is_detected_after_bind(self) -> None:
        path = self.root / "socket" / "rig.sock"
        address = PrivateSocketPath(path, self.root)
        daemon = RigDaemon(address, controller=InMemoryController())
        replacement_requested = threading.Event()
        replacement_complete = threading.Event()
        original_secure = PrivateSocketPath.secure_bound_socket
        old_directory = self.root / "socket-before-replacement"

        def replace_directory() -> None:
            replacement_requested.wait(timeout=2)
            path.parent.rename(old_directory)
            path.parent.mkdir(mode=0o700)
            replacement_complete.set()

        def secure_after_replacement(
            instance: PrivateSocketPath,
            expected_directory: DirectoryIdentity | None = None,
        ) -> os.stat_result:
            replacement_requested.set()
            if not replacement_complete.wait(timeout=2):
                raise AssertionError("replacement thread did not run")
            return original_secure(instance, expected_directory)

        replacer = threading.Thread(target=replace_directory)
        replacer.start()
        try:
            with patch.object(
                PrivateSocketPath,
                "secure_bound_socket",
                secure_after_replacement,
            ):
                with self.assertRaisesRegex(SocketSecurityError, "inode changed"):
                    daemon.start()
        finally:
            replacement_requested.set()
            replacer.join(timeout=2)
        self.assertIsNone(daemon._listener)
        self.assertFalse(path.exists())

    def test_active_duplicate_and_ambiguous_stale_path_are_rejected(self) -> None:
        self.start()
        assert self.running is not None
        duplicate = RigDaemon(
            self.running.address, controller=InMemoryController()
        )
        with self.assertRaises(DaemonAlreadyRunning):
            duplicate.start()
        self.running.close()
        self.running = None
        path = self.root / "other" / "rig.sock"
        path.parent.mkdir(mode=0o700)
        path.touch(mode=0o600)
        with self.assertRaises(StaleSocketAmbiguity):
            RigDaemon(
                PrivateSocketPath(path, self.root), controller=InMemoryController()
            ).start()

    def test_proved_stale_socket_is_replaced_and_restart_is_clean(self) -> None:
        path = self.root / "socket" / "rig.sock"
        path.parent.mkdir(mode=0o700)
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(str(path))
        stale.close()
        os.chmod(path, 0o600)
        client = self.start()
        self.assertEqual(client.call("health")["status"], "ok")
        assert self.running is not None
        self.running.close()
        self.running = RunningDaemon(self.root)
        restarted = RigClient(
            self.running.path,
            approved_root=self.root,
            identity_profile="local-user",
        )
        self.assertEqual(restarted.call("snapshot"), {"snapshot": {"memory": {}}})

    def test_partial_request_write_over_real_socket(self) -> None:
        self.start()
        assert self.running is not None
        request = Request("partial-request", "partial-retry", "health", {})
        payload = request.encode()
        wire = struct.pack("!I", len(payload)) + payload
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(self.running.path))
            for index in range(0, len(wire), 3):
                connection.sendall(wire[index : index + 3])
            response = Response.decode(receive_frame(connection))
        self.assertTrue(response.ok)
        self.assertEqual(response.request_id, "partial-request")


if __name__ == "__main__":
    unittest.main()
