"""Private exec entrypoint for the durable Rig daemon server."""

from __future__ import annotations

import fcntl
import os
import sys


def _seal_inherited_descriptors(platform: str = sys.platform) -> None:
    if platform not in {"darwin", "linux"}:
        raise RuntimeError("unsupported rigd child platform")
    try:
        names = os.listdir("/dev/fd")
    except OSError as error:
        raise RuntimeError("cannot inspect inherited child descriptors") from error
    for name in names:
        try:
            descriptor = int(name)
        except ValueError:
            continue
        if descriptor < 3:
            continue
        try:
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError:
            continue
        try:
            os.close(descriptor)
        except OSError:
            continue
    for name in os.listdir("/dev/fd"):
        try:
            descriptor = int(name)
        except ValueError:
            continue
        if descriptor < 3:
            continue
        try:
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError:
            continue
        raise RuntimeError("unexpected descriptors remained in the Python child")


_seal_inherited_descriptors()

import hashlib
import json
import select
import signal
import threading
from pathlib import Path

from oc_rig.daemon.identity import ServiceIdentityPolicy
from oc_rig.daemon.security import PrivateSocketPath
from oc_rig.daemon.server import _DurableChildDaemon
from oc_rig.store.runtime import PrivateRuntimeDirectory

_CONFIGURATION_LIMIT = 16 * 1024
_CONFIGURATION_FIELDS = {
    "allowed_client_uids",
    "approved_root",
    "artifact_root",
    "bootstrap_fds",
    "bootstrap_hash",
    "client_gid",
    "connection_timeout",
    "configuration_hash",
    "database_name",
    "max_frame_bytes",
    "max_idempotency_entries",
    "runtime_root",
    "readiness_nonce",
    "service_uid",
    "socket_approved_root",
    "socket_path",
    "version",
}


def _configuration() -> dict[str, object]:
    encoded = sys.stdin.buffer.readline(_CONFIGURATION_LIMIT + 1)
    if not encoded or len(encoded) > _CONFIGURATION_LIMIT or not encoded.endswith(b"\n"):
        raise ValueError("invalid child configuration frame")
    value = json.loads(encoded)
    if not isinstance(value, dict) or set(value) != _CONFIGURATION_FIELDS:
        raise ValueError("invalid child configuration fields")
    if value["version"] != 1:
        raise ValueError("unsupported child configuration version")
    configuration_hash = value["configuration_hash"]
    nonce = value["readiness_nonce"]
    if (
        not isinstance(configuration_hash, str)
        or len(configuration_hash) != 64
        or not isinstance(nonce, str)
        or len(nonce) != 64
    ):
        raise ValueError("child readiness binding is invalid")
    public = {
        key: item
        for key, item in value.items()
        if key not in {"configuration_hash", "readiness_nonce"}
    }
    calculated = hashlib.sha256(
        json.dumps(public, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if calculated != configuration_hash:
        raise ValueError("child configuration hash mismatch")
    return value


def _path(value: object) -> Path:
    if not isinstance(value, str):
        raise ValueError("child path must be a string")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("child path must be absolute")
    return path


def _positive_integer(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("child integer must be positive")
    return value


def _daemon(configuration: dict[str, object]) -> _DurableChildDaemon:
    allowed = configuration["allowed_client_uids"]
    if not isinstance(allowed, list) or not allowed:
        raise ValueError("child client allowlist is invalid")
    allowed_uids = frozenset(_positive_integer(uid) for uid in allowed)
    timeout = configuration["connection_timeout"]
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("child connection timeout is invalid")
    database_name = configuration["database_name"]
    if not isinstance(database_name, str):
        raise ValueError("child database name is invalid")
    runtime = PrivateRuntimeDirectory(
        _path(configuration["runtime_root"]),
        _path(configuration["approved_root"]),
        database_name,
    )
    policy = ServiceIdentityPolicy(
        _positive_integer(configuration["service_uid"]),
        allowed_uids,
        _positive_integer(configuration["client_gid"]),
    )
    address = PrivateSocketPath(
        _path(configuration["socket_path"]),
        _path(configuration["socket_approved_root"]),
    )
    return _DurableChildDaemon(
        address,
        runtime=runtime,
        identity_policy=policy,
        max_frame_bytes=_positive_integer(configuration["max_frame_bytes"]),
        max_idempotency_entries=_positive_integer(
            configuration["max_idempotency_entries"]
        ),
        connection_timeout=float(timeout),
    )


def main() -> int:
    daemon: _DurableChildDaemon | None = None
    thread: threading.Thread | None = None
    stopping = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stopping.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    ready = False
    try:
        configuration = _configuration()
        bootstrap_fds = configuration["bootstrap_fds"]
        if not isinstance(bootstrap_fds, list) or any(
            type(descriptor) is not int or descriptor < 3
            for descriptor in bootstrap_fds
        ):
            raise ValueError("child bootstrap descriptors are invalid")
        for descriptor in bootstrap_fds:
            os.close(descriptor)
        for descriptor in bootstrap_fds:
            try:
                os.fstat(descriptor)
            except OSError:
                continue
            raise ValueError("child retained a bootstrap descriptor")
        os.chdir(_path(configuration["artifact_root"]))
        daemon = _daemon(configuration)
        thread = daemon.start_background()
        socket_details = _path(configuration["socket_path"]).lstat()
        status = {
            "child_pid": os.getpid(),
            "configuration_hash": configuration["configuration_hash"],
            "readiness_nonce": configuration["readiness_nonce"],
            "socket_device": socket_details.st_dev,
            "socket_inode": socket_details.st_ino,
            "status": "ready",
            "version": 1,
        }
        sys.stdout.write(
            json.dumps(status, sort_keys=True, separators=(",", ":")) + "\n"
        )
        sys.stdout.flush()
        ready = True
        descriptor = sys.stdin.buffer.fileno()
        while not stopping.is_set():
            readable, _, _ = select.select([descriptor], [], [], 0.2)
            if readable and not os.read(descriptor, 1):
                break
        return 0
    except BaseException as error:
        if not ready:
            try:
                status = {
                    "error_type": type(error).__name__,
                    "message": (
                        f"{error}: {error.__cause__}"
                        if error.__cause__ is not None
                        else str(error)
                    )[:1024],
                    "status": "failed",
                    "version": 1,
                }
                sys.stdout.write(
                    json.dumps(status, sort_keys=True, separators=(",", ":")) + "\n"
                )
                sys.stdout.flush()
            except BaseException:
                pass
        return 1
    finally:
        if daemon is not None:
            daemon.shutdown()
        if thread is not None:
            thread.join(timeout=3.0)


if __name__ == "__main__":
    raise SystemExit(main())
