"""Descriptor-pinned child entry point for the synthetic migration candidate."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import select
import signal
import socket
import stat
import sys
import threading
import weakref
from pathlib import Path
from typing import Any, Mapping

import oc_rig
from oc_rig.daemon import controller as controller_module
from oc_rig.daemon.identity import ServiceIdentityPolicy
from oc_rig.daemon.security import PrivateSocketPath
from oc_rig.daemon.server import _DurableChildDaemon
from oc_rig.migration.rehearsal import _check_root
from oc_rig.migration.release import verify_release_descriptors
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


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing synthetic candidate provenance: {name}")
    return value


wheel_descriptor = int(_required_environment("OC_RIG_SYNTHETIC_WHEEL_DESCRIPTOR"))
manifest_descriptor = int(
    _required_environment("OC_RIG_SYNTHETIC_MANIFEST_DESCRIPTOR")
)
artifact_filename = _required_environment("OC_RIG_SYNTHETIC_WHEEL_FILENAME")
wheel_copy_kind = _required_environment("OC_RIG_SYNTHETIC_WHEEL_COPY_KIND")
expected_wheel_sha256 = _required_environment("OC_RIG_SYNTHETIC_WHEEL_SHA256")
expected_manifest_sha256 = _required_environment("OC_RIG_SYNTHETIC_MANIFEST_SHA256")
client_uid = int(_required_environment("OC_RIG_SYNTHETIC_CLIENT_UID"))
root = _check_root(Path(_required_environment("OC_RIG_SYNTHETIC_ROOT")))
allowed_descriptors = {wheel_descriptor, manifest_descriptor}


def _seal_inherited_descriptors() -> None:
    if sys.platform not in {"darwin", "linux"}:
        raise RuntimeError("unsupported synthetic candidate platform")
    for name in os.listdir("/dev/fd"):
        try:
            descriptor = int(name)
        except ValueError:
            continue
        if descriptor < 3 or descriptor in allowed_descriptors:
            continue
        try:
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError:
            continue
        os.close(descriptor)
    for descriptor in allowed_descriptors:
        os.fstat(descriptor)


_seal_inherited_descriptors()
wheel_facts = os.fstat(wheel_descriptor)
if (
    wheel_copy_kind not in {"sealed-memfd", "unlinked-regular-file"}
    or not stat.S_ISREG(wheel_facts.st_mode)
    or stat.S_IMODE(wheel_facts.st_mode) != 0o400
    or wheel_facts.st_uid != os.geteuid()
    or wheel_facts.st_nlink != 0
    or fcntl.fcntl(wheel_descriptor, fcntl.F_GETFL) & os.O_ACCMODE
    != os.O_RDONLY
):
    raise RuntimeError("synthetic candidate wheel is not an anonymous read-only copy")
if wheel_copy_kind == "sealed-memfd":
    required_seals = (
        fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SEAL
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_WRITE
    )
    if fcntl.fcntl(wheel_descriptor, fcntl.F_GET_SEALS) & required_seals != required_seals:
        raise RuntimeError("synthetic candidate wheel memfd is not sealed")
verified = verify_release_descriptors(
    wheel_descriptor,
    manifest_descriptor,
    artifact_filename=artifact_filename,
)


def _sha256_descriptor(descriptor: int) -> str:
    details = os.fstat(descriptor)
    digest = hashlib.sha256()
    offset = 0
    while offset < details.st_size:
        chunk = os.pread(descriptor, min(65536, details.st_size - offset), offset)
        if not chunk:
            raise RuntimeError("candidate descriptor was truncated")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


manifest_sha256 = _sha256_descriptor(manifest_descriptor)
module_origin = str(Path(__file__))
package_origin = str(Path(oc_rig.__file__))
wheel_import_root = f"/dev/fd/{wheel_descriptor}"
if (
    verified.wheel_sha256 != expected_wheel_sha256
    or manifest_sha256 != expected_manifest_sha256
    or not module_origin.startswith(wheel_import_root + os.sep)
    or not package_origin.startswith(wheel_import_root + os.sep)
    or sys.flags.isolated != 1
    or sys.flags.no_site != 1
    or not sys.dont_write_bytecode
    or sys.path[0] != wheel_import_root
):
    raise RuntimeError("synthetic candidate is not isolated to pinned wheel bytes")


def _modeled_handler(daemon: _DurableChildDaemon):
    reference = weakref.ref(daemon)

    def handle(connection: socket.socket) -> None:
        current = reference()
        if current is None:
            connection.close()
            return
        current._serve_client(connection, lambda _connection: client_uid)

    return handle


_DurableChildDaemon._create_request_handler = _modeled_handler
_original_execute = controller_module._RigController._execute


def _execute(
    self: Any,
    capability: object,
    connection: Any,
    operation: str,
    params: Mapping[str, Any],
    *,
    idempotency_id: str,
    admission: Any,
    prepared_scope: Any,
) -> Mapping[str, Any]:
    result = _original_execute(
        self,
        capability,
        connection,
        operation,
        params,
        idempotency_id=idempotency_id,
        admission=admission,
        prepared_scope=prepared_scope,
    )
    if operation != "health.v1":
        return result
    wheel_facts = os.fstat(wheel_descriptor)
    health = dict(result)
    health["release_provenance"] = {
        "artifact_binding": "anonymous-descriptor-copy",
        "artifact_filename": artifact_filename,
        "bytecode_enabled": False,
        "descriptor_device": wheel_facts.st_dev,
        "descriptor_inode": wheel_facts.st_ino,
        "descriptor_size": wheel_facts.st_size,
        "descriptor_link_count": wheel_facts.st_nlink,
        "isolated": True,
        "manifest_sha256": manifest_sha256,
        "module_origin": module_origin,
        "package_origin": package_origin,
        "site_enabled": False,
        "wheel_copy_kind": wheel_copy_kind,
        "wheel_sha256": verified.wheel_sha256,
    }
    return health


controller_module._RigController._execute = _execute


def _configuration() -> dict[str, object]:
    encoded = sys.stdin.buffer.readline(_CONFIGURATION_LIMIT + 1)
    if (
        not encoded
        or len(encoded) > _CONFIGURATION_LIMIT
        or not encoded.endswith(b"\n")
    ):
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
        json.dumps(public, sort_keys=True, separators=(",", ":")).encode("utf-8")
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
    timeout = configuration["connection_timeout"]
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or timeout <= 0
    ):
        raise ValueError("child connection timeout is invalid")
    database_name = configuration["database_name"]
    if not isinstance(database_name, str):
        raise ValueError("child database name is invalid")
    return _DurableChildDaemon(
        PrivateSocketPath(
            _path(configuration["socket_path"]),
            _path(configuration["socket_approved_root"]),
        ),
        runtime=PrivateRuntimeDirectory(
            _path(configuration["runtime_root"]),
            _path(configuration["approved_root"]),
            database_name,
        ),
        identity_policy=ServiceIdentityPolicy(
            _positive_integer(configuration["service_uid"]),
            frozenset(_positive_integer(uid) for uid in allowed),
            _positive_integer(configuration["client_gid"]),
        ),
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
        if (
            not isinstance(bootstrap_fds, list)
            or set(bootstrap_fds) != allowed_descriptors
        ):
            raise ValueError("child pinned descriptors are invalid")
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
                    "message": str(error)[:1024],
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


raise SystemExit(main())
