"""Concurrent private Unix-socket daemon for the public protocol."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import select
import secrets
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import weakref
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from oc_rig.adapters import AdapterPort, DisabledAdapter
from oc_rig.adapters.opencode import LiveOpenCodeAdapter, LiveOpenCodeAdapterConfig
from oc_rig.adapters.opencode_store import _create_daemon_live_opencode_adapter
from oc_rig.completion.daemon_monitor import _DaemonOpenCodeCompletionMonitor
from oc_rig.completion.codex_callback import CodexQueueConfig, LocalCodexQueueAdapter
from oc_rig.completion.daemon_callback import _DaemonLocalCodexCallbackPump
from oc_rig.completion.service import _create_completion
from oc_rig.daemon import identity as service_identity
from oc_rig.daemon.controller import (
    Controller,
    DurableController,
    OperationRejected,
    _RigController,
)
from oc_rig.daemon.identity import LocalUserIdentityPolicy, ServiceIdentityPolicy
from oc_rig.daemon.security import (
    PrivateSocketPath,
    SocketSecurityError,
    peer_credentials_supported,
    peer_pid,
    peer_uid,
)
from oc_rig.protocol.framing import (
    DEFAULT_MAX_FRAME_BYTES,
    FrameError,
    FrameTooLarge,
    IncompleteFrame,
    receive_frame,
    send_frame,
)
from oc_rig.protocol.messages import ProtocolError, Request, Response
from oc_rig.recovery.service import _create_recovery
from oc_rig.scheduler.service import _Scheduler
from oc_rig.store.database import (
    DaemonAuthorityError,
    RigStore,
    StoreQuiescenceError,
    _DaemonAuthority,
    _utc_now,
)
from oc_rig.store.runtime import PrivateRuntimeDirectory
from oc_rig.store.runtime import RuntimeContainmentError
from oc_rig.transport.service import _create_transport


@dataclass(frozen=True, slots=True)
class _CachedOutcome:
    fingerprint: bytes
    ok: bool
    value: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class PinnedExecutable:
    """Provisioned immutable source identity for one bootstrap executable."""

    path: Path
    digest: str
    device: int
    inode: int
    owner_uid: int
    mode: int
    size: int


@dataclass(frozen=True, slots=True)
class RigdChildArtifact:
    """Pinned helper/interpreter pair for platform-safe execution."""

    artifact_root: Path
    bootstrap: PinnedExecutable
    helper: PinnedExecutable
    interpreter: PinnedExecutable


@dataclass(frozen=True, slots=True)
class _ArtifactFacts:
    path: Path
    mode: int
    uid: int
    gid: int
    links: int
    device: int
    inode: int
    size: int
    has_extended_acl: bool


@dataclass(slots=True)
class _VerifiedBootstrap:
    bootstrap_fd: int
    helper_fd: int
    interpreter_fd: int
    artifact: RigdChildArtifact
    launcher: str
    path_proof: tuple[_ArtifactFacts, ...] = ()

    @property
    def child_descriptors(self) -> tuple[int, ...]:
        # The native gate consumes and closes the fixed bootstrap descriptors
        # before the trusted Python entrypoint begins.
        return ()

    def close(self) -> None:
        for name in ("bootstrap_fd", "helper_fd", "interpreter_fd"):
            descriptor = getattr(self, name)
            if descriptor >= 0:
                os.close(descriptor)
                setattr(self, name, -1)


class _SpawnedChild:
    """Small ``posix_spawn`` process handle with bounded lifecycle methods."""

    __slots__ = ("args", "pid", "stdin", "stdout", "_lock", "_returncode")

    def __init__(
        self,
        pid: int,
        stdin: Any,
        stdout: Any,
        args: tuple[str, ...],
    ):
        self.args = args
        self.pid = pid
        self.stdin = stdin
        self.stdout = stdout
        self._lock = threading.Lock()
        self._returncode: int | None = None

    @staticmethod
    def _decode_status(status: int) -> int:
        if os.WIFEXITED(status):
            return os.WEXITSTATUS(status)
        if os.WIFSIGNALED(status):
            return -os.WTERMSIG(status)
        raise RuntimeError("daemon child returned an unsupported wait status")

    def poll(self) -> int | None:
        with self._lock:
            if self._returncode is not None:
                return self._returncode
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid == 0:
                return None
            self._returncode = self._decode_status(status)
            return self._returncode

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            result = self.poll()
            if result is not None:
                return result
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(self.args, timeout)
            time.sleep(0.01)

    def terminate(self) -> None:
        if self.poll() is None:
            os.kill(self.pid, signal.SIGTERM)

    def kill(self) -> None:
        if self.poll() is None:
            os.kill(self.pid, signal.SIGKILL)


class _DaemonResources:
    """Resource owner that can be finalized without retaining ``RigDaemon``."""

    __slots__ = (
        "address",
        "bootstrap",
        "controller",
        "controller_close",
        "durable",
        "listener",
        "monitor_close",
        "process",
        "read_snapshot",
        "read_source_inbox",
        "wait_snapshot",
        "snapshot_feed_close",
        "read_submission_result",
        "socket_identity",
        "_lock",
    )

    def __init__(
        self,
        address: PrivateSocketPath,
        controller: Controller | DurableController | None,
        durable: bool,
    ):
        self.address = address
        self.bootstrap: _VerifiedBootstrap | None = None
        self.controller = controller
        self.controller_close: Callable[[], None] | None = None
        self.durable = durable
        self.listener: socket.socket | None = None
        self.monitor_close: Callable[[], None] | None = None
        self.process: _SpawnedChild | None = None
        self.read_snapshot: Callable[[], Mapping[str, Any]] | None = None
        self.read_source_inbox: Callable[[object], Mapping[str, Any]] | None = None
        self.wait_snapshot: Callable[[int], Mapping[str, Any]] | None = None
        self.snapshot_feed_close: Callable[[], None] | None = None
        self.read_submission_result: (
            Callable[[object, object], Mapping[str, Any]] | None
        ) = None
        self.socket_identity: os.stat_result | None = None
        self._lock = threading.Lock()

    def __copy__(self) -> None:
        raise TypeError("daemon resources cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("daemon resources cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("daemon resources cannot be serialized")

    def __reduce_ex__(self, _protocol: int) -> None:
        raise TypeError("daemon resources cannot be serialized")

    def current_listener(self) -> socket.socket | None:
        with self._lock:
            return self.listener

    def detach_listener(self) -> socket.socket | None:
        with self._lock:
            listener, self.listener = self.listener, None
            return listener

    def current_process(self) -> _SpawnedChild | None:
        with self._lock:
            return self.process

    def install_process(self, process: _SpawnedChild) -> None:
        with self._lock:
            if self.process is not None:
                raise RuntimeError("daemon child is already started")
            self.process = process

    def detach_process(self) -> _SpawnedChild | None:
        with self._lock:
            process, self.process = self.process, None
            return process

    def detach_bootstrap(self) -> _VerifiedBootstrap | None:
        with self._lock:
            bootstrap, self.bootstrap = self.bootstrap, None
            return bootstrap

    def close(self) -> None:
        with self._lock:
            listener, self.listener = self.listener, None
            socket_identity, self.socket_identity = self.socket_identity, None
            process, self.process = self.process, None
            self.read_snapshot = None
            self.read_source_inbox = None
            self.wait_snapshot = None
            snapshot_feed_close, self.snapshot_feed_close = (
                self.snapshot_feed_close,
                None,
            )
            self.read_submission_result = None
            bootstrap, self.bootstrap = self.bootstrap, None
            controller = self.controller
            controller_close = self.controller_close
            monitor_close, self.monitor_close = self.monitor_close, None
            if self.durable:
                self.controller = None
                self.controller_close = None
        first_error: BaseException | None = None
        if callable(snapshot_feed_close):
            try:
                snapshot_feed_close()
            except BaseException as error:
                first_error = error
        if callable(monitor_close):
            try:
                monitor_close()
            except BaseException as error:
                first_error = error
        if process is not None:
            try:
                _stop_child_process(process)
            except BaseException as error:
                first_error = error
        if bootstrap is not None:
            try:
                bootstrap.close()
            except BaseException as error:
                if first_error is None:
                    first_error = error
        if listener is not None:
            try:
                listener.close()
            except BaseException as error:
                first_error = error
        if socket_identity is not None:
            try:
                self.address.remove_if_same(socket_identity)
            except BaseException as error:
                if first_error is None:
                    first_error = error
        close_controller = (
            controller_close
            if self.durable
            else getattr(controller, "close", None)
        )
        if callable(close_controller):
            try:
                close_controller()
            except BaseException as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error


def _finalize_resources(resources: _DaemonResources) -> None:
    try:
        resources.close()
    except BaseException:
        pass


def _read_child_status(
    process: Any,
    *,
    timeout: float,
) -> dict[str, object]:
    stdout = process.stdout
    if stdout is None:
        raise RuntimeError("daemon child has no status pipe")
    deadline = time.monotonic() + timeout
    value = bytearray()
    while b"\n" not in value:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("daemon child readiness timed out")
        readable, _, _ = select.select([stdout.fileno()], [], [], remaining)
        if not readable:
            raise TimeoutError("daemon child readiness timed out")
        chunk = os.read(stdout.fileno(), 16 * 1024 + 1)
        if not chunk:
            if process.poll() is not None:
                raise RuntimeError("daemon child exited before readiness")
            raise RuntimeError("daemon child closed its status pipe")
        value.extend(chunk)
        if len(value) > 16 * 1024:
            raise RuntimeError("daemon child status exceeded its limit")
    try:
        decoded = json.loads(bytes(value).split(b"\n", 1)[0])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("daemon child status was invalid") from error
    if not isinstance(decoded, dict):
        raise RuntimeError("daemon child status was not an object")
    return decoded


def _stop_child_process(process: Any) -> None:
    if process.stdin is not None:
        try:
            process.stdin.close()
        except OSError:
            pass
        process.stdin = None
    try:
        process.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2.0)
    finally:
        if process.stdout is not None:
            process.stdout.close()
            process.stdout = None


def _sha256_descriptor(descriptor: int, limit: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise DaemonAuthorityError("bootstrap executable exceeds its pinned size")
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _artifact_facts(path: Path) -> _ArtifactFacts:
    try:
        before = path.lstat()
        has_extended_acl = service_identity._has_extended_acl(path)
        after = path.lstat()
    except (OSError, service_identity.ServiceIdentityError) as error:
        raise DaemonAuthorityError(
            f"could not inspect bootstrap artifact path: {path}"
        ) from error
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise DaemonAuthorityError("bootstrap artifact changed during inspection")
    return _ArtifactFacts(
        path,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_nlink,
        before.st_dev,
        before.st_ino,
        before.st_size,
        has_extended_acl,
    )


def _validate_root_owned_artifact(
    artifact: RigdChildArtifact,
) -> tuple[_ArtifactFacts, ...]:
    """Prove non-root identities cannot replace a macOS bootstrap pathname."""

    root = artifact.artifact_root
    try:
        root_is_canonical = root.resolve(strict=True) == root
    except OSError as error:
        raise DaemonAuthorityError("macOS artifact root is unavailable") from error
    if not root.is_absolute() or not root_is_canonical:
        raise DaemonAuthorityError("macOS artifact root is not canonical")
    files = (artifact.bootstrap, artifact.helper, artifact.interpreter)
    directories = {root, *root.parents}
    for pinned in files:
        try:
            path_is_canonical = pinned.path.resolve(strict=True) == pinned.path
        except OSError as error:
            raise DaemonAuthorityError("macOS artifact path is unavailable") from error
        if not pinned.path.is_absolute() or not path_is_canonical:
            raise DaemonAuthorityError("macOS artifact path is not canonical")
        try:
            relative = pinned.path.relative_to(root)
        except ValueError as error:
            raise DaemonAuthorityError(
                "macOS artifact path escapes its root"
            ) from error
        current = root
        for component in relative.parts[:-1]:
            current /= component
            directories.add(current)

    proof: list[_ArtifactFacts] = []
    for path in sorted(directories, key=lambda item: (len(item.parts), str(item))):
        facts = _artifact_facts(path)
        mode = stat.S_IMODE(facts.mode)
        if (
            not stat.S_ISDIR(facts.mode)
            or facts.uid != 0
            or mode & 0o022
            or not mode & 0o001
            or facts.inode <= 0
            or facts.has_extended_acl
        ):
            raise DaemonAuthorityError(
                "macOS artifact ancestors must be root-owned and non-writable"
            )
        proof.append(facts)

    for pinned in files:
        facts = _artifact_facts(pinned.path)
        if (
            not stat.S_ISREG(facts.mode)
            or facts.uid != 0
            or stat.S_IMODE(facts.mode) != 0o555
            or facts.links != 1
            or facts.has_extended_acl
            or (
                facts.device,
                facts.inode,
                facts.uid,
                stat.S_IMODE(facts.mode),
                facts.size,
            )
            != (
                pinned.device,
                pinned.inode,
                pinned.owner_uid,
                pinned.mode,
                pinned.size,
            )
        ):
            raise DaemonAuthorityError(
                "macOS artifact must be root-owned mode 0555 and single-link"
            )
        proof.append(facts)
    return tuple(proof)


def _proof_allows_nonroot_replacement(
    proof: tuple[_ArtifactFacts, ...],
    path: Path,
    *,
    uid: int,
    groups: frozenset[int],
) -> bool:
    """Model whether a non-root identity can rename an exact proved pathname."""

    if uid == 0:
        raise ValueError("root is outside the modeled attacker identities")
    parents = {facts.path: facts for facts in proof if stat.S_ISDIR(facts.mode)}
    parent = parents.get(path.parent)
    if parent is None or parent.has_extended_acl:
        return True
    mode = stat.S_IMODE(parent.mode)
    if uid == parent.uid:
        permissions = (mode >> 6) & 0o7
    elif parent.gid in groups:
        permissions = (mode >> 3) & 0o7
    else:
        permissions = mode & 0o7
    return permissions & 0o3 == 0o3


def _open_pinned_executable(
    pinned: PinnedExecutable,
    *,
    artifact_root: Path,
    expected_uid: int,
    expected_mode: int,
) -> tuple[int, os.stat_result]:
    if (
        not isinstance(pinned, PinnedExecutable)
        or not pinned.path.is_absolute()
        or pinned.owner_uid != expected_uid
        or pinned.mode != expected_mode
        or pinned.size <= 0
        or pinned.size > 128 * 1024 * 1024
        or len(pinned.digest) != 64
        or any(character not in "0123456789abcdef" for character in pinned.digest)
    ):
        raise DaemonAuthorityError("bootstrap executable pin is invalid")
    try:
        pinned.path.relative_to(artifact_root)
    except ValueError as error:
        raise DaemonAuthorityError("bootstrap executable escapes artifact root") from error
    if pinned.path.resolve(strict=True) != pinned.path:
        raise DaemonAuthorityError("bootstrap executable path is not canonical")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise DaemonAuthorityError("O_NOFOLLOW is required for bootstrap")
    descriptor = os.open(pinned.path, os.O_RDONLY | no_follow)
    try:
        opened = os.fstat(descriptor)
        linked = pinned.path.lstat()
        facts = (
            opened.st_dev,
            opened.st_ino,
            opened.st_uid,
            stat.S_IMODE(opened.st_mode),
            opened.st_size,
        )
        expected = (
            pinned.device,
            pinned.inode,
            pinned.owner_uid,
            pinned.mode,
            pinned.size,
        )
        if (
            facts != expected
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
            or _sha256_descriptor(descriptor, pinned.size) != pinned.digest
        ):
            raise DaemonAuthorityError("bootstrap executable failed immutable provenance")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _private_bootstrap_root(
    path: Path,
    *,
    approved_root: Path,
    service_uid: int,
) -> Path:
    if not path.is_absolute():
        raise DaemonAuthorityError("bootstrap root must be absolute")
    try:
        path.relative_to(approved_root)
    except ValueError as error:
        raise DaemonAuthorityError("bootstrap root escapes approved root") from error
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise DaemonAuthorityError("bootstrap root is not canonical")
    details = path.lstat()
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != service_uid
        or stat.S_IMODE(details.st_mode) != 0o700
    ):
        raise DaemonAuthorityError("bootstrap root is not owner-private")
    return path


def _prepare_bootstrap_core(
    artifact: RigdChildArtifact | None,
    *,
    approved_root: Path,
    service_uid: int,
    platform: str,
) -> _VerifiedBootstrap:
    if platform not in {"darwin", "linux"}:
        raise DaemonAuthorityError("unsupported rigd bootstrap platform")
    if not isinstance(artifact, RigdChildArtifact):
        raise DaemonAuthorityError("provisioned rigd child artifact is required")
    if any(
        not isinstance(pinned, PinnedExecutable)
        for pinned in (artifact.bootstrap, artifact.helper, artifact.interpreter)
    ):
        raise DaemonAuthorityError("pinned native bootstrap and Python pair are required")
    if not hasattr(os, "posix_spawn"):
        raise DaemonAuthorityError("fork-safe execution is unavailable")
    if platform == "darwin":
        # Root compromise is outside the launcher threat model.  The proof
        # below denies pathname replacement or in-place writes to every
        # dedicated service/client identity before pathname spawning is used.
        artifact_root = artifact.artifact_root
        path_proof = _validate_root_owned_artifact(artifact)
        expected_uid = 0
        expected_mode = 0o555
        launcher = "macos-path"
    else:
        artifact_root = _private_bootstrap_root(
            artifact.artifact_root,
            approved_root=approved_root,
            service_uid=service_uid,
        )
        if not Path("/dev/fd").is_dir():
            raise DaemonAuthorityError("descriptor execution is unavailable")
        path_proof = ()
        expected_uid = service_uid
        expected_mode = 0o500
        launcher = "descriptor"
    bootstrap_fd, _ = _open_pinned_executable(
        artifact.bootstrap,
        artifact_root=artifact_root,
        expected_uid=expected_uid,
        expected_mode=expected_mode,
    )
    try:
        helper_fd, _ = _open_pinned_executable(
            artifact.helper,
            artifact_root=artifact_root,
            expected_uid=expected_uid,
            expected_mode=expected_mode,
        )
    except BaseException:
        os.close(bootstrap_fd)
        raise
    try:
        interpreter_fd, _ = _open_pinned_executable(
            artifact.interpreter,
            artifact_root=artifact_root,
            expected_uid=expected_uid,
            expected_mode=expected_mode,
        )
    except BaseException:
        os.close(bootstrap_fd)
        os.close(helper_fd)
        raise
    bootstrap = _VerifiedBootstrap(
        bootstrap_fd,
        helper_fd,
        interpreter_fd,
        artifact,
        launcher,
        path_proof,
    )
    if launcher == "macos-path":
        try:
            _revalidate_macos_bootstrap(bootstrap)
        except BaseException:
            bootstrap.close()
            raise
    return bootstrap


def _seal_bootstrap_preparation(
    platform: str,
    core: Callable[..., _VerifiedBootstrap],
) -> Callable[..., _VerifiedBootstrap]:
    """Bind the native platform once without leaving an injectable hook."""

    def prepare(
        artifact: RigdChildArtifact | None,
        *,
        approved_root: Path,
        service_uid: int,
    ) -> _VerifiedBootstrap:
        return core(
            artifact,
            approved_root=approved_root,
            service_uid=service_uid,
            platform=platform,
        )

    prepare.__name__ = "_prepare_bootstrap"
    return prepare


_prepare_bootstrap = _seal_bootstrap_preparation(sys.platform, _prepare_bootstrap_core)
del _prepare_bootstrap_core
del _seal_bootstrap_preparation


def _revalidate_macos_bootstrap(bootstrap: _VerifiedBootstrap) -> None:
    if bootstrap.launcher != "macos-path":
        raise DaemonAuthorityError("macOS bootstrap proof has the wrong launcher")
    if _validate_root_owned_artifact(bootstrap.artifact) != bootstrap.path_proof:
        raise DaemonAuthorityError("macOS bootstrap pathname identity changed")
    for pinned, descriptor in (
        (bootstrap.artifact.bootstrap, bootstrap.bootstrap_fd),
        (bootstrap.artifact.helper, bootstrap.helper_fd),
        (bootstrap.artifact.interpreter, bootstrap.interpreter_fd),
    ):
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or (
                details.st_dev,
                details.st_ino,
                details.st_uid,
                stat.S_IMODE(details.st_mode),
                details.st_size,
            )
            != (
                pinned.device,
                pinned.inode,
                0,
                0o555,
                pinned.size,
            )
            or _sha256_descriptor(descriptor, pinned.size) != pinned.digest
        ):
            raise DaemonAuthorityError("macOS bootstrap descriptor identity changed")


_CHILD_INTERPRETER_FD = 3
_CHILD_HELPER_FD = 4
_CHILD_NATIVE_FD = 5


def _verify_descriptor_path(descriptor: int) -> None:
    path = f"/dev/fd/{descriptor}"
    try:
        duplicate = os.open(path, os.O_RDONLY)
        linked = os.fstat(duplicate)
        opened = os.fstat(descriptor)
    except OSError as error:
        raise DaemonAuthorityError("descriptor execution is unavailable") from error
    else:
        os.close(duplicate)
        if (linked.st_dev, linked.st_ino) != (opened.st_dev, opened.st_ino):
            raise DaemonAuthorityError("descriptor execution identity mismatch")


def _spawn_verified_child(bootstrap: _VerifiedBootstrap) -> _SpawnedChild:
    """Spawn using the selected fork-safe platform strategy."""

    if (
        not hasattr(os, "posix_spawn")
        or bootstrap.bootstrap_fd < 0
        or bootstrap.interpreter_fd < 0
        or bootstrap.helper_fd < 0
    ):
        raise DaemonAuthorityError("verified bootstrap is unavailable")
    if bootstrap.launcher == "descriptor":
        for descriptor in (
            bootstrap.bootstrap_fd,
            bootstrap.interpreter_fd,
            bootstrap.helper_fd,
        ):
            _verify_descriptor_path(descriptor)
        executable = f"/dev/fd/{_CHILD_NATIVE_FD}"
        interpreter_argument = f"/dev/fd/{_CHILD_INTERPRETER_FD}"
        helper_argument = f"/dev/fd/{_CHILD_HELPER_FD}"
    elif bootstrap.launcher == "macos-path":
        executable = str(bootstrap.artifact.bootstrap.path)
        interpreter_argument = str(bootstrap.artifact.interpreter.path)
        helper_argument = str(bootstrap.artifact.helper.path)
    else:
        raise DaemonAuthorityError("unknown bootstrap launcher")
    argv = (
        executable,
        "--oc-rig-bootstrap-v1",
        bootstrap.launcher,
        interpreter_argument,
        helper_argument,
    )

    staged: list[int] = []
    config_read, config_write = os.pipe()
    status_read, status_write = os.pipe()
    null_fd = os.open(os.devnull, os.O_RDWR)
    process: _SpawnedChild | None = None
    spawned_pid: int | None = None
    try:
        minimum = 64
        for descriptor in (
            bootstrap.interpreter_fd,
            bootstrap.helper_fd,
            bootstrap.bootstrap_fd,
        ):
            staged_descriptor = fcntl.fcntl(
                descriptor,
                fcntl.F_DUPFD_CLOEXEC,
                minimum,
            )
            staged.append(staged_descriptor)
            minimum = staged_descriptor + 1
        actions: list[tuple[int, ...]] = [
            (os.POSIX_SPAWN_DUP2, config_read, 0),
            (os.POSIX_SPAWN_DUP2, status_write, 1),
            (os.POSIX_SPAWN_DUP2, null_fd, 2),
            (os.POSIX_SPAWN_DUP2, staged[0], _CHILD_INTERPRETER_FD),
            (os.POSIX_SPAWN_DUP2, staged[1], _CHILD_HELPER_FD),
            (os.POSIX_SPAWN_DUP2, staged[2], _CHILD_NATIVE_FD),
        ]
        try:
            if bootstrap.launcher == "macos-path":
                _revalidate_macos_bootstrap(bootstrap)
            pid = os.posix_spawn(
                executable,
                argv,
                {
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PYTHONNOUSERSITE": "1",
                },
                file_actions=actions,
                setsid=True,
                setsigmask=(),
                setsigdef=(signal.SIGINT, signal.SIGTERM),
            )
            spawned_pid = pid
            if bootstrap.launcher == "macos-path":
                _revalidate_macos_bootstrap(bootstrap)
        except (NotImplementedError, TypeError, OSError) as error:
            raise DaemonAuthorityError(
                "fork-safe descriptor execution is unavailable"
            ) from error
        os.close(config_read)
        config_read = -1
        os.close(status_write)
        status_write = -1
        process = _SpawnedChild(
            pid,
            os.fdopen(config_write, "wb", buffering=0),
            os.fdopen(status_read, "rb", buffering=0),
            argv,
        )
        config_write = -1
        status_read = -1
        spawned_pid = None
        return process
    except BaseException:
        if process is not None:
            _stop_child_process(process)
        elif spawned_pid is not None:
            try:
                os.kill(spawned_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(spawned_pid, 0)
        raise
    finally:
        for descriptor in (
            *staged,
            config_read,
            config_write,
            status_read,
            status_write,
            null_fd,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _bootstrap_manifest_hash(artifact: RigdChildArtifact) -> str:
    value = {
        name: {
            "device": pinned.device,
            "digest": pinned.digest,
            "inode": pinned.inode,
            "mode": pinned.mode,
            "owner_uid": pinned.owner_uid,
            "path": str(pinned.path),
            "size": pinned.size,
        }
        for name, pinned in (
            ("bootstrap", artifact.bootstrap),
            ("helper", artifact.helper),
            ("interpreter", artifact.interpreter),
        )
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _verify_ready_socket(
    address: PrivateSocketPath,
    status: Mapping[str, object],
    *,
    service_uid: int,
    client_gid: int,
    child_pid: int,
) -> None:
    try:
        path = address.validate_for_connect(service_uid, client_gid)
        details = path.lstat()
    except (FileNotFoundError, OSError) as error:
        raise SocketSecurityError("daemon child readiness socket is unavailable") from error
    if (
        status.get("socket_device") != details.st_dev
        or status.get("socket_inode") != details.st_ino
        or not stat.S_ISSOCK(details.st_mode)
        or details.st_uid != service_uid
        or details.st_gid != client_gid
        or details.st_nlink != 1
        or stat.S_IMODE(details.st_mode) != 0o620
    ):
        raise SocketSecurityError("daemon child readiness socket identity mismatch")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2.0)
            connection.connect(str(path))
            if peer_uid(connection) != service_uid:
                raise SocketSecurityError("daemon child readiness peer UID mismatch")
            authenticated_pid = peer_pid(connection)
            if authenticated_pid is not None and authenticated_pid != child_pid:
                raise SocketSecurityError("daemon child readiness peer PID mismatch")
            rechecked = path.lstat()
            if (rechecked.st_dev, rechecked.st_ino) != (details.st_dev, details.st_ino):
                raise SocketSecurityError("daemon child socket changed during readiness")
    except OSError as error:
        raise SocketSecurityError("daemon child readiness socket connect failed") from error


class _RigDaemonBase:
    """Own the controller and serialize all mutations behind one socket boundary."""

    __slots__ = (
        "address",
        "__runtime",
        "__identity_policy",
        "__child_artifact",
        "__adapter_config",
        "__callback_config",
        "__topology_hash",
        "__durable",
        "max_frame_bytes",
        "max_idempotency_entries",
        "connection_timeout",
        "__resources",
        "__finalizer",
        "__request_handler",
        "_stop",
        "_threads",
        "_connections",
        "_threads_lock",
        "_idempotency",
        "_execution_lock",
        "__weakref__",
    )
    _require_native_peer = True

    def __init__(
        self,
        socket_path: PrivateSocketPath,
        *,
        controller: Controller | DurableController | None = None,
        runtime: PrivateRuntimeDirectory | None = None,
        identity_policy: ServiceIdentityPolicy | LocalUserIdentityPolicy | None = None,
        child_artifact: RigdChildArtifact | None = None,
        adapter_config: LiveOpenCodeAdapterConfig | None = None,
        callback_config: CodexQueueConfig | None = None,
        read_snapshot_provider: Callable[[], Mapping[str, Any]] | None = None,
        read_source_inbox_provider: Callable[[object], Mapping[str, Any]] | None = None,
        wait_snapshot_provider: Callable[[int], Mapping[str, Any]] | None = None,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        max_idempotency_entries: int = 4096,
        connection_timeout: float = 5.0,
    ):
        if max_frame_bytes <= 0 or max_idempotency_entries <= 0:
            raise ValueError("protocol limits must be positive")
        durable = runtime is not None or identity_policy is not None
        if adapter_config is not None and type(adapter_config) is not LiveOpenCodeAdapterConfig:
            raise TypeError("validated LiveOpenCodeAdapterConfig required")
        if callback_config is not None and type(callback_config) is not CodexQueueConfig:
            raise TypeError("validated CodexQueueConfig required")
        if durable:
            if type(self) not in (RigDaemon, _DurableChildDaemon):
                raise PermissionError("durable mode requires exact RigDaemon type")
            if controller is not None or runtime is None or identity_policy is None:
                raise ValueError(
                    "durable mode requires runtime and identity_policy without a controller"
                )
            if (
                read_snapshot_provider is not None
                or read_source_inbox_provider is not None
                or wait_snapshot_provider is not None
            ):
                raise ValueError("durable mode provisions its read-only snapshot providers")
        elif child_artifact is not None:
            raise ValueError("child_artifact is valid only for durable mode")
        elif controller is None:
            raise ValueError("an in-memory controller is required")
        if adapter_config is not None and (
            type(self) is not _DurableChildDaemon
            or not isinstance(identity_policy, LocalUserIdentityPolicy)
        ):
            raise ValueError(
                "live adapter configuration is valid only for the explicit local-user child"
            )
        if callback_config is not None and (
            adapter_config is None
            or type(self) is not _DurableChildDaemon
            or not isinstance(identity_policy, LocalUserIdentityPolicy)
        ):
            raise ValueError(
                "local Codex callbacks require the explicit local-user OpenCode child"
            )
        self.address = socket_path
        self.__runtime = runtime
        self.__identity_policy = identity_policy
        self.__child_artifact = child_artifact
        self.__adapter_config = adapter_config
        self.__callback_config = callback_config
        self.__topology_hash: str | None = None
        self.__durable = durable
        self.max_frame_bytes = max_frame_bytes
        self.max_idempotency_entries = max_idempotency_entries
        self.connection_timeout = connection_timeout
        self.__resources = _DaemonResources(socket_path, controller, durable)
        self.__resources.read_snapshot = read_snapshot_provider
        self.__resources.read_source_inbox = read_source_inbox_provider
        self.__resources.wait_snapshot = wait_snapshot_provider
        self.__finalizer = weakref.finalize(
            self,
            _finalize_resources,
            self.__resources,
        )
        self.__request_handler: Callable[[socket.socket], None] | None = None
        self._stop = threading.Event()
        self._threads: set[threading.Thread] = set()
        self._connections: set[socket.socket] = set()
        self._threads_lock = threading.Lock()
        self._idempotency: OrderedDict[str, _CachedOutcome] = OrderedDict()
        self._execution_lock = threading.Lock()

    def __copy__(self) -> None:
        raise TypeError("RigDaemon cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("RigDaemon cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("RigDaemon cannot be serialized")

    def __reduce_ex__(self, _protocol: int) -> None:
        raise TypeError("RigDaemon cannot be serialized")

    @property
    def _listener(self) -> socket.socket | None:
        """Private lifecycle probe retained for exact resource-closure tests."""
        return self.__resources.current_listener()

    @property
    def child_pid(self) -> int | None:
        """PID is the only durable child identity exposed to the launcher."""
        process = self.__resources.current_process()
        if process is None or process.poll() is not None:
            return None
        return process.pid

    @property
    def topology_hash(self) -> str | None:
        """Immutable public hash of the child topology accepted at readiness."""
        return self.__topology_hash

    def _create_request_handler(self) -> Callable[[socket.socket], None]:
        raise NotImplementedError

    def _validate_durable_topology(
        self,
        runtime: PrivateRuntimeDirectory,
        identity_policy: ServiceIdentityPolicy | LocalUserIdentityPolicy,
    ) -> None:
        raise NotImplementedError

    def _start(self) -> None:
        if self.__durable and type(self) is RigDaemon:
            self._start_child_process()
            return
        self._start_local()

    def _start_child_process(self) -> None:
        if self.__resources.current_process() is not None:
            raise RuntimeError("daemon is already started")
        assert self.__runtime is not None
        assert self.__identity_policy is not None
        artifact = self.__child_artifact
        bootstrap = _prepare_bootstrap(
            artifact,
            approved_root=self.address.approved_root,
            service_uid=self.__identity_policy.service_uid,
        )
        self.__resources.bootstrap = bootstrap
        assert artifact is not None
        public_configuration = {
            "approved_root": str(self.__runtime.approved_root),
            "artifact_root": str(artifact.artifact_root),
            "bootstrap_fds": list(bootstrap.child_descriptors),
            "bootstrap_hash": _bootstrap_manifest_hash(artifact),
            "client_gid": self.__identity_policy.client_gid,
            "connection_timeout": self.connection_timeout,
            "database_name": self.__runtime.database_name,
            "max_frame_bytes": self.max_frame_bytes,
            "max_idempotency_entries": self.max_idempotency_entries,
            "runtime_root": str(self.__runtime.root),
            "service_uid": self.__identity_policy.service_uid,
            "allowed_client_uids": sorted(
                self.__identity_policy.allowed_client_uids
            ),
            "socket_approved_root": str(self.address.approved_root),
            "socket_path": str(self.address.socket_path),
            "version": 1,
        }
        topology_hash = hashlib.sha256(
            json.dumps(
                public_configuration,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        nonce = secrets.token_hex(32)
        configuration = dict(public_configuration)
        configuration["configuration_hash"] = topology_hash
        configuration["readiness_nonce"] = nonce
        try:
            process = _spawn_verified_child(bootstrap)
        except BaseException:
            self.__resources.close()
            raise
        self.__resources.install_process(process)
        try:
            assert process.stdin is not None
            encoded = json.dumps(
                configuration,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            if len(encoded) > 16 * 1024:
                raise RuntimeError("daemon child configuration is too large")
            process.stdin.write(encoded + b"\n")
            process.stdin.flush()
            status = _read_child_status(process, timeout=self.connection_timeout + 5.0)
            ready_fields = {
                "child_pid",
                "configuration_hash",
                "readiness_nonce",
                "socket_device",
                "socket_inode",
                "status",
                "version",
            }
            if (
                set(status) != ready_fields
                or status.get("status") != "ready"
                or status.get("version") != 1
                or status.get("child_pid") != process.pid
                or status.get("configuration_hash") != topology_hash
                or not secrets.compare_digest(
                    str(status.get("readiness_nonce", "")),
                    nonce,
                )
            ):
                message = status.get("message")
                error_type = status.get("error_type")
                if not isinstance(message, str):
                    message = "daemon child rejected its configuration"
                exception = {
                    "DaemonAuthorityError": DaemonAuthorityError,
                    "RuntimeContainmentError": RuntimeContainmentError,
                    "ServiceIdentityError": service_identity.ServiceIdentityError,
                    "SocketSecurityError": SocketSecurityError,
                }.get(error_type, RuntimeError)
                raise exception(message)
            _verify_ready_socket(
                self.address,
                status,
                service_uid=self.__identity_policy.service_uid,
                client_gid=self.__identity_policy.client_gid,
                child_pid=process.pid,
            )
            detached = self.__resources.detach_bootstrap()
            if detached is not bootstrap:
                raise DaemonAuthorityError("bootstrap descriptor ownership changed")
            bootstrap.close()
            self.__topology_hash = topology_hash
            # The launcher retains no durable topology/authority configuration
            # after the exec boundary has acknowledged ownership.
            self.__runtime = None
            self.__identity_policy = None
            self.__child_artifact = None
        except BaseException:
            self.__resources.close()
            raise

    def _start_local(self) -> None:
        if self.__resources.current_listener() is not None:
            raise RuntimeError("daemon is already started")
        if self.__durable and type(self) is not _DurableChildDaemon:
            raise PermissionError("durable mode requires exact RigDaemon type")
        if self._require_native_peer and not peer_credentials_supported():
            self._close_controller()
            raise SocketSecurityError("peer UID authentication is unavailable")
        listener: socket.socket | None = None
        try:
            if self.__durable:
                assert self.__runtime is not None
                assert self.__identity_policy is not None
                self._validate_durable_topology(
                    self.__runtime,
                    self.__identity_policy,
                )
                store = RigStore._open_provisioned(
                    self.__runtime,
                    service_uid=self.__identity_policy.service_uid,
                )
                lock_path = store.path.parent / "rigd.lock"
                no_follow = getattr(os, "O_NOFOLLOW", None)
                if no_follow is None:
                    raise DaemonAuthorityError(
                        "O_NOFOLLOW is required for daemon authority"
                    )
                descriptor = os.open(lock_path, os.O_RDWR | no_follow)
                try:
                    opened = os.fstat(descriptor)
                    linked = lock_path.lstat()
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or opened.st_uid != self.__identity_policy.service_uid
                        or opened.st_nlink != 1
                        or stat.S_IMODE(opened.st_mode) != 0o600
                        or (opened.st_dev, opened.st_ino)
                        != (linked.st_dev, linked.st_ino)
                    ):
                        raise DaemonAuthorityError(
                            "daemon lock failed private inode validation"
                        )
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError as error:
                        raise DaemonAuthorityError(
                            "another rigd owns this runtime"
                        ) from error
                except BaseException:
                    os.close(descriptor)
                    raise
                authority = object.__new__(_DaemonAuthority)
                authority._store = store
                authority._closed = False
                authority._descriptor = descriptor
                authority._path = lock_path
                authority._identity = (opened.st_dev, opened.st_ino)
                authority._activate_usage_guard()
                try:
                    authority._assert_for(store)
                    store.initialize()
                    store._open_daemon_connection(authority)
                    scheduler = object.__new__(_Scheduler)
                    scheduler.store = store
                    scheduler._authority = authority
                    scheduler._clock = _utc_now
                    dispatch_capability = object()
                    completion = _create_completion(
                        store, authority, dispatch_capability, scheduler
                    )
                    recovery = _create_recovery(store, authority, dispatch_capability)
                    adapter: AdapterPort = DisabledAdapter()
                    monitor: _DaemonOpenCodeCompletionMonitor | None = None
                    callback_pump: _DaemonLocalCodexCallbackPump | None = None
                    callback_adapter: LocalCodexQueueAdapter | None = None
                    if self.__callback_config is not None:
                        callback_adapter = LocalCodexQueueAdapter(self.__callback_config)
                        callback_pump = _DaemonLocalCodexCallbackPump(
                            store,
                            authority,
                            dispatch_capability,
                            completion,
                            callback_adapter,
                        )
                    if self.__adapter_config is not None:
                        live_adapter = _create_daemon_live_opencode_adapter(
                            store,
                            authority,
                            dispatch_capability,
                            self.__adapter_config,
                        )
                        adapter = live_adapter
                        monitor = _DaemonOpenCodeCompletionMonitor(
                            store,
                            authority,
                            dispatch_capability,
                            completion,
                            recovery,
                            live_adapter,
                            (
                                callback_pump.drain_ready
                                if callback_pump is not None
                                else None
                            ),
                        )
                        monitor.startup_validate()
                    transport = _create_transport(
                        store,
                        authority,
                        dispatch_capability,
                        completion,
                        adapter,
                        (
                            monitor.register_transport
                            if monitor is not None
                            else None
                        ),
                    )
                    with store._daemon_transaction(authority) as connection:
                        connection.row_factory = sqlite3.Row
                        transport.reconcile_startup(dispatch_capability, connection)
                        completion.reconcile_startup(dispatch_capability, connection)
                    if callback_pump is not None:
                        callback_pump.drain_ready()
                    controller = object.__new__(_RigController)
                    controller.store = store
                    controller.max_idempotency_entries = self.max_idempotency_entries
                    controller._authority = authority
                    controller._scheduler = scheduler
                    controller._transport = transport
                    controller._completion = completion
                    controller._recovery = recovery
                    controller._backend_status = (
                        monitor.status
                        if monitor is not None
                        else lambda: {
                            "configured": False,
                            "healthy": True,
                            "reason": None,
                        }
                    )
                    controller._topology = (
                        self.__adapter_config.topology
                        if self.__adapter_config is not None
                        else None
                    )
                    controller._callback_adapter_configured = callback_pump is not None

                    def durable_dispatch(
                        idempotency_id: str,
                        fingerprint: str,
                        operation: str,
                        params: Mapping[str, Any],
                    ) -> Mapping[str, Any]:
                        if operation == "callback.delivery.reconcile.v1":
                            if callback_adapter is None:
                                raise OperationRejected(
                                    "callback_unavailable",
                                    "local Codex callback adapter is not configured",
                                )
                            result = controller.reconcile_callback_delivery(
                                dispatch_capability,
                                idempotency_id,
                                fingerprint,
                                params,
                                callback_adapter.prove_delivery,
                            )
                        else:
                            result = controller.execute_durable(
                                dispatch_capability,
                                idempotency_id,
                                fingerprint,
                                operation,
                                params,
                            )
                        if callback_pump is not None:
                            callback_pump.drain_ready()
                        return result

                    def durable_close() -> None:
                        if callback_pump is not None:
                            callback_pump.close()
                        authority.close()
                except BaseException:
                    authority.close()
                    raise
                self.__resources.controller = durable_dispatch
                self.__resources.controller_close = durable_close
                self.__resources.monitor_close = (
                    monitor.close if monitor is not None else None
                )
                self.__resources.read_snapshot = lambda: controller.cockpit_snapshot(
                    dispatch_capability
                )
                self.__resources.read_source_inbox = (
                    lambda thread_id: controller.source_inbox(
                        dispatch_capability, thread_id
                    )
                )

                def wait_snapshot(after_sequence: int) -> Mapping[str, Any]:
                    store._wait_for_event_sequence(after_sequence)
                    return controller.cockpit_snapshot(dispatch_capability)

                self.__resources.wait_snapshot = wait_snapshot
                self.__resources.snapshot_feed_close = store._close_event_feed
                self.__resources.read_submission_result = (
                    lambda submission_id, reservation_attempt: controller.submission_result(
                        dispatch_capability, submission_id, reservation_attempt
                    )
                )
                if isinstance(self.__identity_policy, LocalUserIdentityPolicy):
                    path = self.address.prepare_for_bind()
                    directory_identity = self.address.directory_identity()
                else:
                    path = self.address.prepare_service_for_bind(
                        self.__identity_policy.service_uid,
                        self.__identity_policy.client_gid,
                    )
                    directory_identity = self.address.service_directory_identity(
                        self.__identity_policy.service_uid,
                        self.__identity_policy.client_gid,
                    )
            else:
                path = self.address.prepare_for_bind()
                directory_identity = self.address.directory_identity()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.__resources.listener = listener
            local_user = self.__durable and isinstance(
                self.__identity_policy, LocalUserIdentityPolicy
            )
            if self.__durable and not local_user:
                assert self.__identity_policy is not None
                self.address.assert_service_directory_identity(
                    directory_identity,
                    self.__identity_policy.service_uid,
                    self.__identity_policy.client_gid,
                )
            else:
                self.address.assert_directory_identity(directory_identity)
            listener.bind(str(path))
            if self.__durable and not local_user:
                assert self.__identity_policy is not None
                self.__resources.socket_identity = (
                    self.address.secure_service_bound_socket(
                        directory_identity,
                        self.__identity_policy.service_uid,
                        self.__identity_policy.client_gid,
                    )
                )
            else:
                self.__resources.socket_identity = self.address.secure_bound_socket(
                    directory_identity
                )
            listener.listen(64)
            listener.settimeout(0.2)
            if self.__durable and not local_user:
                assert self.__identity_policy is not None
                self.address.assert_service_bound_identity(
                    directory_identity,
                    self.__resources.socket_identity,
                    self.__identity_policy.service_uid,
                    self.__identity_policy.client_gid,
                )
            else:
                self.address.assert_bound_identity(
                    directory_identity,
                    self.__resources.socket_identity,
                )
            if self.__durable and monitor is not None:
                monitor.start()
        except BaseException:
            self.__resources.close()
            raise
        assert listener is not None
        self._stop.clear()
        self.__request_handler = self._create_request_handler()

    def serve_forever(self) -> None:
        if self.__durable and type(self) is RigDaemon:
            if self.__resources.current_process() is None:
                self.start()
            process = self.__resources.current_process()
            assert process is not None
            process.wait()
            return
        if self.__resources.current_listener() is None:
            self.start()
        try:
            while not self._stop.is_set():
                try:
                    listener = self.__resources.current_listener()
                    if listener is None:
                        break
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                thread = threading.Thread(
                    target=self.__request_handler,
                    args=(connection,),
                    name="rigd-client",
                    daemon=True,
                )
                with self._threads_lock:
                    self._threads.add(thread)
                    self._connections.add(connection)
                thread.start()
        finally:
            self.shutdown()

    def start_background(self) -> threading.Thread:
        self.start()
        thread = threading.Thread(target=self.serve_forever, name="rigd", daemon=True)
        thread.start()
        return thread

    def shutdown(self) -> None:
        if self.__durable and type(self) is RigDaemon:
            process = self.__resources.detach_process()
            if process is not None:
                _stop_child_process(process)
            bootstrap = self.__resources.detach_bootstrap()
            if bootstrap is not None:
                bootstrap.cleanup()
            return
        self._stop.set()
        self.__request_handler = None
        listener = self.__resources.detach_listener()
        if listener is not None:
            listener.close()
        close_snapshot_feed = self.__resources.snapshot_feed_close
        if callable(close_snapshot_feed):
            close_snapshot_feed()
        current = threading.current_thread()
        with self._threads_lock:
            clients = [thread for thread in self._threads if thread is not current]
            connections = list(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        for thread in clients:
            thread.join(timeout=self.connection_timeout + 0.5)
        self.__resources.close()

    def _close_controller(self) -> None:
        close_controller = (
            self.__resources.controller_close
            if self.__durable
            else getattr(self.__resources.controller, "close", None)
        )
        if callable(close_controller):
            close_controller()
        if self.__durable:
            self.__resources.controller = None
            self.__resources.controller_close = None

    def close(self) -> None:
        self.shutdown()

    def __enter__(self) -> "_RigDaemonBase":
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.shutdown()

    def _serve_client(
        self,
        connection: socket.socket,
        resolver: Callable[[socket.socket], int | None],
    ) -> None:
        try:
            with connection:
                connection.settimeout(self.connection_timeout)
                request: Request | None = None
                try:
                    try:
                        uid = resolver(connection)
                    except (OSError, SocketSecurityError):
                        self._send_error(
                            connection,
                            None,
                            "peer_credentials_unavailable",
                            "peer credentials could not be authenticated",
                        )
                        return
                    if uid is None or type(uid) is not int or uid < 0:
                        self._send_error(
                            connection,
                            None,
                            "peer_credentials_unavailable",
                            "peer credentials could not be authenticated",
                        )
                        return
                    allowed_uids = (
                        self.__identity_policy.allowed_client_uids
                        if self.__durable and self.__identity_policy is not None
                        else frozenset({os.geteuid()})
                    )
                    if uid not in allowed_uids:
                        self._send_error(
                            connection,
                            None,
                            "peer_uid_mismatch",
                            "peer is not authorized",
                        )
                        return
                    payload = receive_frame(connection, max_bytes=self.max_frame_bytes)
                    request = Request.decode(payload)
                    if request.operation == "cockpit.watch.v1":
                        connection.settimeout(None)
                    response = self._dispatch(request)
                    connection.settimeout(self.connection_timeout)
                except FrameTooLarge:
                    response = Response.failure(
                        None,
                        "frame_too_large",
                        "request exceeds the frame limit",
                    )
                except IncompleteFrame:
                    return
                except FrameError:
                    response = Response.failure(None, "invalid_frame", "request frame is invalid")
                except ProtocolError as error:
                    response = Response.failure(None, error.code, str(error))
                except (socket.timeout, ConnectionError, OSError):
                    return
                try:
                    encoded = response.encode()
                    send_frame(connection, encoded, max_bytes=self.max_frame_bytes)
                except FrameTooLarge:
                    self._send_error(
                        connection,
                        request,
                        "response_too_large",
                        "response exceeds the frame limit",
                    )
        finally:
            with self._threads_lock:
                self._threads.discard(threading.current_thread())
                self._connections.discard(connection)

    def _send_error(
        self,
        connection: socket.socket,
        request: Request | None,
        code: str,
        message: str,
    ) -> None:
        send_frame(
            connection,
            Response.failure(request, code, message).encode(),
            max_bytes=self.max_frame_bytes,
        )

    def _dispatch(self, request: Request) -> Response:
        if self.__durable and type(self) is RigDaemon:
            return Response.failure(
                request,
                "socket_required",
                "durable operations require the authenticated socket",
            )
        controller = self.__resources.controller
        if controller is None:
            return Response.failure(request, "daemon_not_started", "daemon is not started")
        if request.operation == "cockpit.snapshot.v1":
            if request.params:
                return Response.failure(
                    request,
                    "invalid_params",
                    "cockpit snapshot does not accept parameters",
                )
            read_snapshot = self.__resources.read_snapshot
            if read_snapshot is None:
                return Response.failure(
                    request,
                    "snapshot_unavailable",
                    "read-only cockpit projection is unavailable",
                )
            with self._execution_lock:
                try:
                    snapshot = dict(read_snapshot())
                except Exception:
                    return Response.failure(
                        request,
                        "snapshot_unavailable",
                        "read-only cockpit projection is unavailable",
                    )
            return Response.success(request, {"snapshot": snapshot})
        if request.operation == "cockpit.watch.v1":
            if set(request.params) != {"after_event_sequence"}:
                return Response.failure(
                    request,
                    "invalid_params",
                    "cockpit watch parameters do not match schema",
                )
            after_sequence = request.params["after_event_sequence"]
            if (
                type(after_sequence) is not int
                or after_sequence < 0
                or after_sequence > 2**63 - 1
            ):
                return Response.failure(
                    request,
                    "invalid_params",
                    "event sequence must be a non-negative signed-64 integer",
                )
            wait_snapshot = self.__resources.wait_snapshot
            if wait_snapshot is None:
                return Response.failure(
                    request,
                    "snapshot_unavailable",
                    "change-driven cockpit projection is unavailable",
                )
            try:
                snapshot = dict(wait_snapshot(after_sequence))
            except Exception:
                return Response.failure(
                    request,
                    "snapshot_unavailable",
                    "change-driven cockpit projection is unavailable",
                )
            return Response.success(request, {"snapshot": snapshot})
        if request.operation == "codex.source.inbox.v1":
            if set(request.params) != {"thread_id"}:
                return Response.failure(
                    request,
                    "invalid_params",
                    "source inbox parameters do not match schema",
                )
            read_source_inbox = self.__resources.read_source_inbox
            if read_source_inbox is None:
                return Response.failure(
                    request, "source_inbox_unavailable", "source inbox is unavailable"
                )
            with self._execution_lock:
                try:
                    result = dict(read_source_inbox(request.params["thread_id"]))
                except OperationRejected as error:
                    return Response.failure(request, error.code, str(error))
                except Exception:
                    return Response.failure(
                        request, "source_inbox_unavailable", "source inbox is unavailable"
                    )
            return Response.success(request, result)
        if request.operation == "submission.result.v1":
            if set(request.params) != {"submission_id", "reservation_attempt"}:
                return Response.failure(
                    request,
                    "invalid_params",
                    "task result parameters do not match schema",
                )
            read_result = self.__resources.read_submission_result
            if read_result is None:
                return Response.failure(
                    request, "result_unavailable", "task result is unavailable"
                )
            with self._execution_lock:
                try:
                    result = dict(
                        read_result(
                            request.params["submission_id"],
                            request.params["reservation_attempt"],
                        )
                    )
                except OperationRejected as error:
                    return Response.failure(request, error.code, str(error))
                except Exception:
                    return Response.failure(
                        request, "result_unavailable", "task result is unavailable"
                    )
            return Response.success(request, result)
        fingerprint = hashlib.sha256(
            Request(
                request_id="fingerprint",
                idempotency_id="fingerprint",
                operation=request.operation,
                params=request.params,
            ).encode()
        ).digest()
        with self._execution_lock:
            durable_execute = (
                controller if self.__durable and callable(controller)
                else getattr(controller, "execute_durable", None)
            )
            if callable(durable_execute):
                try:
                    result = dict(
                        durable_execute(
                            request.idempotency_id,
                            fingerprint.hex(),
                            request.operation,
                            request.params,
                        )
                    )
                except OperationRejected as error:
                    return Response.failure(request, error.code, str(error))
                except StoreQuiescenceError:
                    return Response.failure(
                        request,
                        "store_not_quiescent",
                        "durable outcome requires an idempotent retry",
                    )
                except Exception:
                    return Response.failure(
                        request,
                        "internal_error",
                        "controller operation failed",
                    )
                return Response.success(request, result)
            cached = self._idempotency.get(request.idempotency_id)
            if cached is not None:
                self._idempotency.move_to_end(request.idempotency_id)
                if cached.fingerprint != fingerprint:
                    return Response.failure(
                        request,
                        "idempotency_conflict",
                        "idempotency ID was reused for a different request",
                    )
                if cached.ok:
                    return Response.success(request, cached.value)
                return Response.failure(
                    request,
                    cached.value["code"],
                    cached.value["message"],
                )
            if len(self._idempotency) >= self.max_idempotency_entries:
                return Response.failure(
                    request,
                    "idempotency_capacity",
                    "idempotency capacity is exhausted",
                )
            try:
                result = dict(controller.execute(request.operation, request.params))
            except OperationRejected as error:
                outcome = _CachedOutcome(
                    fingerprint,
                    False,
                    {"code": error.code, "message": str(error)},
                )
                response = Response.failure(request, error.code, str(error))
            except Exception:
                outcome = _CachedOutcome(
                    fingerprint,
                    False,
                    {"code": "internal_error", "message": "controller operation failed"},
                )
                response = Response.failure(
                    request,
                    "internal_error",
                    "controller operation failed",
                )
            else:
                outcome = _CachedOutcome(fingerprint, True, result)
                response = Response.success(request, result)
            self._idempotency[request.idempotency_id] = outcome
            return response


def _production_request_handler_method() -> Callable[
    [_RigDaemonBase], Callable[[socket.socket], None]
]:
    """Bind the native resolver once, before module globals can be replaced."""
    resolver = peer_uid

    def create_request_handler(
        daemon: _RigDaemonBase,
    ) -> Callable[[socket.socket], None]:
        daemon_reference = weakref.ref(daemon)

        def request_handler(connection: socket.socket) -> None:
            current = daemon_reference()
            if current is None:
                connection.close()
                return
            current._serve_client(connection, resolver)

        return request_handler

    return create_request_handler


def _production_topology_validation_method() -> Callable[
    [
        _RigDaemonBase,
        PrivateRuntimeDirectory,
        ServiceIdentityPolicy | LocalUserIdentityPolicy,
    ],
    None,
]:
    """Capture native identity validation before module globals can be replaced."""
    native_probe = service_identity.OsIdentityProbe()
    native_type = type(native_probe)
    effective_uid = native_type.effective_uid
    effective_gid = native_type.effective_gid
    inspect = native_type.inspect
    groups_for_uid = native_type.groups_for_uid
    validate_service = service_identity.validate_service_topology
    validate_local_user = service_identity.validate_local_user_topology

    class CapturedNativeProbe:
        __slots__ = ()

        def effective_uid(self) -> int:
            return effective_uid(native_probe)

        def effective_gid(self) -> int:
            return effective_gid(native_probe)

        def inspect(self, path: Path) -> service_identity.FileFacts:
            return inspect(native_probe, path)

        def groups_for_uid(self, uid: int) -> frozenset[int]:
            return groups_for_uid(native_probe, uid)

    probe = CapturedNativeProbe()

    def validate_topology(
        daemon: _RigDaemonBase,
        runtime: PrivateRuntimeDirectory,
        identity_policy: ServiceIdentityPolicy | LocalUserIdentityPolicy,
    ) -> None:
        if isinstance(identity_policy, LocalUserIdentityPolicy):
            validate_local_user(runtime, daemon.address, identity_policy, probe)
        else:
            validate_service(runtime, daemon.address, identity_policy, probe)

    return validate_topology


class _DurableChildDaemon(_RigDaemonBase):
    """Child-process-only durable server; never returned to a launcher."""

    __slots__ = ()
    _create_request_handler = _production_request_handler_method()
    _validate_durable_topology = _production_topology_validation_method()

    def start(self) -> None:
        self._start_local()


class RigDaemon(_RigDaemonBase):
    """Sealed production daemon using only the definition-time native resolver."""

    __slots__ = ()
    _create_request_handler = _production_request_handler_method()
    _validate_durable_topology = _production_topology_validation_method()

    def start(self) -> None:
        self._start()

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("RigDaemon is sealed")


del _production_request_handler_method
del _production_topology_validation_method
