"""Isolated synthetic daemon launcher bound to a verified wheel."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from oc_rig.daemon.identity import ServiceIdentityPolicy
from oc_rig.daemon.security import PrivateSocketPath
from oc_rig.daemon.server import (
    _read_child_status,
    _stop_child_process,
    _verify_ready_socket,
)
from oc_rig.migration.guarded import (
    GuardedQuarantineError,
    QuarantinedDirectory,
    directory_identity,
    quarantine_directory,
)
from oc_rig.migration.release import ReleaseArtifact, verify_release_descriptors
from oc_rig.store.runtime import PrivateRuntimeDirectory


class WheelCandidateDaemon:
    """Run rigd from a verified wheel with no checkout or site-package imports."""

    __slots__ = (
        "address",
        "artifact",
        "before_spawn",
        "candidate_home_evidence",
        "candidate_home_identity",
        "connection_timeout",
        "identity_policy",
        "max_frame_bytes",
        "max_idempotency_entries",
        "process",
        "runtime",
    )

    def __init__(
        self,
        address: PrivateSocketPath,
        *,
        runtime: PrivateRuntimeDirectory,
        identity_policy: ServiceIdentityPolicy,
        artifact: ReleaseArtifact,
        max_frame_bytes: int = 1024 * 1024,
        max_idempotency_entries: int = 4096,
        connection_timeout: float = 5.0,
        before_spawn: Callable[[], None] | None = None,
    ):
        self.address = address
        self.runtime = runtime
        self.identity_policy = identity_policy
        self.artifact = artifact
        self.max_frame_bytes = max_frame_bytes
        self.max_idempotency_entries = max_idempotency_entries
        self.connection_timeout = connection_timeout
        self.before_spawn = before_spawn
        self.candidate_home_evidence: list[QuarantinedDirectory] = []
        self.candidate_home_identity: tuple[int, int, int, int, int] | None = None
        self.process: subprocess.Popen[bytes] | None = None

    @property
    def child_pid(self) -> int | None:
        if self.process is None or self.process.poll() is not None:
            return None
        return self.process.pid

    @staticmethod
    def _identity(details: os.stat_result) -> tuple[int, ...]:
        return (
            details.st_dev,
            details.st_ino,
            details.st_mode,
            details.st_uid,
            details.st_gid,
            details.st_nlink,
            details.st_size,
            details.st_mtime_ns,
            details.st_ctime_ns,
        )

    @classmethod
    def _open_pinned(cls, path: Path) -> int:
        details = path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or path.is_symlink()
            or details.st_nlink != 1
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) != 0o444
        ):
            raise RuntimeError("candidate release path is not an immutable regular file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            if cls._identity(os.fstat(descriptor)) != cls._identity(details):
                raise RuntimeError("candidate release identity changed while opening")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @classmethod
    def _assert_path_pinned(cls, path: Path, descriptor: int) -> None:
        details = path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or path.is_symlink()
            or cls._identity(details) != cls._identity(os.fstat(descriptor))
        ):
            raise RuntimeError("candidate release pathname changed before spawn")

    @staticmethod
    def _sha256_descriptor(descriptor: int) -> str:
        details = os.fstat(descriptor)
        digest = hashlib.sha256()
        offset = 0
        while offset < details.st_size:
            chunk = os.pread(descriptor, min(65536, details.st_size - offset), offset)
            if not chunk:
                raise RuntimeError("candidate release descriptor was truncated")
            digest.update(chunk)
            offset += len(chunk)
        return digest.hexdigest()

    @staticmethod
    def _copy_descriptor(source: int, destination: int) -> int:
        size = os.fstat(source).st_size
        offset = 0
        while offset < size:
            chunk = os.pread(source, min(65536, size - offset), offset)
            if not chunk:
                raise RuntimeError("verified wheel ended during anonymous copy")
            view = memoryview(chunk)
            while view:
                written = os.write(destination, view)
                if written <= 0:
                    raise RuntimeError("anonymous wheel copy stopped early")
                view = view[written:]
            offset += len(chunk)
        return size

    @classmethod
    def _verify_anonymous_copy(
        cls,
        descriptor: int,
        *,
        expected_hash: str,
        expected_size: int,
    ) -> None:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_IMODE(details.st_mode) != 0o400
            or details.st_uid != os.geteuid()
            or details.st_nlink != 0
            or details.st_size != expected_size
            or fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
            != os.O_RDONLY
            or cls._sha256_descriptor(descriptor) != expected_hash
        ):
            raise RuntimeError("anonymous wheel copy does not match verified bytes")

    @classmethod
    def _sealed_memfd_copy(
        cls,
        source: int,
        *,
        expected_hash: str,
        expected_size: int,
    ) -> tuple[int, str] | None:
        seal_names = (
            "F_ADD_SEALS",
            "F_GET_SEALS",
            "F_SEAL_GROW",
            "F_SEAL_SEAL",
            "F_SEAL_SHRINK",
            "F_SEAL_WRITE",
        )
        if not hasattr(os, "memfd_create") or not all(
            hasattr(fcntl, name) for name in seal_names
        ):
            return None
        flags = getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0)
        writable = os.memfd_create("oc-rig-verified-wheel", flags)
        readonly = -1
        try:
            cls._copy_descriptor(source, writable)
            os.fchmod(writable, 0o400)
            seals = (
                fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SEAL
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_WRITE
            )
            fcntl.fcntl(writable, fcntl.F_ADD_SEALS, seals)
            readonly = os.open(f"/proc/self/fd/{writable}", os.O_RDONLY)
            os.close(writable)
            writable = -1
            cls._verify_anonymous_copy(
                readonly,
                expected_hash=expected_hash,
                expected_size=expected_size,
            )
            if fcntl.fcntl(readonly, fcntl.F_GET_SEALS) & seals != seals:
                raise RuntimeError("anonymous wheel memfd is not fully sealed")
            return readonly, "sealed-memfd"
        except BaseException:
            if readonly >= 0:
                os.close(readonly)
            if writable >= 0:
                os.close(writable)
            raise

    @classmethod
    def _anonymous_wheel_copy(
        cls,
        source: int,
        approved_root: Path,
        *,
        expected_hash: str,
    ) -> tuple[int, str]:
        expected_size = os.fstat(source).st_size
        sealed = cls._sealed_memfd_copy(
            source,
            expected_hash=expected_hash,
            expected_size=expected_size,
        )
        if sealed is not None:
            return sealed
        directory = os.open(
            approved_root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        name = f".candidate-wheel-copy-{secrets.token_hex(16)}"
        writable = -1
        readonly = -1
        try:
            writable = os.open(
                name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory,
            )
            cls._copy_descriptor(source, writable)
            os.fsync(writable)
            os.fchmod(writable, 0o400)
            os.close(writable)
            writable = -1
            path_facts = os.stat(name, dir_fd=directory, follow_symlinks=False)
            readonly = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
            if cls._identity(os.fstat(readonly)) != cls._identity(path_facts):
                raise RuntimeError("anonymous wheel copy changed while reopening")
            os.unlink(name, dir_fd=directory)
            cls._verify_anonymous_copy(
                readonly,
                expected_hash=expected_hash,
                expected_size=expected_size,
            )
            return readonly, "unlinked-regular-file"
        except BaseException:
            if readonly >= 0:
                os.close(readonly)
            if writable >= 0:
                os.close(writable)
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(directory)

    def _create_candidate_home(self) -> Path:
        path = self.runtime.approved_root / "candidate-home"
        directory = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.mkdir(path.name, 0o700, dir_fd=directory)
            details = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            self.candidate_home_identity = directory_identity(details)
            if (
                not stat.S_ISDIR(details.st_mode)
                or stat.S_IMODE(details.st_mode) != 0o700
                or details.st_uid != os.geteuid()
            ):
                raise RuntimeError("candidate home is not a private directory")
            return path
        except BaseException:
            if self.candidate_home_identity is not None:
                self._cleanup_candidate_home()
            raise
        finally:
            os.close(directory)

    def _cleanup_candidate_home(self) -> None:
        expected = self.candidate_home_identity
        if expected is None:
            return
        path = self.runtime.approved_root / "candidate-home"
        try:
            evidence = quarantine_directory(
                path,
                expected,
                label="candidate home",
            )
        except GuardedQuarantineError as error:
            if error.evidence is not None:
                self.candidate_home_evidence.append(error.evidence)
            raise
        except FileNotFoundError as error:
            raise RuntimeError("candidate home disappeared before cleanup") from error
        self.candidate_home_evidence.append(evidence)
        self.candidate_home_identity = None

    def start(self) -> None:
        if self.process is not None:
            raise RuntimeError("synthetic wheel candidate is already started")
        approved_root = self.runtime.approved_root.resolve(strict=True)
        for path in (self.artifact.wheel, self.artifact.manifest):
            try:
                path.resolve(strict=True).relative_to(approved_root)
            except ValueError as error:
                raise RuntimeError(
                    "candidate release path escapes the synthetic root"
                ) from error
            if stat.S_IMODE(path.lstat().st_mode) != 0o444:
                raise RuntimeError("candidate release inputs must remain read-only")
        source_wheel_descriptor = self._open_pinned(self.artifact.wheel)
        manifest_descriptor = self._open_pinned(self.artifact.manifest)
        wheel_descriptor = -1
        candidate_home: Path | None = None
        try:
            source_verified = verify_release_descriptors(
                source_wheel_descriptor,
                manifest_descriptor,
                artifact_filename=self.artifact.wheel.name,
            )
            if source_verified.wheel_sha256 != self.artifact.wheel_sha256:
                raise RuntimeError("candidate wheel provenance changed")
            wheel_descriptor, wheel_copy_kind = self._anonymous_wheel_copy(
                source_wheel_descriptor,
                approved_root,
                expected_hash=source_verified.wheel_sha256,
            )
            os.close(source_wheel_descriptor)
            source_wheel_descriptor = -1
            verified = verify_release_descriptors(
                wheel_descriptor,
                manifest_descriptor,
                artifact_filename=self.artifact.wheel.name,
            )
            if verified.wheel_sha256 != source_verified.wheel_sha256:
                raise RuntimeError("anonymous wheel copy provenance changed")
            manifest_sha256 = self._sha256_descriptor(manifest_descriptor)
            if self.before_spawn is not None:
                self.before_spawn()
            self._assert_path_pinned(self.artifact.manifest, manifest_descriptor)
            candidate_home = self._create_candidate_home()
        except BaseException:
            if candidate_home is not None:
                self._cleanup_candidate_home()
            if wheel_descriptor >= 0:
                os.close(wheel_descriptor)
            os.close(manifest_descriptor)
            if source_wheel_descriptor >= 0:
                os.close(source_wheel_descriptor)
            raise
        wheel_import_path = f"/dev/fd/{wheel_descriptor}"
        bootstrap = (
            "import runpy,sys;"
            f"sys.path.insert(0,{wheel_import_path!r});"
            "runpy.run_module('oc_rig.migration.candidate_child',run_name='__main__')"
        )
        environment = {
            "HOME": str(candidate_home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "OC_RIG_SYNTHETIC_CLIENT_UID": str(
                min(self.identity_policy.allowed_client_uids)
            ),
            "OC_RIG_SYNTHETIC_MANIFEST_DESCRIPTOR": str(manifest_descriptor),
            "OC_RIG_SYNTHETIC_MANIFEST_SHA256": manifest_sha256,
            "OC_RIG_SYNTHETIC_ROOT": str(self.runtime.approved_root),
            "OC_RIG_SYNTHETIC_WHEEL_DESCRIPTOR": str(wheel_descriptor),
            "OC_RIG_SYNTHETIC_WHEEL_COPY_KIND": wheel_copy_kind,
            "OC_RIG_SYNTHETIC_WHEEL_FILENAME": self.artifact.wheel.name,
            "OC_RIG_SYNTHETIC_WHEEL_SHA256": verified.wheel_sha256,
            "TMPDIR": str(self.runtime.approved_root.parent),
        }
        try:
            process = subprocess.Popen(
                [sys.executable, "-I", "-S", "-B", "-c", bootstrap],
                executable=sys.executable,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd=self.runtime.approved_root,
                close_fds=True,
                pass_fds=(wheel_descriptor, manifest_descriptor),
                start_new_session=True,
            )
        except BaseException:
            self._cleanup_candidate_home()
            raise
        finally:
            os.close(manifest_descriptor)
            os.close(wheel_descriptor)
        self.process = process
        try:
            public_configuration = {
                "allowed_client_uids": sorted(
                    self.identity_policy.allowed_client_uids
                ),
                "approved_root": str(self.runtime.approved_root),
                "artifact_root": str(self.runtime.approved_root),
                "bootstrap_fds": [wheel_descriptor, manifest_descriptor],
                "bootstrap_hash": verified.wheel_sha256,
                "client_gid": self.identity_policy.client_gid,
                "connection_timeout": self.connection_timeout,
                "database_name": self.runtime.database_name,
                "max_frame_bytes": self.max_frame_bytes,
                "max_idempotency_entries": self.max_idempotency_entries,
                "runtime_root": str(self.runtime.root),
                "service_uid": self.identity_policy.service_uid,
                "socket_approved_root": str(self.address.approved_root),
                "socket_path": str(self.address.socket_path),
                "version": 1,
            }
            topology_hash = hashlib.sha256(
                json.dumps(
                    public_configuration,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            nonce = secrets.token_hex(32)
            configuration = dict(public_configuration)
            configuration["configuration_hash"] = topology_hash
            configuration["readiness_nonce"] = nonce
            assert process.stdin is not None
            process.stdin.write(
                json.dumps(
                    configuration,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )
            process.stdin.flush()
            try:
                status = _read_child_status(
                    process,
                    timeout=self.connection_timeout + 5.0,
                )
            except RuntimeError as error:
                assert process.stderr is not None
                detail = (
                    process.stderr.read(16 * 1024)
                    .decode("utf-8", "replace")
                    .strip()
                )
                process.stderr.close()
                process.stderr = None
                raise RuntimeError(
                    f"synthetic wheel candidate failed before readiness: {detail}"
                ) from error
            if (
                status.get("status") != "ready"
                or status.get("version") != 1
                or status.get("child_pid") != process.pid
                or status.get("configuration_hash") != topology_hash
                or status.get("readiness_nonce") != nonce
            ):
                message = status.get("message")
                raise RuntimeError(
                    message
                    if isinstance(message, str)
                    else "synthetic wheel candidate failed to start"
                )
            _verify_ready_socket(
                self.address,
                status,
                service_uid=self.identity_policy.service_uid,
                client_gid=self.identity_policy.client_gid,
                child_pid=process.pid,
            )
        except BaseException:
            self.shutdown()
            raise

    def shutdown(self) -> None:
        process, self.process = self.process, None
        try:
            if process is not None:
                try:
                    _stop_child_process(process)
                finally:
                    if process.stderr is not None:
                        process.stderr.close()
                        process.stderr = None
        finally:
            self._cleanup_candidate_home()

    close = shutdown
