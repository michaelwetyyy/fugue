"""Non-production launch handle for socket-authenticated durable tests."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
from functools import cache
from pathlib import Path

from oc_rig.daemon.identity import ServiceIdentityPolicy
from oc_rig.daemon.security import PrivateSocketPath
from oc_rig.daemon.server import (
    PinnedExecutable,
    RigdChildArtifact,
    _read_child_status,
    _stop_child_process,
    _verify_ready_socket,
)
from oc_rig.store.runtime import PrivateRuntimeDirectory


_NATIVE_BOOTSTRAP_SOURCE = r"""
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif

static DIR *open_descriptor_directory(void) {
#if defined(__APPLE__)
    return opendir("/dev/fd");
#elif defined(__linux__)
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) directory = opendir("/dev/fd");
    return directory;
#else
#error unsupported test bootstrap platform
#endif
}

static int sweep_descriptor_directory(void) {
    DIR *directory = open_descriptor_directory();
    if (directory == NULL) _exit(120);
    int enumeration_fd = dirfd(directory);
    if (enumeration_fd < 0) _exit(120);
    int found = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) _exit(120);
            break;
        }
        char *end = NULL;
        errno = 0;
        long candidate = strtol(entry->d_name, &end, 10);
        if (errno != 0 || end == entry->d_name || *end != '\0') continue;
        if (candidate <= 5 || candidate > INT_MAX || candidate == enumeration_fd) continue;
        found = 1;
        if (close((int)candidate) != 0 && errno != EBADF) _exit(120);
    }
    if (closedir(directory) != 0) _exit(120);
    return found;
}

static void close_tail(void) {
#if defined(__linux__) && defined(SYS_close_range)
    (void)syscall(SYS_close_range, 6U, ~0U, 0U);
#elif defined(F_MAXFD)
    int maximum = fcntl(0, F_MAXFD);
    if (maximum < 0) _exit(120);
    for (int descriptor = 6; descriptor <= maximum; ++descriptor) {
        (void)close(descriptor);
    }
#endif
    /* Enumeration is both the portable fallback and the mandatory proof that
       sparse descriptors above a lowered RLIMIT were not missed. */
    int empty_passes = 0;
    while (empty_passes < 2) {
        if (sweep_descriptor_directory()) {
            empty_passes = 0;
        } else {
            ++empty_passes;
        }
    }
}

int main(int argc, char **argv) {
    close_tail();
    if (argc != 5 || strcmp(argv[1], "--oc-rig-bootstrap-v1") != 0) _exit(121);
    if (fcntl(5, F_SETFD, FD_CLOEXEC) != 0) _exit(122);
    char *child_argv[] = {argv[3], "-I", "-B", argv[4], NULL};
    if (strcmp(argv[2], "descriptor") == 0) {
        if (fcntl(3, F_SETFD, FD_CLOEXEC) != 0) _exit(123);
    } else if (strcmp(argv[2], "macos-path") == 0) {
        (void)close(3);
        (void)close(4);
    } else {
        _exit(124);
    }
    execv(argv[3], child_argv);
    _exit(125);
}
"""


def modeled_bootstrap_strategy(platform: str) -> str:
    """Test-only pure model of the sealed production platform allowlist."""
    if platform == "darwin":
        return "macos-path"
    if platform == "linux":
        return "descriptor"
    raise ValueError("unsupported rigd bootstrap platform")


@cache
def descriptor_execution_supported() -> bool:
    """Return whether this kernel permits executable ``/dev/fd`` paths."""
    descriptor = os.open(sys.executable, os.O_RDONLY)
    try:
        try:
            pid = os.posix_spawn(
                f"/dev/fd/{descriptor}",
                (f"/dev/fd/{descriptor}", "-I", "-c", "pass"),
                {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            )
        except OSError:
            return False
        _, status = os.waitpid(pid, 0)
        return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    finally:
        os.close(descriptor)


def _pin(path: Path) -> PinnedExecutable:
    details = path.lstat()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return PinnedExecutable(
        path,
        digest,
        details.st_dev,
        details.st_ino,
        details.st_uid,
        details.st_mode & 0o777,
        details.st_size,
    )


def provision_child_artifact(
    approved_root: Path,
    *,
    helper_prelude: str = "",
    native_bootstrap_source: str = _NATIVE_BOOTSTRAP_SOURCE,
) -> RigdChildArtifact:
    """Build an explicit pinned bootstrap solely for isolated tests."""
    artifact_root = approved_root / "test-rigd-artifact"
    artifact_root.mkdir(mode=0o700, exist_ok=True)
    artifact_root.chmod(0o700)
    interpreter = artifact_root / "python"
    helper = artifact_root / "rigd-child.py"
    bootstrap = artifact_root / "rigd-native-bootstrap"
    if not bootstrap.exists():
        source_path = approved_root / "test-rigd-native-bootstrap.c"
        source_path.write_text(native_bootstrap_source, encoding="utf-8")
        try:
            subprocess.run(
                [
                    "/usr/bin/cc",
                    "-Os",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(source_path),
                    "-o",
                    str(bootstrap),
                ],
                check=True,
                env={"PATH": "/usr/bin:/bin", "TMPDIR": str(approved_root)},
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            bootstrap.chmod(0o500)
        finally:
            source_path.unlink(missing_ok=True)
    if not interpreter.exists():
        shutil.copyfile(sys.executable, interpreter)
        interpreter.chmod(0o500)
    if not helper.exists() or helper_prelude:
        source = Path(__file__).resolve().parents[2] / "src"
        if helper.exists():
            helper.chmod(0o700)
        helper.write_text(
            "import os, sys\n"
            f"os.chdir({str(artifact_root)!r})\n"
            f"{helper_prelude}\n"
            f"sys.path.insert(0, {str(source)!r})\n"
            "from oc_rig.daemon.child import main\n"
            "raise SystemExit(main())\n",
            encoding="utf-8",
        )
        helper.chmod(0o500)
    return RigdChildArtifact(
        artifact_root,
        _pin(bootstrap),
        _pin(helper),
        _pin(interpreter),
    )


class ModeledDurableDaemon:
    __slots__ = (
        "address",
        "connection_timeout",
        "identity_policy",
        "max_frame_bytes",
        "max_idempotency_entries",
        "_mode",
        "process",
        "runtime",
    )

    def __init__(
        self,
        address: PrivateSocketPath,
        *,
        runtime: PrivateRuntimeDirectory,
        identity_policy: ServiceIdentityPolicy,
        max_frame_bytes: int = 1024 * 1024,
        max_idempotency_entries: int = 4096,
        connection_timeout: float = 5.0,
        mode: str = "normal",
    ):
        self.address = address
        self.runtime = runtime
        self.identity_policy = identity_policy
        self.max_frame_bytes = max_frame_bytes
        self.max_idempotency_entries = max_idempotency_entries
        self.connection_timeout = connection_timeout
        self.process: subprocess.Popen[bytes] | None = None
        self._mode = mode

    @property
    def child_pid(self) -> int | None:
        if self.process is None or self.process.poll() is not None:
            return None
        return self.process.pid

    def start(self) -> None:
        if self.process is not None:
            raise RuntimeError("test daemon already started")
        fixture = Path(__file__).with_name("durable_daemon_child.py").resolve(strict=True)
        project = fixture.parents[2]
        environment = dict(os.environ)
        environment["OC_RIG_TEST_CLIENT_UID"] = str(
            min(self.identity_policy.allowed_client_uids)
        )
        environment["OC_RIG_TEST_DAEMON_MODE"] = self._mode
        environment["OC_RIG_TEST_DATABASE"] = str(self.runtime.database)
        source = str(project / "src")
        environment["PYTHONPATH"] = os.pathsep.join(
            value for value in (source, environment.get("PYTHONPATH", "")) if value
        )
        process = subprocess.Popen(
            [sys.executable, str(fixture)],
            executable=sys.executable,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            close_fds=True,
            start_new_session=True,
        )
        self.process = process
        try:
            public_configuration = {
                "allowed_client_uids": sorted(
                    self.identity_policy.allowed_client_uids
                ),
                "approved_root": str(self.runtime.approved_root),
                "artifact_root": str(self.runtime.approved_root),
                "bootstrap_fds": [],
                "bootstrap_hash": "0" * 64,
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
                ).encode()
            ).hexdigest()
            nonce = secrets.token_hex(32)
            configuration = dict(public_configuration)
            configuration["configuration_hash"] = topology_hash
            configuration["readiness_nonce"] = nonce
            assert process.stdin is not None
            process.stdin.write(
                json.dumps(
                    configuration, sort_keys=True, separators=(",", ":")
                ).encode()
                + b"\n"
            )
            process.stdin.flush()
            status = _read_child_status(
                process, timeout=self.connection_timeout + 5.0
            )
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
                    else "test durable child failed to start"
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
        if process is not None:
            _stop_child_process(process)

    close = shutdown
