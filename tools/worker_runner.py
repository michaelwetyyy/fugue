#!/usr/bin/env python3
"""Fail-closed, isolated runner for synthetic Fugue worker exercises.

This module is deliberately outside the installed ``oc_rig`` package.  It is a
development foundation, not a live controller integration.  A caller must
explicitly arm each runner, provide an executable, allow the repository root,
and inject the command adapter that performs process creation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol, Sequence


SAFE_CLASSIFICATIONS = frozenset(
    {"development", "non-sensitive", "non_sensitive", "public", "synthetic", "test"}
)
SENSITIVE_KEY_PARTS = frozenset(
    {
        "api_key",
        "authorization",
        "browser_profile",
        "cookie",
        "credential",
        "password",
        "private_key",
        "secret",
        "token",
        "transcript",
    }
)
SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*\S+", re.I),
    re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
)
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DEFAULT_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


class WorkerRunnerError(RuntimeError):
    """Base class for fail-closed runner errors."""


class ConfigurationError(WorkerRunnerError):
    """The runner was not explicitly and safely configured."""


class PacketRejected(WorkerRunnerError):
    """The task packet was not demonstrably non-sensitive."""


class RepositoryRejected(WorkerRunnerError):
    """The repository was outside policy or was not clean."""


class CancellationToken:
    """Thread-safe cooperative cancellation shared with a command adapter."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


@dataclass(frozen=True)
class CommandRequest:
    argv: tuple[str, ...]
    cwd: Path
    env: Mapping[str, str]
    timeout_seconds: float
    startup_ack_path: Path | None = None
    startup_timeout_seconds: float = 10.0


@dataclass(frozen=True)
class CommandOutcome:
    returncode: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    cancelled: bool = False
    startup_acknowledged: bool = False
    startup_timed_out: bool = False
    startup_error: str | None = None
    launch_error: str | None = None
    duration_seconds: float = 0.0


class CommandAdapter(Protocol):
    """The sole process-launch boundary used by :class:`WorkerRunner`."""

    def execute(
        self,
        request: CommandRequest,
        cancellation: CancellationToken,
    ) -> CommandOutcome: ...


@dataclass(frozen=True)
class ScopedPath:
    relative: str
    absolute: Path
    is_directory: bool


@dataclass(frozen=True)
class SandboxPolicy:
    repository: Path
    run_directory: Path
    executable: Path
    scope: tuple[ScopedPath, ...]
    profile_path: Path


class MacOSSandboxExecAdapter:
    """Kernel-enforced filesystem containment through macOS ``sandbox-exec``."""

    _PINNED_EXECUTABLE = Path("/usr/bin/sandbox-exec")

    @property
    def name(self) -> str:
        return "macos-sandbox-exec"

    def ensure_enforceable(self) -> None:
        executable = self._resolved_executable()
        if (
            sys.platform != "darwin"
            or not executable.is_file()
            or not os.access(executable, os.X_OK)
        ):
            raise ConfigurationError(
                "armed execution requires an available enforceable sandbox adapter"
            )

    def wrap(self, request: CommandRequest, policy: SandboxPolicy) -> CommandRequest:
        self.ensure_enforceable()
        executable = self._resolved_executable()
        profile = _macos_sandbox_profile(policy)
        _atomic_write(policy.profile_path, profile.encode("utf-8"))
        return CommandRequest(
            argv=(
                str(executable),
                "-f",
                str(policy.profile_path),
                *request.argv,
            ),
            cwd=request.cwd,
            env=request.env,
            timeout_seconds=request.timeout_seconds,
            startup_ack_path=request.startup_ack_path,
            startup_timeout_seconds=request.startup_timeout_seconds,
        )

    def _resolved_executable(self) -> Path:
        try:
            resolved = self._PINNED_EXECUTABLE.resolve(strict=True)
        except OSError as error:
            raise ConfigurationError(
                "the pinned macOS sandbox executable is unavailable"
            ) from error
        if resolved != self._PINNED_EXECUTABLE:
            raise ConfigurationError(
                "the pinned macOS sandbox executable must not be redirected"
            )
        return resolved


class SubprocessCommandAdapter:
    """Local adapter with process-group timeout and cancellation cleanup."""

    def __init__(self, *, terminate_grace_seconds: float = 0.25) -> None:
        if terminate_grace_seconds <= 0:
            raise ValueError("terminate_grace_seconds must be positive")
        self._terminate_grace_seconds = terminate_grace_seconds

    def execute(
        self,
        request: CommandRequest,
        cancellation: CancellationToken,
    ) -> CommandOutcome:
        started = time.monotonic()
        if cancellation.cancelled:
            return CommandOutcome(returncode=None, cancelled=True)

        try:
            process = subprocess.Popen(
                request.argv,
                cwd=request.cwd,
                env=dict(request.env),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as error:
            return CommandOutcome(
                returncode=None,
                launch_error=f"{type(error).__name__}: {error}",
                duration_seconds=time.monotonic() - started,
            )

        startup_acknowledged = request.startup_ack_path is None
        startup_timed_out = False
        startup_error = None
        timed_out = False
        cancelled = False
        process_finished = False
        stdout = b""
        stderr = b""

        if request.startup_ack_path is not None:
            startup_deadline = time.monotonic() + request.startup_timeout_seconds
            while True:
                if request.startup_ack_path.exists():
                    startup_acknowledged = True
                    break
                if cancellation.cancelled:
                    cancelled = True
                    stdout, stderr = self._terminate(process)
                    break
                remaining = startup_deadline - time.monotonic()
                if remaining <= 0:
                    startup_timed_out = True
                    stdout, stderr = self._terminate(process)
                    break
                try:
                    stdout, stderr = process.communicate(timeout=min(remaining, 0.05))
                    process_finished = True
                    if request.startup_ack_path.exists():
                        startup_acknowledged = True
                    else:
                        startup_error = "process exited before startup acknowledgement"
                    break
                except subprocess.TimeoutExpired:
                    continue

        deadline = time.monotonic() + request.timeout_seconds
        while True:
            if not startup_acknowledged or process_finished:
                break
            if cancellation.cancelled:
                cancelled = True
                stdout, stderr = self._terminate(process)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                stdout, stderr = self._terminate(process)
                break
            try:
                stdout, stderr = process.communicate(timeout=min(remaining, 0.05))
                break
            except subprocess.TimeoutExpired:
                continue

        return CommandOutcome(
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            cancelled=cancelled,
            startup_acknowledged=startup_acknowledged,
            startup_timed_out=startup_timed_out,
            startup_error=startup_error,
            duration_seconds=time.monotonic() - started,
        )

    def _terminate(self, process: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            return process.communicate(timeout=self._terminate_grace_seconds)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            return process.communicate()


@dataclass(frozen=True)
class RunnerConfig:
    runtime_root: Path
    allowed_repository_roots: tuple[Path, ...]
    armed: bool = False
    executable: Path | None = None
    executable_args: tuple[str, ...] = ()
    timeout_seconds: float = 300.0
    startup_timeout_seconds: float = 10.0
    port: int | None = None
    namespace: str | None = None
    max_packet_bytes: int = 64 * 1024


@dataclass(frozen=True)
class WorkerRunResult:
    status: str
    run_id: str
    run_directory: Path
    result_path: Path
    returncode: int | None
    port: int
    namespace: str


@dataclass
class WorkerRunner:
    config: RunnerConfig
    command_adapter: CommandAdapter

    def run(
        self,
        packet: Mapping[str, Any],
        repository: Path,
        *,
        cancellation: CancellationToken | None = None,
        run_id: str | None = None,
    ) -> WorkerRunResult:
        """Validate, isolate, execute, and atomically record one worker run."""

        canonical_packet = _validate_packet(packet, self.config.max_packet_bytes)
        repository = _validate_repository_path(
            repository, self.config.allowed_repository_roots
        )
        executable = _validate_execution_config(self.config)
        scope = _normalize_scope(canonical_packet.get("scope"), repository)
        canonical_packet["scope"] = [entry.relative for entry in scope]
        sandbox_adapter = MacOSSandboxExecAdapter()
        sandbox_adapter.ensure_enforceable()
        runtime_root = _safe_creation_path(self.config.runtime_root)
        if _is_within(runtime_root, repository):
            raise ConfigurationError("runtime_root must not be inside the repository")
        if any(_is_within(runtime_root, path) for path in _prohibited_live_paths()):
            raise ConfigurationError("runtime_root is a prohibited live-state location")

        run_id = run_id or uuid.uuid4().hex
        _validate_identifier(run_id, "run_id")
        namespace = (
            self.config.namespace
            if self.config.namespace is not None
            else f"oc-rig-v2-{run_id}"
        )
        if not isinstance(namespace, str):
            raise ConfigurationError("namespace must be a string")
        _validate_identifier(namespace, "namespace")
        port = (
            self.config.port
            if self.config.port is not None
            else 49152 + secrets.randbelow(16384)
        )
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 1024 <= port <= 65535
        ):
            raise ConfigurationError("port must be between 1024 and 65535")
        if self.config.timeout_seconds <= 0:
            raise ConfigurationError("timeout_seconds must be positive")
        if self.config.startup_timeout_seconds <= 0:
            raise ConfigurationError("startup_timeout_seconds must be positive")

        run_directory = runtime_root / f"run-{run_id}"
        _prepare_runtime_root(runtime_root)
        _mkdir_private(run_directory, exist_ok=False)
        home = run_directory / "home"
        state = run_directory / "state"
        output = run_directory / "output"
        cache = run_directory / "cache"
        config_home = run_directory / "config"
        temporary = run_directory / "tmp"
        for directory in (home, state, output, cache, config_home, temporary):
            _mkdir_private(directory, exist_ok=False)

        packet_path = state / "task-packet.json"
        startup_ack_path = state / "worker-started.ack"
        sandbox_profile_path = state / "worker-sandbox.sb"
        packet_bytes = json.dumps(
            canonical_packet, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        _atomic_write(packet_path, packet_bytes)

        environment = {
            "HOME": str(home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NO_COLOR": "1",
            "PATH": DEFAULT_PATH,
            "TMPDIR": str(temporary),
            "XDG_CACHE_HOME": str(cache),
            "XDG_CONFIG_HOME": str(config_home),
            "XDG_DATA_HOME": str(state / "data"),
            "XDG_STATE_HOME": str(state),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "OC_RIG_EXECUTION_MODE": "isolated-development",
            "OC_RIG_NAMESPACE": namespace,
            "OC_RIG_OUTPUT_DIR": str(output),
            "OC_RIG_PORT": str(port),
            "OC_RIG_REPOSITORY": str(repository),
            "OC_RIG_RUN_DIRECTORY": str(run_directory),
            "OC_RIG_RUN_ID": run_id,
            "OC_RIG_TASK_PACKET": str(packet_path),
            "OC_RIG_STARTUP_ACK": str(startup_ack_path),
        }
        cancellation = cancellation or CancellationToken()

        clean_check = self.command_adapter.execute(
            CommandRequest(
                argv=(
                    "/usr/bin/git",
                    "-C",
                    str(repository),
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=all",
                ),
                cwd=repository,
                env=environment,
                timeout_seconds=min(self.config.timeout_seconds, 10.0),
            ),
            cancellation,
        )
        if (
            clean_check.returncode != 0
            or clean_check.stdout.strip()
            or clean_check.timed_out
            or clean_check.cancelled
            or clean_check.launch_error
        ):
            reason = "repository must be a clean Git worktree"
            if clean_check.cancelled:
                reason = "repository validation was cancelled"
            raise RepositoryRejected(reason)

        _verify_scope_link_safety(scope)

        started_at = datetime.now(timezone.utc)
        worker_request = CommandRequest(
            argv=(str(executable), *self.config.executable_args),
            cwd=repository,
            env=environment,
            timeout_seconds=self.config.timeout_seconds,
            startup_ack_path=startup_ack_path,
            startup_timeout_seconds=self.config.startup_timeout_seconds,
        )
        request = sandbox_adapter.wrap(
            worker_request,
            SandboxPolicy(
                repository=repository,
                run_directory=run_directory,
                executable=executable,
                scope=scope,
                profile_path=sandbox_profile_path,
            ),
        )
        outcome = self.command_adapter.execute(request, cancellation)
        finished_at = datetime.now(timezone.utc)

        stdout_path = output / "stdout.bin"
        stderr_path = output / "stderr.bin"
        _atomic_write(stdout_path, outcome.stdout)
        _atomic_write(stderr_path, outcome.stderr)
        status = _status_for(outcome)
        result_path = output / "result.json"
        result_document = {
            "schema_version": 1,
            "status": status,
            "run_id": run_id,
            "task_id": canonical_packet["task_id"],
            "classification": canonical_packet["classification"],
            "returncode": outcome.returncode,
            "timed_out": outcome.timed_out,
            "cancelled": outcome.cancelled,
            "startup_acknowledged": outcome.startup_acknowledged,
            "startup_timed_out": outcome.startup_timed_out,
            "startup_error": outcome.startup_error,
            "launch_error": outcome.launch_error,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_seconds": outcome.duration_seconds,
            "provenance": {
                "repository": str(repository),
                "executable": str(executable),
                "argv": list(worker_request.argv),
                "sandbox_argv": list(request.argv),
                "sandbox_adapter": sandbox_adapter.name,
                "declared_scope": [entry.relative for entry in scope],
                "namespace": namespace,
                "port": port,
                "packet_sha256": hashlib.sha256(packet_bytes).hexdigest(),
                "stdout_sha256": hashlib.sha256(outcome.stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(outcome.stderr).hexdigest(),
                "environment_keys": sorted(environment),
                "command_adapter": type(self.command_adapter).__name__,
            },
        }
        _atomic_write(
            result_path,
            json.dumps(result_document, sort_keys=True, indent=2).encode("utf-8")
            + b"\n",
        )
        return WorkerRunResult(
            status=status,
            run_id=run_id,
            run_directory=run_directory,
            result_path=result_path,
            returncode=outcome.returncode,
            port=port,
            namespace=namespace,
        )


def _status_for(outcome: CommandOutcome) -> str:
    if outcome.cancelled:
        return "cancelled"
    if outcome.launch_error:
        return "launch_error"
    if outcome.startup_timed_out:
        return "startup_timed_out"
    if outcome.startup_error or not outcome.startup_acknowledged:
        return "startup_failed"
    if outcome.timed_out:
        return "timed_out"
    if outcome.returncode == 0:
        return "succeeded"
    return "failed"


def _validate_packet(packet: Mapping[str, Any], max_bytes: int) -> dict[str, Any]:
    if not isinstance(packet, Mapping):
        raise PacketRejected("task packet must be a JSON object")
    try:
        normalized = json.loads(json.dumps(packet, ensure_ascii=False))
    except (TypeError, ValueError) as error:
        raise PacketRejected("task packet must contain only JSON values") from error
    encoded = json.dumps(normalized, ensure_ascii=False).encode("utf-8")
    if len(encoded) > max_bytes:
        raise PacketRejected("task packet exceeds the configured size limit")

    task_id = normalized.get("task_id")
    classification = normalized.get("classification")
    instructions = normalized.get("instructions")
    if not isinstance(task_id, str):
        raise PacketRejected("task_id is required")
    _validate_identifier(task_id, "task_id", error_type=PacketRejected)
    if not isinstance(classification, str) or classification.casefold() not in SAFE_CLASSIFICATIONS:
        raise PacketRejected("classification is not explicitly non-sensitive")
    if not isinstance(instructions, str) or not instructions.strip():
        raise PacketRejected("non-empty instructions are required")
    _reject_sensitive_content(normalized)
    normalized["classification"] = classification.casefold().replace("-", "_")
    return normalized


def _reject_sensitive_content(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).casefold().replace("-", "_")
            if any(part in lowered for part in SENSITIVE_KEY_PARTS):
                raise PacketRejected(f"sensitive field is prohibited: {'.'.join((*path, str(key)))}")
            _reject_sensitive_content(child, (*path, str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_sensitive_content(child, (*path, str(index)))
    elif isinstance(value, str):
        if "\x00" in value:
            raise PacketRejected("NUL bytes are prohibited in task packets")
        if any(pattern.search(value) for pattern in SENSITIVE_VALUE_PATTERNS):
            raise PacketRejected("task packet appears to contain secret material")


def _validate_repository_path(repository: Path, allowed_roots: Sequence[Path]) -> Path:
    if not allowed_roots:
        raise ConfigurationError("at least one allowed_repository_root is required")
    try:
        repository = Path(repository).resolve(strict=True)
    except OSError as error:
        raise RepositoryRejected("repository does not exist") from error
    if not repository.is_dir():
        raise RepositoryRejected("repository must be a directory")
    resolved_roots = []
    for root in allowed_roots:
        try:
            resolved_roots.append(Path(root).resolve(strict=True))
        except OSError as error:
            raise ConfigurationError(f"allowed repository root does not exist: {root}") from error
    if not any(_is_within(repository, root) for root in resolved_roots):
        raise RepositoryRejected("repository is outside the explicit allowlist")

    if any(_is_within(repository, path) for path in _prohibited_live_paths()):
        raise RepositoryRejected("repository path is a prohibited live-state location")
    return repository


def _normalize_scope(value: Any, repository: Path) -> tuple[ScopedPath, ...]:
    if not isinstance(value, list) or not value:
        raise PacketRejected("scope must be a non-empty list of relative paths")
    normalized: dict[str, ScopedPath] = {}
    for item in value:
        if not isinstance(item, str) or not item:
            raise PacketRejected("every scope entry must be a non-empty string")
        if "\x00" in item or "\\" in item:
            raise PacketRejected("scope entries contain prohibited path characters")
        pure = PurePosixPath(item)
        if pure.is_absolute() or item.startswith("/"):
            raise PacketRejected("scope entries must be relative paths")
        raw_parts = item.split("/")
        if any(part in {"", ".", ".."} for part in raw_parts):
            raise PacketRejected("scope entries may not contain empty, dot, or traversal parts")
        if raw_parts[0] == ".git":
            raise PacketRejected("Git administrative paths may not be delegated")

        candidate = repository.joinpath(*pure.parts)
        cursor = candidate
        while cursor != repository:
            if cursor.is_symlink():
                raise PacketRejected(f"scope entry traverses a symlink: {item}")
            cursor = cursor.parent
        resolved = candidate.resolve(strict=False)
        if not _is_within(resolved, repository):
            raise PacketRejected(f"scope entry escapes the repository: {item}")
        if candidate.exists() and not (candidate.is_file() or candidate.is_dir()):
            raise PacketRejected(f"scope entry is not a regular file or directory: {item}")
        relative = pure.as_posix()
        normalized[relative] = ScopedPath(
            relative=relative,
            absolute=resolved,
            is_directory=candidate.is_dir(),
        )
    scope = tuple(normalized[key] for key in sorted(normalized))
    _verify_scope_link_safety(scope)
    return scope


def _verify_scope_link_safety(scope: Sequence[ScopedPath]) -> None:
    for entry in scope:
        if not entry.absolute.exists():
            continue
        _verify_scoped_node(entry.absolute, entry.relative)


def _verify_scoped_node(path: Path, display: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PacketRejected(f"unable to inspect declared scope path: {display}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise PacketRejected(f"declared scope contains a symlink: {display}")
    if stat.S_ISREG(metadata.st_mode):
        if metadata.st_nlink != 1:
            raise PacketRejected(
                f"declared scope contains a multi-link regular file: {display}"
            )
        return
    if not stat.S_ISDIR(metadata.st_mode):
        raise PacketRejected(f"declared scope contains a non-regular node: {display}")

    try:
        children = list(os.scandir(path))
    except OSError as error:
        raise PacketRejected(f"unable to inspect declared scope directory: {display}") from error
    for child in children:
        child_display = f"{display}/{child.name}"
        if child.name == ".git":
            raise PacketRejected(
                f"declared scope contains Git administrative data: {child_display}"
            )
        _verify_scoped_node(Path(child.path), child_display)


def _macos_sandbox_profile(policy: SandboxPolicy) -> str:
    read_rules = [
        _sandbox_literal(policy.repository),
        _sandbox_literal(policy.executable),
        _sandbox_subpath(policy.run_directory),
        _sandbox_literal(Path("/dev/null")),
        _sandbox_literal(Path("/dev/urandom")),
    ]
    for root in (
        Path("/usr/bin"),
        Path("/bin"),
        Path("/sbin"),
    ):
        if root.exists():
            read_rules.append(_sandbox_subpath(root.resolve()))
    for path in (
        Path("/private/etc/localtime"),
        Path("/private/var/select/sh"),
    ):
        if path.exists():
            read_rules.append(_sandbox_literal(path))
            resolved = path.resolve()
            if resolved != path:
                read_rules.append(_sandbox_literal(resolved))

    write_rules = [
        _sandbox_subpath(policy.run_directory),
        _sandbox_literal(Path("/dev/null")),
    ]
    for entry in policy.scope:
        matcher = (
            _sandbox_subpath(entry.absolute)
            if entry.is_directory
            else _sandbox_literal(entry.absolute)
        )
        read_rules.append(matcher)
        write_rules.append(matcher)

    prohibited = "\n".join(
        f"  {_sandbox_subpath(path)}"
        for path in _prohibited_live_paths()
    )
    reads = "\n".join(f"  {rule}" for rule in dict.fromkeys(read_rules))
    writes = "\n".join(f"  {rule}" for rule in dict.fromkeys(write_rules))
    return (
        "(version 1)\n"
        "(deny default)\n"
        "(import \"system.sb\")\n"
        "(deny network*)\n"
        "(deny file-write* (subpath \"/cores\"))\n"
        "; Explicit live-state denial; all other home and host paths remain denied by default.\n"
        "(deny file-read* file-write*\n"
        f"{prohibited})\n"
        "(allow process*)\n"
        "(allow signal (target same-sandbox))\n"
        "(allow sysctl-read)\n"
        "(allow file-read*\n"
        f"{reads})\n"
        "(allow file-write*\n"
        f"{writes})\n"
    )


def _sandbox_literal(path: Path) -> str:
    return f"(literal {json.dumps(str(path))})"


def _sandbox_subpath(path: Path) -> str:
    return f"(subpath {json.dumps(str(path))})"


def _validate_execution_config(config: RunnerConfig) -> Path:
    if not config.armed:
        raise ConfigurationError("runner is disarmed; explicit armed=True is required")
    if config.executable is None:
        raise ConfigurationError("an explicit executable is required")
    executable = Path(config.executable)
    if not executable.is_absolute():
        raise ConfigurationError("executable must be an absolute path")
    try:
        executable = executable.resolve(strict=True)
    except OSError as error:
        raise ConfigurationError("executable does not exist") from error
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ConfigurationError("executable must be an executable regular file")
    if any(_is_within(executable, path) for path in _prohibited_live_paths()):
        raise ConfigurationError("executable is inside a prohibited live-state location")
    if any("\x00" in argument for argument in config.executable_args):
        raise ConfigurationError("executable arguments may not contain NUL bytes")
    return executable


def _safe_creation_path(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute():
        raise ConfigurationError("runtime_root must be absolute")
    missing: list[str] = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor.name)
        if cursor.parent == cursor:
            raise ConfigurationError("runtime_root has no existing ancestor")
        cursor = cursor.parent
    resolved = cursor.resolve(strict=True)
    for component in reversed(missing):
        resolved /= component
    return resolved


def _mkdir_private(path: Path, *, exist_ok: bool) -> None:
    path.mkdir(mode=0o700, parents=False, exist_ok=exist_ok)
    path.chmod(0o700)


def _prepare_runtime_root(path: Path) -> None:
    missing = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    for directory in reversed(missing):
        _mkdir_private(directory, exist_ok=False)
    path.chmod(0o700)


def _atomic_write(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _prohibited_live_paths() -> tuple[Path, ...]:
    home = Path.home().resolve()
    return (
        home / ".config" / "opencode",
        home / ".local" / "share" / "opencode",
        home / "Library" / "Application Support" / "opencode",
    )


def _validate_identifier(
    value: str,
    label: str,
    *,
    error_type: type[WorkerRunnerError] = ConfigurationError,
) -> None:
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise error_type(f"{label} must match {IDENTIFIER_PATTERN.pattern}")


def _parse_packet(path: Path) -> Mapping[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise PacketRejected("packet file must contain a JSON object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", required=True, type=Path)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--allow-root", required=True, action="append", type=Path)
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--executable", type=Path)
    parser.add_argument("--arg", action="append", default=[])
    parser.add_argument("--arm", action="store_true")
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--startup-timeout", type=float, default=10.0)
    parser.add_argument("--port", type=int)
    parser.add_argument("--namespace")
    parser.add_argument("--run-id")
    arguments = parser.parse_args(argv)
    try:
        runner = WorkerRunner(
            RunnerConfig(
                runtime_root=arguments.runtime_root,
                allowed_repository_roots=tuple(arguments.allow_root),
                armed=arguments.arm,
                executable=arguments.executable,
                executable_args=tuple(arguments.arg),
                timeout_seconds=arguments.timeout,
                startup_timeout_seconds=arguments.startup_timeout,
                port=arguments.port,
                namespace=arguments.namespace,
            ),
            SubprocessCommandAdapter(),
        )
        result = runner.run(
            _parse_packet(arguments.packet),
            arguments.repo,
            run_id=arguments.run_id,
        )
    except (OSError, ValueError, WorkerRunnerError, json.JSONDecodeError) as error:
        print(f"worker-runner: {error}", file=sys.stderr)
        return 2
    print(result.result_path)
    return 0 if result.status == "succeeded" else 1


if __name__ == "__main__":
    raise SystemExit(main())
