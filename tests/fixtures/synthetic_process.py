"""Non-durable synthetic adapter fixture; never imported by production code."""

from __future__ import annotations

import atexit
import hashlib
import json
import os
import re
import select
import stat
import struct
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from oc_rig.adapters.models import (
    AdapterDisposition,
    AdapterRequest,
    AdapterResult,
    Cancellation,
    ExecutableProvenance,
    IdentityRecorder,
    ProcessIdentity,
)

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TRANSPORT_ID = re.compile(r"transport-[A-Za-z0-9._:-]{1,127}\Z")
_CONTROL_LIMIT = 4096
_MANIFEST_NAME = ".synthetic-adapter-manifest.json"
_MANIFEST_LIMIT = 4096
_SWEEP_STATE_NAME = ".synthetic-adapter-sweep.json"
_SWEEP_STATE_LIMIT = 64 * 1024
_SWEEP_STATE_ENTRIES = 4096
_SWEEP_SCANS: dict[Path, object] = {}


def _close_sweep_scans() -> None:
    for iterator in _SWEEP_SCANS.values():
        close = getattr(iterator, "close", None)
        if callable(close):
            close()
        else:
            exit_context = getattr(iterator, "__exit__", None)
            if callable(exit_context):
                exit_context(None, None, None)
    _SWEEP_SCANS.clear()


atexit.register(_close_sweep_scans)


class ProcessAdapterConfigurationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SyntheticProcessAdapterConfig:
    executable: Path
    fixture_root: Path
    runtime_root: Path
    timeout_seconds: float = 2.0
    max_frame_bytes: int = 64 * 1024
    max_output_bytes: int = 64 * 1024
    max_executable_bytes: int = 16 * 1024 * 1024
    max_sweep_entries: int = 64

    def __post_init__(self) -> None:
        for field in ("executable", "fixture_root", "runtime_root"):
            value = getattr(self, field)
            if not isinstance(value, Path) or not value.is_absolute():
                raise ProcessAdapterConfigurationError(f"{field} must be an absolute path")
        try:
            self.executable.relative_to(self.fixture_root)
            self.runtime_root.relative_to(self.fixture_root)
        except ValueError as error:
            raise ProcessAdapterConfigurationError(
                "executable and runtime roots must remain inside the explicit fixture root"
            ) from error
        if not 0 < self.timeout_seconds <= 30:
            raise ProcessAdapterConfigurationError("timeout must be between 0 and 30 seconds")
        if not 256 <= self.max_frame_bytes <= 1024 * 1024:
            raise ProcessAdapterConfigurationError("frame limit is outside the safe range")
        if not 256 <= self.max_output_bytes <= 1024 * 1024:
            raise ProcessAdapterConfigurationError("output limit is outside the safe range")
        if not 1024 <= self.max_executable_bytes <= 64 * 1024 * 1024:
            raise ProcessAdapterConfigurationError("executable limit is outside the safe range")
        if not 1 <= self.max_sweep_entries <= 256:
            raise ProcessAdapterConfigurationError("sweep limit is outside the safe range")


def encode_adapter_frame(value: dict[str, object], *, max_bytes: int) -> bytes:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(payload) > max_bytes:
        raise ValueError("adapter frame exceeds configured limit")
    return struct.pack("!I", len(payload)) + payload


class SyntheticProcessAdapter:
    """Explicit fake-process adapter kept wholly outside the package surface."""

    __slots__ = ("config",)

    def __init__(self, config: SyntheticProcessAdapterConfig):
        if not isinstance(config, SyntheticProcessAdapterConfig):
            raise TypeError("synthetic process adapter configuration is required")
        self.config = config

    @property
    def kind(self) -> str:
        return "synthetic-process-fixture"

    @property
    def provenance(self) -> None:
        return None

    def prepare(self, request: AdapterRequest) -> "_PreparedSyntheticProcess":
        _validate_request_id(request.transport_id)
        _prepare_runtime_root(self.config)
        _sweep_orphans(self.config)
        source, source_details = _open_source(self.config)
        invocation: Path | None = None
        provenance: ExecutableProvenance | None = None
        try:
            invocation = _prepare_invocation(self.config, request)
            provenance = _copy_executable(
                self.config,
                source,
                source_details,
                invocation,
            )
            _write_manifest(invocation, provenance)
            return _PreparedSyntheticProcess(
                self.config,
                request,
                invocation,
                provenance,
            )
        except BaseException:
            if invocation is not None:
                _cleanup_invocation(invocation, provenance)
            raise
        finally:
            os.close(source)


class _PreparedSyntheticProcess:
    __slots__ = ("_closed", "_config", "_invocation", "_provenance", "_request")

    def __init__(
        self,
        config: SyntheticProcessAdapterConfig,
        request: AdapterRequest,
        invocation: Path,
        provenance: ExecutableProvenance,
    ):
        self._config = config
        self._request = request
        self._invocation = invocation
        self._provenance = provenance
        self._closed = False

    @property
    def provenance(self) -> ExecutableProvenance:
        return self._provenance

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        _cleanup_invocation(self._invocation, self._provenance)

    def send(
        self,
        cancellation: Cancellation,
        identity_recorder: IdentityRecorder | None = None,
    ) -> AdapterResult:
        if self._closed:
            return AdapterResult.definite_failure("prepared_adapter_closed")
        provenance = self._provenance
        if cancellation.is_set():
            self.close()
            return AdapterResult.cancelled(provenance=provenance)
        supervisor: subprocess.Popen[bytes] | None = None
        identity: ProcessIdentity | None = None
        try:
            frame = encode_adapter_frame(
                {
                    "callback_registration_id": self._request.callback_registration_id,
                    "completion_registration_id": self._request.completion_registration_id,
                    "message_type": "rig-v2-transport",
                    "payload": json.loads(self._request.payload_json),
                    "pool": self._request.pool,
                    "transport_id": self._request.transport_id,
                    "version": 1,
                    "work_id": self._request.work_id,
                },
                max_bytes=self._config.max_frame_bytes,
            )
            _assert_copy_identity(provenance)
            token = uuid.uuid4().hex
            supervisor = _launch_supervisor(
                provenance,
                self._invocation,
                token,
                self._config.timeout_seconds,
                self._config.max_output_bytes,
            )
            ready = _read_control(supervisor, 2.0)
            identity = _identity_from_ready(supervisor, ready, token)
            if identity_recorder is not None:
                identity_recorder(identity)
            assert supervisor.stdin is not None
            _write_all(supervisor.stdin.fileno(), frame)
            status = _wait_for_status(
                supervisor,
                cancellation,
                self._config.timeout_seconds + 2.0,
            )
            _verify_status_identity(status, identity)
            return _adapter_result(status, provenance, identity)
        except BaseException as error:
            if supervisor is not None:
                _stop_supervisor(supervisor)
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            factory = (
                AdapterResult.unknown
                if supervisor is not None
                else AdapterResult.definite_failure
            )
            return factory(
                f"adapter_process_error_{type(error).__name__.lower()}",
                provenance=provenance,
                process_identity=identity,
            )
        finally:
            if supervisor is not None:
                _stop_supervisor(supervisor)
            self.close()


def _launch_supervisor(
    provenance: ExecutableProvenance,
    invocation: Path,
    token: str,
    timeout_seconds: float,
    max_output_bytes: int,
) -> subprocess.Popen[bytes]:
    helper = Path(__file__).with_name("process_supervisor.py").resolve(strict=True)
    return subprocess.Popen(
        [
            sys.executable,
            str(helper),
            str(provenance.path),
            str(invocation),
            str(provenance.device),
            str(provenance.inode),
            str(provenance.size),
            provenance.digest,
            token,
            repr(timeout_seconds),
            str(max_output_bytes),
        ],
        executable=sys.executable,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=invocation,
        env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        close_fds=True,
        start_new_session=True,
    )


def _read_control(process: subprocess.Popen[bytes], timeout: float) -> dict[str, object]:
    assert process.stdout is not None
    descriptor = process.stdout.fileno()
    deadline = time.monotonic() + timeout
    value = bytearray()
    while b"\n" not in value:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("supervisor control response timed out")
        readable, _, _ = select.select([descriptor], [], [], remaining)
        if not readable:
            raise TimeoutError("supervisor control response timed out")
        chunk = os.read(descriptor, _CONTROL_LIMIT + 1)
        if not chunk:
            raise RuntimeError("supervisor closed without a control response")
        value.extend(chunk)
        if len(value) > _CONTROL_LIMIT:
            raise RuntimeError("supervisor control response exceeded its limit")
    decoded = json.loads(bytes(value).split(b"\n", 1)[0])
    if not isinstance(decoded, dict):
        raise RuntimeError("supervisor control response was not an object")
    return decoded


def _wait_for_status(
    process: subprocess.Popen[bytes],
    cancellation: Cancellation,
    timeout: float,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while True:
        if cancellation.is_set() and process.stdin is not None:
            process.stdin.close()
            process.stdin = None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("supervisor did not finish in its bounded grace period")
        try:
            return _read_control(process, min(remaining, 0.05))
        except TimeoutError:
            continue


def _identity_from_ready(
    process: subprocess.Popen[bytes],
    value: dict[str, object],
    token: str,
) -> ProcessIdentity:
    if set(value) != {"event", "supervisor_pid", "target_pid", "pgid", "token"}:
        raise RuntimeError("supervisor identity fields were invalid")
    if value["event"] != "ready" or value["supervisor_pid"] != process.pid:
        raise RuntimeError("supervisor identity did not match the launched helper")
    if value["target_pid"] != value["pgid"] or value["token"] != token:
        raise RuntimeError("supervisor target group identity was invalid")
    return ProcessIdentity(process.pid, value["target_pid"], token)  # type: ignore[arg-type]


def _verify_status_identity(value: dict[str, object], identity: ProcessIdentity) -> None:
    if (
        value.get("event") != "result"
        or value.get("supervisor_pid") != identity.supervisor_pid
        or value.get("target_pid") != identity.target_pid
        or value.get("pgid") != identity.target_pid
        or value.get("token") != identity.token
    ):
        raise RuntimeError("supervisor result identity did not match its ready record")


def _adapter_result(
    value: dict[str, object],
    provenance: ExecutableProvenance,
    identity: ProcessIdentity,
) -> AdapterResult:
    output = json.dumps(value["output"], sort_keys=True, separators=(",", ":"))
    exit_code = value.get("exit_code")
    if exit_code is not None and type(exit_code) is not int:
        raise RuntimeError("supervisor exit code was invalid")
    disposition = value.get("disposition")
    if disposition == AdapterDisposition.ACCEPTED.value:
        acknowledgement = value.get("acknowledgement_id")
        if not isinstance(acknowledgement, str) or not _IDENTIFIER.fullmatch(acknowledgement):
            raise RuntimeError("supervisor acknowledgement was invalid")
        return AdapterResult.accepted(
            acknowledgement,
            exit_code=exit_code,
            output=output,
            provenance=provenance,
            process_identity=identity,
        )
    error_code = value.get("error_code")
    if not isinstance(error_code, str) or not _IDENTIFIER.fullmatch(error_code):
        raise RuntimeError("supervisor error code was invalid")
    factory = {
        AdapterDisposition.DEFINITE_FAILED.value: AdapterResult.definite_failure,
        AdapterDisposition.DELIVERY_UNKNOWN.value: AdapterResult.unknown,
        AdapterDisposition.CANCELLED.value: AdapterResult.cancelled,
    }.get(disposition)
    if factory is None:
        raise RuntimeError("supervisor disposition was invalid")
    return factory(
        error_code,
        exit_code=exit_code,
        output=output,
        provenance=provenance,
        process_identity=identity,
    )


def _stop_supervisor(process: subprocess.Popen[bytes]) -> None:
    if process.stdin is not None:
        process.stdin.close()
        process.stdin = None
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
    if process.stdout is not None:
        process.stdout.close()


def _open_source(config: SyntheticProcessAdapterConfig) -> tuple[int, os.stat_result]:
    fixture_root = config.fixture_root.resolve(strict=True)
    details = fixture_root.lstat()
    if (
        fixture_root != config.fixture_root
        or not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o700
    ):
        raise ProcessAdapterConfigurationError(
            "fixture root must be a canonical owner-private directory"
        )
    executable = config.executable
    if executable.resolve(strict=True) != executable:
        raise ProcessAdapterConfigurationError("executable must use its canonical path")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ProcessAdapterConfigurationError("O_NOFOLLOW is required")
    descriptor = os.open(executable, os.O_RDONLY | no_follow)
    try:
        opened = os.fstat(descriptor)
        linked = executable.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) & 0o022
            or not stat.S_IMODE(opened.st_mode) & 0o100
            or opened.st_size > config.max_executable_bytes
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise ProcessAdapterConfigurationError("executable failed provenance checks")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _prepare_runtime_root(config: SyntheticProcessAdapterConfig) -> None:
    root = config.runtime_root
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = root.lstat()
    if (
        root.resolve(strict=True) != root
        or not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o700
    ):
        raise ProcessAdapterConfigurationError("adapter runtime root must be private")


def _prepare_invocation(
    config: SyntheticProcessAdapterConfig,
    request: AdapterRequest,
) -> Path:
    invocation = config.runtime_root / request.transport_id
    invocation.mkdir(mode=0o700, exist_ok=False)
    for name in ("home", "state", "cache", "config", "tmp", "bin"):
        (invocation / name).mkdir(mode=0o700)
    _register_invocation(config, invocation.name)
    return invocation


def _copy_executable(
    config: SyntheticProcessAdapterConfig,
    source: int,
    source_details: os.stat_result,
    invocation: Path,
) -> ExecutableProvenance:
    destination = invocation / "bin" / "adapter"
    no_follow = getattr(os, "O_NOFOLLOW", None)
    assert no_follow is not None
    target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow, 0o500)
    created_details = os.fstat(target)
    digest = hashlib.sha256()
    copied = 0
    try:
        os.fchmod(target, 0o500)
        while True:
            chunk = os.read(source, 65536)
            if not chunk:
                break
            copied += len(chunk)
            if copied > config.max_executable_bytes:
                raise ProcessAdapterConfigurationError("executable exceeds copy limit")
            digest.update(chunk)
            _write_all(target, chunk)
        os.fsync(target)
        target_details = os.fstat(target)
        rechecked = os.fstat(source)
        source_identity = (
            source_details.st_dev,
            source_details.st_ino,
            source_details.st_size,
            source_details.st_mtime_ns,
            source_details.st_ctime_ns,
        )
        if (
            (
                rechecked.st_dev,
                rechecked.st_ino,
                rechecked.st_size,
                rechecked.st_mtime_ns,
                rechecked.st_ctime_ns,
            )
            != source_identity
            or copied != source_details.st_size
            or not stat.S_ISREG(target_details.st_mode)
            or target_details.st_uid != os.geteuid()
            or target_details.st_nlink != 1
            or stat.S_IMODE(target_details.st_mode) != 0o500
        ):
            raise ProcessAdapterConfigurationError("executable copy failed containment")
    except BaseException:
        try:
            linked = destination.lstat()
            if (
                stat.S_ISREG(linked.st_mode)
                and linked.st_uid == os.geteuid()
                and linked.st_nlink == 1
                and (linked.st_dev, linked.st_ino)
                == (created_details.st_dev, created_details.st_ino)
            ):
                destination.unlink()
        finally:
            os.close(target)
        raise
    else:
        os.close(target)
    os.chmod(destination.parent, 0o500)
    linked = destination.lstat()
    if (linked.st_dev, linked.st_ino) != (target_details.st_dev, target_details.st_ino):
        raise ProcessAdapterConfigurationError("executable copy identity changed")
    return ExecutableProvenance(
        path=destination,
        device=target_details.st_dev,
        inode=target_details.st_ino,
        mode=stat.S_IMODE(target_details.st_mode),
        size=target_details.st_size,
        digest=digest.hexdigest(),
        source_path=config.executable,
        source_device=source_details.st_dev,
        source_inode=source_details.st_ino,
        source_digest=digest.hexdigest(),
    )


def _write_manifest(invocation: Path, provenance: ExecutableProvenance) -> None:
    path = invocation / _MANIFEST_NAME
    no_follow = getattr(os, "O_NOFOLLOW", None)
    assert no_follow is not None
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow, 0o400)
    encoded = json.dumps(
        {
            "device": provenance.device,
            "digest": provenance.digest,
            "inode": provenance.inode,
            "mode": provenance.mode,
            "size": provenance.size,
            "version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    try:
        os.fchmod(descriptor, 0o400)
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _assert_copy_identity(provenance: ExecutableProvenance) -> None:
    details = provenance.path.lstat()
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_nlink != 1
        or stat.S_IMODE(details.st_mode) != 0o500
        or (details.st_dev, details.st_ino) != (provenance.device, provenance.inode)
        or details.st_size != provenance.size
        or _digest(provenance.path, provenance.size) != provenance.digest
    ):
        raise ProcessAdapterConfigurationError("immutable executable copy changed")


def _sweep_orphans(config: SyntheticProcessAdapterConfig) -> None:
    state = _load_sweep_state(config)
    names = state["entries"]
    cursor = state["cursor"]
    assert isinstance(names, list)
    assert isinstance(cursor, int)
    remaining = config.max_sweep_entries
    while names and remaining:
        if cursor >= len(names):
            cursor = 0
        name = names[cursor]
        assert isinstance(name, str)
        invocation = config.runtime_root / name
        _cleanup_invocation(invocation, None)
        remaining -= 1
        if invocation.exists() or invocation.is_symlink():
            cursor += 1
        else:
            names.pop(cursor)
    state["cursor"] = 0 if not names else cursor

    # Legacy discovery is deliberately bounded. Current invocations are indexed
    # before their manifest can exist, so unrelated/unverified root entries can
    # never starve a verified invocation created by this fixture.
    iterator = _SWEEP_SCANS.get(config.runtime_root)
    try:
        if iterator is None:
            iterator = os.scandir(config.runtime_root)
            _SWEEP_SCANS[config.runtime_root] = iterator
        for _ in range(config.max_sweep_entries):
            try:
                entry = next(iterator)  # type: ignore[arg-type]
            except StopIteration:
                close = getattr(iterator, "close", None)
                if callable(close):
                    close()
                else:
                    exit_context = getattr(iterator, "__exit__", None)
                    if callable(exit_context):
                        exit_context(None, None, None)
                _SWEEP_SCANS.pop(config.runtime_root, None)
                break
            if (
                entry.name not in names
                and _TRANSPORT_ID.fullmatch(entry.name)
                and _verified_manifest(Path(entry.path)) is not None
                and len(names) < _SWEEP_STATE_ENTRIES
            ):
                names.append(entry.name)
    except FileNotFoundError:
        _SWEEP_SCANS.pop(config.runtime_root, None)
        return
    _save_sweep_state(config, state)


def _register_invocation(config: SyntheticProcessAdapterConfig, name: str) -> None:
    state = _load_sweep_state(config)
    entries = state["entries"]
    assert isinstance(entries, list)
    if name not in entries:
        if len(entries) >= _SWEEP_STATE_ENTRIES:
            raise ProcessAdapterConfigurationError("sweep index capacity is exhausted")
        entries.append(name)
    _save_sweep_state(config, state)


def _load_sweep_state(config: SyntheticProcessAdapterConfig) -> dict[str, object]:
    path = config.runtime_root / _SWEEP_STATE_NAME
    try:
        details = path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_size > _SWEEP_STATE_LIMIT
        ):
            raise ProcessAdapterConfigurationError("sweep index failed containment")
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"cursor": 0, "entries": [], "version": 1}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProcessAdapterConfigurationError("sweep index is invalid") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"cursor", "entries", "version"}
        or value["version"] != 1
        or type(value["cursor"]) is not int
        or value["cursor"] < 0
        or not isinstance(value["entries"], list)
        or len(value["entries"]) > _SWEEP_STATE_ENTRIES
        or any(
            not isinstance(name, str) or not _TRANSPORT_ID.fullmatch(name)
            for name in value["entries"]
        )
        or len(set(value["entries"])) != len(value["entries"])
    ):
        raise ProcessAdapterConfigurationError("sweep index is invalid")
    return value


def _save_sweep_state(
    config: SyntheticProcessAdapterConfig,
    state: dict[str, object],
) -> None:
    path = config.runtime_root / _SWEEP_STATE_NAME
    encoded = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > _SWEEP_STATE_LIMIT:
        raise ProcessAdapterConfigurationError("sweep index exceeds its limit")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ProcessAdapterConfigurationError("O_NOFOLLOW is required")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | no_follow, 0o600)
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
        ):
            raise ProcessAdapterConfigurationError("sweep index failed containment")
        os.fchmod(descriptor, 0o600)
        os.ftruncate(descriptor, 0)
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _cleanup_invocation(
    invocation: Path,
    provenance: ExecutableProvenance | None,
) -> None:
    manifest = _verified_manifest(invocation)
    expected = provenance
    if expected is None and manifest is not None:
        expected = ExecutableProvenance(
            path=invocation / "bin" / "adapter",
            device=manifest["device"],
            inode=manifest["inode"],
            mode=manifest["mode"],
            size=manifest["size"],
            digest=manifest["digest"],
            source_path=invocation,
            source_device=0,
            source_inode=0,
            source_digest=manifest["digest"],
        )  # type: ignore[arg-type]
    executable_removed = False
    if expected is not None:
        try:
            _assert_copy_identity(expected)
        except (OSError, ProcessAdapterConfigurationError):
            pass
        else:
            bin_dir = invocation / "bin"
            if _verified_directory(bin_dir, {0o500}):
                bin_dir.chmod(0o700)
                expected.path.unlink()
                executable_removed = True
    bin_dir = invocation / "bin"
    if executable_removed or not (bin_dir / "adapter").exists():
        _remove_verified_empty_directory(bin_dir, {0o500, 0o700})
    manifest_path = invocation / _MANIFEST_NAME
    if manifest is not None and not bin_dir.exists():
        try:
            manifest_path.unlink()
        except FileNotFoundError:
            pass
    for name in ("home", "state", "cache", "config", "tmp"):
        _remove_verified_empty_directory(invocation / name, {0o700})
    _remove_verified_empty_directory(invocation, {0o700})


def _verified_manifest(invocation: Path) -> dict[str, object] | None:
    path = invocation / _MANIFEST_NAME
    try:
        details = path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
            or stat.S_IMODE(details.st_mode) != 0o400
            or details.st_size > _MANIFEST_LIMIT
        ):
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    if set(value) != {"device", "digest", "inode", "mode", "size", "version"}:
        return None
    if value["version"] != 1 or value["mode"] != 0o500:
        return None
    if any(type(value[name]) is not int for name in ("device", "inode", "mode", "size")):
        return None
    digest = value["digest"]
    if not isinstance(digest, str) or len(digest) != 64:
        return None
    return value


def _remove_verified_empty_directory(path: Path, modes: set[int]) -> None:
    try:
        if not _verified_directory(path, modes):
            return
        path.rmdir()
    except (FileNotFoundError, OSError):
        return


def _verified_directory(path: Path, modes: set[int]) -> bool:
    try:
        details = path.lstat()
    except FileNotFoundError:
        return False
    return (
        stat.S_ISDIR(details.st_mode)
        and details.st_uid == os.geteuid()
        and details.st_nlink >= 1
        and stat.S_IMODE(details.st_mode) in modes
    )


def _digest(path: Path, expected_size: int) -> str:
    if expected_size > 64 * 1024 * 1024:
        raise ProcessAdapterConfigurationError("executable copy is unexpectedly large")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]


def _validate_request_id(value: str) -> None:
    if not isinstance(value, str) or not _TRANSPORT_ID.fullmatch(value):
        raise ProcessAdapterConfigurationError("transport ID is invalid for fixture runtime")
