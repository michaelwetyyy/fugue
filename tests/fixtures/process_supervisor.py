"""Single-purpose subprocess supervisor for the synthetic adapter fixture."""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

_FRAME_LIMIT = 1024 * 1024


def _write_control(value: dict[str, object]) -> None:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    view = memoryview(encoded)
    while view:
        written = os.write(1, view)
        view = view[written:]


def _digest(path: Path, maximum: int) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise RuntimeError("supervisor executable exceeded its verified size")
            digest.update(chunk)
    if total != maximum:
        raise RuntimeError("supervisor executable size changed")
    return digest.hexdigest()


def _validate_executable(
    executable: Path,
    invocation: Path,
    device: int,
    inode: int,
    size: int,
    digest: str,
) -> None:
    if executable != invocation / "bin" / "adapter":
        raise RuntimeError("supervisor executable was outside the invocation")
    details = executable.lstat()
    if (
        executable.resolve(strict=True) != executable
        or not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_nlink != 1
        or stat.S_IMODE(details.st_mode) != 0o500
        or (details.st_dev, details.st_ino, details.st_size) != (device, inode, size)
        or _digest(executable, size) != digest
    ):
        raise RuntimeError("supervisor executable identity was not exact")


def _target_environment(invocation: Path, namespace: str) -> dict[str, str]:
    return {
        "HOME": str(invocation / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "OC_RIG_V2_NAMESPACE": namespace,
        "TMPDIR": str(invocation / "tmp"),
        "XDG_CACHE_HOME": str(invocation / "cache"),
        "XDG_CONFIG_HOME": str(invocation / "config"),
        "XDG_STATE_HOME": str(invocation / "state"),
    }


def _exact_group_kill(target_pid: int, pgid: int, sentinel_pid: int) -> None:
    if pgid != target_pid or os.getpgid(sentinel_pid) != pgid:
        raise RuntimeError("target process group identity changed")
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _leader_exited_unreaped(target_pid: int) -> bool:
    return os.waitid(
        os.P_PID,
        target_pid,
        os.WEXITED | os.WNOHANG | os.WNOWAIT,
    ) is not None


def _decode_result(stdout: bytes) -> tuple[str, str | None, str | None]:
    if len(stdout) < 4:
        return "delivery_unknown", None, "invalid_adapter_response"
    size = struct.unpack("!I", stdout[:4])[0]
    if size > _FRAME_LIMIT or len(stdout) != size + 4:
        return "delivery_unknown", None, "invalid_adapter_response"
    try:
        value = json.loads(stdout[4:].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return "delivery_unknown", None, "invalid_adapter_response"
    if not isinstance(value, dict):
        return "delivery_unknown", None, "invalid_adapter_response"
    if value.get("status") == "accepted" and set(value) == {
        "status",
        "acknowledgement_id",
    }:
        acknowledgement = value["acknowledgement_id"]
        if isinstance(acknowledgement, str):
            return "accepted", acknowledgement, None
    if value.get("status") in {"definite_failed", "delivery_unknown"} and set(value) == {
        "status",
        "error_code",
    }:
        error_code = value["error_code"]
        if isinstance(error_code, str):
            return value["status"], None, error_code
    return "delivery_unknown", None, "invalid_adapter_response"


def _run(
    executable: Path,
    invocation: Path,
    token: str,
    timeout_seconds: float,
    max_output_bytes: int,
) -> int:
    target = subprocess.Popen(
        [str(executable), "--rig-v2-synthetic-adapter"],
        executable=str(executable),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=invocation,
        env=_target_environment(invocation, invocation.name),
        close_fds=True,
        process_group=0,
    )
    assert target.stdin is not None and target.stdout is not None and target.stderr is not None
    target_pid = target.pid
    deadline = time.monotonic() + 2
    while os.getpgid(target_pid) != target_pid:
        if time.monotonic() >= deadline:
            raise RuntimeError("target process group was not established")
        time.sleep(0.001)
    pgid = target_pid
    sentinel_script = Path(__file__).with_name("process_group_sentinel.py").resolve(
        strict=True
    )
    sentinel = subprocess.Popen(
        [sys.executable, str(sentinel_script)],
        executable=sys.executable,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=invocation,
        env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        close_fds=True,
        process_group=pgid,
    )
    if os.getpgid(sentinel.pid) != pgid:
        raise RuntimeError("target process group sentinel was not exact")
    _write_control(
        {
            "event": "ready",
            "pgid": pgid,
            "supervisor_pid": os.getpid(),
            "target_pid": target_pid,
            "token": token,
        }
    )

    selector = selectors.DefaultSelector()
    parent_fd = 0
    target_in = target.stdin.fileno()
    target_out = target.stdout.fileno()
    target_err = target.stderr.fileno()
    for descriptor in (parent_fd, target_in, target_out, target_err):
        os.set_blocking(descriptor, False)
    selector.register(parent_fd, selectors.EVENT_READ, "parent")
    selector.register(target_out, selectors.EVENT_READ, "stdout")
    selector.register(target_err, selectors.EVENT_READ, "stderr")
    input_frame = bytearray()
    expected_frame: int | None = None
    sent = 0
    stdout = bytearray()
    stdout_hash = hashlib.sha256()
    stderr_hash = hashlib.sha256()
    stdout_bytes = 0
    stderr_bytes = 0
    overflowed = timed_out = cancelled = False
    leader_reaped = False
    exit_code: int | None = None
    output_open = {"stdout": True, "stderr": True}
    run_deadline = time.monotonic() + timeout_seconds

    def kill_and_reap_group() -> None:
        nonlocal exit_code, leader_reaped
        if leader_reaped:
            return
        _exact_group_kill(target_pid, pgid, sentinel.pid)
        target_exit = target.wait()
        sentinel.wait()
        leader_reaped = True
        if exit_code is None:
            exit_code = target_exit
        try:
            selector.unregister(target_in)
        except KeyError:
            pass
        target.stdin.close()

    try:
        while not (leader_reaped and not any(output_open.values())):
            if not leader_reaped and _leader_exited_unreaped(target_pid):
                kill_and_reap_group()
            if not leader_reaped and time.monotonic() >= run_deadline:
                timed_out = True
                kill_and_reap_group()
            for key, _mask in selector.select(0.02):
                descriptor = key.fd
                kind = key.data
                if kind == "parent":
                    chunk = os.read(descriptor, 65536)
                    if not chunk:
                        cancelled = True
                        selector.unregister(descriptor)
                        kill_and_reap_group()
                        continue
                    input_frame.extend(chunk)
                    if len(input_frame) > _FRAME_LIMIT + 4:
                        raise RuntimeError("parent frame exceeded its bound")
                    if expected_frame is None and len(input_frame) >= 4:
                        expected_frame = struct.unpack("!I", input_frame[:4])[0] + 4
                        if expected_frame > _FRAME_LIMIT + 4:
                            raise RuntimeError("parent frame exceeded its bound")
                    if expected_frame is not None and len(input_frame) == expected_frame:
                        selector.register(target_in, selectors.EVENT_WRITE, "target_stdin")
                    elif expected_frame is not None and len(input_frame) > expected_frame:
                        raise RuntimeError("parent sent trailing control bytes")
                    continue
                if kind == "target_stdin":
                    try:
                        written = os.write(descriptor, input_frame[sent : sent + 65536])
                    except BrokenPipeError:
                        selector.unregister(descriptor)
                        target.stdin.close()
                    else:
                        sent += written
                        if sent == len(input_frame):
                            selector.unregister(descriptor)
                            target.stdin.close()
                    continue
                remaining = max_output_bytes - stdout_bytes - stderr_bytes
                chunk = os.read(descriptor, max(1, min(65536, remaining + 1)))
                if not chunk:
                    selector.unregister(descriptor)
                    output_open[kind] = False
                    continue
                keep = chunk[: max(0, remaining)]
                if kind == "stdout":
                    stdout.extend(keep)
                    stdout_hash.update(keep)
                    stdout_bytes += len(keep)
                else:
                    stderr_hash.update(keep)
                    stderr_bytes += len(keep)
                if len(chunk) > remaining:
                    overflowed = True
                    kill_and_reap_group()
                    for stream in ("stdout", "stderr"):
                        file_object = getattr(target, stream)
                        if output_open[stream]:
                            try:
                                selector.unregister(file_object.fileno())
                            except KeyError:
                                pass
                            file_object.close()
                            output_open[stream] = False
            if not leader_reaped and _leader_exited_unreaped(target_pid):
                kill_and_reap_group()
        if exit_code is None:
            exit_code = target.wait()
    finally:
        selector.close()
        if not leader_reaped:
            try:
                _exact_group_kill(target_pid, pgid, sentinel.pid)
            finally:
                target_exit = target.wait()
                sentinel.wait()
                if exit_code is None:
                    exit_code = target_exit

    if cancelled:
        disposition, acknowledgement, error_code = "cancelled", None, "cancelled"
    elif timed_out:
        disposition, acknowledgement, error_code = (
            "delivery_unknown",
            None,
            "adapter_timeout",
        )
    elif overflowed:
        disposition, acknowledgement, error_code = (
            "delivery_unknown",
            None,
            "adapter_output_too_large",
        )
    else:
        disposition, acknowledgement, error_code = _decode_result(bytes(stdout))
    _write_control(
        {
            "acknowledgement_id": acknowledgement,
            "disposition": disposition,
            "error_code": error_code,
            "event": "result",
            "exit_code": exit_code,
            "output": {
                "stderr_bytes": stderr_bytes,
                "stderr_sha256": stderr_hash.hexdigest(),
                "stdout_bytes": stdout_bytes,
                "stdout_sha256": stdout_hash.hexdigest(),
                "truncated": overflowed,
            },
            "pgid": pgid,
            "supervisor_pid": os.getpid(),
            "target_pid": target_pid,
            "token": token,
        }
    )
    return 0


def main() -> int:
    if len(sys.argv) != 10:
        return 125
    executable = Path(sys.argv[1])
    invocation = Path(sys.argv[2])
    device, inode, size = map(int, sys.argv[3:6])
    digest, token = sys.argv[6:8]
    timeout_seconds = float(sys.argv[8])
    max_output_bytes = int(sys.argv[9])
    _validate_executable(executable, invocation, device, inode, size, digest)
    return _run(executable, invocation, token, timeout_seconds, max_output_bytes)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BaseException as error:
        try:
            _write_control({"event": "fatal", "message": repr(error)})
        except BaseException:
            pass
        raise SystemExit(126)
