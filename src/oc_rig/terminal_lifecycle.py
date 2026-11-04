"""Attended terminal ownership for the local-user Rig v2 deployment.

The terminal wrapper is deliberately separate from the daemon and its durable
state.  It records only resources started by one terminal invocation and never
uses process-name matching or a shared OpenCode label for cleanup.
"""

from __future__ import annotations

import json
import fcntl
import hashlib
import os
import re
import selectors
import signal
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from oc_rig.cockpit import CockpitClient, normalize_snapshot, render_terminal
from oc_rig.deployment.user import (
    DeploymentError,
    UserDeployment,
    _paths,
    validated_failed_start_historical_opencode_configuration,
    validated_historical_opencode_configuration,
    validated_polluted_historical_opencode_configuration,
)
from oc_rig.opencode_authority import (
    AUTOMATED_BACKEND_RELATIVE,
    OpenCodeAuthorityInvalid,
    automated_backend_authority,
)


class TerminalLifecycleError(RuntimeError):
    """The attended lifecycle could not safely establish or release ownership."""


class _ProcessAbsent(TerminalLifecycleError):
    """The exact PID is conclusively absent from local process inspection."""


def _managed_backend_directory(home: Path, candidate: Path) -> Path:
    expected = home / AUTOMATED_BACKEND_RELATIVE
    if not candidate.is_absolute() or candidate != expected:
        raise TerminalLifecycleError(
            "automated backend directory is not the managed path"
        )
    return candidate


_OPENCODE_ISOLATION_ENVIRONMENT = {
    "OPENCODE_DISABLE_CLAUDE_CODE": "1",
    "OPENCODE_DISABLE_DEFAULT_PLUGINS": "1",
    "OPENCODE_DISABLE_EXTERNAL_SKILLS": "1",
    "OPENCODE_DISABLE_LSP_DOWNLOAD": "1",
    "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
    "OPENCODE_PURE": "1",
}

@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    pgid: int
    started: str
    command: tuple[str, ...]

    def as_json(self) -> dict[str, object]:
        result: dict[str, object] = {
            "command": list(self.command),
            "pgid": self.pgid,
            "pid": self.pid,
            "started": self.started,
        }
        return result

    @classmethod
    def from_json(cls, value: object) -> "ProcessIdentity":
        if not isinstance(value, Mapping):
            raise TerminalLifecycleError("backend ownership record is malformed")
        command = value.get("command")
        if not isinstance(command, list) or not all(isinstance(v, str) for v in command):
            raise TerminalLifecycleError("backend ownership command is malformed")
        try:
            return cls(
                pid=int(value["pid"]),
                pgid=int(value["pgid"]),
                started=str(value["started"]),
                command=tuple(command),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise TerminalLifecycleError("backend ownership identity is malformed") from error


@dataclass(frozen=True, slots=True)
class _ProcessObservation:
    identity: ProcessIdentity
    state: str


def snapshot_is_quiescent(snapshot: object) -> tuple[bool, str]:
    """Require an exact, available projection with no queued or assigned work."""
    view = normalize_snapshot(snapshot)
    availability = view["availability"]
    if availability.get("status") != "available":
        return False, "cockpit projection is not fully available"
    queue = view["queue"]
    if queue.get("status") != "available" or queue.get("total_status") != "exact":
        return False, "durable queue count is not exact"
    if queue.get("total") != 0:
        return False, "durable queue is not empty"
    workers = view["worker_graph"]["workers"]
    if any(worker.get("slot_state") != "clear" for worker in workers):
        return False, "one or more worker slots are assigned"
    for key in ("automatic_recovery", "operator_required"):
        attention = view["attention"][key]
        if attention.get("status") != "available" or attention.get("total_status") != "exact":
            return False, f"{key} attention count is not exact"
        if key == "automatic_recovery" and attention.get("total") != 0:
            return False, f"{key} attention is not empty"
    return True, "quiescent"


def _process_observation(pid: int) -> _ProcessObservation:
    result = subprocess.run(
        ["/bin/ps", "-p", str(pid), "-o", "pgid=", "-o", "lstart=", "-o", "state=", "-o", "command="],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode == 1 and not result.stdout.strip() and not result.stderr.strip():
        raise _ProcessAbsent("owned backend process is no longer present")
    if result.returncode != 0:
        raise TerminalLifecycleError("owned backend process inspection failed")
    if not result.stdout.strip():
        raise TerminalLifecycleError("owned backend process identity is ambiguous")
    line = result.stdout.strip()
    fields = line.split(None, 7)
    if len(fields) not in {7, 8}:
        raise TerminalLifecycleError("owned backend process identity is ambiguous")
    try:
        pgid = int(fields[0])
    except ValueError as error:
        raise TerminalLifecycleError("owned backend process group is invalid") from error
    started = " ".join(fields[1:6])
    state = fields[6]
    if re.fullmatch(r"[A-Z][A-Za-z0-9+<]*", state) is None:
        raise TerminalLifecycleError("owned backend process state is ambiguous")
    command = tuple(fields[7].split()) if len(fields) == 8 else ()
    if not command and state[0] not in {"X", "Z"}:
        raise TerminalLifecycleError("owned backend process command is ambiguous")
    return _ProcessObservation(
        identity=ProcessIdentity(pid=pid, pgid=pgid, started=started, command=command),
        state=state,
    )


def _process_identity(pid: int, expected_command: tuple[str, ...]) -> ProcessIdentity:
    observation = _process_observation(pid)
    identity = observation.identity
    if observation.state[0] in {"X", "Z"}:
        raise _ProcessAbsent("owned backend process is terminated")
    if identity.command != expected_command or identity.pgid != pid:
        raise TerminalLifecycleError("backend process does not match exact ownership")
    return identity


def _same_process(identity: ProcessIdentity) -> bool:
    try:
        return _process_identity(identity.pid, identity.command) == identity
    except TerminalLifecycleError:
        return False


def _process_state(identity: ProcessIdentity) -> str:
    try:
        observation = _process_observation(identity.pid)
    except _ProcessAbsent:
        return "absent"
    except TerminalLifecycleError:
        return "error"
    observed = observation.identity
    if observed.pgid != identity.pgid or observed.started != identity.started:
        return "mismatch"
    if observation.state[0] in {"X", "Z"}:
        return "terminated"
    return "exact" if observed.command == identity.command else "mismatch"


def _listener_pid(port: int) -> int | None:
    result = subprocess.run(
        ["/usr/sbin/lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        env={"LANG": "C", "PATH": "/usr/bin:/bin:/usr/sbin"},
    )
    values = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if result.returncode != 0:
        return None
    if len(values) != 1 or not values[0].isdigit():
        raise TerminalLifecycleError("backend listener ownership is ambiguous")
    return int(values[0])


def _directory_identity(details: os.stat_result) -> list[int]:
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o700
        or details.st_nlink < 1
    ):
        raise TerminalLifecycleError("private backend directory identity is unsafe")
    return [details.st_dev, details.st_ino, details.st_mode, details.st_uid, details.st_nlink]


def _backend_binding_matches(recorded: object, expected: object) -> bool:
    """Compare backend ownership while treating directory link counts as mutable.

    The device, inode, mode, owner, process, listener, configuration, and
    provider-auth bindings remain exact.  A private runtime directory's link
    count can legitimately change when OpenCode creates or removes a child
    directory, so it is validated as positive but is not ownership identity.
    """

    def normalized(value: object) -> dict[str, object] | None:
        if not isinstance(value, Mapping):
            return None
        result = dict(value)
        roots = result.get("private_roots")
        if not isinstance(roots, Mapping):
            return None
        stable: dict[str, list[int]] = {}
        for name, identity in roots.items():
            if (
                not isinstance(name, str)
                or not isinstance(identity, list)
                or len(identity) not in {4, 5}
                or any(type(item) is not int for item in identity)
                or (len(identity) == 5 and identity[4] < 1)
            ):
                return None
            stable[name] = list(identity[:4])
        result["private_roots"] = stable
        work = result.get("working_directory")
        if isinstance(work, Mapping) and "ancestors" in work:
            ancestors = work.get("ancestors")
            if not isinstance(ancestors, list):
                return None
            stable_ancestors: list[list[object]] = []
            for item in ancestors:
                if (
                    not isinstance(item, list)
                    or len(item) != 2
                    or not isinstance(item[0], str)
                    or not isinstance(item[1], list)
                    or len(item[1]) != 5
                    or any(type(field) is not int for field in item[1])
                    or item[1][4] < 1
                ):
                    return None
                stable_ancestors.append([item[0], list(item[1][:4])])
            stable_work = dict(work)
            stable_work["ancestors"] = stable_ancestors
            result["working_directory"] = stable_work
        return result

    left = normalized(recorded)
    right = normalized(expected)
    return left is not None and right is not None and left == right


def _prepare_private_backend_tree(
    root: Path, *, include_config: bool = True
) -> dict[str, list[int]]:
    if not root.is_absolute():
        raise TerminalLifecycleError("backend directory must be absolute")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = root.parts[1:]
        for index, component in enumerate(parts):
            last = index == len(parts) - 1
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not last:
                    raise TerminalLifecycleError("backend ancestry is missing") from None
                os.mkdir(component, 0o700, dir_fd=descriptor)
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            os.close(descriptor)
            descriptor = child
        identities = {"root": _directory_identity(os.fstat(descriptor))}
        allowed = {"home", "data", "cache", "state", "work"}
        if include_config:
            allowed.add("config")
        names = set(os.listdir(descriptor))
        if names - allowed:
            raise TerminalLifecycleError("automated backend directory contains an unexpected entry")
        for name in sorted(allowed):
            try:
                child = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                os.mkdir(name, 0o700, dir_fd=descriptor)
                child = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            try:
                identities[name] = _directory_identity(os.fstat(child))
                if name == "work" and os.listdir(child):
                    raise TerminalLifecycleError("automated backend working directory is not empty")
            finally:
                os.close(child)
        if include_config:
            config_fd = os.open(
                "config", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            try:
                try:
                    opencode_fd = os.open(
                        "opencode", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=config_fd,
                    )
                except FileNotFoundError:
                    os.mkdir("opencode", 0o700, dir_fd=config_fd)
                    opencode_fd = os.open(
                        "opencode", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=config_fd,
                    )
                try:
                    identities["config_opencode"] = _directory_identity(
                        os.fstat(opencode_fd)
                    )[:4]
                finally:
                    os.close(opencode_fd)
                identities["config"] = _directory_identity(os.fstat(config_fd))
            finally:
                os.close(config_fd)
        identities["root"] = _directory_identity(os.fstat(descriptor))
        return identities
    except OSError as error:
        raise TerminalLifecycleError("private backend directory traversal failed") from error
    finally:
        os.close(descriptor)


def _prepare_backend_work_directory(path: Path) -> dict[str, object]:
    if not path.is_absolute():
        raise TerminalLifecycleError("backend work directory must be absolute")
    forbidden = ("opencode.json", "opencode.jsonc", ".opencode")
    descriptors: list[tuple[str, int]] = []
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptors.append(("/", descriptor))
    try:
        current = ""
        for index, component in enumerate(path.parts[1:]):
            leaf = index == len(path.parts[1:]) - 1
            parent_fd = descriptors[-1][1]
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
            except FileNotFoundError:
                if not leaf:
                    raise TerminalLifecycleError("backend work ancestry is missing") from None
                os.mkdir(component, 0o700, dir_fd=parent_fd)
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
            current += "/" + component
            descriptors.append((current, child))
        snapshots: list[tuple[str, list[int]]] = []
        for name, item in descriptors:
            details = os.fstat(item)
            if name == str(path):
                identity = _directory_identity(details)
            else:
                mode = stat.S_IMODE(details.st_mode)
                if (
                    not stat.S_ISDIR(details.st_mode)
                    or details.st_uid not in {0, os.geteuid()}
                    or mode & 0o022
                    or not mode & 0o100
                ):
                    raise TerminalLifecycleError("backend work ancestry is unsafe")
                identity = [
                    details.st_dev, details.st_ino, details.st_mode,
                    details.st_uid, details.st_nlink,
                ]
            for candidate in forbidden:
                try:
                    os.stat(candidate, dir_fd=item, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise TerminalLifecycleError(
                    "backend work ancestry contains OpenCode configuration"
                )
            snapshots.append((name, identity))
        leaf_fd = descriptors[-1][1]
        if os.listdir(leaf_fd):
            raise TerminalLifecycleError("backend work directory is not empty")
        for (name, item), expected in zip(descriptors, snapshots, strict=True):
            details = os.fstat(item)
            observed = [
                details.st_dev, details.st_ino, details.st_mode,
                details.st_uid, details.st_nlink,
            ]
            if name != expected[0] or observed != expected[1]:
                raise TerminalLifecycleError("backend work ancestry changed")
            for candidate in forbidden:
                try:
                    os.stat(candidate, dir_fd=item, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise TerminalLifecycleError("backend work ancestry changed")
        return {
            "ancestors": [[name, identity] for name, identity in snapshots[:-1]],
            "leaf": snapshots[-1][1],
            "path": str(path),
        }
    except OSError as error:
        raise TerminalLifecycleError("backend work directory preparation failed") from error
    finally:
        for _name, item in reversed(descriptors):
            os.close(item)


_EMPTY_PROVIDER_AUTH = b"{}\n"


def _pinned_file_identity(
    descriptor: int,
    expected: bytes,
    *,
    label: str,
) -> dict[str, object]:
    details = os.fstat(descriptor)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_nlink != 1
        or stat.S_IMODE(details.st_mode) != 0o600
    ):
        raise TerminalLifecycleError(f"{label} identity is unsafe")
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        chunks.append(chunk)
        if sum(map(len, chunks)) > len(expected):
            break
    content = b"".join(chunks)
    after = os.fstat(descriptor)
    facts = (details.st_dev, details.st_ino, details.st_mode, details.st_uid,
             details.st_nlink, details.st_size)
    after_facts = (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
                   after.st_nlink, after.st_size)
    if facts != after_facts or content != expected:
        raise TerminalLifecycleError(f"{label} changed or contains provider credentials")
    return {
        "device": details.st_dev,
        "inode": details.st_ino,
        "mode": details.st_mode,
        "owner": details.st_uid,
        "links": details.st_nlink,
        "size": details.st_size,
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _prepare_runtime_auth(
    generation: Path,
    data_root: Path,
    *,
    create: bool,
) -> dict[str, object]:
    """Materialize one empty provider auth file without trusting path traversal."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    generation_fd = data_fd = opencode_fd = auth_fd = seed_fd = -1
    try:
        generation_before = generation.lstat()
        generation_fd = os.open(generation, flags | os.O_DIRECTORY)
        generation_details = os.fstat(generation_fd)
        generation_after = generation.lstat()
        generation_facts = (generation_details.st_dev, generation_details.st_ino)
        if generation_facts != (generation_before.st_dev, generation_before.st_ino) or (
            generation_facts != (generation_after.st_dev, generation_after.st_ino)
        ):
            raise TerminalLifecycleError("managed config generation changed during auth binding")
        seed_fd = os.open("provider-auth-seed.json", flags, dir_fd=generation_fd)
        seed = _pinned_file_identity(
            seed_fd, _EMPTY_PROVIDER_AUTH, label="provider auth seed"
        )
        seed_path = os.stat(
            "provider-auth-seed.json", dir_fd=generation_fd, follow_symlinks=False
        )
        if (seed_path.st_dev, seed_path.st_ino) != (seed["device"], seed["inode"]):
            raise TerminalLifecycleError("provider auth seed changed during binding")

        data_before = data_root.lstat()
        data_fd = os.open(data_root, flags | os.O_DIRECTORY)
        data_details = os.fstat(data_fd)
        if _directory_identity(data_details)[:2] != [data_before.st_dev, data_before.st_ino]:
            raise TerminalLifecycleError("private data root changed during auth binding")
        try:
            opencode_fd = os.open("opencode", flags | os.O_DIRECTORY, dir_fd=data_fd)
        except FileNotFoundError:
            if not create:
                raise TerminalLifecycleError("runtime provider auth directory is absent") from None
            os.mkdir("opencode", 0o700, dir_fd=data_fd)
            opencode_fd = os.open("opencode", flags | os.O_DIRECTORY, dir_fd=data_fd)
        opencode_before = _directory_identity(os.fstat(opencode_fd))
        try:
            auth_fd = os.open("auth.json", flags, dir_fd=opencode_fd)
        except FileNotFoundError:
            if not create:
                raise TerminalLifecycleError("runtime provider auth file is absent") from None
            auth_fd = os.open(
                "auth.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=opencode_fd,
            )
            view = memoryview(_EMPTY_PROVIDER_AUTH)
            while view:
                written = os.write(auth_fd, view)
                if written <= 0:
                    raise TerminalLifecycleError("runtime provider auth write failed")
                view = view[written:]
            os.fsync(auth_fd)
            os.close(auth_fd)
            auth_fd = -1
            auth_fd = os.open("auth.json", flags, dir_fd=opencode_fd)
            os.fsync(opencode_fd)
        auth = _pinned_file_identity(
            auth_fd, _EMPTY_PROVIDER_AUTH, label="runtime provider auth"
        )
        auth_path = os.stat("auth.json", dir_fd=opencode_fd, follow_symlinks=False)
        if (auth_path.st_dev, auth_path.st_ino) != (auth["device"], auth["inode"]):
            raise TerminalLifecycleError("runtime provider auth changed during binding")
        opencode_identity = _directory_identity(os.fstat(opencode_fd))
        if opencode_identity[:2] != opencode_before[:2]:
            raise TerminalLifecycleError("runtime provider auth directory changed")
        data_after = data_root.lstat()
        if (data_after.st_dev, data_after.st_ino) != (
            data_details.st_dev, data_details.st_ino
        ):
            raise TerminalLifecycleError("private data root changed during auth binding")
        return {"auth": auth, "directory": opencode_identity[:4], "seed": seed}
    except OSError as error:
        raise TerminalLifecycleError("runtime provider auth preparation failed") from error
    finally:
        for descriptor in (auth_fd, seed_fd, opencode_fd, data_fd, generation_fd):
            if descriptor >= 0:
                os.close(descriptor)


class _ProcessGroupParser:
    def __init__(self, identity: ProcessIdentity):
        self.identity = identity
        self.live = False
        self.leader = False
        self.found = False
        self.seen: set[int] = set()
        self.invalid = False
        self.line_count = 0

    def consume(self, raw: bytes) -> None:
        self.line_count += 1
        if self.line_count > 65536 or not raw or len(raw) > 1024 * 1024:
            self.invalid = True
            return
        try:
            line = raw.decode("utf-8", errors="strict")
        except UnicodeError:
            self.invalid = True
            return
        prefix = line.strip().split(None, 2)
        if len(prefix) < 2:
            self.invalid = True
            return
        try:
            candidate_pid = int(prefix[0])
            candidate_pgid = int(prefix[1])
        except ValueError:
            self.invalid = True
            return
        if candidate_pid <= 0 or candidate_pgid <= 0:
            self.invalid = True
            return
        if candidate_pgid != self.identity.pgid:
            return
        self.found = True
        if candidate_pid in self.seen:
            self.invalid = True
            return
        self.seen.add(candidate_pid)
        fields = line.strip().split(None, 8)
        if len(fields) not in {8, 9}:
            self.invalid = True
            return
        try:
            pid = int(fields[0])
            pgid = int(fields[1])
        except ValueError:
            self.invalid = True
            return
        started = " ".join(fields[2:7])
        state = fields[7]
        command = tuple(fields[8].split()) if len(fields) == 9 else ()
        if pgid != self.identity.pgid or re.fullmatch(r"[A-Z][A-Za-z0-9+<]*", state) is None:
            self.invalid = True
            return
        terminated = state[0] in {"X", "Z"}
        if not command and not terminated:
            self.invalid = True
            return
        if pid == self.identity.pid:
            if started != self.identity.started or (
                not terminated and command != self.identity.command
            ):
                self.invalid = True
                return
            self.leader = True
        if not terminated:
            self.live = True

    def result(self) -> str:
        if self.invalid:
            return "error"
        if not self.found:
            return "empty"
        if self.live and not self.leader:
            return "unanchored_live"
        return "live" if self.live else "terminated"


def _terminate_probe(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1.0)


def _process_group_state(
    identity: ProcessIdentity,
    *,
    command: tuple[str, ...] = (
        "/bin/ps", "-axo", "pid=,pgid=,lstart=,state=,command=",
    ),
) -> str:
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError:
        return "error"
    assert process.stdout is not None and process.stderr is not None
    parser = _ProcessGroupParser(identity)
    partial = bytearray()
    stdout_total = 0
    stderr_total = 0
    failed = False
    deadline = time.monotonic() + 5.0
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failed = True
                _terminate_probe(process)
                break
            events = selector.select(min(remaining, 0.25))
            if not events:
                continue
            for key, _mask in events:
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stderr":
                    stderr_total += len(chunk)
                    failed = True
                    _terminate_probe(process)
                    break
                stdout_total += len(chunk)
                if stdout_total > 8 * 1024 * 1024:
                    failed = True
                    _terminate_probe(process)
                    break
                partial.extend(chunk)
                if len(partial) > 1024 * 1024 and b"\n" not in partial:
                    failed = True
                    _terminate_probe(process)
                    break
                while True:
                    newline = partial.find(b"\n")
                    if newline < 0:
                        break
                    if newline > 1024 * 1024:
                        failed = True
                        _terminate_probe(process)
                        break
                    line = bytes(partial[:newline])
                    del partial[: newline + 1]
                    parser.consume(line)
                    if parser.invalid:
                        failed = True
                        _terminate_probe(process)
                        break
                if failed:
                    break
            if failed:
                break
        if not failed and partial:
            failed = True
        if not failed:
            try:
                returncode = process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                failed = True
                _terminate_probe(process)
            else:
                failed = returncode != 0 or stderr_total != 0
    except (OSError, ValueError):
        failed = True
        _terminate_probe(process)
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return "error" if failed else parser.result()


@contextmanager
def _defer_terminal_signals() -> Any:
    if threading.current_thread() is not threading.main_thread():
        raise TerminalLifecycleError("terminal signal deferral requires main thread")
    watched = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
    previous = {item: signal.getsignal(item) for item in watched}
    pending: list[int] = []

    def defer(signum: int, _frame: object) -> None:
        pending.append(signum)

    for item in watched:
        signal.signal(item, defer)
    succeeded = False
    try:
        yield
        succeeded = True
    finally:
        for item, handler in previous.items():
            signal.signal(item, handler)
    if succeeded and pending:
        raise TerminalLifecycleError(
            f"terminal signal {pending[0]} deferred across ownership publication"
        )


class TerminalLifecycle:
    """Own one attended controller/backend pair for a terminal invocation."""

    def __init__(
        self,
        *,
        deployment: UserDeployment,
        opencode: Path,
        ownership_path: Path,
        backend_directory: Path,
        backend_work_directory: Path | None = None,
        adopt_running_controller: bool = False,
        require_backend_ownership: bool = False,
    ):
        self.deployment = deployment
        self.opencode = opencode.resolve()
        self.ownership_path = ownership_path.resolve()
        self.backend_directory = (
            _managed_backend_directory(deployment.home, backend_directory)
            if isinstance(deployment, UserDeployment)
            else backend_directory.resolve()
        )
        self.backend_work_directory = (
            backend_work_directory
            if backend_work_directory is not None
            else self.backend_directory / "work"
        )
        self.adopt_running_controller = adopt_running_controller
        self.require_backend_ownership = require_backend_ownership
        self.invocation_id = uuid.uuid4().hex
        self.controller_owned = False
        self.controller_pid: int | None = None
        self.controller_starting = False
        self.backend_owned = False
        self.backend: subprocess.Popen[bytes] | None = None
        self.backend_identity: ProcessIdentity | None = None
        self.backend_binding: dict[str, object] | None = None
        self.backend_started_by_invocation = False
        self.snapshot: object | None = None
        self.tmux_session_id: str | None = None
        self.tmux_nonce: str | None = None
        self.cutover_intent: dict[str, object] | None = None
        self.completed_cutover: dict[str, object] | None = None
        self.cleanup_authorized = False
        self._lock_descriptor: int | None = None
        self._deployment_operation_context: object | None = None

    def _acquire_lock(self) -> None:
        self.ownership_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock = self.ownership_path.with_suffix(".lock")
        descriptor = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(descriptor)
            raise TerminalLifecycleError("another terminal lifecycle is active") from error
        self._lock_descriptor = descriptor

    def _release_lock(self) -> None:
        if self._lock_descriptor is not None:
            fcntl.flock(self._lock_descriptor, fcntl.LOCK_UN)
            os.close(self._lock_descriptor)
            self._lock_descriptor = None
        if self._deployment_operation_context is not None:
            context = self._deployment_operation_context
            self._deployment_operation_context = None
            context.__exit__(None, None, None)

    def _acquire_deployment_operation(self) -> None:
        if (
            isinstance(self.deployment, UserDeployment)
            and self._deployment_operation_context is None
        ):
            context = self.deployment._operation_lock()
            context.__enter__()
            self._deployment_operation_context = context

    def _pending_path(self) -> Path:
        return self.ownership_path.with_name(f".{self.ownership_path.name}.pending")

    def _receipt_path(self, proof: Mapping[str, object]) -> Path:
        material = proof.get("material")
        destination = material.get("destination") if isinstance(material, Mapping) else None
        release_id = destination.get("release_id") if isinstance(destination, Mapping) else None
        config_id = destination.get("config_id") if isinstance(destination, Mapping) else None
        if (
            not isinstance(release_id, str)
            or re.fullmatch(r"[0-9A-Za-z.]+-[0-9a-f]{16}", release_id) is None
            or not isinstance(config_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", config_id) is None
        ):
            raise TerminalLifecycleError("completed cutover destination is malformed")
        return self.ownership_path.with_name(
            f"completed-cutover-receipt-{release_id}-{config_id}.json"
        )

    def _recover_pending(self) -> None:
        """Promote one complete crash-left publication or discard a partial one."""
        pending = self._pending_path()
        try:
            details = pending.lstat()
        except FileNotFoundError:
            return
        if (
            not pending.is_file()
            or details.st_uid != os.geteuid()
            or details.st_mode & 0o777 != 0o600
            or details.st_nlink != 1
        ):
            raise TerminalLifecycleError("pending ownership publication is unsafe")
        try:
            data = pending.read_bytes()
            value = json.loads(data)
            canonical = (
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            )
            valid = (
                data == canonical
                and isinstance(value, dict)
                and value.get("format") == 1
                and value.get("phase") in {
                    "cutover",
                    "migrated",
                    "starting",
                    "running",
                    "retained",
                    "stopped",
                }
            )
        except (OSError, UnicodeError, json.JSONDecodeError):
            valid = False
        if valid:
            os.replace(pending, self.ownership_path)
        else:
            pending.unlink()
        directory = os.open(self.ownership_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _write_record(self, phase: str, reason: str) -> None:
        self.ownership_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.ownership_path.parent, 0o700)
        value: dict[str, object] = {
            "backend": self.backend_identity.as_json() if self.backend_identity else None,
            "backend_owned": self.backend_owned,
            "controller_owned": self.controller_owned,
            "controller_pid": self.controller_pid,
            "controller_starting": self.controller_starting,
            "completed_cutover": self.completed_cutover,
            "cutover_intent": self.cutover_intent,
            "format": 1,
            "invocation_id": self.invocation_id,
            "phase": phase,
            "reason": reason,
            "tmux_session_id": self.tmux_session_id,
            "tmux_nonce": self.tmux_nonce,
        }
        if phase != "stopped":
            value["backend_binding"] = self.backend_binding
        temporary = self._pending_path()
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        try:
            descriptor = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                offset = 0
                while offset < len(data):
                    try:
                        written = os.write(descriptor, data[offset:])
                    except InterruptedError:
                        continue
                    if written <= 0:
                        raise TerminalLifecycleError("ownership record write made no progress")
                    offset += written
                os.fsync(descriptor)
                os.lseek(descriptor, 0, os.SEEK_SET)
                verified = bytearray()
                while len(verified) < len(data):
                    try:
                        chunk = os.read(descriptor, len(data) - len(verified))
                    except InterruptedError:
                        continue
                    if not chunk:
                        raise TerminalLifecycleError("ownership record readback was truncated")
                    verified.extend(chunk)
                if hashlib.sha256(verified).digest() != hashlib.sha256(data).digest():
                    raise TerminalLifecycleError("ownership record readback hash differed")
            finally:
                os.close(descriptor)
            os.replace(temporary, self.ownership_path)
            directory = os.open(self.ownership_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise

    def _load_retained(self) -> dict[str, object] | None:
        try:
            value = json.loads(self.ownership_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise TerminalLifecycleError("existing ownership record is unreadable") from error
        if not isinstance(value, dict) or value.get("format") != 1:
            raise TerminalLifecycleError("existing ownership record is malformed")
        if value.get("phase") == "stopped":
            return None
        if value.get("phase") not in {
            "cutover",
            "migrated",
            "starting",
            "running",
            "retained",
        }:
            raise TerminalLifecycleError("existing ownership phase is invalid")
        return value

    def _deployment_status(self, *, for_cleanup: bool) -> Mapping[str, object]:
        return (
            self.deployment.stop_status()
            if for_cleanup and isinstance(self.deployment, UserDeployment)
            else self.deployment.status()
        )

    def _configuration(
        self,
        *,
        for_cleanup: bool = False,
        deployment_status: Mapping[str, object] | None = None,
    ) -> tuple[str, str, str, int]:
        result = (
            deployment_status
            if deployment_status is not None
            else self._deployment_status(for_cleanup=for_cleanup)
        )
        state = json.loads((self.deployment.root / "deployment-state.json").read_text())
        opencode = state.get("opencode")
        if not isinstance(opencode, dict):
            raise TerminalLifecycleError("v2 OpenCode configuration is absent")
        endpoint = opencode.get("endpoint")
        config_id = opencode.get("config_id")
        if not isinstance(endpoint, str) or not isinstance(config_id, str):
            raise TerminalLifecycleError("v2 OpenCode configuration is malformed")
        parsed = urlparse(endpoint)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise TerminalLifecycleError("v2 OpenCode endpoint is not explicit loopback HTTP")
        if parsed.port is None or parsed.path not in {"", "/"}:
            raise TerminalLifecycleError("v2 OpenCode endpoint is not a bare loopback port")
        auth_path = self.deployment.root / "config" / "opencode" / config_id / "auth.json"
        auth = json.loads(auth_path.read_text(encoding="utf-8"))
        if not isinstance(auth, dict) or auth.get("type") != "basic":
            raise TerminalLifecycleError("v2 OpenCode authentication is not Basic")
        username, password = auth.get("username"), auth.get("password")
        if not isinstance(username, str) or not isinstance(password, str) or not password:
            raise TerminalLifecycleError("v2 OpenCode authentication is malformed")
        socket_path = result.get("socket")
        if not isinstance(socket_path, str):
            raise TerminalLifecycleError("v2 deployment status omitted its socket")
        return endpoint.rstrip("/"), username, password, parsed.port

    @staticmethod
    def _health(endpoint: str, username: str, password: str) -> bool:
        import base64

        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        request = urllib.request.Request(
            endpoint + "/global/health", headers={"Authorization": f"Basic {token}"}
        )
        try:
            with urllib.request.urlopen(request, timeout=1.0) as response:
                return response.status == 200
        except (OSError, urllib.error.URLError):
            return False

    @staticmethod
    def _backend_authority(
        endpoint: str, username: str, password: str, data_home: Path
    ) -> str:
        import base64

        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        values: dict[str, object] = {}
        for name in ("config", "agent"):
            request = urllib.request.Request(
                endpoint + f"/{name}",
                headers={"Authorization": f"Basic {token}"},
            )
            try:
                with urllib.request.urlopen(request, timeout=1.0) as response:
                    if response.status != 200:
                        raise TerminalLifecycleError(
                            "automated backend authority attestation failed"
                        )
                    values[name] = json.loads(response.read(1024 * 1024))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise TerminalLifecycleError(
                    "automated backend authority attestation failed"
                ) from error
        tool_output = str(data_home / "opencode" / "tool-output" / "*")
        try:
            return automated_backend_authority(
                values["config"], values["agent"],
                tool_output_pattern=tool_output,
            )
        except OpenCodeAuthorityInvalid as error:
            raise TerminalLifecycleError(
                "automated backend authority is invalid"
            ) from error

    def _expected_backend_binding(
        self, *, for_cleanup: bool = False
    ) -> dict[str, object]:
        state = self._deployment_status(for_cleanup=for_cleanup)
        _endpoint, username, password, _port = self._configuration(
            for_cleanup=for_cleanup,
            deployment_status=state,
        )
        config_id = state["opencode"]["config_id"]
        return self._automated_backend_binding(config_id, username, password)

    def _expected_retained_backend_binding_for_cleanup(
        self, retained_binding: object
    ) -> dict[str, object]:
        """Authenticate a retained pre-upgrade backend only for termination."""

        current = self._expected_backend_binding(for_cleanup=True)
        if _backend_binding_matches(retained_binding, current):
            return current
        if not isinstance(retained_binding, Mapping):
            raise TerminalLifecycleError("retained backend binding changed")
        config_id = retained_binding.get("config_id")
        if not isinstance(config_id, str):
            raise TerminalLifecycleError("retained backend binding changed")
        state = self._deployment_status(for_cleanup=True)
        opencode = state.get("opencode")
        if not isinstance(opencode, Mapping):
            raise TerminalLifecycleError("retained backend binding changed")
        endpoint = opencode.get("endpoint")
        if not isinstance(endpoint, str):
            raise TerminalLifecycleError("retained backend binding changed")
        try:
            historical = validated_historical_opencode_configuration(
                self.deployment.root,
                config_id=config_id,
                endpoint=endpoint,
            )
            auth = json.loads(historical.auth.read_text(encoding="utf-8"))
        except (DeploymentError, OSError, UnicodeError, json.JSONDecodeError) as error:
            raise TerminalLifecycleError("retained backend binding changed") from error
        if (
            not isinstance(auth, dict)
            or auth.get("type") != "basic"
            or not isinstance(auth.get("username"), str)
            or not isinstance(auth.get("password"), str)
            or not auth["password"]
        ):
            raise TerminalLifecycleError("retained backend binding changed")
        expected = self._automated_backend_binding(
            config_id,
            auth["username"],
            auth["password"],
        )
        if not _backend_binding_matches(retained_binding, expected):
            raise TerminalLifecycleError("retained backend binding changed")
        return expected

    def _automated_backend_binding(
        self,
        config_id: str,
        username: str,
        password: str,
        *,
        legacy_work: bool = False,
    ) -> dict[str, object]:
        generation = self.deployment.root / "config" / "opencode" / config_id
        roots = _prepare_private_backend_tree(self.backend_directory)
        if legacy_work:
            details = (self.backend_directory / "work").lstat()
            work_identity: list[int] = [
                details.st_dev, details.st_ino, details.st_mode, details.st_uid,
            ]
        else:
            work_identity = _prepare_backend_work_directory(
                self.backend_work_directory
            )
        provider_auth = _prepare_runtime_auth(
            generation, self.backend_directory / "data", create=False
        )
        roots = _prepare_private_backend_tree(self.backend_directory)
        material = {
            "HOME": str(self.backend_directory / "home"),
            "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1",
            **_OPENCODE_ISOLATION_ENVIRONMENT,
            "OPENCODE_CONFIG": str(generation / "automated-backend-policy.json"),
            "OPENCODE_SERVER_USERNAME": username,
            "OPENCODE_SERVER_PASSWORD": password,
            "XDG_CONFIG_HOME": str(self.backend_directory / "config"),
            "XDG_DATA_HOME": str(self.backend_directory / "data"),
            "XDG_CACHE_HOME": str(self.backend_directory / "cache"),
            "XDG_STATE_HOME": str(self.backend_directory / "state"),
        }
        result: dict[str, object] = {
            "config_id": config_id,
            "environment_sha256": hashlib.sha256(
                json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "working_directory": work_identity,
            "private_roots": roots,
            "provider_auth": provider_auth,
        }
        if not legacy_work:
            result["working_directory_path"] = str(self.backend_work_directory)
        return result

    def _backend_binding_for_generation(
        self, config_id: str, username: str, password: str
    ) -> dict[str, object]:
        generation = self.deployment.root / "config" / "opencode" / config_id
        roots = _prepare_private_backend_tree(
            self.backend_directory, include_config=False
        )
        provider_auth = _prepare_runtime_auth(
            generation, self.backend_directory / "data", create=False
        )
        roots = _prepare_private_backend_tree(
            self.backend_directory, include_config=False
        )
        details = (self.backend_directory / "work").lstat()
        material = {
            "HOME": str(self.backend_directory / "home"),
            "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1",
            "OPENCODE_SERVER_USERNAME": username,
            "OPENCODE_SERVER_PASSWORD": password,
            "XDG_CONFIG_HOME": str(generation / "xdg"),
            "XDG_DATA_HOME": str(self.backend_directory / "data"),
            "XDG_CACHE_HOME": str(self.backend_directory / "cache"),
            "XDG_STATE_HOME": str(self.backend_directory / "state"),
        }
        return {
            "config_id": config_id,
            "environment_sha256": hashlib.sha256(
                json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "working_directory": [details.st_dev, details.st_ino, details.st_mode, details.st_uid],
            "private_roots": roots,
            "provider_auth": provider_auth,
        }

    def _start_backend(self, endpoint: str, username: str, password: str, port: int) -> None:
        if self._health(endpoint, username, password):
            if (
                self.backend_owned
                and self.backend_identity is not None
                and _process_state(self.backend_identity) == "exact"
                and _backend_binding_matches(
                    self.backend_binding, self._expected_backend_binding()
                )
                and _listener_pid(port) == self.backend_identity.pid
            ):
                if isinstance(self.deployment, UserDeployment):
                    try:
                        data_home = self.backend_directory / "data"
                        first = self._backend_authority(
                            endpoint, username, password, data_home
                        )
                        second = self._backend_authority(
                            endpoint, username, password, data_home
                        )
                        if first != second:
                            raise TerminalLifecycleError(
                                "automated backend authority changed during attestation"
                            )
                    except TerminalLifecycleError:
                        self._stop_backend()
                        raise
                return
            raise TerminalLifecycleError(
                "healthy OpenCode backend is not owned by this lifecycle"
            )
        root_identities = _prepare_private_backend_tree(self.backend_directory)
        private_home = self.backend_directory / "home"
        data_home = self.backend_directory / "data"
        cache_home = self.backend_directory / "cache"
        config_home = self.backend_directory / "config"
        state_home = self.backend_directory / "state"
        work_directory = self.backend_work_directory
        work_identity = _prepare_backend_work_directory(work_directory)
        command = (str(self.opencode), "serve", "--port", str(port), "--pure")
        environment = {
            "HOME": str(private_home),
            "LANG": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "PYTHONNOUSERSITE": "1",
            **_OPENCODE_ISOLATION_ENVIRONMENT,
            "OPENCODE_SERVER_USERNAME": username,
            "OPENCODE_SERVER_PASSWORD": password,
            "XDG_CONFIG_HOME": str(config_home),
            "XDG_DATA_HOME": str(data_home),
            "XDG_CACHE_HOME": str(cache_home),
            "XDG_STATE_HOME": str(state_home),
        }
        status_method = getattr(self.deployment, "status", None)
        provider_auth: dict[str, object] | None = None
        if callable(status_method):
            config_id = status_method()["opencode"]["config_id"]
            generation = self.deployment.root / "config" / "opencode" / config_id
            policy = generation / "automated-backend-policy.json"
            if not policy.is_file() or policy.is_symlink():
                for directory in (state_home, cache_home, data_home, private_home):
                    directory.rmdir()
                raise TerminalLifecycleError(
                    "automated backend configuration requires managed policy migration"
                )
            environment["OPENCODE_CONFIG"] = str(policy)
            provider_auth = _prepare_runtime_auth(
                generation, data_home, create=True
            )
            root_identities = _prepare_private_backend_tree(self.backend_directory)
        else:
            environment.pop("XDG_CONFIG_HOME", None)
        self.backend_binding = {
            "config_id": config_id if callable(status_method) else None,
            "environment_sha256": hashlib.sha256(
                json.dumps(environment, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "working_directory": work_identity,
            "working_directory_path": str(work_directory),
            "private_roots": root_identities,
            "provider_auth": provider_auth,
        }
        if _prepare_private_backend_tree(self.backend_directory) != root_identities:
            raise TerminalLifecycleError("private backend directory identity changed")
        if _prepare_backend_work_directory(work_directory) != work_identity:
            raise TerminalLifecycleError("backend work directory identity changed")
        with _defer_terminal_signals():
            provisional = subprocess.Popen(
                command,
                cwd=work_directory,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            self.backend = provisional
            try:
                self.backend_identity = _process_identity(provisional.pid, command)
                self.backend_owned = True
                self.backend_started_by_invocation = True
                self._write_record("starting", "backend started")
            except BaseException:
                try:
                    os.killpg(provisional.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    provisional.wait(timeout=10.0)
                except subprocess.TimeoutExpired:
                    os.killpg(provisional.pid, signal.SIGKILL)
                    provisional.wait(timeout=5.0)
                self.backend = None
                self.backend_identity = None
                self.backend_owned = False
                raise
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            if self.backend.poll() is not None:
                break
            if self._health(endpoint, username, password):
                identity = self.backend_identity
                exact = (
                    identity is not None
                    and _listener_pid(port) == provisional.pid
                    and _process_state(identity) == "exact"
                    and _backend_binding_matches(
                        self.backend_binding, self._expected_backend_binding()
                    )
                )
                if exact and isinstance(self.deployment, UserDeployment):
                    try:
                        first = self._backend_authority(
                            endpoint, username, password, data_home
                        )
                        second = self._backend_authority(
                            endpoint, username, password, data_home
                        )
                        exact = first == second
                    except TerminalLifecycleError:
                        exact = False
                if exact:
                    return
                self._stop_backend()
                raise TerminalLifecycleError(
                    "fresh backend readiness lost exact ownership binding"
                )
            time.sleep(0.1)
        self._stop_backend()
        raise TerminalLifecycleError("owned OpenCode backend failed authenticated readiness")

    def _adopt_retained(self, retained: Mapping[str, object], running_pid: int | None) -> None:
        backend_identity: ProcessIdentity | None = None
        backend_state = "absent"
        if retained.get("backend_owned") is True:
            backend_identity = ProcessIdentity.from_json(retained.get("backend"))
            binding = retained.get("backend_binding")
            expected_binding = self._expected_backend_binding()
            if not _backend_binding_matches(binding, expected_binding):
                raise TerminalLifecycleError("retained backend binding changed")
            backend_state = _process_state(backend_identity)
            if backend_state in {"mismatch", "error"}:
                raise TerminalLifecycleError(
                    "retained backend ownership cannot be authenticated"
                )
        if retained.get("controller_owned") is True:
            recorded_pid = retained.get("controller_pid")
            if not isinstance(recorded_pid, int) or recorded_pid != running_pid:
                raise TerminalLifecycleError("retained controller ownership no longer matches")
            self.controller_owned = True
            self.controller_pid = recorded_pid
        elif retained.get("controller_starting") is True and running_pid is not None:
            self.controller_owned = True
            self.controller_pid = running_pid
        self.controller_starting = False
        if backend_identity is not None and backend_state == "exact":
            self.backend_owned = True
            self.backend_identity = backend_identity
            self.backend_binding = expected_binding
        tmux_session_id = retained.get("tmux_session_id")
        if isinstance(tmux_session_id, str) and tmux_session_id:
            self.tmux_session_id = tmux_session_id
        tmux_nonce = retained.get("tmux_nonce")
        if isinstance(tmux_nonce, str) and tmux_nonce:
            self.tmux_nonce = tmux_nonce
        cutover_intent = retained.get("cutover_intent")
        if isinstance(cutover_intent, dict):
            self.cutover_intent = dict(cutover_intent)
        completed_cutover = retained.get("completed_cutover")
        if isinstance(completed_cutover, dict):
            self.completed_cutover = dict(completed_cutover)

    def prepare_cutover(
        self,
        *,
        controller_pid: int,
        intent: Mapping[str, object],
    ) -> None:
        """Lock and durably authorize one exact, quiescence-bound legacy removal."""
        if self._lock_descriptor is None:
            self._acquire_lock()
            self._recover_pending()
        retained = self._load_retained()
        canonical = dict(intent)
        if retained is not None:
            existing = retained.get("cutover_intent")
            if existing != canonical:
                raise TerminalLifecycleError("cutover intent does not match durable proof")
            self._adopt_retained(retained, controller_pid)
        self.controller_owned = True
        self.controller_pid = controller_pid
        self.cutover_intent = canonical
        self._write_record("cutover", "exact legacy removal authorized")

    def adopt_completed_cutover(
        self,
        *,
        proof: Mapping[str, object],
        expected_existing: Mapping[str, object] | None,
    ) -> None:
        """Persist one validated prior-cutover proof before a fresh release starts."""

        if (
            proof.get("format") != 2
            or not isinstance(proof.get("material"), Mapping)
            or not isinstance(proof.get("receipt_id"), str)
        ):
            raise TerminalLifecycleError("completed cutover proof is malformed")
        if self._lock_descriptor is None:
            self._acquire_lock()
        try:
            self._recover_pending()
            try:
                current = json.loads(self.ownership_path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                current = None
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise TerminalLifecycleError(
                    "existing ownership record changed during cutover adoption"
                ) from error
            expected = dict(expected_existing) if expected_existing is not None else None
            if current != expected:
                raise TerminalLifecycleError(
                    "existing ownership record changed during cutover adoption"
                )
            if (
                current is None
                or current.get("phase") != "stopped"
                or current.get("backend_owned") is not False
                or current.get("controller_owned") is not False
                or current.get("controller_starting") is not False
                or current.get("controller_pid") is not None
            ):
                raise TerminalLifecycleError(
                    "completed cutover requires exact stopped ownership"
                )
            receipt = self._receipt_path(proof)
            receipt_data = (
                json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
                + b"\n"
            )
            if current.get("completed_cutover") == dict(proof):
                try:
                    descriptor = os.open(
                        receipt, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                    )
                    try:
                        before = os.fstat(descriptor)
                        chunks: list[bytes] = []
                        while chunk := os.read(descriptor, 65536):
                            chunks.append(chunk)
                        after = os.fstat(descriptor)
                    finally:
                        os.close(descriptor)
                except OSError as error:
                    raise TerminalLifecycleError(
                        "completed cutover receipt anchor changed"
                    ) from error
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.geteuid()
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_nlink != 1
                    or (before.st_dev, before.st_ino, before.st_ctime_ns, before.st_size)
                    != (after.st_dev, after.st_ino, after.st_ctime_ns, after.st_size)
                    or b"".join(chunks) != receipt_data
                ):
                    raise TerminalLifecycleError(
                        "completed cutover receipt anchor changed"
                    )
            else:
                try:
                    descriptor = os.open(
                        receipt,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                    )
                except FileExistsError as error:
                    prior = current.get("completed_cutover")
                    prior_material = (
                        prior.get("material") if isinstance(prior, Mapping) else None
                    )
                    if (
                        not isinstance(prior, dict)
                        or set(prior) != {"format", "material", "receipt_id"}
                        or prior.get("format") != 2
                        or not isinstance(prior_material, Mapping)
                        or prior_material.get("intent") != current.get("cutover_intent")
                        or not isinstance(prior.get("receipt_id"), str)
                        or re.fullmatch(r"[0-9a-f]{32}", prior["receipt_id"]) is None
                    ):
                        raise TerminalLifecycleError(
                            "completed cutover receipt was already consumed"
                        ) from error
                    self._validate_completed_cutover_receipt(prior)
                    try:
                        self._validate_completed_cutover_receipt(proof)
                    except TerminalLifecycleError as receipt_error:
                        raise TerminalLifecycleError(
                            "completed cutover receipt was already consumed"
                        ) from receipt_error
                    descriptor = -1
                try:
                    if descriptor >= 0:
                        offset = 0
                        while offset < len(receipt_data):
                            written = os.write(descriptor, receipt_data[offset:])
                            if written <= 0:
                                raise TerminalLifecycleError(
                                    "completed cutover receipt write made no progress"
                                )
                            offset += written
                        os.fsync(descriptor)
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                if descriptor >= 0:
                    directory = os.open(receipt.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
            self.completed_cutover = dict(proof)
            self.cutover_intent = dict(proof["material"]["intent"])
            self._write_record("migrated", "validated completed direct cutover adopted")
        except BaseException:
            self._release_lock()
            raise

    def _validate_completed_cutover_receipt(
        self, proof: Mapping[str, object]
    ) -> None:
        receipt = self._receipt_path(proof)
        expected = json.dumps(
            proof, sort_keys=True, separators=(",", ":")
        ).encode() + b"\n"
        try:
            descriptor = os.open(
                receipt, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                before = os.fstat(descriptor)
                chunks: list[bytes] = []
                while chunk := os.read(descriptor, 65536):
                    chunks.append(chunk)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
        except OSError as error:
            raise TerminalLifecycleError(
                "completed cutover receipt anchor changed"
            ) from error
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino, before.st_ctime_ns, before.st_size)
            != (after.st_dev, after.st_ino, after.st_ctime_ns, after.st_size)
            or b"".join(chunks) != expected
        ):
            raise TerminalLifecycleError("completed cutover receipt anchor changed")

    def _prior_backend_authority_from_completed_proof(
        self, proof: Mapping[str, object]
    ) -> tuple[str, str, str]:
        self._validate_completed_cutover_receipt(proof)
        material = proof.get("material")
        destination = material.get("destination") if isinstance(material, Mapping) else None
        intent = material.get("intent") if isinstance(material, Mapping) else None
        old_config_id = destination.get("config_id") if isinstance(destination, Mapping) else None
        old_release_id = destination.get("release_id") if isinstance(destination, Mapping) else None
        old_root = destination.get("root") if isinstance(destination, Mapping) else None
        pin_sha256 = destination.get("release_pin_sha256") if isinstance(destination, Mapping) else None
        state_sha256 = destination.get("state_sha256") if isinstance(destination, Mapping) else None
        endpoint = intent.get("endpoint") if isinstance(intent, Mapping) else None
        if (
            not isinstance(old_config_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", old_config_id) is None
            or not isinstance(old_release_id, str)
            or re.fullmatch(r"[0-9A-Za-z.]+-[0-9a-f]{16}", old_release_id) is None
            or old_root != str(self.deployment.root)
            or not isinstance(pin_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", pin_sha256) is None
            or not isinstance(state_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", state_sha256) is None
            or not isinstance(endpoint, str)
        ):
            raise TerminalLifecycleError("stale stopped backend prior destination is invalid")
        self.deployment.status()
        release_pin = self.deployment.root / "releases" / old_release_id / "release-pin.json"
        try:
            descriptor = os.open(
                release_pin, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                pin_before = os.fstat(descriptor)
                chunks: list[bytes] = []
                while chunk := os.read(descriptor, 65536):
                    chunks.append(chunk)
                pin_after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            release_details = release_pin.parent.lstat()
        except OSError as error:
            raise TerminalLifecycleError(
                "stale stopped backend prior release changed"
            ) from error
        if (
            not stat.S_ISDIR(release_details.st_mode)
            or release_details.st_uid != os.geteuid()
            or stat.S_IMODE(release_details.st_mode) != 0o500
            or not stat.S_ISREG(pin_before.st_mode)
            or pin_before.st_uid != os.geteuid()
            or stat.S_IMODE(pin_before.st_mode) != 0o400
            or pin_before.st_nlink != 1
            or (pin_before.st_dev, pin_before.st_ino, pin_before.st_ctime_ns, pin_before.st_size)
            != (pin_after.st_dev, pin_after.st_ino, pin_after.st_ctime_ns, pin_after.st_size)
            or hashlib.sha256(b"".join(chunks)).hexdigest() != pin_sha256
        ):
            raise TerminalLifecycleError("stale stopped backend prior release changed")
        try:
            try:
                old_config = validated_historical_opencode_configuration(
                    self.deployment.root,
                    config_id=old_config_id,
                    endpoint=endpoint,
                )
            except DeploymentError:
                try:
                    old_config = validated_failed_start_historical_opencode_configuration(
                        self.deployment.root,
                        config_id=old_config_id,
                        endpoint=endpoint,
                    )
                except DeploymentError:
                    old_config = validated_polluted_historical_opencode_configuration(
                        self.deployment.root,
                        config_id=old_config_id,
                        endpoint=endpoint,
                    )
            old_auth = json.loads(old_config.auth.read_text(encoding="utf-8"))
        except (DeploymentError, OSError, UnicodeError, json.JSONDecodeError) as error:
            raise TerminalLifecycleError(
                "stale stopped backend prior config changed"
            ) from error
        if (
            not isinstance(old_auth, dict)
            or old_auth.get("type") != "basic"
            or not isinstance(old_auth.get("username"), str)
            or not isinstance(old_auth.get("password"), str)
            or not old_auth["password"]
        ):
            raise TerminalLifecycleError(
                "stale stopped backend prior authentication is invalid"
            )
        return old_config_id, old_auth["username"], old_auth["password"]

    def _prior_backend_binding_from_completed_proof(
        self, proof: Mapping[str, object]
    ) -> dict[str, object]:
        config_id, username, password = (
            self._prior_backend_authority_from_completed_proof(proof)
        )
        return self._backend_binding_for_generation(config_id, username, password)

    def _prior_policy_backend_binding_from_completed_proof(
        self, proof: Mapping[str, object]
    ) -> dict[str, object]:
        config_id, username, password = (
            self._prior_backend_authority_from_completed_proof(proof)
        )
        return self._automated_backend_binding(
            config_id, username, password, legacy_work=True
        )

    def _validate_current_completed_cutover_proof(
        self, proof: Mapping[str, object], selected_config_id: str
    ) -> None:
        material = proof.get("material")
        destination = material.get("destination") if isinstance(material, Mapping) else None
        if (
            set(proof) != {"format", "material", "receipt_id"}
            or proof.get("format") != 2
            or not isinstance(proof.get("receipt_id"), str)
            or re.fullmatch(r"[0-9a-f]{32}", str(proof.get("receipt_id"))) is None
            or not isinstance(material, Mapping)
            or set(material) != {"destination", "evidence", "intent", "source"}
            or not isinstance(destination, Mapping)
            or set(destination) != {
                "config_id", "release_id", "release_pin_sha256", "root",
                "state_sha256",
            }
            or destination.get("config_id") != selected_config_id
            or re.fullmatch(r"[0-9a-f]{64}", selected_config_id) is None
            or destination.get("root") != str(self.deployment.root)
            or not isinstance(destination.get("release_id"), str)
            or re.fullmatch(
                r"[0-9A-Za-z.]+-[0-9a-f]{16}", str(destination.get("release_id"))
            ) is None
            or not isinstance(destination.get("release_pin_sha256"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}", str(destination.get("release_pin_sha256"))
            ) is None
            or not isinstance(destination.get("state_sha256"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}", str(destination.get("state_sha256"))
            ) is None
        ):
            raise TerminalLifecycleError("starting ownership recovery destination changed")
        status = self.deployment.status()
        opencode = status.get("opencode") if isinstance(status, Mapping) else None
        if (
            not isinstance(status, Mapping)
            or status.get("current") != destination["release_id"]
            or not isinstance(opencode, Mapping)
            or opencode.get("config_id") != selected_config_id
        ):
            raise TerminalLifecycleError("starting ownership recovery destination changed")
        files = (
            (
                self.deployment.root / "deployment-state.json",
                0o600,
                destination["state_sha256"],
            ),
            (
                self.deployment.root / "releases" / str(destination["release_id"])
                / "release-pin.json",
                0o400,
                destination["release_pin_sha256"],
            ),
        )
        for path, mode, expected_sha256 in files:
            try:
                descriptor = os.open(
                    path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                )
                try:
                    before = os.fstat(descriptor)
                    chunks: list[bytes] = []
                    while chunk := os.read(descriptor, 65536):
                        chunks.append(chunk)
                    after = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
            except OSError as error:
                raise TerminalLifecycleError(
                    "starting ownership recovery destination changed"
                ) from error
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != mode
                or before.st_nlink != 1
                or (
                    before.st_dev, before.st_ino, before.st_ctime_ns, before.st_size
                ) != (
                    after.st_dev, after.st_ino, after.st_ctime_ns, after.st_size
                )
                or hashlib.sha256(b"".join(chunks)).hexdigest() != expected_sha256
            ):
                raise TerminalLifecycleError(
                    "starting ownership recovery destination changed"
                )

    def recover_stale_stopped_backend(
        self,
        *,
        proof: Mapping[str, object],
        selected_config_id: str,
        expected_existing: Mapping[str, object],
    ) -> dict[str, object]:
        """Repair only a conclusively dead backend in one malformed stopped record."""
        fields = {
            "backend", "backend_binding", "backend_owned", "completed_cutover",
            "controller_owned", "controller_pid", "controller_starting",
            "cutover_intent", "format", "invocation_id", "phase", "reason",
            "tmux_nonce", "tmux_session_id",
        }
        material = proof.get("material")
        destination = material.get("destination") if isinstance(material, Mapping) else None
        intent = material.get("intent") if isinstance(material, Mapping) else None
        old_proof = expected_existing.get("completed_cutover")
        old_material = old_proof.get("material") if isinstance(old_proof, Mapping) else None
        old_destination = (
            old_material.get("destination") if isinstance(old_material, Mapping) else None
        )
        old_intent = old_material.get("intent") if isinstance(old_material, Mapping) else None
        if (
            set(expected_existing) != fields
            or expected_existing.get("format") != 1
            or expected_existing.get("phase") != "stopped"
            or expected_existing.get("backend_owned") is not False
            or expected_existing.get("controller_owned") is not False
            or expected_existing.get("controller_starting") is not False
            or expected_existing.get("controller_pid") is not None
            or expected_existing.get("tmux_nonce") is not None
            or expected_existing.get("tmux_session_id") is not None
            or not isinstance(expected_existing.get("backend_binding"), dict)
            or not isinstance(intent, Mapping)
            or not isinstance(destination, Mapping)
            or destination.get("config_id") != selected_config_id
            or not isinstance(old_proof, Mapping)
            or old_proof.get("format") != 2
            or not isinstance(old_proof.get("receipt_id"), str)
            or re.fullmatch(r"[0-9a-f]{32}", str(old_proof.get("receipt_id"))) is None
            or not isinstance(old_destination, Mapping)
            or not isinstance(old_intent, Mapping)
            or expected_existing.get("cutover_intent") != dict(old_intent)
            or proof.get("format") != 2
            or not isinstance(proof.get("receipt_id"), str)
            or re.fullmatch(r"[0-9a-f]{32}", str(proof.get("receipt_id"))) is None
            or not isinstance(expected_existing.get("invocation_id"), str)
            or re.fullmatch(
                r"[0-9a-f]{32}", str(expected_existing.get("invocation_id"))
            ) is None
            or re.fullmatch(r"[0-9a-f]{64}", selected_config_id) is None
            or not isinstance(expected_existing.get("reason"), str)
            or not expected_existing.get("reason")
        ):
            raise TerminalLifecycleError("stale stopped backend recovery record is invalid")
        self._acquire_lock()
        try:
            self._recover_pending()
            try:
                current = json.loads(self.ownership_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise TerminalLifecycleError(
                    "stale stopped backend record changed during recovery"
                ) from error
            if current != dict(expected_existing):
                raise TerminalLifecycleError(
                    "stale stopped backend record changed during recovery"
                )
            expected_binding = self._prior_backend_binding_from_completed_proof(
                old_proof
            )
            identity = ProcessIdentity.from_json(expected_existing.get("backend"))
            process_state = _process_state(identity)
            if process_state not in {"absent", "terminated"}:
                raise TerminalLifecycleError(
                    "stale stopped backend is not conclusively dead"
                )
            group_state = _process_group_state(identity)
            if group_state not in {"empty", "terminated"}:
                raise TerminalLifecycleError(
                    "stale stopped backend group is not conclusively empty"
                )
            if expected_existing.get("backend_binding") != expected_binding:
                raise TerminalLifecycleError("stale stopped backend binding changed")
            if (
                _process_state(identity) not in {"absent", "terminated"}
                or _process_group_state(identity) not in {"empty", "terminated"}
            ):
                raise TerminalLifecycleError(
                    "stale stopped backend changed during recovery"
                )
            self.invocation_id = str(expected_existing["invocation_id"])
            self.completed_cutover = dict(old_proof)
            self.cutover_intent = dict(old_intent)
            self.backend_owned = False
            self.controller_owned = False
            self.controller_starting = False
            self._normalize_stopped_resources()
            self._write_record(
                "stopped", "recovered conclusively terminated startup backend"
            )
            return json.loads(self.ownership_path.read_text(encoding="utf-8"))
        finally:
            self._release_lock()

    def recover_conclusively_dead_running_record(
        self,
        *,
        proof: Mapping[str, object],
        selected_config_id: str,
        expected_existing: Mapping[str, object],
        port: int,
        tmux_absent: bool,
    ) -> dict[str, object]:
        """Emergency-repair only a fully dead record left running by manual stop."""
        fields = {
            "backend", "backend_binding", "backend_owned", "completed_cutover",
            "controller_owned", "controller_pid", "controller_starting",
            "cutover_intent", "format", "invocation_id", "phase", "reason",
            "tmux_nonce", "tmux_session_id",
        }
        if (
            set(expected_existing) != fields
            or expected_existing.get("format") != 1
            or expected_existing.get("phase") != "running"
            or expected_existing.get("backend_owned") is not True
            or expected_existing.get("controller_owned") is not True
            or expected_existing.get("controller_starting") is not False
            or not isinstance(expected_existing.get("controller_pid"), int)
            or not isinstance(expected_existing.get("backend_binding"), dict)
            or not isinstance(expected_existing.get("tmux_nonce"), str)
            or not isinstance(expected_existing.get("tmux_session_id"), str)
            or not isinstance(expected_existing.get("invocation_id"), str)
            or re.fullmatch(
                r"[0-9a-f]{32}", str(expected_existing.get("invocation_id"))
            ) is None
            or not tmux_absent
        ):
            raise TerminalLifecycleError("running ownership recovery record is invalid")
        old_proof = expected_existing.get("completed_cutover")
        if not isinstance(old_proof, Mapping):
            raise TerminalLifecycleError("running ownership recovery proof is absent")
        material = proof.get("material")
        destination = material.get("destination") if isinstance(material, Mapping) else None
        old_material = old_proof.get("material")
        old_intent = old_material.get("intent") if isinstance(old_material, Mapping) else None
        if (
            not isinstance(destination, Mapping)
            or destination.get("config_id") != selected_config_id
            or proof.get("format") != 2
            or not isinstance(old_intent, Mapping)
            or expected_existing.get("cutover_intent") != dict(old_intent)
        ):
            raise TerminalLifecycleError("running ownership recovery destination changed")
        identity = ProcessIdentity.from_json(expected_existing.get("backend"))
        self._acquire_lock()
        try:
            self._recover_pending()
            current = json.loads(self.ownership_path.read_text(encoding="utf-8"))
            if current != dict(expected_existing):
                raise TerminalLifecycleError("running ownership record changed during recovery")
            expected_binding = self._prior_backend_binding_from_completed_proof(old_proof)
            if expected_existing.get("backend_binding") != expected_binding:
                raise TerminalLifecycleError("running ownership backend binding changed")
            for _ in range(2):
                if (
                    _process_state(identity) not in {"absent", "terminated"}
                    or _process_group_state(identity) not in {"empty", "terminated"}
                    or _listener_pid(port) is not None
                ):
                    raise TerminalLifecycleError("running ownership resources are not dead")
                job = self.deployment.status().get("job")
                if (
                    not isinstance(job, Mapping)
                    or job.get("running") is not False
                    or job.get("pid") is not None
                ):
                    raise TerminalLifecycleError("running ownership controller is not stopped")
            self.invocation_id = str(expected_existing.get("invocation_id"))
            self.completed_cutover = dict(old_proof)
            self.cutover_intent = dict(old_intent) if isinstance(old_intent, Mapping) else None
            self.backend_owned = False
            self.controller_owned = False
            self.controller_starting = False
            self._normalize_stopped_resources()
            self._write_record("stopped", "recovered conclusively dead manually stopped resources")
            return json.loads(self.ownership_path.read_text(encoding="utf-8"))
        finally:
            self._release_lock()

    def recover_conclusively_dead_starting_record(
        self,
        *,
        proof: Mapping[str, object],
        selected_config_id: str,
        expected_existing: Mapping[str, object],
        port: int,
    ) -> dict[str, object]:
        """Repair only a dead fresh backend left in starting before controller start."""
        fields = {
            "backend", "backend_binding", "backend_owned", "completed_cutover",
            "controller_owned", "controller_pid", "controller_starting",
            "cutover_intent", "format", "invocation_id", "phase", "reason",
            "tmux_nonce", "tmux_session_id",
        }
        if (
            set(expected_existing) != fields
            or expected_existing.get("format") != 1
            or expected_existing.get("phase") != "starting"
            or expected_existing.get("reason") != "backend started"
            or expected_existing.get("backend_owned") is not True
            or expected_existing.get("controller_owned") is not False
            or expected_existing.get("controller_starting") is not False
            or expected_existing.get("controller_pid") is not None
            or expected_existing.get("tmux_nonce") is not None
            or expected_existing.get("tmux_session_id") is not None
            or not isinstance(expected_existing.get("backend_binding"), dict)
            or not isinstance(expected_existing.get("invocation_id"), str)
            or re.fullmatch(
                r"[0-9a-f]{32}", str(expected_existing.get("invocation_id"))
            ) is None
        ):
            raise TerminalLifecycleError("starting ownership recovery record is invalid")
        old_proof = expected_existing.get("completed_cutover")
        old_material = old_proof.get("material") if isinstance(old_proof, Mapping) else None
        old_intent = old_material.get("intent") if isinstance(old_material, Mapping) else None
        backend_record = expected_existing.get("backend")
        if (
            not isinstance(old_proof, Mapping)
            or set(old_proof) != {"format", "material", "receipt_id"}
            or old_proof.get("format") != 2
            or not isinstance(old_proof.get("receipt_id"), str)
            or re.fullmatch(r"[0-9a-f]{32}", str(old_proof.get("receipt_id"))) is None
            or not isinstance(old_intent, Mapping)
            or expected_existing.get("cutover_intent") != dict(old_intent)
            or not isinstance(backend_record, Mapping)
            or set(backend_record) != {"command", "pgid", "pid", "started"}
        ):
            raise TerminalLifecycleError("starting ownership recovery proof is absent")
        material = proof.get("material")
        destination = material.get("destination") if isinstance(material, Mapping) else None
        new_intent = material.get("intent") if isinstance(material, Mapping) else None
        if (
            not isinstance(destination, Mapping)
            or destination.get("config_id") != selected_config_id
            or new_intent != old_intent
        ):
            raise TerminalLifecycleError("starting ownership recovery destination changed")
        identity = ProcessIdentity.from_json(expected_existing.get("backend"))
        self._acquire_lock()
        try:
            self._recover_pending()
            current = json.loads(self.ownership_path.read_text(encoding="utf-8"))
            if current != dict(expected_existing):
                raise TerminalLifecycleError("starting ownership record changed during recovery")
            self._validate_current_completed_cutover_proof(
                proof, selected_config_id
            )
            expected_binding = (
                self._prior_policy_backend_binding_from_completed_proof(old_proof)
            )
            if expected_existing.get("backend_binding") != expected_binding:
                raise TerminalLifecycleError("starting ownership backend binding changed")
            for _ in range(2):
                if (
                    _process_state(identity) not in {"absent", "terminated"}
                    or _process_group_state(identity) not in {"empty", "terminated"}
                    or _listener_pid(port) is not None
                ):
                    raise TerminalLifecycleError("starting ownership resources are not dead")
                job = self.deployment.status().get("job")
                if not isinstance(job, Mapping) or job.get("running") is not False or job.get("pid") is not None:
                    raise TerminalLifecycleError("starting ownership controller is not stopped")
            self.invocation_id = str(expected_existing.get("invocation_id"))
            self.completed_cutover = dict(old_proof)
            self.cutover_intent = dict(old_intent) if isinstance(old_intent, Mapping) else None
            self.backend_owned = False
            self.controller_owned = False
            self.controller_starting = False
            self._normalize_stopped_resources()
            self._write_record("stopped", "recovered conclusively dead starting backend")
            return json.loads(self.ownership_path.read_text(encoding="utf-8"))
        finally:
            self._release_lock()

    def prepare_tmux(self, nonce: str) -> None:
        if self._lock_descriptor is None or not nonce:
            raise TerminalLifecycleError("tmux preparation requires lifecycle lock and nonce")
        if self.tmux_nonce is not None and self.tmux_nonce != nonce:
            raise TerminalLifecycleError("tmux nonce differs from durable expectation")
        self.tmux_nonce = nonce
        self.tmux_session_id = None
        self._write_record("starting", "exact tmux session expected")

    def start(self) -> object:
        if self._lock_descriptor is None:
            self._acquire_lock()
        try:
            self._recover_pending()
            retained = self._load_retained()
            status = self.deployment.status()
            job = status.get("job")
            running = isinstance(job, Mapping) and job.get("running") is True
            running_pid = job.get("pid") if isinstance(job, Mapping) else None
            if retained is not None:
                self._adopt_retained(
                    retained, running_pid if isinstance(running_pid, int) else None
                )
            elif running and self.adopt_running_controller:
                self.controller_owned = True
                self.controller_pid = int(running_pid)
            self._write_record("starting", "ownership established")
            endpoint, username, password, port = self._configuration()
            self._start_backend(endpoint, username, password, port)
            if self.require_backend_ownership and not self.backend_owned:
                raise TerminalLifecycleError(
                    "healthy backend is not owned by this lifecycle"
                )
            if not running:
                self.controller_starting = True
                self._write_record("starting", "starting authenticated controller")
                with _defer_terminal_signals():
                    self.deployment.start()
                    updated = self.deployment.status()["job"]
                    if not isinstance(updated, Mapping) or updated.get("running") is not True:
                        raise TerminalLifecycleError("v2 controller did not report running")
                    self.controller_owned = True
                    self.controller_pid = int(updated["pid"])
                    self.controller_starting = False
                    self._write_record("starting", "controller started")
            elif self.controller_owned:
                self.controller_pid = int(running_pid)
            self._write_record("running", "terminal attached")
            self.snapshot = self.refresh()
            return self.snapshot
        except BaseException as error:
            cleanup = "startup failed before resources were owned"
            if (
                retained is not None
                and not self.controller_owned
                and not self.backend_owned
                and not self.backend_started_by_invocation
            ):
                self._release_lock()
                raise TerminalLifecycleError(
                    "retained ownership could not be authenticated; record preserved"
                ) from error
            try:
                if self.controller_starting and not self.controller_owned:
                    candidate = self.deployment.status().get("job")
                    if isinstance(candidate, Mapping) and candidate.get("running") is True:
                        self.controller_owned = True
                        self.controller_pid = int(candidate["pid"])
                    self.controller_starting = False
                if self.controller_owned:
                    stopped, cleanup = self.close(terminal_lost=True)
                    if not stopped:
                        cleanup = "startup failed; owned resources retained: " + cleanup
                elif self.backend_owned:
                    self._stop_backend()
                    self._normalize_stopped_resources()
                    self._write_record("stopped", "startup failed before controller start")
                    self._release_lock()
                else:
                    if (
                        self.backend is not None
                        or self.backend_identity is not None
                        or self.backend_binding is not None
                    ):
                        raise TerminalLifecycleError(
                            "unowned backend evidence cannot be normalized"
                        )
                    self._normalize_stopped_resources()
                    self._write_record("stopped", cleanup)
                    self._release_lock()
            except BaseException as cleanup_error:
                try:
                    self._write_record(
                        "retained",
                        f"startup failure cleanup failed: {type(cleanup_error).__name__}",
                    )
                finally:
                    self._release_lock()
            raise TerminalLifecycleError(cleanup) from error

    def resume_cleanup(self) -> None:
        """Adopt exact retained resources for shutdown without starting replacements."""

        self._acquire_lock()
        try:
            self._recover_pending()
            retained = self._load_retained()
            if retained is None:
                raise TerminalLifecycleError("cleanup has no retained ownership")
            self._acquire_deployment_operation()
            backend_identity: ProcessIdentity | None = None
            backend_state = "absent"
            if retained.get("backend_owned") is True:
                backend_identity = ProcessIdentity.from_json(retained.get("backend"))
                binding = retained.get("backend_binding")
                expected_binding = None
                if binding is not None:
                    expected_binding = (
                        self._expected_retained_backend_binding_for_cleanup(binding)
                    )
                    if not _backend_binding_matches(binding, expected_binding):
                        raise TerminalLifecycleError("retained backend binding changed")
                backend_state = _process_state(backend_identity)
                if backend_state in {"mismatch", "error"}:
                    raise TerminalLifecycleError(
                        "retained backend ownership cannot be authenticated"
                    )
                if backend_state in {"absent", "terminated"} and _process_group_state(
                    backend_identity
                ) in {"unanchored_live", "mismatch", "error"}:
                    raise TerminalLifecycleError(
                        "retained backend process group is not anchored"
                    )
            recorded_pid = retained.get("controller_pid")
            deployment_status = (
                self.deployment.stop_status()
                if isinstance(self.deployment, UserDeployment)
                else self.deployment.status()
            )
            if retained.get("controller_owned") is True:
                if not isinstance(recorded_pid, int):
                    raise TerminalLifecycleError("retained controller identity is malformed")
                status_state = self._classify_controller_status(
                    deployment_status.get("job"), recorded_pid
                )
                if status_state == "original_running":
                    self.controller_owned = True
                    self.controller_pid = recorded_pid
                elif status_state == "exact_stopped":
                    self.cleanup_authorized = True
                elif status_state == "changed":
                    raise TerminalLifecycleError(
                        "retained controller ownership no longer matches"
                    )
                elif status_state == "transitional":
                    raise TerminalLifecycleError(
                        "retained controller stop status is transitional"
                    )
                else:
                    raise TerminalLifecycleError("controller status is not exact")
            else:
                status_state = self._classify_controller_status(
                    deployment_status.get("job"), -1
                )
                if status_state != "exact_stopped":
                    raise TerminalLifecycleError(
                        "running or transitional controller is not lifecycle-owned"
                    )
                self.cleanup_authorized = True
            if backend_identity is not None and backend_state in {"exact", "absent", "terminated"}:
                self.backend_owned = True
                self.backend_identity = backend_identity
                self.backend_binding = expected_binding
            self.tmux_session_id = retained.get("tmux_session_id") if isinstance(retained.get("tmux_session_id"), str) else None
            self.tmux_nonce = retained.get("tmux_nonce") if isinstance(retained.get("tmux_nonce"), str) else None
            completed = retained.get("completed_cutover")
            if isinstance(completed, dict):
                self.completed_cutover = dict(completed)
            intent = retained.get("cutover_intent")
            if isinstance(intent, dict):
                self.cutover_intent = dict(intent)
            self._write_record("retained", "exact shutdown ownership resumed")
        except BaseException:
            self._release_lock()
            raise

    def handoff(self) -> None:
        """Publish durable ownership before handing control to tmux hooks."""
        if self._lock_descriptor is None:
            raise TerminalLifecycleError("lifecycle handoff requires the active lock")
        self._write_record("running", "tmux finalizer owns terminal loss cleanup")
        self._release_lock()

    def bind_tmux(self, session_id: str, nonce: str) -> None:
        if not session_id or self._lock_descriptor is None:
            raise TerminalLifecycleError("tmux binding requires active lifecycle ownership")
        if nonce != self.tmux_nonce:
            raise TerminalLifecycleError("tmux binding nonce differs from durable expectation")
        self.tmux_session_id = session_id
        self._write_record("running", "exact tmux session bound")

    def refresh(self) -> object:
        paths = _paths(self.deployment.root)
        return CockpitClient(
            paths.socket,
            approved_root=paths.socket_root,
            identity_profile="local-user",
        ).refresh()

    def render(self, *, width: int) -> str:
        self.snapshot = self.refresh()
        return render_terminal(self.snapshot, width=width, ansi=False)

    def _stop_backend(self) -> None:
        identity = self.backend_identity
        if not self.backend_owned or identity is None:
            return
        initial = _process_group_state(identity)
        if initial in {"empty", "terminated"}:
            self._clear_confirmed_backend()
            return
        if initial != "live":
            raise TerminalLifecycleError("owned backend process group changed; left untouched")
        confirmed = _process_group_state(identity)
        if confirmed in {"empty", "terminated"}:
            self._clear_confirmed_backend()
            return
        if confirmed != "live":
            raise TerminalLifecycleError(
                "owned backend process group changed during signal authorization"
            )
        os.killpg(identity.pgid, signal.SIGTERM)
        deadline = time.monotonic() + 10.0
        changed = False
        while time.monotonic() < deadline:
            state = _process_group_state(identity)
            if state in {"empty", "terminated"}:
                self._clear_confirmed_backend()
                return
            if state in {"error", "mismatch", "unanchored_live"}:
                changed = True
            time.sleep(0.1)
        if changed:
            raise TerminalLifecycleError(
                "owned backend group inspection remained uncertain; ownership retained"
            )
        raise TerminalLifecycleError("owned backend did not stop after SIGTERM")

    def _clear_confirmed_backend(self) -> None:
        self.backend_owned = False
        self.backend = None
        self.backend_identity = None
        self.backend_binding = None

    def _normalize_stopped_resources(self) -> None:
        if self.backend_owned or self.controller_owned or self.controller_starting:
            raise TerminalLifecycleError("cannot publish stopped ownership for live resources")
        self.backend = None
        self.backend_identity = None
        self.backend_binding = None
        self.controller_pid = None
        self.tmux_session_id = None
        self.tmux_nonce = None

    @staticmethod
    def _classify_controller_status(
        status: object, controller_pid: int
    ) -> str:
        if (
            not isinstance(status, Mapping)
            or not isinstance(status.get("loaded"), bool)
            or not isinstance(status.get("running"), bool)
            or not isinstance(status.get("detail"), str)
            or (
                status.get("pid") is not None
                and (
                    isinstance(status.get("pid"), bool)
                    or not isinstance(status.get("pid"), int)
                )
            )
        ):
            return "malformed"
        loaded = status["loaded"] is True
        running = status["running"] is True
        pid = status.get("pid")
        detail = status["detail"]
        if not running and pid is None and (
            (not loaded and detail == "not-loaded")
            or (loaded and detail in {"not", "waiting"})
        ):
            return "exact_stopped"
        if running:
            if pid != controller_pid:
                return "changed"
            if loaded and detail == "running":
                return "original_running"
            return "malformed"
        if pid is not None:
            return "malformed"
        return "transitional"

    def _wait_controller_stopped(
        self, controller_pid: int, stop_error: Exception | None
    ) -> None:
        deadline = time.monotonic() + 5.0
        while True:
            try:
                status = self.deployment.status().get("job")
            except Exception as error:
                raise TerminalLifecycleError(
                    "controller stop status inspection failed"
                ) from error
            state = self._classify_controller_status(status, controller_pid)
            if state == "malformed":
                raise TerminalLifecycleError("controller stop status is malformed")
            if state == "exact_stopped":
                return
            if state == "changed":
                raise TerminalLifecycleError(
                    "controller identity changed during stop"
                )
            if time.monotonic() >= deadline:
                raise TerminalLifecycleError(
                    "controller stop outcome is uncertain"
                ) from stop_error
            time.sleep(0.05)

    def close(
        self,
        *,
        terminal_lost: bool,
        should_abort: Callable[[], bool] | None = None,
    ) -> tuple[bool, str]:
        if not self.cleanup_authorized:
            try:
                snapshot = self.refresh()
                quiescent, reason = snapshot_is_quiescent(snapshot)
            except Exception:
                reason = "cockpit snapshot validation failed"
                self._write_record("retained", reason)
                if terminal_lost:
                    self._release_lock()
                return False, reason
            if not quiescent:
                self._write_record("retained", reason)
                if terminal_lost:
                    self._release_lock()
                return False, reason
        if should_abort is not None and should_abort():
            reason = "terminal reattached"
            self._write_record("running", reason)
            return False, reason
        production = isinstance(self.deployment, UserDeployment)
        operation = (
            nullcontext()
            if self._deployment_operation_context is not None
            else (
                self.deployment._operation_lock() if production else nullcontext()
            )
        )
        stop_controller = (
            self.deployment._stop_unlocked
            if production
            else getattr(self.deployment, "stop", lambda: None)
        )
        with operation:
            if self.controller_owned:
                status = self.deployment.status()["job"]
                if (
                    not isinstance(status, Mapping)
                    or status.get("loaded") is not True
                    or status.get("running") is not True
                    or status.get("detail") != "running"
                    or status.get("pid") != self.controller_pid
                ):
                    reason = "owned controller identity changed; resources retained"
                    self._write_record("retained", reason)
                    if terminal_lost:
                        self._release_lock()
                    return False, reason
                controller_published = False
                try:
                    with _defer_terminal_signals():
                        stop_error: Exception | None = None
                        try:
                            stop_controller()
                        except Exception as error:
                            stop_error = error
                        self._wait_controller_stopped(
                            int(self.controller_pid), stop_error
                        )
                        self.controller_owned = False
                        self.controller_pid = None
                        self._write_record(
                            "starting", "controller stopped; backend cleanup pending"
                        )
                        controller_published = True
                except TerminalLifecycleError as error:
                    if not controller_published or not str(error).startswith(
                        "terminal signal "
                    ):
                        raise
            published = False
            try:
                with _defer_terminal_signals():
                    self._stop_backend()
                    self._normalize_stopped_resources()
                    self._write_record(
                        "stopped",
                        "terminal lost" if terminal_lost else "operator closed",
                    )
                    published = True
            except TerminalLifecycleError as error:
                if not published or not str(error).startswith("terminal signal "):
                    raise
        self._release_lock()
        return True, "stopped invocation-owned resources"
