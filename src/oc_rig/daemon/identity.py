"""Production service-identity and filesystem-topology validation."""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import pwd
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from oc_rig.daemon.security import (
    PrivateSocketPath,
    SocketSecurityError,
)
from oc_rig.store.runtime import PrivateRuntimeDirectory, RuntimeContainmentError


class ServiceIdentityError(RuntimeError):
    """The durable daemon is not running in its provisioned OS identity."""


@dataclass(frozen=True, slots=True)
class ServiceIdentityPolicy:
    """Expected dedicated daemon UID and exact authenticated client UID allowlist."""

    service_uid: int
    allowed_client_uids: frozenset[int]
    client_gid: int

    def __post_init__(self) -> None:
        if type(self.service_uid) is not int or self.service_uid <= 0:
            raise ValueError("service_uid must be a positive dedicated UID")
        if not self.allowed_client_uids:
            raise ValueError("at least one client UID is required")
        if any(type(uid) is not int or uid <= 0 for uid in self.allowed_client_uids):
            raise ValueError("client UIDs must be positive non-root integers")
        if type(self.client_gid) is not int or self.client_gid <= 0:
            raise ValueError("client_gid must be a positive non-root group ID")


@dataclass(frozen=True, slots=True)
class LocalUserIdentityPolicy:
    """Explicit single-login profile with no cross-UID isolation claim."""

    user_uid: int
    user_gid: int

    def __post_init__(self) -> None:
        if type(self.user_uid) is not int or self.user_uid <= 0:
            raise ValueError("user_uid must be a positive non-root UID")
        if type(self.user_gid) is not int or self.user_gid <= 0:
            raise ValueError("user_gid must be a positive non-root GID")

    @property
    def service_uid(self) -> int:
        return self.user_uid

    @property
    def client_gid(self) -> int:
        return self.user_gid

    @property
    def allowed_client_uids(self) -> frozenset[int]:
        return frozenset({self.user_uid})


@dataclass(frozen=True, slots=True)
class FileFacts:
    mode: int
    uid: int
    gid: int
    links: int
    device: int
    inode: int
    has_extended_acl: bool


class IdentityProbe(Protocol):
    """Read-only OS facts; modeled probes are used only by validator unit tests."""

    def effective_uid(self) -> int: ...

    def effective_gid(self) -> int: ...

    def inspect(self, path: Path) -> FileFacts: ...

    def groups_for_uid(self, uid: int) -> frozenset[int]: ...


class OsIdentityProbe:
    def effective_uid(self) -> int:
        return os.geteuid()

    def effective_gid(self) -> int:
        return os.getegid()

    def inspect(self, path: Path) -> FileFacts:
        details = path.lstat()
        has_extended_acl = _has_extended_acl(path)
        rechecked = path.lstat()
        if (details.st_dev, details.st_ino) != (rechecked.st_dev, rechecked.st_ino):
            raise ServiceIdentityError(
                f"filesystem identity changed during inspection: {path}"
            )
        return FileFacts(
            mode=details.st_mode,
            uid=details.st_uid,
            gid=details.st_gid,
            links=details.st_nlink,
            device=details.st_dev,
            inode=details.st_ino,
            has_extended_acl=has_extended_acl,
        )

    def groups_for_uid(self, uid: int) -> frozenset[int]:
        account = pwd.getpwuid(uid)
        return frozenset(os.getgrouplist(account.pw_name, account.pw_gid))


@dataclass(frozen=True, slots=True)
class ServiceTopology:
    policy: ServiceIdentityPolicy
    state_directory: FileFacts
    database: FileFacts
    lock: FileFacts
    socket_root: FileFacts
    socket_directory: FileFacts
    controlled_ancestors: tuple[FileFacts, ...]
    sidecars: tuple[FileFacts, ...]

    def database_open_allowed(self, uid: int) -> bool:
        """Model traversal/open permission for the exact private production layout."""
        if uid == self.state_directory.uid:
            return bool(stat.S_IMODE(self.state_directory.mode) & 0o300)
        return bool(stat.S_IMODE(self.state_directory.mode) & 0o003)

    def socket_connect_allowed(self, uid: int, groups: frozenset[int]) -> bool:
        """Model traversal and connect permission for the provisioned socket."""

        def permissions(facts: FileFacts) -> int:
            mode = stat.S_IMODE(facts.mode)
            if uid == facts.uid:
                return (mode >> 6) & 0o7
            if facts.gid in groups:
                return (mode >> 3) & 0o7
            return mode & 0o7

        if not all(
            permissions(directory) & 0o1
            for directory in (self.socket_root, self.socket_directory)
        ):
            return False
        socket_mode = 0o620
        if uid == self.policy.service_uid:
            socket_permissions = (socket_mode >> 6) & 0o7
        elif self.policy.client_gid in groups:
            socket_permissions = (socket_mode >> 3) & 0o7
        else:
            socket_permissions = socket_mode & 0o7
        return bool(socket_permissions & 0o2)


_OS_IDENTITY_PROBE: IdentityProbe = OsIdentityProbe()


def _has_extended_acl(path: Path) -> bool:
    """Use the native ACL API and fail closed when ACLs cannot be inspected."""
    library_name = None if sys.platform == "darwin" else ctypes.util.find_library("acl")
    try:
        library = ctypes.CDLL(library_name, use_errno=True)
        get_acl = library.acl_get_file
        get_acl.argtypes = (ctypes.c_char_p, ctypes.c_int)
        get_acl.restype = ctypes.c_void_p
        get_entry = library.acl_get_entry
        get_entry.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
        )
        get_entry.restype = ctypes.c_int
        free_acl = library.acl_free
        free_acl.argtypes = (ctypes.c_void_p,)
        free_acl.restype = ctypes.c_int
        equivalent_mode = None
        if sys.platform != "darwin":
            equivalent_mode = library.acl_equiv_mode
            equivalent_mode.argtypes = (
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_uint),
            )
            equivalent_mode.restype = ctypes.c_int
    except (AttributeError, OSError) as error:
        raise ServiceIdentityError("native ACL inspection is unavailable") from error

    if sys.platform == "darwin":
        acl_types = ((0x00000100, False),)
    else:
        acl_types = [(0x8000, True)]
        if path.is_dir():
            acl_types.append((0x4000, False))
    for acl_type, compare_mode in acl_types:
        ctypes.set_errno(0)
        acl = get_acl(os.fsencode(path), acl_type)
        if not acl:
            error_number = ctypes.get_errno()
            no_acl_errors = {getattr(errno, "ENODATA", -1)}
            if sys.platform == "darwin":
                no_acl_errors.add(errno.ENOENT)
            if error_number in no_acl_errors:
                continue
            raise ServiceIdentityError(f"could not inspect ACLs for {path}")
        try:
            if compare_mode:
                assert equivalent_mode is not None
                mode = ctypes.c_uint()
                result = equivalent_mode(acl, ctypes.byref(mode))
                if result > 0:
                    return True
                if result == 0:
                    continue
                raise ServiceIdentityError(f"could not inspect ACLs for {path}")
            entry = ctypes.c_void_p()
            result = get_entry(acl, 0, ctypes.byref(entry))
            if result == 0 and entry.value is not None:
                return True
            if result < 0:
                raise ServiceIdentityError(f"could not inspect ACLs for {path}")
        finally:
            free_acl(acl)
    return False


def _require_directory(facts: FileFacts, uid: int, mode: int, label: str) -> None:
    if (
        not stat.S_ISDIR(facts.mode)
        or facts.uid != uid
        or stat.S_IMODE(facts.mode) != mode
        or facts.inode <= 0
        or facts.has_extended_acl
    ):
        raise ServiceIdentityError(
            f"{label} must be service-owned mode {mode:04o}"
        )


def _require_regular(facts: FileFacts, uid: int, label: str) -> None:
    if (
        not stat.S_ISREG(facts.mode)
        or facts.uid != uid
        or stat.S_IMODE(facts.mode) != 0o600
        or facts.links != 1
        or facts.inode <= 0
        or facts.has_extended_acl
    ):
        raise ServiceIdentityError(
            f"{label} must be a service-owned mode 0600 single-link file"
        )


def _require_controlled_ancestor(facts: FileFacts, uid: int) -> None:
    mode = stat.S_IMODE(facts.mode)
    if (
        not stat.S_ISDIR(facts.mode)
        or facts.uid != uid
        or (mode & 0o700) != 0o700
        or mode & 0o022
        or facts.inode <= 0
        or facts.has_extended_acl
    ):
        raise ServiceIdentityError(
            "controlled ancestors must be service-owned and not externally writable"
        )


def validate_service_topology(
    runtime: PrivateRuntimeDirectory,
    address: PrivateSocketPath,
    policy: ServiceIdentityPolicy,
    probe: IdentityProbe,
) -> ServiceTopology:
    """Fail closed unless the durable daemon has an isolated production layout."""
    if probe.effective_uid() != policy.service_uid:
        raise ServiceIdentityError("rigd effective UID does not match service UID")
    if probe.effective_gid() != policy.client_gid:
        raise ServiceIdentityError("rigd effective GID does not match client group")
    if policy.service_uid in policy.allowed_client_uids:
        raise ServiceIdentityError("service UID must differ from every client UID")
    try:
        if any(
            policy.client_gid not in probe.groups_for_uid(uid)
            for uid in policy.allowed_client_uids
        ):
            raise ServiceIdentityError("an allowed client UID is not in the client group")
    except KeyError as error:
        raise ServiceIdentityError("an allowed client UID is not provisioned") from error
    try:
        runtime.validate_provisioned(policy.service_uid)
        socket_root, socket_directory, _ = address._layout()
    except (OSError, RuntimeContainmentError, SocketSecurityError) as error:
        raise ServiceIdentityError("service filesystem topology is not provisioned") from error

    state_path = runtime.root.resolve(strict=True)
    runtime_root = runtime.approved_root.resolve(strict=True)
    state = probe.inspect(state_path)
    database = probe.inspect(runtime.database.resolve(strict=True))
    lock = probe.inspect(runtime.root.joinpath("rigd.lock").resolve(strict=True))
    sidecars = tuple(
        probe.inspect(entry.resolve(strict=True))
        for entry in runtime.root.iterdir()
        if entry.name not in {runtime.database_name, "rigd.lock"}
    )
    socket_root_facts = probe.inspect(socket_root)
    socket_directory_facts = probe.inspect(socket_directory)
    ancestor_paths = {runtime_root, socket_root}
    for base, child in (
        (runtime_root, state_path),
        (socket_root, socket_directory),
    ):
        current = base
        for component in child.relative_to(base).parts[:-1]:
            current /= component
            ancestor_paths.add(current)
    controlled_ancestors = tuple(
        probe.inspect(path) for path in sorted(ancestor_paths, key=str)
    )
    _require_directory(state, policy.service_uid, 0o700, "state directory")
    _require_regular(database, policy.service_uid, "database")
    _require_regular(lock, policy.service_uid, "daemon lock")
    _require_directory(socket_root_facts, policy.service_uid, 0o710, "socket root")
    _require_directory(
        socket_directory_facts,
        policy.service_uid,
        0o710,
        "socket directory",
    )
    if (
        socket_root_facts.gid != policy.client_gid
        or socket_directory_facts.gid != policy.client_gid
    ):
        raise ServiceIdentityError("socket directories have the wrong client group")
    for sidecar in sidecars:
        _require_regular(sidecar, policy.service_uid, "database sidecar")
    for ancestor in controlled_ancestors:
        _require_controlled_ancestor(ancestor, policy.service_uid)
    if state.device == socket_directory_facts.device and state.inode == socket_directory_facts.inode:
        raise ServiceIdentityError("state and socket directories must be separate")
    topology = ServiceTopology(
        policy=policy,
        state_directory=state,
        database=database,
        lock=lock,
        socket_root=socket_root_facts,
        socket_directory=socket_directory_facts,
        controlled_ancestors=controlled_ancestors,
        sidecars=sidecars,
    )
    if any(topology.database_open_allowed(uid) for uid in policy.allowed_client_uids):
        raise ServiceIdentityError("an allowed client UID can open the state database")
    if any(
        not topology.socket_connect_allowed(uid, probe.groups_for_uid(uid))
        for uid in policy.allowed_client_uids
    ):
        raise ServiceIdentityError("an allowed client UID cannot reach the service socket")
    return topology


def validate_local_user_topology(
    runtime: PrivateRuntimeDirectory,
    address: PrivateSocketPath,
    policy: LocalUserIdentityPolicy,
    probe: IdentityProbe,
) -> None:
    """Validate the opt-in owner-only topology without weakening service mode."""
    if probe.effective_uid() != policy.user_uid:
        raise ServiceIdentityError("rigd effective UID does not match local user UID")
    if probe.effective_gid() != policy.user_gid:
        raise ServiceIdentityError("rigd effective GID does not match local user GID")
    try:
        runtime.validate_provisioned(policy.user_uid)
        socket_root, socket_directory, _ = address._layout()
    except (OSError, RuntimeContainmentError, SocketSecurityError) as error:
        raise ServiceIdentityError(
            "local-user filesystem topology is not provisioned"
        ) from error

    state_path = runtime.root.resolve(strict=True)
    runtime_root = runtime.approved_root.resolve(strict=True)
    state = probe.inspect(state_path)
    database = probe.inspect(runtime.database.resolve(strict=True))
    lock = probe.inspect(runtime.root.joinpath("rigd.lock").resolve(strict=True))
    sidecars = tuple(
        probe.inspect(entry.resolve(strict=True))
        for entry in runtime.root.iterdir()
        if entry.name not in {runtime.database_name, "rigd.lock"}
    )
    socket_root_facts = probe.inspect(socket_root)
    socket_directory_facts = probe.inspect(socket_directory)
    ancestor_paths = {runtime_root, socket_root}
    for base, child in (
        (runtime_root, state_path),
        (socket_root, socket_directory),
    ):
        current = base
        for component in child.relative_to(base).parts[:-1]:
            current /= component
            ancestor_paths.add(current)
    controlled_ancestors = tuple(
        probe.inspect(path) for path in sorted(ancestor_paths, key=str)
    )
    _require_directory(state, policy.user_uid, 0o700, "state directory")
    _require_regular(database, policy.user_uid, "database")
    _require_regular(lock, policy.user_uid, "daemon lock")
    _require_directory(socket_root_facts, policy.user_uid, 0o700, "socket root")
    _require_directory(
        socket_directory_facts,
        policy.user_uid,
        0o700,
        "socket directory",
    )
    for sidecar in sidecars:
        _require_regular(sidecar, policy.user_uid, "database sidecar")
    for ancestor in controlled_ancestors:
        _require_controlled_ancestor(ancestor, policy.user_uid)
    if (
        state.device == socket_directory_facts.device
        and state.inode == socket_directory_facts.inode
    ):
        raise ServiceIdentityError("state and socket directories must be separate")
