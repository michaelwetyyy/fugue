"""Filesystem and peer-identity guards for the private Unix socket."""

from __future__ import annotations

import errno
import os
import socket
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


class SocketSecurityError(RuntimeError):
    """A socket path, inode, or peer failed the private boundary."""


class DaemonAlreadyRunning(SocketSecurityError):
    """A live listener already owns the configured socket."""


class StaleSocketAmbiguity(SocketSecurityError):
    """An existing socket could not be proved safely stale."""


@dataclass(frozen=True, slots=True)
class DirectoryIdentity:
    device: int
    inode: int


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _assert_no_symlink_ancestors(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            details = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(details.st_mode):
            raise SocketSecurityError(f"socket path traverses a symlink: {current}")


def _assert_no_symlinks_below(root: Path, path: Path) -> None:
    current = root
    for part in path.relative_to(root).parts:
        current /= part
        try:
            details = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(details.st_mode):
            raise SocketSecurityError(f"socket path traverses a symlink: {current}")


def _same_inode(path: Path, expected: os.stat_result) -> bool:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return False
    return current.st_dev == expected.st_dev and current.st_ino == expected.st_ino


def _directory_flags() -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        raise SocketSecurityError("O_NOFOLLOW and O_DIRECTORY are required")
    return os.O_RDONLY | no_follow | directory


def _open_directory_chain(path: Path) -> int:
    """Open a lexical directory path one no-follow component at a time."""
    flags = _directory_flags()
    descriptor = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _prepare_private_directory(root: Path, directory: Path) -> DirectoryIdentity:
    """Create descendants through guarded directory descriptors without escape."""
    flags = _directory_flags()
    descriptor = _open_directory_chain(root)
    try:
        root_details = root.lstat()
        opened_root = os.fstat(descriptor)
        if (
            opened_root.st_dev != root_details.st_dev
            or opened_root.st_ino != root_details.st_ino
        ):
            raise SocketSecurityError("approved socket root changed during guarded open")
        for part in directory.relative_to(root).parts:
            try:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            details = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(details.st_mode)
                or details.st_uid != os.geteuid()
                or stat.S_IMODE(details.st_mode) & 0o022
            ):
                raise SocketSecurityError(
                    "socket directory ancestry is not privately owned"
                )
        os.fchmod(descriptor, 0o700)
        details = os.fstat(descriptor)
        return DirectoryIdentity(details.st_dev, details.st_ino)
    finally:
        os.close(descriptor)


@dataclass(frozen=True, slots=True)
class PrivateSocketPath:
    """A socket inside an explicit owner-only approved runtime root."""

    socket_path: Path
    approved_root: Path

    def _layout(self) -> tuple[Path, Path, Path]:
        path = _absolute(self.socket_path)
        root = _absolute(self.approved_root)
        if path.name in {"", ".", ".."} or path.parent == path:
            raise SocketSecurityError("socket path must include a filename")
        if len(os.fsencode(path)) > 100:
            raise SocketSecurityError("socket path is too long for a portable Unix socket")
        _assert_no_symlink_ancestors(root)
        _assert_no_symlink_ancestors(path)
        try:
            root_details = root.lstat()
        except FileNotFoundError as error:
            raise SocketSecurityError(
                f"approved socket root is not a directory: {root}"
            ) from error
        if stat.S_ISLNK(root_details.st_mode):
            raise SocketSecurityError("approved socket root must not be a symlink")
        if not stat.S_ISDIR(root_details.st_mode):
            raise SocketSecurityError(f"approved socket root is not a directory: {root}")
        if root_details.st_uid != os.geteuid():
            raise SocketSecurityError("approved socket root has the wrong owner")
        if stat.S_IMODE(root_details.st_mode) & 0o022:
            raise SocketSecurityError("approved socket root is writable by another user")
        try:
            relative_path = path.relative_to(root)
        except ValueError as error:
            raise SocketSecurityError("socket path escapes the approved root") from error
        resolved_root = root
        path = root / relative_path
        if len(os.fsencode(path)) > 100:
            raise SocketSecurityError("resolved socket path is too long for a portable Unix socket")
        _assert_no_symlinks_below(resolved_root, path)
        return resolved_root, path.parent, path

    def prepare_for_bind(self) -> Path:
        root, directory, path = self._layout()
        prepared_identity = _prepare_private_directory(root, directory)
        rechecked_root, rechecked_directory, rechecked_path = self._layout()
        if (rechecked_root, rechecked_directory, rechecked_path) != (
            root,
            directory,
            path,
        ):
            raise SocketSecurityError("socket layout changed during directory creation")
        _assert_no_symlinks_below(root, directory)
        resolved_directory = directory.resolve(strict=True)
        try:
            resolved_directory.relative_to(root)
        except ValueError as error:
            raise SocketSecurityError("socket directory escapes the approved root") from error
        details = directory.stat()
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid():
            raise SocketSecurityError("socket directory has the wrong type or owner")
        os.chmod(directory, 0o700)
        if stat.S_IMODE(directory.stat().st_mode) != 0o700:
            raise SocketSecurityError("socket directory is not owner-only")
        if path.exists() or path.is_symlink():
            self._remove_proved_stale_socket(path)
        if self.directory_identity() != prepared_identity:
            raise SocketSecurityError(
                "socket directory inode changed during directory creation"
            )
        return path

    def prepare_service_for_bind(self, service_uid: int, client_gid: int) -> Path:
        """Validate a pre-provisioned cross-UID socket directory without repair."""
        root, directory, path = self._layout()
        for candidate in {root, directory}:
            details = candidate.lstat()
            if (
                not stat.S_ISDIR(details.st_mode)
                or details.st_uid != service_uid
                or details.st_gid != client_gid
                or stat.S_IMODE(details.st_mode) != 0o710
            ):
                raise SocketSecurityError(
                    "service socket directories must be mode 0710 with the client group"
                )
        if path.exists() or path.is_symlink():
            self._remove_proved_stale_socket(
                path,
                owner_uid=service_uid,
                socket_mode=0o620,
            )
        return path

    def directory_identity(self) -> DirectoryIdentity:
        """Return the validated parent inode used to fence bind-time replacement."""
        _, directory, _ = self._layout()
        details = directory.lstat()
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) != 0o700
        ):
            raise SocketSecurityError("socket directory is not private")
        return DirectoryIdentity(details.st_dev, details.st_ino)

    def assert_directory_identity(self, expected: DirectoryIdentity) -> None:
        actual = self.directory_identity()
        if actual != expected:
            raise SocketSecurityError("socket directory inode changed during bind")

    def service_directory_identity(
        self,
        service_uid: int,
        client_gid: int,
    ) -> DirectoryIdentity:
        _, directory, _ = self._layout()
        details = directory.lstat()
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid != service_uid
            or details.st_gid != client_gid
            or stat.S_IMODE(details.st_mode) != 0o710
        ):
            raise SocketSecurityError("service socket directory is not provisioned")
        return DirectoryIdentity(details.st_dev, details.st_ino)

    def assert_service_directory_identity(
        self,
        expected: DirectoryIdentity,
        service_uid: int,
        client_gid: int,
    ) -> None:
        if self.service_directory_identity(service_uid, client_gid) != expected:
            raise SocketSecurityError("service socket directory inode changed during bind")

    def _remove_proved_stale_socket(
        self,
        path: Path,
        *,
        owner_uid: int | None = None,
        socket_mode: int = 0o600,
    ) -> None:
        details = path.lstat()
        if not stat.S_ISSOCK(details.st_mode) or details.st_nlink != 1:
            raise StaleSocketAmbiguity("existing socket path is not a socket")
        expected_uid = os.geteuid() if owner_uid is None else owner_uid
        if (
            details.st_uid != expected_uid
            or stat.S_IMODE(details.st_mode) != socket_mode
        ):
            raise StaleSocketAmbiguity("existing socket ownership or mode is ambiguous")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(0.2)
        try:
            probe.connect(str(path))
        except OSError as error:
            if error.errno != errno.ECONNREFUSED:
                raise StaleSocketAmbiguity(
                    "existing socket could not be proved stale"
                ) from error
        else:
            raise DaemonAlreadyRunning("a daemon is already listening")
        finally:
            probe.close()
        if not _same_inode(path, details):
            raise StaleSocketAmbiguity("socket inode changed during stale check")
        path.unlink()

    def secure_bound_socket(
        self,
        expected_directory: DirectoryIdentity | None = None,
    ) -> os.stat_result:
        _, directory, path = self._layout()
        if expected_directory is not None:
            self.assert_directory_identity(expected_directory)
        if stat.S_IMODE(directory.stat().st_mode) != 0o700:
            raise SocketSecurityError("socket directory is not owner-only")
        details = path.lstat()
        if (
            not stat.S_ISSOCK(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
        ):
            raise SocketSecurityError("bound socket has the wrong type or owner")
        os.chmod(path, 0o600)
        details = path.lstat()
        if stat.S_IMODE(details.st_mode) != 0o600:
            raise SocketSecurityError("bound socket is not owner-only")
        if expected_directory is not None:
            self.assert_directory_identity(expected_directory)
        return details

    def secure_service_bound_socket(
        self,
        expected_directory: DirectoryIdentity,
        service_uid: int,
        client_gid: int,
    ) -> os.stat_result:
        _, _, path = self._layout()
        self.assert_service_directory_identity(
            expected_directory,
            service_uid,
            client_gid,
        )
        details = path.lstat()
        if (
            not stat.S_ISSOCK(details.st_mode)
            or details.st_uid != service_uid
            or details.st_gid != client_gid
            or details.st_nlink != 1
        ):
            raise SocketSecurityError("bound service socket has the wrong identity")
        os.chmod(path, 0o620)
        details = path.lstat()
        if stat.S_IMODE(details.st_mode) != 0o620:
            raise SocketSecurityError("bound service socket must have mode 0620")
        self.assert_service_directory_identity(
            expected_directory,
            service_uid,
            client_gid,
        )
        return details

    def assert_bound_identity(
        self,
        expected_directory: DirectoryIdentity,
        expected_socket: os.stat_result,
    ) -> None:
        """Revalidate both path inodes after bind and listen configuration."""
        self.assert_directory_identity(expected_directory)
        _, _, path = self._layout()
        if not _same_inode(path, expected_socket):
            raise SocketSecurityError("socket inode changed during bind")

    def assert_service_bound_identity(
        self,
        expected_directory: DirectoryIdentity,
        expected_socket: os.stat_result,
        service_uid: int,
        client_gid: int,
    ) -> None:
        self.assert_service_directory_identity(
            expected_directory,
            service_uid,
            client_gid,
        )
        _, _, path = self._layout()
        if not _same_inode(path, expected_socket):
            raise SocketSecurityError("service socket inode changed during bind")

    def validate_for_connect(
        self,
        service_uid: int | None = None,
        client_gid: int | None = None,
        identity_profile: str | None = None,
    ) -> Path:
        _, directory, path = self._layout()
        directory_details = directory.stat()
        directory_mode = stat.S_IMODE(directory_details.st_mode)
        local_user_directory = (
            directory_details.st_uid == os.geteuid() and directory_mode == 0o700
        )
        service_directory = (
            service_uid is not None
            and client_gid is not None
            and directory_details.st_uid == service_uid
            and directory_details.st_gid == client_gid
            and directory_mode == 0o710
        )
        profile = identity_profile
        if profile is None:
            profile = "dedicated-service"
        if profile not in {"dedicated-service", "local-user"}:
            raise SocketSecurityError("socket identity profile is invalid")
        if (service_uid is None) != (client_gid is None):
            raise SocketSecurityError(
                "service UID and client GID must be selected together"
            )
        if profile == "local-user" and service_uid is not None:
            raise SocketSecurityError(
                "local-user socket validation does not accept service identity fields"
            )
        if profile == "dedicated-service" and service_uid is None:
            raise SocketSecurityError(
                "dedicated-service socket validation requires service identity fields"
            )
        selected_directory = local_user_directory if profile == "local-user" else service_directory
        if not stat.S_ISDIR(directory_details.st_mode) or not selected_directory:
            raise SocketSecurityError("socket directory is not safely permissioned")
        details = path.lstat()
        local_user_socket = (
            details.st_uid == os.geteuid()
            and stat.S_IMODE(details.st_mode) == 0o600
        )
        service_socket = (
            service_uid is not None
            and client_gid is not None
            and details.st_uid == service_uid
            and details.st_gid == client_gid
            and stat.S_IMODE(details.st_mode) == 0o620
        )
        if (
            not stat.S_ISSOCK(details.st_mode)
            or details.st_nlink != 1
            or not (local_user_socket if profile == "local-user" else service_socket)
        ):
            raise SocketSecurityError("socket inode is not safely permissioned")
        return path

    def remove_if_same(self, expected: os.stat_result) -> None:
        _, _, path = self._layout()
        if _same_inode(path, expected):
            path.unlink()


def peer_uid(connection: socket.socket) -> int | None:
    """Return the authenticated peer UID where the host exposes it."""
    getpeereid = getattr(connection, "getpeereid", None)
    if getpeereid is not None:
        uid, _ = getpeereid()
        return int(uid)
    local_peer_cred = getattr(socket, "LOCAL_PEERCRED", None)
    if local_peer_cred is not None:
        raw = connection.getsockopt(0, local_peer_cred, 256)
        if len(raw) < 8:
            raise SocketSecurityError("peer credential record is incomplete")
        version, uid = struct.unpack_from("=II", raw)
        if version != 0:
            raise SocketSecurityError("peer credential record version is unsupported")
        return uid
    peer_cred = getattr(socket, "SO_PEERCRED", None)
    if peer_cred is not None:
        raw = connection.getsockopt(socket.SOL_SOCKET, peer_cred, struct.calcsize("3i"))
        _, uid, _ = struct.unpack("3i", raw)
        return uid
    return None


def peer_pid(connection: socket.socket) -> int | None:
    """Return the authenticated peer PID when the host exposes it."""
    peer_cred = getattr(socket, "SO_PEERCRED", None)
    if peer_cred is not None:
        raw = connection.getsockopt(
            socket.SOL_SOCKET,
            peer_cred,
            struct.calcsize("3i"),
        )
        pid, _, _ = struct.unpack("3i", raw)
    elif sys.platform == "darwin":
        # LOCAL_PEERPID is stable Darwin ABI value 2 even though CPython does
        # not currently publish the constant.
        raw = connection.getsockopt(0, 2, struct.calcsize("i"))
        (pid,) = struct.unpack("=i", raw)
    else:
        return None
    if pid <= 0:
        raise SocketSecurityError("peer PID is invalid")
    return pid


def peer_credentials_supported() -> bool:
    """Return whether this Python/host exposes a supported peer-UID primitive."""
    return any(
        (
            hasattr(socket.socket, "getpeereid"),
            hasattr(socket, "LOCAL_PEERCRED"),
            hasattr(socket, "SO_PEERCRED"),
        )
    )
