"""Private and contained filesystem contract for mutable controller state."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


class RuntimeContainmentError(ValueError):
    """A runtime path or inode failed the private containment contract."""


@dataclass(frozen=True, slots=True)
class FileIdentity:
    """Stable identity used to fence pathname replacement between opens."""

    device: int
    inode: int


def _absolute_without_symlink_resolution(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _assert_no_symlink_ancestors(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.exists() or current.is_symlink():
            if current.is_symlink():
                raise RuntimeContainmentError(
                    f"runtime path must not traverse a symlink: {current}"
                )


def _private_regular_file(
    path: Path,
    *,
    expected_uid: int | None = None,
) -> FileIdentity:
    try:
        details = path.lstat()
    except FileNotFoundError as error:
        raise RuntimeContainmentError(f"required runtime file disappeared: {path}") from error
    if not stat.S_ISREG(details.st_mode):
        raise RuntimeContainmentError(f"runtime entry must be a regular file: {path}")
    owner_uid = os.geteuid() if expected_uid is None else expected_uid
    if details.st_uid != owner_uid:
        raise RuntimeContainmentError(f"runtime entry has the wrong owner: {path}")
    if details.st_nlink != 1:
        raise RuntimeContainmentError(f"runtime entry must have one link: {path}")
    if stat.S_IMODE(details.st_mode) != 0o600:
        raise RuntimeContainmentError(f"runtime entry must have mode 0600: {path}")
    return FileIdentity(details.st_dev, details.st_ino)


@dataclass(frozen=True, slots=True)
class PrivateRuntimeDirectory:
    """An owner-only state directory contained by an explicit approved root."""

    root: Path
    approved_root: Path
    database_name: str = "rig.sqlite3"

    @property
    def database(self) -> Path:
        return self.root / self.database_name

    def prepare(self) -> Path:
        """Create a guarded database file without following a caller-provided inode."""
        root, database = self._validated_layout(create_directory=True)
        self._validate_entries(root, database, require_database=False)
        if not database.exists():
            no_follow = getattr(os, "O_NOFOLLOW", None)
            if no_follow is None:
                raise RuntimeContainmentError("O_NOFOLLOW is required for database creation")
            descriptor = os.open(
                database,
                os.O_CREAT | os.O_EXCL | os.O_RDWR | no_follow,
                0o600,
            )
            try:
                os.fchmod(descriptor, 0o600)
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != os.geteuid()
                    or opened.st_nlink != 1
                ):
                    raise RuntimeContainmentError(
                        f"new database inode failed containment: {database}"
                    )
            finally:
                os.close(descriptor)
        self._validate_entries(root, database, require_database=True)
        return database

    def database_identity(self) -> FileIdentity:
        """Validate the complete runtime directory and return the database inode."""
        root, database = self._validated_layout(create_directory=False)
        return self._validate_entries(root, database, require_database=True)

    def validate_provisioned(self, service_uid: int) -> FileIdentity:
        """Validate pre-existing service-owned state without repairing it."""
        if type(service_uid) is not int or service_uid < 0:
            raise RuntimeContainmentError("service UID must be a non-negative integer")
        root, database = self._validated_layout(
            create_directory=False,
            expected_uid=service_uid,
            repair_permissions=False,
        )
        return self._validate_entries(
            root,
            database,
            require_database=True,
            expected_uid=service_uid,
            require_lock=True,
        )

    def assert_open_identity(self, expected: FileIdentity) -> FileIdentity:
        """Fail if the database was replaced or any runtime entry became unsafe."""
        actual = self.database_identity()
        if actual != expected:
            raise RuntimeContainmentError(
                "database inode changed during the lifetime of the store"
            )
        return actual

    def secure_database_file(self) -> None:
        """Revalidate the database and all SQLite sidecars without repairing them."""
        self.database_identity()

    def _validated_layout(
        self,
        *,
        create_directory: bool,
        expected_uid: int | None = None,
        repair_permissions: bool = True,
    ) -> tuple[Path, Path]:
        root = _absolute_without_symlink_resolution(self.root)
        approved = _absolute_without_symlink_resolution(self.approved_root)
        _assert_no_symlink_ancestors(approved)
        if not approved.exists() or not approved.is_dir():
            raise NotADirectoryError(f"approved runtime root must exist: {approved}")
        resolved_approved = approved.resolve(strict=True)
        try:
            root.relative_to(approved)
        except ValueError as error:
            raise RuntimeContainmentError(
                f"runtime directory is outside approved root: {root}"
            ) from error

        _assert_no_symlink_ancestors(root)
        if create_directory:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
        _assert_no_symlink_ancestors(root)
        if not root.exists() or not root.is_dir():
            raise NotADirectoryError(root)
        root_details = root.stat()
        owner_uid = os.geteuid() if expected_uid is None else expected_uid
        if root_details.st_uid != owner_uid:
            raise RuntimeContainmentError(f"runtime directory has the wrong owner: {root}")
        if repair_permissions:
            os.chmod(root, 0o700)
        if stat.S_IMODE(root.stat().st_mode) != 0o700:
            raise PermissionError(f"runtime directory is not private: {root}")

        resolved_root = root.resolve(strict=True)
        try:
            resolved_root.relative_to(resolved_approved)
        except ValueError as error:
            raise RuntimeContainmentError(
                f"resolved runtime directory escapes approved root: {resolved_root}"
            ) from error
        if Path(self.database_name).name != self.database_name or self.database_name in {
            "",
            ".",
            "..",
        }:
            raise RuntimeContainmentError("database_name must be one filename")
        return resolved_root, resolved_root / self.database_name

    def _validate_entries(
        self,
        root: Path,
        database: Path,
        *,
        require_database: bool,
        expected_uid: int | None = None,
        require_lock: bool = False,
    ) -> FileIdentity:
        allowed_names = {
            self.database_name,
            f"{self.database_name}-journal",
            f"{self.database_name}-shm",
            f"{self.database_name}-wal",
            "rigd.lock",
        }
        entries = list(root.iterdir())
        unexpected = sorted(entry.name for entry in entries if entry.name not in allowed_names)
        if unexpected:
            raise RuntimeContainmentError(
                f"unexpected entry in private runtime directory: {unexpected[0]}"
            )
        identities: dict[str, FileIdentity] = {}
        for entry in entries:
            identities[entry.name] = _private_regular_file(
                entry,
                expected_uid=expected_uid,
            )
        if self.database_name not in identities:
            if require_database:
                raise RuntimeContainmentError(f"database is missing: {database}")
            return FileIdentity(-1, -1)
        if require_lock and "rigd.lock" not in identities:
            raise RuntimeContainmentError("provisioned runtime is missing rigd.lock")
        return identities[self.database_name]
