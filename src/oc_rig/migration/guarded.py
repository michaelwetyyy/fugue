"""Descriptor-guarded quarantine for synthetic migration directories."""

from __future__ import annotations

import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path


DirectoryIdentity = tuple[int, int, int, int, int]


class GuardedQuarantineError(RuntimeError):
    """A directory could not be safely bound to its quarantine pathname."""

    def __init__(self, message: str):
        super().__init__(message)
        self.evidence: QuarantinedDirectory | None = None


@dataclass(frozen=True, slots=True)
class QuarantinedDirectory:
    path: Path
    identity: DirectoryIdentity
    verified: bool = True


def directory_identity(details: os.stat_result) -> DirectoryIdentity:
    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_uid,
        details.st_gid,
    )


def _guarded_quarantine_seam(_path: Path, _descriptor: int) -> None:
    """Test seam immediately before the final pathname/inode binding check."""


def _guarded_quarantine_preopen_seam(_path: Path) -> None:
    """Test seam after the post-rename stat and before descriptor open."""


def quarantine_directory(
    path: Path,
    expected_identity: DirectoryIdentity,
    *,
    label: str,
) -> QuarantinedDirectory:
    """Atomically quarantine and retain a directory without pathname deletion.

    Unix has no portable compare-and-remove-directory operation. The safe
    fallback is therefore to retain the exact quarantined inode as evidence.
    """
    directory = os.open(
        path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    quarantine_name = f".{path.name}.quarantine-{secrets.token_hex(12)}"
    quarantine_path = path.parent / quarantine_name
    descriptor = -1
    quarantined = False
    try:
        try:
            os.stat(quarantine_name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise GuardedQuarantineError(f"{label} quarantine already exists")
        os.replace(
            path.name,
            quarantine_name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        quarantined = True
        details = os.stat(
            quarantine_name,
            dir_fd=directory,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(details.st_mode)
            or directory_identity(details) != expected_identity
        ):
            raise GuardedQuarantineError(
                f"{label} changed during atomic quarantine"
            )
        _guarded_quarantine_preopen_seam(quarantine_path)
        descriptor = os.open(
            quarantine_name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
        if directory_identity(os.fstat(descriptor)) != expected_identity:
            raise GuardedQuarantineError(f"{label} changed while opening quarantine")
        _guarded_quarantine_seam(quarantine_path, descriptor)
        path_details = os.stat(
            quarantine_name,
            dir_fd=directory,
            follow_symlinks=False,
        )
        if (
            directory_identity(path_details) != expected_identity
            or directory_identity(os.fstat(descriptor)) != expected_identity
        ):
            raise GuardedQuarantineError(
                f"{label} pathname changed before evidence retention"
            )
        return QuarantinedDirectory(quarantine_path, expected_identity)
    except BaseException as error:
        guarded_error: GuardedQuarantineError | None = None
        if quarantined:
            guarded_error = (
                error
                if isinstance(error, GuardedQuarantineError)
                else GuardedQuarantineError(
                    f"{label} quarantine failed after atomic rename"
                )
            )
            guarded_error.evidence = QuarantinedDirectory(
                quarantine_path,
                expected_identity,
                verified=False,
            )
        if quarantined:
            try:
                details = os.stat(
                    quarantine_name,
                    dir_fd=directory,
                    follow_symlinks=False,
                )
                if (
                    directory_identity(details) == expected_identity
                    and not path.exists()
                    and not path.is_symlink()
                ):
                    os.replace(
                        quarantine_name,
                        path.name,
                        src_dir_fd=directory,
                        dst_dir_fd=directory,
                    )
            except FileNotFoundError:
                pass
            except BaseException as retention_error:
                assert guarded_error is not None
                guarded_error.add_note(
                    "quarantine retention check also failed: "
                    f"{type(retention_error).__name__}: {retention_error}"
                )
        if guarded_error is not None and guarded_error is not error:
            raise guarded_error from error
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)
