"""Exact filesystem-scope admission checks.

This module performs admission-time inspection only. It does not claim to be a
replacement for the runner's execution sandbox or race-resistant file access.
"""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from pathlib import Path, PurePosixPath

from oc_rig.policy.models import ReasonCode, ScopeInspection, ScopedPath


class _ScopeRejected(Exception):
    def __init__(self, reason: ReasonCode) -> None:
        self.reason = reason


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _collision_key(path: str) -> tuple[str, ...]:
    return tuple(
        unicodedata.normalize("NFKC", part).casefold()
        for part in path.split("/")
    )


def _inspect_node(path: Path) -> bool:
    """Recursively inspect a present path; return whether it is a directory."""

    try:
        metadata = path.lstat()
    except OSError as error:
        raise _ScopeRejected(ReasonCode.SCOPE_INSPECTION_FAILED) from error
    if stat.S_ISLNK(metadata.st_mode):
        raise _ScopeRejected(ReasonCode.SCOPE_SYMLINK)
    if stat.S_ISREG(metadata.st_mode):
        if metadata.st_nlink != 1:
            raise _ScopeRejected(ReasonCode.SCOPE_HARDLINK)
        return False
    if not stat.S_ISDIR(metadata.st_mode):
        raise _ScopeRejected(ReasonCode.SCOPE_NON_REGULAR)
    try:
        children = sorted(os.scandir(path), key=lambda child: child.name)
    except OSError as error:
        raise _ScopeRejected(ReasonCode.SCOPE_INSPECTION_FAILED) from error
    for child in children:
        if unicodedata.normalize("NFKC", child.name).casefold() == ".git":
            raise _ScopeRejected(ReasonCode.SCOPE_GIT_ADMIN)
        _inspect_node(Path(child.path))
    return True


def _inspect_ancestors(repository: Path, candidate: Path) -> None:
    cursor = candidate.parent
    ancestors: list[Path] = []
    while cursor != repository:
        ancestors.append(cursor)
        if cursor.parent == cursor:
            raise _ScopeRejected(ReasonCode.SCOPE_OUTSIDE_REPOSITORY)
        cursor = cursor.parent
    for ancestor in reversed(ancestors):
        if not ancestor.exists() and not ancestor.is_symlink():
            continue
        try:
            metadata = ancestor.lstat()
        except (OSError, RuntimeError) as error:
            raise _ScopeRejected(ReasonCode.SCOPE_INSPECTION_FAILED) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise _ScopeRejected(ReasonCode.SCOPE_SYMLINK)
        if not stat.S_ISDIR(metadata.st_mode):
            raise _ScopeRejected(ReasonCode.SCOPE_NON_REGULAR)


def inspect_scope(repository: object, value: object) -> ScopeInspection:
    """Normalize and inspect an exact scope, returning a fail-closed result."""

    try:
        if not isinstance(repository, (str, os.PathLike)) or isinstance(repository, bytes):
            raise _ScopeRejected(ReasonCode.REPOSITORY_INVALID)
        repository_path = Path(repository)
        if not repository_path.is_absolute():
            raise _ScopeRejected(ReasonCode.REPOSITORY_INVALID)
        try:
            repository_path = repository_path.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise _ScopeRejected(ReasonCode.REPOSITORY_INVALID) from error
        if not repository_path.is_dir():
            raise _ScopeRejected(ReasonCode.REPOSITORY_INVALID)
        if not isinstance(value, (list, tuple)) or not value:
            raise _ScopeRejected(ReasonCode.SCOPE_REQUIRED)

        entries: list[tuple[str, tuple[str, ...], Path]] = []
        seen: set[tuple[str, ...]] = set()
        for item in value:
            if not isinstance(item, str) or not item:
                raise _ScopeRejected(ReasonCode.SCOPE_INVALID_ENTRY)
            if "\x00" in item or "\\" in item or any(unicodedata.category(ch) == "Cf" for ch in item):
                raise _ScopeRejected(ReasonCode.SCOPE_INVALID_ENTRY)
            if unicodedata.normalize("NFC", item) != item:
                raise _ScopeRejected(ReasonCode.SCOPE_INVALID_ENTRY)
            pure = PurePosixPath(item)
            if pure.is_absolute() or item.startswith("/") or re.match(r"^[A-Za-z]:", item):
                raise _ScopeRejected(ReasonCode.SCOPE_ABSOLUTE)
            raw_parts = item.split("/")
            if any(part in {"", ".", ".."} for part in raw_parts):
                raise _ScopeRejected(ReasonCode.SCOPE_TRAVERSAL)
            if any(unicodedata.normalize("NFKC", part).casefold() == ".git" for part in raw_parts):
                raise _ScopeRejected(ReasonCode.SCOPE_GIT_ADMIN)
            key = _collision_key(item)
            if key in seen:
                raise _ScopeRejected(ReasonCode.SCOPE_COLLISION)
            seen.add(key)
            entries.append((pure.as_posix(), key, repository_path.joinpath(*pure.parts)))

        keys = sorted(key for _, key, _ in entries)
        for previous, current in zip(keys, keys[1:]):
            if len(previous) < len(current) and current[: len(previous)] == previous:
                raise _ScopeRejected(ReasonCode.SCOPE_PREFIX_AMBIGUITY)

        normalized: list[ScopedPath] = []
        for relative, _, candidate in sorted(entries):
            _inspect_ancestors(repository_path, candidate)
            try:
                resolved = candidate.resolve(strict=False)
            except (OSError, RuntimeError) as error:
                raise _ScopeRejected(ReasonCode.SCOPE_INSPECTION_FAILED) from error
            if not _is_within(resolved, repository_path):
                raise _ScopeRejected(ReasonCode.SCOPE_OUTSIDE_REPOSITORY)
            is_directory = False
            if candidate.exists() or candidate.is_symlink():
                is_directory = _inspect_node(candidate)
            normalized.append(ScopedPath(relative, resolved, is_directory))
        return ScopeInspection(True, repository_path, tuple(normalized), ())
    except _ScopeRejected as rejection:
        resolved_repository = locals().get("repository_path")
        if not isinstance(resolved_repository, Path) or not resolved_repository.is_absolute():
            resolved_repository = None
        return ScopeInspection(False, resolved_repository, (), (rejection.reason,))
