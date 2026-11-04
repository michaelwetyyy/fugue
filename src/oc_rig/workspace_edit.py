"""Capability-bounded direct workspace edits for Fugue task completions."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from oc_rig.policy.capsule import (
    ScopeCapsuleError,
    validate_public_replacement_text,
    validate_task_envelope,
)


MAX_EDIT_FILES = 1
MAX_EDIT_FILE_BYTES = 512 * 1024
MAX_EDIT_TOTAL_BYTES = 2 * 1024 * 1024
MAX_EDIT_RESULT_BYTES = MAX_EDIT_FILE_BYTES + 64 * 1024
_STAGE_PREFIX = ".fugue-edit-"
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY_FLAGS = _OPEN_FLAGS | getattr(os, "O_DIRECTORY", 0)
_FILE_FLAGS = _OPEN_FLAGS | getattr(os, "O_NONBLOCK", 0)


class WorkspaceEditRejected(RuntimeError):
    """A worker edit plan or current workspace failed closed validation."""


class WorkspaceEditIndeterminate(RuntimeError):
    """A write crossed its commit boundary and requires exact recovery."""


@dataclass(frozen=True, slots=True)
class _Edit:
    path: str
    before_sha256: str
    content: bytes
    after_sha256: str


@dataclass(frozen=True, slots=True)
class _PatchPlan:
    path: str
    before_sha256: str
    line_start: int
    line_end: int
    before_text_sha256: str
    replacement: str


@dataclass(frozen=True, slots=True)
class _ManifestFile:
    path: str
    content_hash: str
    device: int
    inode: int
    mode: int
    size: int
    ctime_ns: int


@dataclass(frozen=True, slots=True)
class _CurrentFile:
    device: int
    inode: int
    mode: int
    links: int
    size: int
    ctime_ns: int
    owner: int
    sha256: str
    content: bytes


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _load_plan_json(final_text: object, error_code: str) -> dict[str, Any]:
    if type(final_text) is not str:
        raise WorkspaceEditRejected(error_code.replace("_invalid", "_missing"))
    try:
        encoded = final_text.encode("utf-8")
        if len(encoded) > MAX_EDIT_RESULT_BYTES:
            raise WorkspaceEditRejected(error_code)
        value = json.loads(
            final_text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except WorkspaceEditRejected:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError):
        raise WorkspaceEditRejected(error_code) from None
    if type(value) is not dict:
        raise WorkspaceEditRejected(error_code)
    return value


def _parse_plan(
    final_text: object,
    manifest: Mapping[str, _ManifestFile],
    repository: Path,
) -> tuple[_Edit, ...]:
    value = _load_plan_json(final_text, "workspace_edit_result_invalid")
    if type(value) is not dict or set(value) != {"edits", "summary", "version"}:
        raise WorkspaceEditRejected("workspace_edit_result_invalid")
    if type(value.get("version")) is not int or value.get("version") != 1:
        raise WorkspaceEditRejected("workspace_edit_result_invalid")
    summary = value.get("summary")
    try:
        summary_size = len(summary.encode("utf-8")) if type(summary) is str else None
    except UnicodeError:
        summary_size = None
    if type(summary) is not str or not summary.strip() or summary_size is None or summary_size > 1024:
        raise WorkspaceEditRejected("workspace_edit_summary_invalid")
    raw_edits = value.get("edits")
    if type(raw_edits) is not list or len(raw_edits) != MAX_EDIT_FILES:
        raise WorkspaceEditRejected("workspace_edit_count_invalid")
    edits: list[_Edit] = []
    seen: set[str] = set()
    total = 0
    for raw in raw_edits:
        if type(raw) is not dict or set(raw) != {"before_sha256", "content", "path"}:
            raise WorkspaceEditRejected("workspace_edit_entry_invalid")
        path = raw.get("path")
        before = raw.get("before_sha256")
        content = raw.get("content")
        if (
            type(path) is not str
            or path not in manifest
            or path in seen
            or type(before) is not str
            or before != manifest[path].content_hash
            or type(content) is not str
        ):
            raise WorkspaceEditRejected("workspace_edit_entry_invalid")
        try:
            encoded = content.encode("utf-8")
        except UnicodeEncodeError:
            raise WorkspaceEditRejected("workspace_edit_content_invalid") from None
        if len(encoded) > MAX_EDIT_FILE_BYTES or b"\x00" in encoded:
            raise WorkspaceEditRejected("workspace_edit_content_invalid")
        try:
            validate_public_replacement_text(content, repository)
        except ScopeCapsuleError:
            raise WorkspaceEditRejected("workspace_edit_content_unsafe") from None
        total += len(encoded)
        if total > MAX_EDIT_TOTAL_BYTES:
            raise WorkspaceEditRejected("workspace_edit_size_exceeded")
        seen.add(path)
        edits.append(
            _Edit(path, before, encoded, hashlib.sha256(encoded).hexdigest())
        )
    return tuple(edits)


def _parse_patch_plan(
    final_text: object,
    manifest: Mapping[str, _ManifestFile],
    repository: Path,
    authority: object,
) -> tuple[_Edit, _PatchPlan]:
    if type(authority) is not dict or set(authority) != {
        "content", "content_hash", "line_end", "line_start", "path",
        "scope_hash", "version", "window_hash",
    }:
        raise WorkspaceEditRejected("workspace_patch_authority_invalid")
    path = authority.get("path")
    line_start = authority.get("line_start")
    line_end = authority.get("line_end")
    base_text = authority.get("content")
    if (
        type(authority.get("version")) is not int
        or authority.get("version") != 1
        or type(path) is not str
        or path not in manifest
        or type(line_start) is not int
        or type(line_end) is not int
        or line_start < 1
        or line_end < line_start
        or type(base_text) is not str
        or type(authority.get("content_hash")) is not str
        or type(authority.get("scope_hash")) is not str
        or type(authority.get("window_hash")) is not str
    ):
        raise WorkspaceEditRejected("workspace_patch_authority_invalid")
    try:
        base = base_text.encode("utf-8")
    except UnicodeError:
        raise WorkspaceEditRejected("workspace_patch_authority_invalid") from None
    expected = manifest[path]
    if (
        len(base) != expected.size
        or hashlib.sha256(base).hexdigest() != expected.content_hash
        or authority["content_hash"] != expected.content_hash
    ):
        raise WorkspaceEditRejected("workspace_patch_authority_invalid")
    lines = base_text.splitlines(keepends=True)
    if line_end > len(lines):
        raise WorkspaceEditRejected("workspace_patch_authority_invalid")
    before_text = "".join(lines[line_start - 1 : line_end])
    before_text_hash = hashlib.sha256(before_text.encode("utf-8")).hexdigest()
    if before_text_hash != authority["window_hash"]:
        raise WorkspaceEditRejected("workspace_patch_authority_invalid")

    value = _load_plan_json(final_text, "workspace_patch_result_invalid")
    if type(value) is not dict or set(value) != {"edits", "summary", "version"}:
        raise WorkspaceEditRejected("workspace_patch_result_invalid")
    if type(value.get("version")) is not int or value.get("version") != 1:
        raise WorkspaceEditRejected("workspace_patch_result_invalid")
    summary = value.get("summary")
    try:
        summary_size = len(summary.encode("utf-8")) if type(summary) is str else None
    except UnicodeError:
        summary_size = None
    if type(summary) is not str or not summary.strip() or summary_size is None or summary_size > 1024:
        raise WorkspaceEditRejected("workspace_patch_summary_invalid")
    edits = value.get("edits")
    if type(edits) is not list or len(edits) != MAX_EDIT_FILES or type(edits[0]) is not dict:
        raise WorkspaceEditRejected("workspace_patch_count_invalid")
    raw = edits[0]
    if set(raw) != {
        "before_sha256", "before_text_sha256", "line_end", "line_start",
        "path", "replacement",
    }:
        raise WorkspaceEditRejected("workspace_patch_entry_invalid")
    replacement = raw.get("replacement")
    if (
        raw.get("path") != path
        or raw.get("before_sha256") != expected.content_hash
        or type(raw.get("line_start")) is not int
        or type(raw.get("line_end")) is not int
        or raw.get("line_start") != line_start
        or raw.get("line_end") != line_end
        or raw.get("before_text_sha256") != before_text_hash
        or type(replacement) is not str
        or replacement == before_text
    ):
        raise WorkspaceEditRejected("workspace_patch_entry_invalid")
    try:
        replacement_bytes = replacement.encode("utf-8")
        validate_public_replacement_text(replacement, repository)
    except (UnicodeEncodeError, ScopeCapsuleError):
        raise WorkspaceEditRejected("workspace_patch_content_unsafe") from None
    if len(replacement_bytes) > MAX_EDIT_FILE_BYTES or b"\x00" in replacement_bytes:
        raise WorkspaceEditRejected("workspace_patch_content_invalid")
    post_text = "".join(lines[: line_start - 1]) + replacement + "".join(lines[line_end:])
    try:
        validate_public_replacement_text(post_text, repository)
        post = post_text.encode("utf-8")
    except (ScopeCapsuleError, UnicodeEncodeError):
        raise WorkspaceEditRejected("workspace_patch_postimage_unsafe") from None
    if len(post) > MAX_EDIT_FILE_BYTES or b"\x00" in post:
        raise WorkspaceEditRejected("workspace_patch_postimage_too_large")
    patch = _PatchPlan(path, expected.content_hash, line_start, line_end, before_text_hash, replacement)
    return _Edit(path, expected.content_hash, post, hashlib.sha256(post).hexdigest()), patch


def _open_root(
    repository: str,
    expected: Mapping[str, object],
) -> tuple[int, Path, os.stat_result]:
    path = Path(repository)
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise WorkspaceEditRejected("workspace_repository_invalid")
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise WorkspaceEditRejected("workspace_repository_unavailable") from None
    if resolved != path or not resolved.is_dir():
        raise WorkspaceEditRejected("workspace_repository_invalid")
    descriptor: int | None = None
    try:
        descriptor = os.open("/", _DIRECTORY_FLAGS)
        for component in resolved.parts[1:]:
            child: int | None = None
            try:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
                child_details = os.fstat(child)
            except (OSError, ValueError):
                if child is not None:
                    os.close(child)
                raise WorkspaceEditRejected("workspace_repository_invalid") from None
            if (
                not stat.S_ISDIR(child_details.st_mode)
                or child_details.st_uid not in {0, os.geteuid()}
                or child_details.st_mode & 0o022
            ):
                os.close(child)
                raise WorkspaceEditRejected("workspace_repository_invalid")
            os.close(descriptor)
            descriptor = child
        details = os.fstat(descriptor)
    except (OSError, ValueError, WorkspaceEditRejected):
        if descriptor is not None:
            os.close(descriptor)
        raise WorkspaceEditRejected("workspace_repository_unavailable") from None
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_mode & 0o022
        or details.st_dev != expected.get("device")
        or details.st_ino != expected.get("inode")
        or details.st_mode != expected.get("mode")
    ):
        os.close(descriptor)
        raise WorkspaceEditRejected("workspace_repository_invalid")
    return descriptor, resolved, details


def _open_parent(root: int, relative: str) -> tuple[int, str]:
    pure = PurePosixPath(relative)
    parts = relative.split("/")
    if (
        pure.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
        or any(part.casefold() == ".git" for part in parts)
        or "\x00" in relative
        or parts[-1].startswith(_STAGE_PREFIX)
    ):
        raise WorkspaceEditRejected("workspace_edit_path_invalid")
    parent = os.dup(root)
    try:
        for component in parts[:-1]:
            child: int | None = None
            try:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent)
                details = os.fstat(child)
            except (OSError, ValueError):
                if child is not None:
                    os.close(child)
                raise WorkspaceEditRejected("workspace_edit_path_unsafe") from None
            if (
                not stat.S_ISDIR(details.st_mode)
                or details.st_uid != os.geteuid()
                or details.st_mode & 0o022
            ):
                os.close(child)
                raise WorkspaceEditRejected("workspace_edit_path_unsafe")
            os.close(parent)
            parent = child
        return parent, parts[-1]
    except (OSError, ValueError, WorkspaceEditRejected):
        os.close(parent)
        raise WorkspaceEditRejected("workspace_edit_path_unsafe") from None


def _read_current(parent: int, name: str) -> _CurrentFile:
    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent)
    except (OSError, ValueError):
        raise WorkspaceEditRejected("workspace_edit_target_unavailable") from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o022
        ):
            raise WorkspaceEditRejected("workspace_edit_target_unsafe")
        if before.st_size > MAX_EDIT_FILE_BYTES:
            raise WorkspaceEditRejected("workspace_edit_target_too_large")
        chunks: list[bytes] = []
        remaining = MAX_EDIT_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_size,
            item.st_ctime_ns,
        )
        if len(content) != after.st_size or identity(before) != identity(after):
            raise WorkspaceEditRejected("workspace_edit_target_raced")
        return _CurrentFile(
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_ctime_ns,
            before.st_uid,
            hashlib.sha256(content).hexdigest(),
            content,
        )
    except OSError:
        raise WorkspaceEditRejected("workspace_edit_target_unavailable") from None
    finally:
        os.close(descriptor)


def _current_identity(current: _CurrentFile) -> tuple[int, int, int, int, int, int]:
    return (
        current.device,
        current.inode,
        current.mode,
        current.links,
        current.size,
        current.ctime_ns,
    )


def _manifest_identity(item: _ManifestFile) -> tuple[int, int, int, int, int, int]:
    return (
        item.device,
        item.inode,
        item.mode,
        1,
        item.size,
        item.ctime_ns,
    )


def _swap_identity(current: _CurrentFile) -> tuple[int, int, int, int, int]:
    return (
        current.device,
        current.inode,
        current.mode,
        current.links,
        current.size,
    )


def _swap_names(parent: int, first: str, second: str) -> None:
    if "\x00" in first or "\x00" in second:
        raise WorkspaceEditRejected("workspace_edit_path_invalid")
    if sys.platform != "darwin":
        raise WorkspaceEditRejected("workspace_edit_atomic_swap_unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    renameatx = getattr(libc, "renameatx_np", None)
    if renameatx is None:
        raise WorkspaceEditRejected("workspace_edit_atomic_swap_unavailable")
    renameatx.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameatx.restype = ctypes.c_int
    if renameatx(
        parent,
        os.fsencode(first),
        parent,
        os.fsencode(second),
        0x00000002,
    ) != 0:
        raise WorkspaceEditRejected("workspace_edit_atomic_swap_failed")


def _temporary_name(edit: _Edit) -> str:
    material = f"{edit.path}\0{edit.before_sha256}\0{edit.after_sha256}".encode()
    return f"{_STAGE_PREFIX}{hashlib.sha256(material).hexdigest()[:32]}.tmp"


def _optional_current(parent: int, name: str) -> _CurrentFile | None:
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        raise WorkspaceEditIndeterminate("workspace_edit_recovery_unavailable") from None
    try:
        return _read_current(parent, name)
    except WorkspaceEditRejected as error:
        raise WorkspaceEditIndeterminate("workspace_edit_recovery_unsafe") from error


def _same_swapped_file(left: _CurrentFile, right: _CurrentFile) -> bool:
    return (
        _swap_identity(left) == _swap_identity(right)
        and left.owner == right.owner
        and left.sha256 == right.sha256
    )


def _rollback_swap(
    parent: int,
    temporary: str,
    name: str,
    stage: _CurrentFile,
) -> None:
    try:
        target = _read_current(parent, name)
        if not _same_swapped_file(target, stage):
            raise WorkspaceEditIndeterminate("workspace_edit_rollback_target_changed")
        _swap_names(parent, temporary, name)
        restored_stage = _read_current(parent, temporary)
        if not _same_swapped_file(restored_stage, stage):
            try:
                _swap_names(parent, temporary, name)
            except WorkspaceEditRejected:
                pass
            raise WorkspaceEditIndeterminate("workspace_edit_rollback_identity_changed")
        os.unlink(temporary, dir_fd=parent)
        os.fsync(parent)
    except WorkspaceEditIndeterminate:
        raise
    except (OSError, WorkspaceEditRejected):
        raise WorkspaceEditIndeterminate("workspace_edit_rollback_failed") from None


def _finish_committed_swap(
    parent: int,
    temporary: str,
    expected: _ManifestFile,
) -> None:
    displaced = _optional_current(parent, temporary)
    if displaced is not None and (
        displaced.device != expected.device
        or displaced.inode != expected.inode
        or displaced.mode != expected.mode
        or displaced.links != 1
        or displaced.size != expected.size
        or displaced.sha256 != expected.content_hash
    ):
        raise WorkspaceEditIndeterminate("workspace_edit_displaced_identity_changed")
    try:
        os.fsync(parent)
        if displaced is not None:
            os.unlink(temporary, dir_fd=parent)
            os.fsync(parent)
    except OSError:
        raise WorkspaceEditIndeterminate("workspace_edit_commit_unconfirmed") from None


def _write_replacement(
    parent: int,
    name: str,
    current: _CurrentFile,
    expected: _ManifestFile,
    edit: _Edit,
) -> None:
    temporary = _temporary_name(edit)
    recovered = _optional_current(parent, temporary)
    if current.sha256 == edit.after_sha256:
        confirmed = _read_current(parent, name)
        if (
            _current_identity(confirmed) != _current_identity(current)
            or confirmed.owner != current.owner
            or confirmed.sha256 != current.sha256
        ):
            raise WorkspaceEditRejected("workspace_edit_target_raced")
        _finish_committed_swap(parent, temporary, expected)
        return
    if recovered is not None:
        if (
            recovered.sha256 != edit.after_sha256
            or recovered.owner != current.owner
            or recovered.links != 1
            or recovered.size != len(edit.content)
            or recovered.mode != current.mode
        ):
            raise WorkspaceEditIndeterminate("workspace_edit_stage_collision")
        stage = recovered
    else:
        stage = None
    descriptor: int | None = None
    try:
        if stage is None:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                stat.S_IMODE(current.mode),
                dir_fd=parent,
            )
            view = memoryview(edit.content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short workspace write")
                view = view[written:]
            os.fchmod(descriptor, stat.S_IMODE(current.mode))
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            stage = _read_current(parent, temporary)
        if stage is None:
            raise WorkspaceEditRejected("workspace_edit_stage_unavailable")
        try:
            _swap_names(parent, temporary, name)
        except WorkspaceEditRejected:
            try:
                os.unlink(temporary, dir_fd=parent)
                os.fsync(parent)
            except OSError:
                raise WorkspaceEditIndeterminate(
                    "workspace_edit_stage_cleanup_unconfirmed"
                ) from None
            raise
        try:
            landed = _read_current(parent, name)
            displaced = _read_current(parent, temporary)
        except WorkspaceEditRejected as error:
            raise WorkspaceEditIndeterminate(
                "workspace_edit_post_swap_validation_unavailable"
            ) from error
        if (
            not _same_swapped_file(landed, stage)
            or not _same_swapped_file(displaced, current)
        ):
            _rollback_swap(parent, temporary, name, stage)
            raise WorkspaceEditRejected("workspace_edit_target_raced")
        _finish_committed_swap(parent, temporary, expected)
    except WorkspaceEditRejected:
        raise
    except WorkspaceEditIndeterminate:
        raise
    except OSError:
        raise WorkspaceEditRejected("workspace_edit_write_failed") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def apply_workspace_edit_plan(
    repository: str,
    envelope: Mapping[str, Any],
    final_text: object,
    patch_authority: object = None,
) -> str:
    """Apply one idempotent full-file or line-window plan and return a receipt."""

    task_mode = envelope.get("task_mode")
    if task_mode not in {"workspace_edit", "workspace_patch"}:
        raise WorkspaceEditRejected("workspace_edit_authority_missing")
    try:
        validate_task_envelope(envelope)
    except ScopeCapsuleError:
        raise WorkspaceEditRejected("workspace_edit_authority_invalid") from None
    capsule = envelope.get("scope_capsule")
    if type(capsule) is not dict or set(capsule) != {"files", "manifest"}:
        raise WorkspaceEditRejected("workspace_edit_authority_invalid")
    manifest_value = capsule.get("manifest")
    if type(manifest_value) is not dict:
        raise WorkspaceEditRejected("workspace_edit_authority_invalid")
    files = manifest_value.get("files")
    if type(files) is not list:
        raise WorkspaceEditRejected("workspace_edit_authority_invalid")
    root_value = manifest_value.get("root")
    if type(root_value) is not dict:
        raise WorkspaceEditRejected("workspace_edit_authority_invalid")
    manifest: dict[str, _ManifestFile] = {}
    for item in files:
        base_keys = {
            "content_hash", "ctime_ns", "device", "inode", "line_count",
            "mode", "path", "size_bytes",
        }
        patch_keys = {
            "window_hash", "window_line_end", "window_line_start",
            "window_size_bytes",
        }
        if (
            type(item) is not dict
            or set(item) != (base_keys | patch_keys if task_mode == "workspace_patch" else base_keys)
        ):
            raise WorkspaceEditRejected("workspace_edit_authority_invalid")
        path = item.get("path")
        content_hash = item.get("content_hash")
        numeric = tuple(
            item.get(key)
            for key in ("device", "inode", "mode", "size_bytes", "ctime_ns")
        )
        if (
            type(path) is not str
            or type(content_hash) is not str
            or path in manifest
            or any(type(value) is not int for value in numeric)
        ):
            raise WorkspaceEditRejected("workspace_edit_authority_invalid")
        manifest[path] = _ManifestFile(path, content_hash, *numeric)
    patch_plan: _PatchPlan | None = None
    if task_mode == "workspace_patch":
        patch_entry = files[0] if len(files) == 1 else None
        if (
            type(patch_entry) is not dict
            or type(patch_authority) is not dict
            or patch_authority.get("scope_hash") != manifest_value.get("scope_hash")
            or patch_authority.get("line_start") != patch_entry.get("window_line_start")
            or patch_authority.get("line_end") != patch_entry.get("window_line_end")
            or patch_authority.get("window_hash") != patch_entry.get("window_hash")
        ):
            raise WorkspaceEditRejected("workspace_patch_authority_invalid")
        edit, patch_plan = _parse_patch_plan(
            final_text,
            manifest,
            Path(repository),
            patch_authority,
        )
        edits = (edit,)
    else:
        if patch_authority is not None:
            raise WorkspaceEditRejected("workspace_edit_authority_invalid")
        edits = _parse_plan(final_text, manifest, Path(repository))
    try:
        plan_hash = hashlib.sha256(final_text.encode("utf-8")).hexdigest()
    except UnicodeEncodeError:
        raise WorkspaceEditRejected("workspace_edit_result_invalid") from None
    root, _, _ = _open_root(repository, root_value)
    opened: list[tuple[_Edit, int, str, _CurrentFile]] = []
    try:
        for edit in edits:
            parent, name = _open_parent(root, edit.path)
            try:
                current = _read_current(parent, name)
            except WorkspaceEditRejected as error:
                if _optional_current(parent, _temporary_name(edit)) is not None:
                    os.close(parent)
                    raise WorkspaceEditIndeterminate(
                        "workspace_edit_recovery_target_unavailable"
                    ) from error
                os.close(parent)
                raise
            if current.sha256 not in {edit.before_sha256, edit.after_sha256}:
                if _optional_current(parent, _temporary_name(edit)) is not None:
                    os.close(parent)
                    raise WorkspaceEditIndeterminate(
                        "workspace_edit_recovery_conflicts_with_target"
                    )
                os.close(parent)
                raise WorkspaceEditRejected("workspace_edit_preimage_changed")
            if current.sha256 == edit.before_sha256:
                expected_file = manifest[edit.path]
                if (
                    _current_identity(current) != _manifest_identity(expected_file)
                ):
                    os.close(parent)
                    raise WorkspaceEditRejected("workspace_edit_preimage_identity_changed")
            opened.append((edit, parent, name, current))
        for edit, parent, name, current in opened:
            _write_replacement(parent, name, current, manifest[edit.path], edit)
    finally:
        for _, parent, _, _ in opened:
            os.close(parent)
        os.close(root)
    receipt_kind = "workspace_patch" if patch_plan is not None else "workspace_edit"
    receipt_body: dict[str, object] = {
        "applied": True,
        "edit_count": len(edits),
        "files": [
            {"path": edit.path, "sha256": edit.after_sha256}
            for edit in edits
        ],
        "plan_sha256": plan_hash,
        "version": 1,
    }
    if patch_plan is not None:
        receipt_body["range"] = {
            "line_end": patch_plan.line_end,
            "line_start": patch_plan.line_start,
        }
        receipt_body["before_sha256"] = patch_plan.before_sha256
    receipt = {receipt_kind: receipt_body}
    return _canonical(receipt)
