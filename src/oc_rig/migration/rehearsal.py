"""Strict synthetic v1-to-v2 migration rehearsal boundary.

This module accepts only a tiny, explicit compatibility export inside a marked
OS temporary directory. It contains no discovery of Rig v1 or user runtime
paths and has no production cutover operation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from oc_rig.migration.guarded import GuardedQuarantineError, quarantine_directory
from oc_rig.store import PrivateRuntimeDirectory, RigStore


_MARKER = b"oc-rig-synthetic-migration-rehearsal-v1\n"
_FORMAT = "oc-rig-v1-synthetic-compat-v1"
_EXPECTED_SLOTS = (
    ("tensorhost-1", "tensorhost", 1),
    ("tensorhost-2", "tensorhost", 2),
    ("tensorhost-3", "tensorhost", 3),
    ("homelab-1", "homelab", 1),
    ("homelab-2", "homelab", 2),
    ("homelab-3", "homelab", 3),
    ("personal-1", "personal", 1),
    ("personal-2", "personal", 2),
    ("personal-3", "personal", 3),
    ("control-1", "control", 1),
    ("hands-off-1", "hands-off", 1),
    ("control-2", "control", 2),
    ("control-3", "control", 3),
)
_LANES = frozenset({"tensorhost", "homelab", "personal", "control", "hands-off"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
_TIMESTAMP = re.compile(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_MAX_EXPORT_BYTES = 64 * 1024


class SyntheticRehearsalError(ValueError):
    """The requested action crossed or violated the synthetic boundary."""


@dataclass(frozen=True, slots=True)
class ValidatedExport:
    path: Path
    sha256: str
    size: int
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    nlink: int
    mtime_ns: int
    ctime_ns: int
    migration_id: str
    exported_at: str
    controller_state: str
    queue: tuple[Mapping[str, str], ...]


@dataclass(frozen=True, slots=True)
class ImportResult:
    migration_id: str
    source_sha256: str
    applied: bool
    queued_work: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TreeSnapshot:
    rehearsal_root: Path
    target: Path
    backup: Path
    existed: bool
    digest: str
    entries: tuple[Mapping[str, object], ...]


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _check_root(root: Path) -> Path:
    root = root.resolve(strict=True)
    temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
    if root == temporary_root or not _inside(root, temporary_root):
        raise SyntheticRehearsalError("rehearsal root must be a child of the OS temporary root")
    details = root.lstat()
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) not in {0o700, 0o710}
    ):
        raise SyntheticRehearsalError("rehearsal root must have mode 0700 or 0710")
    marker = root / ".oc-rig-synthetic-rehearsal"
    if marker.is_symlink() or not marker.is_file() or marker.read_bytes() != _MARKER:
        raise SyntheticRehearsalError("synthetic rehearsal marker is missing or invalid")
    return root


def prepare_synthetic_root(root: Path) -> Path:
    """Mark one explicit, fresh OS-temporary directory as synthetic-only."""
    root = root.resolve(strict=True)
    temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
    if root == temporary_root or not _inside(root, temporary_root):
        raise SyntheticRehearsalError("rehearsal root must be a child of the OS temporary root")
    root.chmod(0o700)
    marker = root / ".oc-rig-synthetic-rehearsal"
    if marker.exists() or marker.is_symlink():
        raise SyntheticRehearsalError("synthetic rehearsal marker already exists")
    marker.write_bytes(_MARKER)
    marker.chmod(0o600)
    return _check_root(root)


def _contained(path: Path, root: Path, *, must_exist: bool) -> Path:
    root = _check_root(root)
    lexical = Path(os.path.abspath(path))
    if lexical == root or not _inside(lexical, root):
        raise SyntheticRehearsalError(
            "path is outside the marked synthetic rehearsal root"
        )
    current = root
    for part in lexical.relative_to(root).parts:
        current /= part
        if current.is_symlink():
            raise SyntheticRehearsalError(
                "synthetic rehearsal paths must not contain symlinks"
            )
    candidate = path.resolve(strict=must_exist)
    if candidate == root or not _inside(candidate, root):
        raise SyntheticRehearsalError("path is outside the marked synthetic rehearsal root")
    return candidate


def _file_identity(details: os.stat_result) -> tuple[int, ...]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_uid,
        details.st_gid,
        details.st_nlink,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def _export_bytes(path: Path, *, expected_uid: int) -> tuple[bytes, os.stat_result]:
    details = path.lstat()
    mode = stat.S_IMODE(details.st_mode)
    if (
        not stat.S_ISREG(details.st_mode)
        or path.is_symlink()
        or details.st_uid != expected_uid
        or details.st_nlink != 1
        or not mode & stat.S_IRUSR
        or mode & 0o022
        or details.st_size > _MAX_EXPORT_BYTES
    ):
        raise SyntheticRehearsalError(
            "export must be a small, singly-linked, controlled regular file"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(details):
            raise SyntheticRehearsalError("export identity changed while opening")
        data = b""
        while len(data) <= _MAX_EXPORT_BYTES:
            chunk = os.read(descriptor, min(8192, _MAX_EXPORT_BYTES + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        rechecked = os.fstat(descriptor)
        if _file_identity(rechecked) != _file_identity(opened):
            raise SyntheticRehearsalError("export identity changed while reading")
    finally:
        os.close(descriptor)
    if len(data) > _MAX_EXPORT_BYTES:
        raise SyntheticRehearsalError("export exceeds the compatibility size limit")
    return data, details


def _exact_mapping(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise SyntheticRehearsalError(f"{label} fields are invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise SyntheticRehearsalError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise SyntheticRehearsalError(f"{label} is invalid")
    return value


def validate_synthetic_export(path: Path, rehearsal_root: Path) -> ValidatedExport:
    """Validate the one minimal compatibility format before any destination write."""
    path = _contained(path, rehearsal_root, must_exist=True)
    root = _check_root(rehearsal_root)
    data, details = _export_bytes(path, expected_uid=root.lstat().st_uid)
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SyntheticRehearsalError("export is not valid UTF-8 JSON") from error
    envelope = _exact_mapping(
        value,
        {"format", "schema_version", "migration_id", "exported_at", "controller", "queue"},
        "export",
    )
    if envelope["format"] != _FORMAT or envelope["schema_version"] != 1:
        raise SyntheticRehearsalError("export compatibility version is unsupported")
    migration_id = _identifier(envelope["migration_id"], "migration_id")
    exported_at = _timestamp(envelope["exported_at"], "exported_at")
    controller = _exact_mapping(envelope["controller"], {"state"}, "controller")
    if controller["state"] != "stopped":
        raise SyntheticRehearsalError("synthetic legacy controller must be stopped")
    queue_value = envelope["queue"]
    if not isinstance(queue_value, list) or not 1 <= len(queue_value) <= 8:
        raise SyntheticRehearsalError("synthetic queue must contain one to eight records")
    queue: list[Mapping[str, str]] = []
    work_ids: set[str] = set()
    for index, item in enumerate(queue_value):
        record = _exact_mapping(item, {"id", "lane", "state", "enqueued_at"}, f"queue[{index}]")
        work_id = _identifier(record["id"], f"queue[{index}].id")
        if work_id in work_ids:
            raise SyntheticRehearsalError("synthetic queue contains a duplicate work id")
        work_ids.add(work_id)
        lane = record["lane"]
        if lane not in _LANES or record["state"] != "queued":
            raise SyntheticRehearsalError("synthetic queue record state or lane is invalid")
        queue.append(
            MappingProxyType(
                {
                    "id": work_id,
                    "lane": str(lane),
                    "state": "queued",
                    "enqueued_at": _timestamp(record["enqueued_at"], f"queue[{index}].enqueued_at"),
                }
            )
        )
    return ValidatedExport(
        path=path,
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        device=details.st_dev,
        inode=details.st_ino,
        mode=details.st_mode,
        uid=details.st_uid,
        gid=details.st_gid,
        nlink=details.st_nlink,
        mtime_ns=details.st_mtime_ns,
        ctime_ns=details.st_ctime_ns,
        migration_id=migration_id,
        exported_at=exported_at,
        controller_state="stopped",
        queue=tuple(queue),
    )


def _revalidate_export(export: ValidatedExport, rehearsal_root: Path) -> None:
    root = _check_root(rehearsal_root)
    path = _contained(export.path, root, must_exist=True)
    data, details = _export_bytes(path, expected_uid=root.lstat().st_uid)
    if (
        _file_identity(details)
        != (
            export.device,
            export.inode,
            export.mode,
            export.uid,
            export.gid,
            export.nlink,
            export.size,
            export.mtime_ns,
            export.ctime_ns,
        )
        or hashlib.sha256(data).hexdigest() != export.sha256
    ):
        raise SyntheticRehearsalError("validated export changed before import")


def _topology(connection: sqlite3.Connection) -> tuple[tuple[str, str, int], ...]:
    return tuple(
        (str(row[0]), str(row[1]), int(row[2]))
        for row in connection.execute(
            "SELECT id, lane, position FROM scheduler_slots ORDER BY rowid"
        )
    )


def _mutable_tables(connection: sqlite3.Connection) -> tuple[str, ...]:
    excluded = {
        "schema_migrations",
        "scheduler_slots",
        "scheduler_queue_clock",
        "llm_behaviour_settings",
        "sqlite_sequence",
    }
    return tuple(
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        )
        if row[0] not in excluded and not str(row[0]).startswith("sqlite_")
    )


def import_validated_export(
    export: ValidatedExport,
    runtime: PrivateRuntimeDirectory,
    rehearsal_root: Path,
    *,
    after_initialize: Callable[[], None] | None = None,
    before_commit: Callable[[], None] | None = None,
) -> ImportResult:
    """Atomically import validated synthetic records into a fresh v2 database."""
    root = _check_root(rehearsal_root)
    _contained(runtime.root, root, must_exist=False)
    _revalidate_export(export, root)
    store = RigStore(runtime)
    store.initialize()
    if after_initialize is not None:
        after_initialize()
    marker_key = "migration.synthetic_compat_v1"
    queued_ids = tuple(str(item["id"]) for item in export.queue)
    with store._transaction() as connection:
        marker = connection.execute(
            "SELECT value_json FROM settings WHERE key = ?", (marker_key,)
        ).fetchone()
        expected_marker = {
            "controller_state": export.controller_state,
            "migration_id": export.migration_id,
            "source_sha256": export.sha256,
        }
        applied = marker is None
        if marker is not None:
            if json.loads(marker[0]) != expected_marker:
                raise SyntheticRehearsalError(
                    "migration identity was reused with different content"
                )
        elif _topology(connection) != _EXPECTED_SLOTS:
            raise SyntheticRehearsalError(
                "destination scheduler topology is not the exact v2 topology"
            )
        elif connection.execute(
            "SELECT current_value FROM scheduler_queue_clock"
        ).fetchone() != (0,):
            raise SyntheticRehearsalError("destination scheduler clock is not fresh")
        elif any(
            connection.execute(f'SELECT 1 FROM "{table}" LIMIT 1').fetchone()
            is not None
            for table in _mutable_tables(connection)
        ):
            raise SyntheticRehearsalError("destination v2 state is not fresh")

        if applied:
            connection.execute(
                "INSERT INTO settings(key, value_json, updated_at) VALUES (?, ?, ?)",
                (
                    marker_key,
                    json.dumps(expected_marker, sort_keys=True, separators=(",", ":")),
                    export.exported_at,
                ),
            )
        for queue_order, record in (
            enumerate(export.queue, 1) if applied else ()
        ):
            connection.execute(
                """UPDATE scheduler_queue_clock
                   SET current_value = current_value + 1 WHERE singleton = 1"""
            )
            connection.execute(
                """INSERT INTO scheduler_work(
                       id, idempotency_key, lane, state, attempt,
                       enqueued_at, queue_order
                   ) VALUES (?, ?, ?, 'queued', 0, ?, ?)""",
                (
                    record["id"],
                    f"synthetic-import:{export.migration_id}:{record['id']}",
                    record["lane"],
                    record["enqueued_at"],
                    queue_order,
                ),
            )
        if applied:
            connection.execute(
                """INSERT INTO events(
                       event_id, aggregate_type, aggregate_id, event_type,
                       payload_json, occurred_at
                   ) VALUES (?, 'migration', ?, 'migration.synthetic_imported', ?, ?)""",
                (
                    f"migration-event:{export.migration_id}",
                    export.migration_id,
                    json.dumps(
                        {"queue_count": len(export.queue), "source_sha256": export.sha256},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    export.exported_at,
                ),
            )
        if before_commit is not None:
            before_commit()
        # This is the final fallible source operation. It must remain inside the
        # transaction so a changed export rolls back every imported row.
        _revalidate_export(export, root)
    return ImportResult(export.migration_id, export.sha256, applied, queued_ids)


def _tree_entries(path: Path) -> tuple[Mapping[str, object], ...]:
    if not path.exists():
        if path.is_symlink():
            raise SyntheticRehearsalError("tree target must not be a symlink")
        return ()
    entries: list[Mapping[str, object]] = []
    for item in sorted((path, *path.rglob("*"))):
        details = item.lstat()
        relative = "." if item == path else item.relative_to(path).as_posix()
        if stat.S_ISDIR(details.st_mode):
            kind = "directory"
            digest = None
            size = 0
        elif stat.S_ISREG(details.st_mode) and not item.is_symlink():
            kind = "file"
            data = item.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            size = len(data)
        else:
            raise SyntheticRehearsalError("tree snapshots reject links and special files")
        entries.append(
            MappingProxyType(
                {
                    "path": relative,
                    "kind": kind,
                    "mode": stat.S_IMODE(details.st_mode),
                    "size": size,
                    "sha256": digest,
                }
            )
        )
    return tuple(entries)


def _entries_digest(existed: bool, entries: tuple[Mapping[str, object], ...]) -> str:
    material = {"existed": existed, "entries": [dict(item) for item in entries]}
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def tree_digest(path: Path, rehearsal_root: Path) -> str:
    root = _check_root(rehearsal_root)
    target = _contained(path, root, must_exist=path.exists())
    entries = _tree_entries(target)
    return _entries_digest(target.exists(), entries)


def snapshot_tree(path: Path, backup: Path, rehearsal_root: Path) -> TreeSnapshot:
    """Take a byte-hashed, restorable snapshot of one synthetic subtree."""
    root = _check_root(rehearsal_root)
    target = _contained(path, root, must_exist=path.exists())
    backup = _contained(backup, root, must_exist=False)
    if _inside(backup, target) or _inside(target, backup):
        raise SyntheticRehearsalError("snapshot target and backup must not overlap")
    if backup.exists() or backup.is_symlink():
        raise SyntheticRehearsalError("snapshot backup path already exists")
    existed = target.exists()
    entries = _tree_entries(target)
    backup.mkdir(mode=0o700, parents=True)
    if existed:
        payload = backup / "payload"
        shutil.copytree(target, payload, copy_function=shutil.copyfile)
        for item in entries:
            destination = payload if item["path"] == "." else payload / str(item["path"])
            destination.chmod(int(item["mode"]))
    manifest = {
        "format": "oc-rig-tree-snapshot-v1",
        "existed": existed,
        "digest": _entries_digest(existed, entries),
        "entries": [dict(item) for item in entries],
    }
    (backup / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    snapshot = TreeSnapshot(root, target, backup, existed, manifest["digest"], entries)
    _validate_snapshot_backup(snapshot, root, backup)
    return snapshot


def _validate_snapshot_backup(
    snapshot: TreeSnapshot,
    root: Path,
    backup: Path,
) -> None:
    """Validate all backup bytes and metadata before a restore can touch target."""
    expected_children = {"manifest.json"} | ({"payload"} if snapshot.existed else set())
    if {item.name for item in backup.iterdir()} != expected_children:
        raise SyntheticRehearsalError("snapshot backup contains unexpected entries")
    manifest_path = backup / "manifest.json"
    details = manifest_path.lstat()
    if (
        not stat.S_ISREG(details.st_mode)
        or manifest_path.is_symlink()
        or details.st_size > _MAX_EXPORT_BYTES
    ):
        raise SyntheticRehearsalError("snapshot manifest is not a bounded regular file")
    try:
        manifest = json.loads(manifest_path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SyntheticRehearsalError("snapshot manifest is invalid") from error
    expected_manifest = {
        "format": "oc-rig-tree-snapshot-v1",
        "existed": snapshot.existed,
        "digest": snapshot.digest,
        "entries": [dict(item) for item in snapshot.entries],
    }
    if manifest != expected_manifest:
        raise SyntheticRehearsalError("snapshot manifest does not match its pinned facts")
    if snapshot.existed:
        payload = _contained(backup / "payload", root, must_exist=True)
        entries = _tree_entries(payload)
        if entries != snapshot.entries or _entries_digest(True, entries) != snapshot.digest:
            raise SyntheticRehearsalError("snapshot payload does not match its byte hash")
    elif _entries_digest(False, ()) != snapshot.digest:
        raise SyntheticRehearsalError("absent snapshot digest is invalid")


def _target_state(target: Path) -> tuple[bool, tuple[int, ...] | None, str]:
    if not target.exists():
        if target.is_symlink():
            raise SyntheticRehearsalError("snapshot target must not be a symlink")
        return False, None, _entries_digest(False, ())
    details = target.lstat()
    if not stat.S_ISDIR(details.st_mode) or target.is_symlink():
        raise SyntheticRehearsalError("snapshot target must be a regular directory tree")
    entries = _tree_entries(target)
    identity = (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_uid,
        details.st_gid,
        details.st_nlink,
    )
    return True, identity, _entries_digest(True, entries)


def _remove_staged_tree(path: Path) -> None:
    if not path.exists():
        if path.is_symlink():
            raise SyntheticRehearsalError("restore staging path became a symlink")
        return
    if path.is_symlink() or not path.is_dir():
        raise SyntheticRehearsalError("restore staging path changed type")
    shutil.rmtree(path)


def _guarded_remove_retained_tree(
    path: Path,
    expected_state: tuple[bool, tuple[int, ...] | None, str],
) -> None:
    """Quarantine the exact retained inode without pathname deletion."""
    expected_identity = expected_state[1]
    if expected_identity is None:
        raise SyntheticRehearsalError("retained original identity is missing")
    try:
        quarantine_directory(
            path,
            expected_identity[:5],
            label="retained original",
        )
    except GuardedQuarantineError as error:
        raise SyntheticRehearsalError(str(error)) from error
def restore_tree_snapshot(snapshot: TreeSnapshot) -> None:
    """Stage and atomically swap a validated restore while retaining original."""
    root = _check_root(snapshot.rehearsal_root)
    backup = _contained(snapshot.backup, root, must_exist=True)
    _validate_snapshot_backup(snapshot, root, backup)
    target = _contained(snapshot.target, root, must_exist=snapshot.target.exists())
    original_existed, original_identity, original_digest = _target_state(target)
    suffix = snapshot.digest[:16]
    staging = _contained(
        target.parent / f".{target.name}.restore-staging-{suffix}",
        root,
        must_exist=False,
    )
    retained = _contained(
        target.parent / f".{target.name}.restore-original-{suffix}",
        root,
        must_exist=False,
    )
    if staging.exists() or staging.is_symlink() or retained.exists() or retained.is_symlink():
        raise SyntheticRehearsalError("restore staging paths already exist")
    if snapshot.existed:
        shutil.copytree(backup / "payload", staging, copy_function=shutil.copyfile)
        for item in snapshot.entries:
            destination = staging if item["path"] == "." else staging / str(item["path"])
            destination.chmod(int(item["mode"]))
        staged_entries = _tree_entries(staging)
        if (
            staged_entries != snapshot.entries
            or _entries_digest(True, staged_entries) != snapshot.digest
        ):
            _remove_staged_tree(staging)
            raise SyntheticRehearsalError("staged restore is not byte-identical")

    if _target_state(target) != (
        original_existed,
        original_identity,
        original_digest,
    ):
        _remove_staged_tree(staging)
        raise SyntheticRehearsalError("snapshot target changed before atomic restore")

    moved_original = False
    retained_validated = False
    retained_state: tuple[bool, tuple[int, ...] | None, str] | None = None
    staging_installed = False
    mismatched_retained_state: tuple[bool, tuple[int, ...] | None, str] | None = None
    try:
        if original_existed:
            os.replace(target, retained)
            moved_original = True
            retained_state = _target_state(retained)
            if retained_state != (
                original_existed,
                original_identity,
                original_digest,
            ):
                mismatched_retained_state = retained_state
                raise SyntheticRehearsalError(
                    "snapshot target identity changed during atomic rename"
                )
            retained_validated = True
        if snapshot.existed:
            os.replace(staging, target)
            staging_installed = True
        if tree_digest(target, root) != snapshot.digest:
            raise SyntheticRehearsalError(
                "restored tree is not byte-identical to its snapshot"
            )
    except BaseException:
        if staging_installed:
            os.replace(target, staging)
            staging_installed = False
        if moved_original:
            os.replace(retained, target)
            moved_original = False
        expected_state = (
            mismatched_retained_state
            if mismatched_retained_state is not None
            else (original_existed, original_identity, original_digest)
        )
        if _target_state(target) != expected_state:
            raise SyntheticRehearsalError(
                "atomic restore failed to retain the original target"
            )
        _remove_staged_tree(staging)
        _remove_staged_tree(retained)
        raise
    else:
        if original_existed and (not retained_validated or retained_state is None):
            raise SyntheticRehearsalError("retained target was not identity-validated")
        if retained_state is not None:
            _guarded_remove_retained_tree(retained, retained_state)
        _remove_staged_tree(staging)
