"""Transactional SQLite store for controller state and its operation journal."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
import uuid
import weakref
from collections.abc import Iterator, Mapping
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from oc_rig.domain.models import OperationKind, OperationState, SettingKey, WorkKind
from oc_rig.domain.transitions import require_transition
from oc_rig.store.runtime import (
    FileIdentity,
    PrivateRuntimeDirectory,
    RuntimeContainmentError,
)


class StoreError(RuntimeError):
    """Base persistence error."""


class OwnershipConflict(StoreError):
    """An active owner already holds the requested scope or session."""


class CredentialDataError(ValueError):
    """Data appears to contain credentials, which must not enter the state DB."""


class IdempotencyConflict(StoreError):
    """An idempotency key was reused for a different durable intent."""


class DaemonAuthorityError(StoreError):
    """A rigd-only mutation lacked the exclusive daemon authority."""


class StoreQuiescenceError(StoreError):
    """A committed mutation could not establish a truncated WAL baseline."""


@dataclass(frozen=True, slots=True)
class OwnershipReceipt:
    id: str
    owner_id: str
    attempt: int
    fence_token: str


@dataclass(frozen=True, slots=True)
class WorkReservation:
    id: str
    sequence: int
    operation_id: str | None
    kind: WorkKind
    priority: int
    owner_id: str
    attempt: int
    fence_token: str


class _AuthorityLease:
    """One full-lifetime use of daemon authority."""

    __slots__ = ("_authority", "_closed", "_owner_thread")

    def __init__(self, authority: "_DaemonAuthority"):
        self._authority = authority
        self._closed = False
        self._owner_thread = threading.get_ident()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        authority = self._authority
        with authority._usage_condition:
            current_owner_count = authority._lease_threads.get(
                self._owner_thread, 0
            )
            if authority._active_leases <= 0 or current_owner_count <= 0:
                raise DaemonAuthorityError("daemon authority lease count underflow")
            authority._active_leases -= 1
            owner_count = current_owner_count - 1
            if owner_count > 0:
                authority._lease_threads[self._owner_thread] = owner_count
            else:
                authority._lease_threads.pop(self._owner_thread, None)
            authority._usage_condition.notify_all()


class _DaemonAuthority:
    """Process-local capability backed by an exclusive private runtime lock."""

    def __new__(cls, *_args: object, **_kwargs: object) -> "_DaemonAuthority":
        raise DaemonAuthorityError("daemon authority cannot be constructed directly")

    def _activate_usage_guard(self) -> None:
        self._usage_condition = threading.Condition()
        self._closing = False
        self._active_leases = 0
        self._lease_threads: dict[int, int] = {}

    def _validate_locked(self, store: "RigStore") -> None:
        if self._store is not store:
            raise DaemonAuthorityError("daemon authority is absent or belongs elsewhere")
        opened = os.fstat(self._descriptor)
        linked = self._path.lstat()
        if (
            (opened.st_dev, opened.st_ino) != self._identity
            or (linked.st_dev, linked.st_ino) != self._identity
        ):
            raise DaemonAuthorityError("daemon lock identity changed")
        store.runtime.assert_open_identity(store._database_identity)

    def _assert_for_locked(self, store: "RigStore") -> None:
        with self._usage_condition:
            leased_here = self._lease_threads.get(threading.get_ident(), 0) > 0
            if self._closed or (self._closing and not leased_here):
                raise DaemonAuthorityError("daemon authority is closing or closed")
            self._validate_locked(store)

    def _assert_for(self, store: "RigStore") -> None:
        with store._serialization_lock:
            self._assert_for_locked(store)

    def _authorize(self, store: "RigStore") -> None:
        self._assert_for(store)

    def _acquire_lease_locked(self, store: "RigStore") -> _AuthorityLease:
        with self._usage_condition:
            if self._closed or self._closing:
                raise DaemonAuthorityError("daemon authority is closing or closed")
            self._validate_locked(store)
            self._active_leases += 1
            owner_thread = threading.get_ident()
            self._lease_threads[owner_thread] = (
                self._lease_threads.get(owner_thread, 0) + 1
            )
            return _AuthorityLease(self)

    def close(self) -> None:
        with self._usage_condition:
            while self._closing and not self._closed:
                self._usage_condition.wait()
            if self._closed:
                return
            self._closing = True
            self._usage_condition.notify_all()
        first_error: BaseException | None = None
        with self._store._serialization_lock:
            try:
                self._store._close_daemon_connection()
            except BaseException as error:
                first_error = error
            with self._usage_condition:
                if self._active_leases != 0:
                    self._closing = False
                    self._usage_condition.notify_all()
                    raise DaemonAuthorityError(
                        "daemon authority close refused while leases remain active"
                    )
            try:
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            except BaseException as error:
                if first_error is None:
                    first_error = error
            try:
                os.close(self._descriptor)
            except BaseException as error:
                if first_error is None:
                    first_error = error
            with self._usage_condition:
                self._closed = True
                self._usage_condition.notify_all()
        if first_error is not None:
            raise first_error

_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)(?:access[-_ ]?token|api[-_ ]?key|authorization|credential|password|"
    r"private[-_ ]?key|refresh[-_ ]?token|secret|token)\s*[:=]\s*\S+"
)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@*?+-]{0,255}\Z")
_CHECKPOINT_LOCK_HANDOFF_MS = 100
_LOCK_REGISTRY_GUARD = threading.Lock()
_LOCK_REGISTRY: weakref.WeakValueDictionary[tuple[str, int, int], Any] = (
    weakref.WeakValueDictionary()
)


def _path_identity(path: Path) -> FileIdentity:
    try:
        details = path.lstat()
    except FileNotFoundError as error:
        raise RuntimeContainmentError(f"database disappeared: {path}") from error
    if not stat.S_ISREG(details.st_mode):
        raise RuntimeContainmentError(f"database is not a regular file: {path}")
    return FileIdentity(details.st_dev, details.st_ino)


def _database_serialization_lock(
    path: Path,
    expected_identity: FileIdentity | None = None,
) -> threading.RLock:
    """Return one weakly registered process lock for a canonical database inode."""
    before = _path_identity(path)
    if expected_identity is not None and before != expected_identity:
        raise RuntimeContainmentError("database identity changed before lock creation")
    canonical = path.resolve(strict=True)
    if _path_identity(canonical) != before:
        raise RuntimeContainmentError("database canonical identity is inconsistent")
    key = (str(canonical), before.device, before.inode)
    with _LOCK_REGISTRY_GUARD:
        lock = _LOCK_REGISTRY.get(key)
        if lock is None:
            lock = threading.RLock()
            _LOCK_REGISTRY[key] = lock
    after = _path_identity(path)
    if after != before or path.resolve(strict=True) != canonical:
        raise RuntimeContainmentError("database identity changed during lock creation")
    return lock


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _json(value: Any) -> str:
    _reject_credential_text(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _reject_credential_text(value: Any) -> None:
    if isinstance(value, Mapping):
        for child in value.values():
            _reject_credential_text(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_credential_text(child)
    elif isinstance(value, str) and _CREDENTIAL_ASSIGNMENT.search(value):
        raise CredentialDataError("credential-like free text is forbidden")


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a non-secret stable identifier")
    _reject_credential_text(value)
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a non-secret stable identifier")
    return value


def _free_text(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 1000:
        raise ValueError(f"{field} must be text no longer than 1000 characters")
    _reject_credential_text(value)
    return value


def _positive_attempt(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("attempt must be a positive integer")
    return value


def _setting_value(key: SettingKey, value: bool | int) -> bool | int:
    if key is SettingKey.CONTROLLER_ENABLED:
        if type(value) is not bool:
            raise TypeError(f"{key.value} must be bool")
        return value
    if type(value) is not int:
        raise TypeError(f"{key.value} must be int")
    bounds = {
        SettingKey.MAX_CONCURRENT_WORKERS: (1, 15),
        SettingKey.WORKER_START_TIMEOUT_SECONDS: (1, 300),
        SettingKey.DEFAULT_PRIORITY: (-100, 100),
    }
    minimum, maximum = bounds[key]
    if not minimum <= value <= maximum:
        raise ValueError(f"{key.value} must be between {minimum} and {maximum}")
    return value


def _split_sql(script: str) -> Iterator[str]:
    statement = ""
    for line in script.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            if statement.strip():
                yield statement
            statement = ""
    if statement.strip():
        raise StoreError("incomplete SQL migration")


class RigStore:
    """The single writable store used by the controller.

    Every connection enables foreign keys, WAL, synchronous FULL, and a finite
    busy timeout. Multi-row commands use ``BEGIN IMMEDIATE`` so ownership races
    resolve through a database uniqueness constraint rather than a check/write
    gap. A private reentrant lock orders in-process transactions and cockpit
    snapshots; it complements rather than replaces rigd's inter-process lock.
    """

    def __init__(self, runtime: PrivateRuntimeDirectory, *, busy_timeout_ms: int = 5000):
        if busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be non-negative")
        self.runtime = runtime
        self.path = runtime.prepare()
        self._database_identity = runtime.database_identity()
        self.busy_timeout_ms = busy_timeout_ms
        self._daemon_connection: sqlite3.Connection | None = None
        self._daemon_connection_lease: _AuthorityLease | None = None
        self._serialization_lock = _database_serialization_lock(
            self.path, self._database_identity
        )
        self._event_condition = threading.Condition()
        self._committed_event_sequence = 0
        self._event_feed_closed = False
        self.runtime.assert_open_identity(self._database_identity)

    @classmethod
    def _open_provisioned(
        cls,
        runtime: PrivateRuntimeDirectory,
        *,
        service_uid: int,
        busy_timeout_ms: int = 5000,
    ) -> "RigStore":
        """Open already-provisioned service state without creating or repairing it."""
        if busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be non-negative")
        store = object.__new__(cls)
        store.runtime = runtime
        store.path = runtime.database
        store._database_identity = runtime.validate_provisioned(service_uid)
        store.busy_timeout_ms = busy_timeout_ms
        store._daemon_connection = None
        store._daemon_connection_lease = None
        store._serialization_lock = _database_serialization_lock(
            store.path, store._database_identity
        )
        store._event_condition = threading.Condition()
        store._committed_event_sequence = 0
        store._event_feed_closed = False
        store.runtime.assert_open_identity(store._database_identity)
        return store

    @classmethod
    def at(
        cls,
        database: Path,
        *,
        approved_root: Path,
        busy_timeout_ms: int = 5000,
    ) -> "RigStore":
        """Construct a store from an explicit database path."""
        return cls(
            PrivateRuntimeDirectory(database.parent, approved_root, database.name),
            busy_timeout_ms=busy_timeout_ms,
        )

    def initialize(self) -> None:
        """Configure the database and atomically apply packaged migrations."""
        with self._serialization_lock, closing(self._connect()) as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS schema_migrations (
                       version TEXT PRIMARY KEY,
                       checksum TEXT NOT NULL,
                       applied_at TEXT NOT NULL
                   ) STRICT"""
            )
            migration_root = resources.files("oc_rig.store.migrations")
            migrations = sorted(
                (item for item in migration_root.iterdir() if item.name.endswith(".sql")),
                key=lambda item: item.name,
            )
            applied = dict(
                connection.execute("SELECT version, checksum FROM schema_migrations")
            )
            for migration in migrations:
                script = migration.read_text(encoding="utf-8")
                checksum = hashlib.sha256(script.encode("utf-8")).hexdigest()
                if migration.name in applied:
                    if applied[migration.name] != checksum:
                        raise StoreError(
                            f"applied migration was modified: {migration.name}"
                        )
                    continue
                connection.execute("BEGIN IMMEDIATE")
                try:
                    for statement in _split_sql(script):
                        connection.execute(statement)
                    connection.execute(
                        """INSERT INTO schema_migrations(version, checksum, applied_at)
                           VALUES (?, ?, ?)""",
                        (migration.name, checksum, _utc_now()),
                    )
                except BaseException:
                    connection.rollback()
                    raise
                else:
                    connection.commit()
            self._checkpoint_wal(connection)
            self._publish_event_sequence(self._event_sequence(connection))
        self.runtime.secure_database_file()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """Open an internal atomic transaction; raw writes are not public API."""
        with self._serialization_lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                self._checkpoint_wal(connection)
                raise
            else:
                connection.commit()
                self._publish_event_sequence(self._event_sequence(connection))
                self._checkpoint_wal(connection)

    @contextmanager
    def _daemon_transaction(
        self, authority: _DaemonAuthority
    ) -> Iterator[sqlite3.Connection]:
        """Open one DB-authorized transaction held by the exclusive rigd owner."""
        if not isinstance(authority, _DaemonAuthority):
            raise DaemonAuthorityError("daemon authority is required")
        with self._serialization_lock:
            lease = authority._acquire_lease_locked(self)
            connection = self._daemon_connection
            owns_connection = connection is None
            try:
                if connection is None:
                    connection = self._connect()
                connection.execute("BEGIN IMMEDIATE")
                try:
                    yield connection
                except BaseException:
                    connection.rollback()
                    self._checkpoint_wal(connection)
                    raise
                else:
                    connection.commit()
                    self._publish_event_sequence(self._event_sequence(connection))
                    self._checkpoint_wal(connection)
            finally:
                try:
                    if owns_connection and connection is not None:
                        connection.close()
                finally:
                    lease.close()

    def _open_daemon_connection(self, authority: _DaemonAuthority) -> None:
        """Open the one persistent rigd connection before accepting requests."""
        if not isinstance(authority, _DaemonAuthority):
            raise DaemonAuthorityError("daemon authority is required")
        with self._serialization_lock:
            if self._daemon_connection is not None:
                raise DaemonAuthorityError("daemon database connection is already open")
            lease = authority._acquire_lease_locked(self)
            try:
                connection = self._connect(check_same_thread=False)
            except BaseException:
                lease.close()
                raise
            self._daemon_connection = connection
            self._daemon_connection_lease = lease

    def _close_daemon_connection(self) -> None:
        with self._serialization_lock:
            connection, self._daemon_connection = self._daemon_connection, None
            lease, self._daemon_connection_lease = (
                self._daemon_connection_lease,
                None,
            )
            try:
                if connection is not None:
                    connection.close()
            finally:
                if lease is not None:
                    lease.close()

    def _checkpoint_wal(self, connection: sqlite3.Connection) -> None:
        """Checkpoint after a bounded lock handoff and verify truncation."""
        if connection.in_transaction:
            raise StoreQuiescenceError(
                "WAL checkpoint requires a completed mutation transaction"
            )
        prior_timeout = connection.execute("PRAGMA busy_timeout").fetchone()
        if prior_timeout is None or type(prior_timeout[0]) is not int:
            raise StoreQuiescenceError("SQLite busy timeout is unavailable")
        checkpoint: tuple[object, ...] | None = None
        failure: BaseException | None = None
        try:
            checkpoint_timeout = min(
                prior_timeout[0], _CHECKPOINT_LOCK_HANDOFF_MS
            )
            connection.execute(f"PRAGMA busy_timeout = {checkpoint_timeout:d}")
            row = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            checkpoint = None if row is None else tuple(row)
        except BaseException as error:
            failure = error
        finally:
            try:
                connection.execute(f"PRAGMA busy_timeout = {prior_timeout[0]:d}")
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None:
            raise StoreQuiescenceError(
                "WAL checkpoint and truncation failed"
            ) from failure
        if checkpoint != (0, 0, 0):
            raise StoreQuiescenceError(
                "WAL checkpoint did not establish a quiescent truncated baseline"
            )

    @contextmanager
    def _read_transaction(self) -> Iterator[sqlite3.Connection]:
        """Open one in-process serialized read transaction."""
        with self._serialization_lock, closing(self._connect()) as connection:
            connection.execute("BEGIN")
            try:
                yield connection
            finally:
                connection.rollback()

    @contextmanager
    def _daemon_read_transaction(
        self, authority: _DaemonAuthority
    ) -> Iterator[sqlite3.Connection]:
        """Use the existing serialized rigd connection for one read snapshot."""
        if not isinstance(authority, _DaemonAuthority):
            raise DaemonAuthorityError("daemon authority is required")
        with self._serialization_lock:
            lease = authority._acquire_lease_locked(self)
            try:
                connection = self._daemon_connection
                if connection is None:
                    raise DaemonAuthorityError(
                        "persistent daemon database connection is absent"
                    )
                connection.execute("BEGIN")
                try:
                    yield connection
                finally:
                    connection.rollback()
            finally:
                lease.close()

    def set_setting(self, key: SettingKey, value: bool | int) -> None:
        if not isinstance(key, SettingKey):
            raise TypeError("key must be a SettingKey")
        validated_value = _setting_value(key, value)
        now = _utc_now()
        with self._transaction() as connection:
            connection.execute(
                """INSERT INTO settings(key, value_json, updated_at) VALUES (?, ?, ?)
                   ON CONFLICT(key) DO UPDATE
                   SET value_json = excluded.value_json,
                       updated_at = excluded.updated_at""",
                (key.value, _json(validated_value), now),
            )

    def create_operation(
        self,
        operation_id: str,
        kind: OperationKind,
        *,
        idempotency_key: str | None = None,
        controller_run_id: str | None = None,
    ) -> None:
        if not isinstance(kind, OperationKind):
            raise TypeError("kind must be an OperationKind")
        _identifier(operation_id, "operation_id")
        if idempotency_key is not None:
            _identifier(idempotency_key, "idempotency_key")
        if controller_run_id is not None:
            _identifier(controller_run_id, "controller_run_id")
        now = _utc_now()
        with self._transaction() as connection:
            self._create_operation(
                connection,
                operation_id,
                kind,
                idempotency_key=idempotency_key,
                controller_run_id=controller_run_id,
                now=now,
            )

    def _create_operation(
        self,
        connection: sqlite3.Connection,
        operation_id: str,
        kind: OperationKind,
        *,
        idempotency_key: str | None,
        controller_run_id: str | None,
        now: str,
    ) -> None:
        connection.execute(
            """INSERT INTO operations(
                   id, kind, idempotency_key, state, controller_run_id,
                   created_at, updated_at
               ) VALUES (?, ?, ?, 'pending', ?, ?, ?)""",
            (operation_id, kind.value, idempotency_key, controller_run_id, now, now),
        )
        self._append_event(
            connection,
            "operation",
            operation_id,
            "operation.created",
            {"kind": kind.value, "state": OperationState.PENDING.value},
            now,
        )

    def transition_operation(
        self,
        operation_id: str,
        target: OperationState,
        *,
        error_summary: str | None = None,
    ) -> None:
        if not isinstance(target, OperationState):
            raise TypeError("target must be an OperationState")
        _identifier(operation_id, "operation_id")
        _free_text(error_summary, "error_summary")
        now = _utc_now()
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT state FROM operations WHERE id = ?", (operation_id,)
            ).fetchone()
            if row is None:
                raise KeyError(operation_id)
            current = OperationState(row[0])
            require_transition(current, target)
            finished_at = (
                now
                if target
                in {OperationState.SUCCEEDED, OperationState.FAILED, OperationState.CANCELLED}
                else None
            )
            connection.execute(
                """UPDATE operations
                   SET state = ?, updated_at = ?, finished_at = ?, error_summary = ?
                   WHERE id = ?""",
                (target.value, now, finished_at, error_summary, operation_id),
            )
            self._append_event(
                connection,
                "operation",
                operation_id,
                "operation.state_changed",
                {"from": current.value, "to": target.value},
                now,
            )

    def claim_scope(
        self,
        claim_id: str,
        scope_key: str,
        operation_id: str,
        *,
        attempt: int,
        fence_token: str,
        idempotency_key: str,
    ) -> OwnershipReceipt:
        raise DaemonAuthorityError("scope claims must be created through rigd")

    def _claim_scope(
        self,
        connection: sqlite3.Connection,
        claim_id: str,
        scope_key: str,
        operation_id: str,
        *,
        attempt: int,
        fence_token: str,
        idempotency_key: str,
    ) -> OwnershipReceipt:
        for value, field in (
            (claim_id, "claim_id"),
            (scope_key, "scope_key"),
            (operation_id, "operation_id"),
            (fence_token, "fence_token"),
            (idempotency_key, "idempotency_key"),
        ):
            _identifier(value, field)
        _positive_attempt(attempt)
        now = _utc_now()
        existing = connection.execute(
            """SELECT id, scope_key, owner_operation_id, attempt, fence_token
               FROM scope_claims WHERE idempotency_key = ?""",
            (idempotency_key,),
        ).fetchone()
        if existing is not None:
            if tuple(existing[1:]) != (scope_key, operation_id, attempt, fence_token):
                raise IdempotencyConflict(idempotency_key)
            return OwnershipReceipt(existing[0], existing[2], existing[3], existing[4])
        try:
            connection.execute(
                """INSERT INTO scope_claims(
                       id, scope_key, owner_operation_id, state, claimed_at,
                       attempt, fence_token, idempotency_key
                   ) VALUES (?, ?, ?, 'active', ?, ?, ?, ?)""",
                (
                    claim_id,
                    scope_key,
                    operation_id,
                    now,
                    attempt,
                    fence_token,
                    idempotency_key,
                ),
            )
        except sqlite3.IntegrityError as error:
            if "scope_claims.scope_key" in str(error):
                raise OwnershipConflict(f"scope already claimed: {scope_key}") from error
            raise
        self._append_event(
            connection,
            "scope_claim",
            claim_id,
            "scope.claimed",
            {"owner_id": operation_id, "attempt": attempt, "fence": fence_token},
            now,
        )
        return OwnershipReceipt(claim_id, operation_id, attempt, fence_token)

    def release_scope(
        self,
        claim_id: str,
        operation_id: str,
        *,
        attempt: int,
        fence_token: str,
    ) -> bool:
        raise DaemonAuthorityError("scope claims must be released through rigd")

    def _release_scope(
        self,
        connection: sqlite3.Connection,
        claim_id: str,
        operation_id: str,
        *,
        attempt: int,
        fence_token: str,
    ) -> bool:
        for value, field in (
            (claim_id, "claim_id"),
            (operation_id, "operation_id"),
            (fence_token, "fence_token"),
        ):
            _identifier(value, field)
        _positive_attempt(attempt)
        now = _utc_now()
        cursor = connection.execute(
            """UPDATE scope_claims
               SET state = 'released', released_at = ?
               WHERE id = ? AND owner_operation_id = ? AND attempt = ?
                 AND fence_token = ? AND state = 'active'""",
            (now, claim_id, operation_id, attempt, fence_token),
        )
        if cursor.rowcount != 1:
            return False
        self._append_event(
            connection,
            "scope_claim",
            claim_id,
            "scope.released",
            {"owner_id": operation_id, "attempt": attempt, "fence": fence_token},
            now,
        )
        return True

    def bind_session(
        self,
        binding_id: str,
        operation_id: str,
        session_ref: str,
        *,
        attempt: int,
        fence_token: str,
        idempotency_key: str,
    ) -> OwnershipReceipt:
        for value, field in (
            (binding_id, "binding_id"),
            (operation_id, "operation_id"),
            (session_ref, "session_ref"),
            (fence_token, "fence_token"),
            (idempotency_key, "idempotency_key"),
        ):
            _identifier(value, field)
        _positive_attempt(attempt)
        now = _utc_now()
        with self._transaction() as connection:
            existing = connection.execute(
                """SELECT id, operation_id, session_ref, attempt, fence_token
                   FROM session_bindings WHERE idempotency_key = ?""",
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                if tuple(existing[1:]) != (operation_id, session_ref, attempt, fence_token):
                    raise IdempotencyConflict(idempotency_key)
                return OwnershipReceipt(existing[0], existing[1], existing[3], existing[4])
            try:
                connection.execute(
                    """INSERT INTO session_bindings(
                           id, operation_id, session_ref, state, bound_at,
                           attempt, fence_token, idempotency_key
                       ) VALUES (?, ?, ?, 'active', ?, ?, ?, ?)""",
                    (
                        binding_id,
                        operation_id,
                        session_ref,
                        now,
                        attempt,
                        fence_token,
                        idempotency_key,
                    ),
                )
            except sqlite3.IntegrityError as error:
                message = str(error)
                if (
                    "session_bindings.session_ref" in message
                    or "session_bindings.operation_id" in message
                ):
                    raise OwnershipConflict(
                        f"session or operation already has an active binding: {session_ref}"
                    ) from error
                raise
            self._append_event(
                connection,
                "session_binding",
                binding_id,
                "session.bound",
                {
                    "owner_id": operation_id,
                    "attempt": attempt,
                    "fence": fence_token,
                    "session_ref": session_ref,
                },
                now,
            )
            return OwnershipReceipt(binding_id, operation_id, attempt, fence_token)

    def release_session(
        self,
        binding_id: str,
        operation_id: str,
        *,
        attempt: int,
        fence_token: str,
    ) -> bool:
        for value, field in (
            (binding_id, "binding_id"),
            (operation_id, "operation_id"),
            (fence_token, "fence_token"),
        ):
            _identifier(value, field)
        _positive_attempt(attempt)
        now = _utc_now()
        with self._transaction() as connection:
            cursor = connection.execute(
                """UPDATE session_bindings
                   SET state = 'released', released_at = ?
                   WHERE id = ? AND operation_id = ? AND attempt = ?
                     AND fence_token = ? AND state = 'active'""",
                (now, binding_id, operation_id, attempt, fence_token),
            )
            if cursor.rowcount != 1:
                return False
            self._append_event(
                connection,
                "session_binding",
                binding_id,
                "session.released",
                {"owner_id": operation_id, "attempt": attempt, "fence": fence_token},
                now,
            )
            return True

    def enqueue_work(
        self,
        work_id: str,
        kind: WorkKind,
        *,
        idempotency_key: str,
        operation_id: str | None = None,
        priority: int = 0,
    ) -> int:
        """Durably enqueue work and return its stable FIFO sequence."""
        if not isinstance(kind, WorkKind):
            raise TypeError("kind must be a WorkKind")
        for value, field in (
            (work_id, "work_id"),
            (idempotency_key, "idempotency_key"),
        ):
            _identifier(value, field)
        if operation_id is not None:
            _identifier(operation_id, "operation_id")
        if type(priority) is not int or not -100 <= priority <= 100:
            raise ValueError("priority must be an integer between -100 and 100")
        with self._transaction() as connection:
            return self._enqueue_work(
                connection,
                work_id,
                kind,
                idempotency_key=idempotency_key,
                operation_id=operation_id,
                priority=priority,
                now=_utc_now(),
            )

    def _enqueue_work(
        self,
        connection: sqlite3.Connection,
        work_id: str,
        kind: WorkKind,
        *,
        idempotency_key: str,
        operation_id: str | None,
        priority: int,
        now: str,
    ) -> int:
        existing = connection.execute(
            """SELECT sequence, id, kind, operation_id, priority
               FROM work_queue WHERE idempotency_key = ?""",
            (idempotency_key,),
        ).fetchone()
        if existing is not None:
            if tuple(existing[1:]) != (
                work_id,
                kind.value,
                operation_id,
                priority,
            ):
                raise IdempotencyConflict(idempotency_key)
            return int(existing[0])
        cursor = connection.execute(
            """INSERT INTO work_queue(
                   id, operation_id, idempotency_key, kind, priority,
                   state, enqueued_at
               ) VALUES (?, ?, ?, ?, ?, 'queued', ?)""",
            (work_id, operation_id, idempotency_key, kind.value, priority, now),
        )
        sequence = int(cursor.lastrowid)
        self._append_event(
            connection,
            "work",
            work_id,
            "work.enqueued",
            {"kind": kind.value, "priority": priority, "sequence": sequence},
            now,
        )
        return sequence

    def reserve_work(self, owner_id: str, *, fence_token: str) -> WorkReservation | None:
        """Claim the next ready item by priority and committed FIFO sequence."""
        _identifier(owner_id, "owner_id")
        _identifier(fence_token, "fence_token")
        now = _utc_now()
        with self._transaction() as connection:
            row = connection.execute(
                """SELECT sequence, id, operation_id, kind, priority, attempt
                   FROM work_queue
                   WHERE state = 'queued'
                   ORDER BY priority DESC, sequence ASC
                   LIMIT 1"""
            ).fetchone()
            if row is None:
                return None
            attempt = int(row[5]) + 1
            cursor = connection.execute(
                """UPDATE work_queue
                   SET state = 'claimed', owner_id = ?, fence_token = ?,
                       attempt = ?, claimed_at = ?
                   WHERE sequence = ? AND state = 'queued'""",
                (owner_id, fence_token, attempt, now, row[0]),
            )
            if cursor.rowcount != 1:
                raise OwnershipConflict(f"work was claimed concurrently: {row[1]}")
            self._append_event(
                connection,
                "work",
                row[1],
                "work.claimed",
                {"owner_id": owner_id, "attempt": attempt, "fence": fence_token},
                now,
            )
            return WorkReservation(
                id=row[1],
                sequence=int(row[0]),
                operation_id=row[2],
                kind=WorkKind(row[3]),
                priority=int(row[4]),
                owner_id=owner_id,
                attempt=attempt,
                fence_token=fence_token,
            )

    def reopen_work(
        self,
        work_id: str,
        owner_id: str,
        *,
        attempt: int,
        fence_token: str,
    ) -> bool:
        """Return exactly the matching interrupted claim to its FIFO position."""
        for value, field in (
            (work_id, "work_id"),
            (owner_id, "owner_id"),
            (fence_token, "fence_token"),
        ):
            _identifier(value, field)
        _positive_attempt(attempt)
        now = _utc_now()
        with self._transaction() as connection:
            cursor = connection.execute(
                """UPDATE work_queue
                   SET state = 'queued', owner_id = NULL, fence_token = NULL,
                       claimed_at = NULL
                   WHERE id = ? AND owner_id = ? AND attempt = ?
                     AND fence_token = ? AND state = 'claimed'""",
                (work_id, owner_id, attempt, fence_token),
            )
            if cursor.rowcount != 1:
                return False
            self._append_event(
                connection,
                "work",
                work_id,
                "work.reopened",
                {"owner_id": owner_id, "attempt": attempt, "fence": fence_token},
                now,
            )
            return True

    def complete_work(
        self,
        work_id: str,
        owner_id: str,
        *,
        attempt: int,
        fence_token: str,
    ) -> bool:
        """Complete only the exact active fenced work claim."""
        for value, field in (
            (work_id, "work_id"),
            (owner_id, "owner_id"),
            (fence_token, "fence_token"),
        ):
            _identifier(value, field)
        _positive_attempt(attempt)
        now = _utc_now()
        with self._transaction() as connection:
            cursor = connection.execute(
                """UPDATE work_queue
                   SET state = 'completed', finished_at = ?
                   WHERE id = ? AND owner_id = ? AND attempt = ?
                     AND fence_token = ? AND state = 'claimed'""",
                (now, work_id, owner_id, attempt, fence_token),
            )
            if cursor.rowcount != 1:
                return False
            self._append_event(
                connection,
                "work",
                work_id,
                "work.completed",
                {"owner_id": owner_id, "attempt": attempt, "fence": fence_token},
                now,
            )
            return True

    def _append_event(
        self,
        connection: sqlite3.Connection,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        payload: Any,
        occurred_at: str,
        *,
        event_id: str | None = None,
    ) -> int:
        cursor = connection.execute(
            """INSERT INTO events(
                   event_id, aggregate_type, aggregate_id, event_type,
                   payload_json, occurred_at
               ) VALUES (?, ?, ?, ?, ?, ?)""",
            (
                event_id or str(uuid.uuid4()),
                aggregate_type,
                aggregate_id,
                event_type,
                _json(payload),
                occurred_at,
            ),
        )
        return int(cursor.lastrowid)

    @staticmethod
    def _event_sequence(connection: sqlite3.Connection) -> int:
        row = connection.execute(
            "SELECT coalesce(max(rowid), 0) FROM events"
        ).fetchone()
        if row is None or type(row[0]) is not int or row[0] < 0:
            raise StoreError("committed event sequence is unavailable")
        return row[0]

    def _publish_event_sequence(self, sequence: int) -> None:
        if type(sequence) is not int or not 0 <= sequence <= 2**63 - 1:
            raise StoreError("committed event sequence is invalid")
        with self._event_condition:
            if sequence > self._committed_event_sequence:
                self._committed_event_sequence = sequence
                self._event_condition.notify_all()

    def _wait_for_event_sequence(self, after_sequence: int) -> int:
        """Block until a committed event advances beyond ``after_sequence``."""
        if (
            type(after_sequence) is not int
            or not 0 <= after_sequence <= 2**63 - 1
        ):
            raise ValueError("event sequence must be a non-negative signed-64 integer")
        with self._event_condition:
            while (
                self._committed_event_sequence <= after_sequence
                and not self._event_feed_closed
            ):
                self._event_condition.wait()
            if self._event_feed_closed:
                raise StoreError("event feed is closed")
            return self._committed_event_sequence

    def _close_event_feed(self) -> None:
        with self._event_condition:
            self._event_feed_closed = True
            self._event_condition.notify_all()

    def _connect(self, *, check_same_thread: bool = True) -> sqlite3.Connection:
        before_open = self.runtime.assert_open_identity(self._database_identity)
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
            check_same_thread=check_same_thread,
        )
        try:
            after_open = self.runtime.assert_open_identity(self._database_identity)
            if after_open != before_open:
                raise StoreError("database inode changed across guarded open")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms:d}")
            self.runtime.assert_open_identity(self._database_identity)
        except BaseException:
            connection.close()
            raise
        return connection

    def configuration(self) -> dict[str, Any]:
        """Return effective safety pragmas for diagnostics and tests."""
        with self._serialization_lock, closing(self._connect()) as connection:
            return {
                "foreign_keys": connection.execute("PRAGMA foreign_keys").fetchone()[0],
                "journal_mode": connection.execute("PRAGMA journal_mode").fetchone()[0],
                "synchronous": connection.execute("PRAGMA synchronous").fetchone()[0],
                "busy_timeout": connection.execute("PRAGMA busy_timeout").fetchone()[0],
            }
