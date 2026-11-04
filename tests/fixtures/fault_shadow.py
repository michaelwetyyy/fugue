"""Reusable synthetic-only helpers for the milestone-nine fault exercise."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from collections.abc import Callable
from contextlib import closing
from importlib import resources
from pathlib import Path

from oc_rig.store import PrivateRuntimeDirectory, RigStore
from oc_rig.store.database import _split_sql
from tests.fixtures.durable_daemon import ModeledDurableDaemon


EXPECTED_SLOT_TOPOLOGY = (
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


def hard_crash(daemon: ModeledDurableDaemon) -> int:
    """Kill one isolated fixture daemon without running its cleanup path."""
    process = daemon.process
    if process is None or process.poll() is not None:
        raise RuntimeError("synthetic daemon is not running")
    pid = process.pid
    process.kill()
    process.wait(timeout=5)
    if process.stdin is not None:
        process.stdin.close()
    if process.stdout is not None:
        process.stdout.close()
    daemon.process = None
    return pid


def apply_migrations_with_restarts(
    runtime: PrivateRuntimeDirectory,
    *,
    after_migration: Callable[[str, Path], None] | None = None,
) -> tuple[str, ...]:
    """Apply each packaged migration atomically, closing SQLite after every step."""
    store = RigStore(runtime)
    migration_root = resources.files("oc_rig.store.migrations")
    migrations = sorted(
        (item for item in migration_root.iterdir() if item.name.endswith(".sql")),
        key=lambda item: item.name,
    )
    with closing(sqlite3.connect(store.path)) as connection:
        connection.execute(
            """CREATE TABLE schema_migrations (
                   version TEXT PRIMARY KEY,
                   checksum TEXT NOT NULL,
                   applied_at TEXT NOT NULL
               ) STRICT"""
        )
        connection.commit()

    applied: list[str] = []
    for migration in migrations:
        script = migration.read_text(encoding="utf-8")
        checksum = hashlib.sha256(script.encode("utf-8")).hexdigest()
        with closing(sqlite3.connect(store.path, isolation_level=None)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE")
            try:
                for statement in _split_sql(script):
                    connection.execute(statement)
                connection.execute(
                    """INSERT INTO schema_migrations(version, checksum, applied_at)
                       VALUES (?, ?, 'synthetic-migration-restart')""",
                    (migration.name, checksum),
                )
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()
        runtime.secure_database_file()
        applied.append(migration.name)
        if after_migration is not None:
            after_migration(migration.name, store.path)

        # A new connection and a real integrity pass model the next process start.
        with closing(sqlite3.connect(store.path)) as restarted:
            restarted.execute("PRAGMA foreign_keys = ON")
            if restarted.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise AssertionError(f"migration restart was not integral: {migration.name}")
            if restarted.execute("PRAGMA foreign_key_check").fetchall():
                raise AssertionError(
                    f"migration restart violated foreign keys: {migration.name}"
                )
            recorded = restarted.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
            if recorded != [(version,) for version in applied]:
                raise AssertionError(f"migration restart lost history: {migration.name}")
    return tuple(applied)


def process_is_gone(pid: int) -> bool:
    """Return whether a synthetic child PID can no longer be signalled."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False
