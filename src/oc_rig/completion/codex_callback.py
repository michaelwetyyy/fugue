"""Private local ``codex queue`` completion callback boundary.

The durable completion service owns delivery state.  This adapter performs one
already-journalled attempt and reports only what the local process boundary can
prove; it never retries an ambiguous attempt.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import sqlite3
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from oc_rig.completion.models import CompletionOutcome


_THREAD_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_CALLBACK_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DURABLE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@*?+\-]{0,255}\Z")


def validate_codex_thread_id(value: object) -> str:
    if not isinstance(value, str) or not _THREAD_ID.fullmatch(value):
        raise ValueError("codex_thread_id must be a canonical lowercase UUID")
    return value


def parse_local_codex_return_route(value: object) -> str | None:
    """Parse the private route metadata carried beside, never inside, work content."""

    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != {"kind", "thread_id"}:
        raise ValueError("return_route must contain exactly kind and thread_id")
    if value["kind"] != "local_codex":
        raise ValueError("return_route kind is unsupported")
    return validate_codex_thread_id(value["thread_id"])


class CallbackDisposition(StrEnum):
    DELIVERED = "delivered"
    TRANSIENT = "transient"
    DETERMINISTIC = "deterministic"
    PERMISSION = "permission"
    POLICY = "policy"
    DELIVERY_UNKNOWN = "delivery_unknown"


@dataclass(frozen=True, slots=True)
class CallbackResult:
    disposition: CallbackDisposition
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, CallbackDisposition):
            raise TypeError("callback disposition must be typed")
        if not isinstance(self.reason, str) or not self.reason:
            raise ValueError("callback result requires a reason")


@dataclass(frozen=True, slots=True)
class CallbackDeliveryProof:
    proven: bool
    reason: str

    def __post_init__(self) -> None:
        if type(self.proven) is not bool:
            raise TypeError("callback proof must be boolean")
        if not isinstance(self.reason, str) or not self.reason:
            raise ValueError("callback proof requires a reason")


@dataclass(frozen=True, slots=True)
class CodexCallbackRequest:
    delivery_key: str
    thread_id: str
    work_id: str
    outcome: str
    result_ref: str

    def __post_init__(self) -> None:
        for value, field in (
            (self.delivery_key, "delivery_key"),
            (self.result_ref, "result_ref"),
        ):
            if not isinstance(value, str) or not _CALLBACK_IDENTIFIER.fullmatch(value):
                raise ValueError(f"{field} is invalid")
        if not isinstance(self.work_id, str) or not _DURABLE_IDENTIFIER.fullmatch(
            self.work_id
        ):
            raise ValueError("work_id is invalid")
        validate_codex_thread_id(self.thread_id)
        if self.outcome not in {item.value for item in CompletionOutcome}:
            raise ValueError("outcome is invalid")

    def message(self) -> str:
        return (
            f"[OpenCode completion nudge] {self.work_id} {self.outcome}. "
            f"Read durable result {self.result_ref} and continue the exact workflow; "
            "do not poll. "
            f"[delivery:{self.delivery_key}]"
        )


@dataclass(frozen=True, slots=True)
class CodexQueueConfig:
    executable: Path
    home: Path
    codex_home: Path
    timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        for value, field in (
            (self.executable, "executable"),
            (self.home, "home"),
            (self.codex_home, "codex_home"),
        ):
            if not isinstance(value, Path) or not value.is_absolute():
                raise ValueError(f"{field} must be an absolute path")
        if not isinstance(self.timeout_seconds, (int, float)) or not (
            0 < self.timeout_seconds <= 60
        ):
            raise ValueError("timeout_seconds must be in (0, 60]")


@dataclass(frozen=True, slots=True)
class _ExecutableIdentity:
    device: int
    inode: int
    uid: int
    mode: int
    size: int
    digest: str


def _executable_identity(path: Path) -> _ExecutableIdentity:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise PermissionError("O_NOFOLLOW is required for the Codex executable")
    opened = os.open(path, os.O_RDONLY | no_follow)
    try:
        facts = os.fstat(opened)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_nlink != 1
            or facts.st_uid not in {0, os.geteuid()}
            or facts.st_mode & 0o022
            or not facts.st_mode & stat.S_IXUSR
        ):
            raise PermissionError("codex executable failed private identity policy")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(opened, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        return _ExecutableIdentity(
            facts.st_dev,
            facts.st_ino,
            facts.st_uid,
            stat.S_IMODE(facts.st_mode),
            facts.st_size,
            digest.hexdigest(),
        )
    finally:
        os.close(opened)


def _private_directory(path: Path, field: str) -> None:
    facts = path.lstat()
    if (
        not stat.S_ISDIR(facts.st_mode)
        or facts.st_uid != os.geteuid()
        or facts.st_mode & 0o022
        or not facts.st_mode & stat.S_IXUSR
    ):
        raise PermissionError(f"{field} failed local-user identity policy")


def _private_history_file(path: Path) -> tuple[int, int, int, int]:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise PermissionError("O_NOFOLLOW is required for Codex history")
    descriptor = os.open(path, os.O_RDONLY | no_follow)
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_nlink != 1
            or facts.st_uid != os.geteuid()
            or facts.st_mode & 0o022
        ):
            raise PermissionError("Codex history failed local-user identity policy")
        return (facts.st_dev, facts.st_ino, facts.st_uid, stat.S_IMODE(facts.st_mode))
    finally:
        os.close(descriptor)


class LocalCodexQueueAdapter:
    """One-shot local callback adapter plus read-only durable delivery proof."""

    __slots__ = ("_config", "_identity")

    def __init__(self, config: CodexQueueConfig):
        if not isinstance(config, CodexQueueConfig):
            raise TypeError("exact CodexQueueConfig required")
        for directory, field in ((config.home, "home"), (config.codex_home, "codex_home")):
            _private_directory(directory, field)
        self._config = config
        self._identity = _executable_identity(config.executable)

    def deliver(self, request: CodexCallbackRequest) -> CallbackResult:
        if not isinstance(request, CodexCallbackRequest):
            return CallbackResult(CallbackDisposition.POLICY, "request_invalid")
        try:
            if _executable_identity(self._config.executable) != self._identity:
                return CallbackResult(
                    CallbackDisposition.POLICY, "codex_executable_identity_changed"
                )
        except FileNotFoundError:
            return CallbackResult(CallbackDisposition.DETERMINISTIC, "codex_missing")
        except PermissionError:
            return CallbackResult(CallbackDisposition.PERMISSION, "codex_not_executable")
        except OSError:
            return CallbackResult(
                CallbackDisposition.TRANSIENT, "codex_identity_check_failed"
            )
        environment = {
            "CODEX_HOME": str(self._config.codex_home),
            "HOME": str(self._config.home),
            "LANG": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
        }
        try:
            child = subprocess.Popen(
                [
                    str(self._config.executable),
                    "queue",
                    "--thread",
                    request.thread_id,
                    "--message",
                    request.message(),
                ],
                cwd=self._config.home,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
            )
        except FileNotFoundError:
            return CallbackResult(CallbackDisposition.DETERMINISTIC, "codex_missing")
        except PermissionError:
            return CallbackResult(CallbackDisposition.PERMISSION, "codex_not_executable")
        except OSError:
            return CallbackResult(CallbackDisposition.TRANSIENT, "codex_spawn_failed")
        try:
            return_code = child.wait(timeout=float(self._config.timeout_seconds))
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            return CallbackResult(CallbackDisposition.DELIVERY_UNKNOWN, "codex_timeout")
        if return_code == 0:
            return CallbackResult(CallbackDisposition.DELIVERED, "codex_acknowledged")
        return CallbackResult(
            CallbackDisposition.DELIVERY_UNKNOWN,
            f"codex_nonzero_exit_{return_code}",
        )

    def prove_delivery(self, request: CodexCallbackRequest) -> CallbackDeliveryProof:
        """Prove the exact callback entered the bound Codex thread without returning text."""

        if not isinstance(request, CodexCallbackRequest):
            return CallbackDeliveryProof(False, "request_invalid")
        try:
            if _executable_identity(self._config.executable) != self._identity:
                return CallbackDeliveryProof(False, "codex_executable_identity_changed")
        except (FileNotFoundError, PermissionError, OSError):
            return CallbackDeliveryProof(False, "codex_identity_unavailable")
        history = self._config.codex_home / "thread_history_1.sqlite"
        try:
            before = _private_history_file(history)
        except (FileNotFoundError, PermissionError, OSError):
            return CallbackDeliveryProof(False, "codex_history_unavailable")
        expected_columns = {
            "thread_items": {"thread_id", "turn_id", "item_id", "item_json", "item_type"},
            "thread_turns": {"thread_id", "turn_id", "first_user_item_id", "started_at"},
        }
        marker = f"[delivery:{request.delivery_key}]"
        matches = 0
        try:
            connection = sqlite3.connect(
                history.as_uri() + "?mode=ro", uri=True, timeout=1.0
            )
            try:
                connection.execute("PRAGMA query_only = ON")
                for table, required in expected_columns.items():
                    columns = {
                        str(row[1])
                        for row in connection.execute(f'PRAGMA table_info("{table}")')
                    }
                    if not required.issubset(columns):
                        return CallbackDeliveryProof(False, "codex_history_schema_invalid")
                rows = connection.execute(
                    """SELECT item.thread_id, item.turn_id, item.item_id, item.item_json
                       FROM thread_items AS item
                       WHERE item.thread_id = ? AND item.item_type = 'userMessage'
                         AND instr(item.item_json, ?) > 0
                       ORDER BY item.rollout_ordinal DESC LIMIT 3""",
                    (request.thread_id, marker),
                ).fetchall()
                for thread_id, turn_id, item_id, item_json in rows:
                    if (
                        type(thread_id) is not str
                        or type(turn_id) is not str
                        or type(item_id) is not str
                        or type(item_json) is not str
                        or len(item_json.encode("utf-8")) > 128 * 1024
                    ):
                        continue
                    try:
                        value = json.loads(item_json)
                    except (json.JSONDecodeError, UnicodeError):
                        continue
                    if type(value) is not dict or value.get("type") != "userMessage":
                        continue
                    if value.get("id") != item_id:
                        continue
                    content = value.get("content")
                    if type(content) is not list or len(content) != 1:
                        continue
                    part = content[0]
                    if (
                        type(part) is not dict
                        or part.get("type") != "text"
                        or part.get("text") != request.message()
                    ):
                        continue
                    turn = connection.execute(
                        """SELECT 1 FROM thread_turns
                           WHERE thread_id = ? AND turn_id = ?
                             AND first_user_item_id = ? AND started_at IS NOT NULL
                           LIMIT 2""",
                        (request.thread_id, turn_id, item_id),
                    ).fetchall()
                    if len(turn) == 1:
                        matches += 1
            finally:
                connection.close()
            after = _private_history_file(history)
        except (sqlite3.Error, OSError, PermissionError, UnicodeError):
            return CallbackDeliveryProof(False, "codex_history_unavailable")
        if after != before:
            return CallbackDeliveryProof(False, "codex_history_identity_changed")
        if matches == 1:
            return CallbackDeliveryProof(True, "codex_history_exact_message")
        if matches > 1:
            return CallbackDeliveryProof(False, "codex_history_proof_ambiguous")
        return CallbackDeliveryProof(False, "codex_history_proof_not_found")
