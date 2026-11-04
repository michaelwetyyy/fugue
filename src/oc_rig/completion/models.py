"""Immutable completion and callback delivery values."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath

MAX_FINAL_RESULT_BYTES = 48 * 1024
MAX_FUGUE_HANDOVER_BYTES = 24 * 1024
FUGUE_HANDOVER_SCHEMA = "fugue.handover/v1"
FUGUE_REVIEW_PROFILES = ("correctness", "security", "tests", "minimality")
_FUGUE_HANDOVER_KEYS = {
    "schema",
    "status",
    "summary",
    "changes",
    "reviews",
    "unresolved",
    "codex_actions",
}
_FUGUE_HANDOVER_STATUSES = {"ready", "attention", "failed"}
_MAX_HANDOVER_CHANGES = 32
_MAX_HANDOVER_ITEMS = 16
_MAX_HANDOVER_SUMMARY_BYTES = 4096
_MAX_HANDOVER_REVIEW_BYTES = 2048
_MAX_HANDOVER_ITEM_BYTES = 1024
_MAX_HANDOVER_DIFF_BYTES = 16 * 1024
_HUNK_HEADER = re.compile(
    r"@@ -[0-9]+(?:,[0-9]+)? \+[0-9]+(?:,[0-9]+)? @@(?: .*)?\Z"
)


class CompletionOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FugueHandoverInvalid(ValueError):
    """The model-authored compact Fugue handover failed its closed schema."""


def _bounded_text(value: object, *, maximum: int, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value.strip()):
        raise FugueHandoverInvalid("handover_text_invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise FugueHandoverInvalid("handover_text_invalid") from None
    if len(encoded) > maximum or "\x00" in value or any(
        ord(character) < 0x20 and character not in "\t\n\r" for character in value
    ):
        raise FugueHandoverInvalid("handover_text_invalid")
    return value


def _validate_diff_hunks(value: object) -> str:
    diff = _bounded_text(value, maximum=_MAX_HANDOVER_DIFF_BYTES)
    lines = diff.splitlines()
    if not lines or not _HUNK_HEADER.fullmatch(lines[0]):
        raise FugueHandoverInvalid("handover_change_diff_invalid")
    saw_change = False
    for line in lines[1:]:
        if _HUNK_HEADER.fullmatch(line):
            continue
        if line.startswith("\\ No newline at end of file"):
            continue
        if not line or line[0] not in {" ", "+", "-"}:
            raise FugueHandoverInvalid("handover_change_diff_invalid")
        if line[0] in {"+", "-"}:
            saw_change = True
    if not saw_change:
        raise FugueHandoverInvalid("handover_change_diff_invalid")
    return diff


def _bounded_text_list(value: object) -> tuple[str, ...]:
    if type(value) is not list or len(value) > _MAX_HANDOVER_ITEMS:
        raise FugueHandoverInvalid("handover_list_invalid")
    return tuple(
        _bounded_text(item, maximum=_MAX_HANDOVER_ITEM_BYTES)
        for item in value
    )


def parse_fugue_handover(value: object) -> dict[str, object]:
    """Validate the sole model-authored ``agent_task`` completion payload.

    The durable completion wrapper owns transport/result identity.  This parser
    validates only the compact PUBLIC/SANITIZED handover body and returns a
    detached ordinary dictionary suitable for local controller use.
    """

    if type(value) is not str:
        raise FugueHandoverInvalid("handover_missing")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise FugueHandoverInvalid("handover_invalid_utf8") from None
    if not 1 <= len(encoded) <= MAX_FUGUE_HANDOVER_BYTES:
        raise FugueHandoverInvalid("handover_size_invalid")
    try:
        document = json.loads(value)
    except (json.JSONDecodeError, UnicodeError):
        raise FugueHandoverInvalid("handover_json_invalid") from None
    if type(document) is not dict or set(document) != _FUGUE_HANDOVER_KEYS:
        raise FugueHandoverInvalid("handover_shape_invalid")
    if document.get("schema") != FUGUE_HANDOVER_SCHEMA:
        raise FugueHandoverInvalid("handover_schema_invalid")
    status = document.get("status")
    if status not in _FUGUE_HANDOVER_STATUSES:
        raise FugueHandoverInvalid("handover_status_invalid")
    summary = _bounded_text(
        document.get("summary"), maximum=_MAX_HANDOVER_SUMMARY_BYTES
    )

    raw_changes = document.get("changes")
    if type(raw_changes) is not list or len(raw_changes) > _MAX_HANDOVER_CHANGES:
        raise FugueHandoverInvalid("handover_changes_invalid")
    changes: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    for raw in raw_changes:
        if type(raw) is not dict or set(raw) != {"path", "diff"}:
            raise FugueHandoverInvalid("handover_change_invalid")
        path = _bounded_text(raw.get("path"), maximum=1024)
        candidate = PurePosixPath(path)
        if (
            candidate.is_absolute()
            or not candidate.parts
            or any(part in {"", ".", ".."} for part in candidate.parts)
            or candidate.as_posix() != path
            or "\\" in path
            or path in seen_paths
        ):
            raise FugueHandoverInvalid("handover_change_path_invalid")
        diff = _validate_diff_hunks(raw.get("diff"))
        seen_paths.add(path)
        changes.append({"path": path, "diff": diff})

    raw_reviews = document.get("reviews")
    if type(raw_reviews) is not dict or set(raw_reviews) != set(FUGUE_REVIEW_PROFILES):
        raise FugueHandoverInvalid("handover_reviews_invalid")
    reviews = {
        profile: _bounded_text(
            raw_reviews[profile], maximum=_MAX_HANDOVER_REVIEW_BYTES
        )
        for profile in FUGUE_REVIEW_PROFILES
    }
    unresolved = _bounded_text_list(document.get("unresolved"))
    codex_actions = _bounded_text_list(document.get("codex_actions"))
    if status == "ready" and unresolved:
        raise FugueHandoverInvalid("handover_ready_has_unresolved")

    return {
        "schema": FUGUE_HANDOVER_SCHEMA,
        "status": status,
        "summary": summary,
        "changes": changes,
        "reviews": reviews,
        "unresolved": list(unresolved),
        "codex_actions": list(codex_actions),
    }


@dataclass(frozen=True, slots=True)
class CompletionFinalResult:
    transport_id: str
    work_id: str
    completion_registration_id: str
    callback_registration_id: str
    session_id: str
    generation: int
    prompt_message_id: str
    assistant_message_id: str
    outcome: CompletionOutcome
    final_text: str | None


@dataclass(frozen=True, slots=True)
class CompletionReceipt:
    completion_id: str
    work_id: str
    generation: int
    outcome: CompletionOutcome
    route_state: str
    delivery_state: str
    delivery_key: str
    result_ref: str | None = None
