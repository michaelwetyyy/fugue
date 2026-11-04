"""Bounded transcript projection shared by live and archived worker views."""

from __future__ import annotations

from typing import Any
import unicodedata

from oc_rig.policy.models import FindingCode
from oc_rig.policy.scanner import scan_content

TRANSCRIPT_MESSAGE_LIMIT = 16
TRANSCRIPT_TURN_BYTES = 2_000
TRANSCRIPT_TOTAL_BYTES = 32 * 1024
MAX_TRANSCRIPT_REDACTIONS = 64
_ARCHIVE_REDACTION = "[redacted from archived transcript]"
_ARCHIVE_BLOCKING_FINDINGS = frozenset(
    {
        FindingCode.SECRET_MATERIAL,
        FindingCode.CONFUSABLE_TEXT,
        FindingCode.INVALID_STRUCTURE,
        FindingCode.LIMIT_EXCEEDED,
    }
)


class TranscriptProjectionInvalid(ValueError):
    """The backend transcript shape cannot be projected safely."""


def _utf8_preview(value: str, limit: int = TRANSCRIPT_TURN_BYTES) -> str:
    encoded = value.encode("utf-8", errors="strict")
    if len(encoded) <= limit:
        return value
    suffix = "…"
    prefix_limit = limit - len(suffix.encode("utf-8"))
    return encoded[:prefix_limit].decode("utf-8", errors="ignore").rstrip() + suffix


def project_transcript_turns(
    messages: object, *, durable: bool = False
) -> tuple[list[dict[str, Any]], list[str]]:
    """Project bounded human text while excluding tools and private reasoning.

    Live inspection is already ephemeral and preserves the prior bounded text
    behaviour. Durable archives additionally replace text that trips a secret,
    malformed/confusable-text, or scanner-limit finding with a fixed inert
    marker before persistence.
    """

    if type(messages) is not list or len(messages) > TRANSCRIPT_MESSAGE_LIMIT:
        raise TranscriptProjectionInvalid("worker_transcript_invalid")
    turns: list[dict[str, Any]] = []
    redacted: list[str] = []
    total_bytes = 0

    def redact(path: str) -> None:
        if path in redacted:
            return
        if len(redacted) < MAX_TRANSCRIPT_REDACTIONS - 1:
            redacted.append(path)
        elif len(redacted) == MAX_TRANSCRIPT_REDACTIONS - 1:
            redacted.append("messages[additional]")

    for message_index, raw in enumerate(messages):
        if type(raw) is not dict:
            raise TranscriptProjectionInvalid("worker_transcript_invalid")
        info = raw.get("info")
        parts = raw.get("parts")
        if type(info) is not dict or type(parts) is not list:
            raise TranscriptProjectionInvalid("worker_transcript_invalid")
        raw_role = info.get("role")
        if raw_role not in {"user", "assistant"}:
            redact(f"messages[{message_index}]")
            continue
        text_parts: list[str] = []
        for part_index, part in enumerate(parts):
            if type(part) is not dict:
                raise TranscriptProjectionInvalid("worker_transcript_invalid")
            if part.get("type") == "text" and type(part.get("text")) is str:
                text_parts.append(str(part["text"]))
            else:
                redact(f"messages[{message_index}].parts[{part_index}]")
        if not text_parts:
            continue
        try:
            preview = _utf8_preview("\n".join(text_parts))
        except UnicodeError:
            raise TranscriptProjectionInvalid("worker_transcript_invalid") from None
        if durable:
            scan = scan_content(preview)
            unsafe_control = any(
                (ord(character) < 0x20 and character not in "\t\n\r")
                or unicodedata.category(character) in {"Cf", "Cs"}
                for character in preview
            )
            if unsafe_control or any(
                finding.code in _ARCHIVE_BLOCKING_FINDINGS for finding in scan.findings
            ):
                redact(f"messages[{message_index}].text")
                preview = _ARCHIVE_REDACTION
        preview_bytes = len(preview.encode("utf-8"))
        if total_bytes + preview_bytes > TRANSCRIPT_TOTAL_BYTES:
            redact("messages[remaining]")
            break
        total_bytes += preview_bytes
        completed = info.get("finish") is not None
        time_value = info.get("time")
        if type(time_value) is dict and time_value.get("completed") is not None:
            completed = True
        turns.append(
            {
                "seq": len(turns),
                "role": "user" if raw_role == "user" else "agent",
                "kind": "text",
                "preview": preview,
                "state": "committed" if raw_role == "user" or completed else "inflight",
            }
        )
    return turns, redacted

def validate_projected_transcript(value: object) -> dict[str, object]:
    """Validate a persisted transcript projection without trusting its JSON bytes."""

    if type(value) is not dict or set(value) != {"turns", "redacted"}:
        raise TranscriptProjectionInvalid("archived_transcript_invalid")
    raw_turns = value.get("turns")
    raw_redacted = value.get("redacted")
    if type(raw_turns) is not list or len(raw_turns) > TRANSCRIPT_MESSAGE_LIMIT:
        raise TranscriptProjectionInvalid("archived_transcript_invalid")
    turns: list[dict[str, Any]] = []
    total_bytes = 0
    for index, raw in enumerate(raw_turns):
        if type(raw) is not dict or set(raw) != {"seq", "role", "kind", "preview", "state"}:
            raise TranscriptProjectionInvalid("archived_transcript_invalid")
        if raw.get("seq") != index or raw.get("role") not in {"user", "agent"}:
            raise TranscriptProjectionInvalid("archived_transcript_invalid")
        if raw.get("kind") != "text" or raw.get("state") not in {"committed", "inflight"}:
            raise TranscriptProjectionInvalid("archived_transcript_invalid")
        preview = raw.get("preview")
        if type(preview) is not str:
            raise TranscriptProjectionInvalid("archived_transcript_invalid")
        try:
            encoded = preview.encode("utf-8")
        except UnicodeEncodeError:
            raise TranscriptProjectionInvalid("archived_transcript_invalid") from None
        if not encoded or len(encoded) > TRANSCRIPT_TURN_BYTES or any(
            (ord(character) < 0x20 and character not in "\t\n\r")
            or unicodedata.category(character) in {"Cf", "Cs"}
            for character in preview
        ):
            raise TranscriptProjectionInvalid("archived_transcript_invalid")
        total_bytes += len(encoded)
        if total_bytes > TRANSCRIPT_TOTAL_BYTES:
            raise TranscriptProjectionInvalid("archived_transcript_invalid")
        turns.append(dict(raw))
    if type(raw_redacted) is not list or len(raw_redacted) > MAX_TRANSCRIPT_REDACTIONS:
        raise TranscriptProjectionInvalid("archived_transcript_invalid")
    redacted: list[str] = []
    for raw in raw_redacted:
        if type(raw) is not str or not raw or len(raw.encode("utf-8")) > 256 or raw in redacted:
            raise TranscriptProjectionInvalid("archived_transcript_invalid")
        redacted.append(raw)
    return {"turns": turns, "redacted": redacted}
