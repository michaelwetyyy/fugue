"""Fail-closed discovery primitives for child-enabled OpenCode turns."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping

from oc_rig.completion.models import FUGUE_REVIEW_PROFILES
from oc_rig.opencode_authority import CHILD_AGENT_NAME

from oc_rig.adapters.opencode_client import OpenCodeClientError, validate_identifier


MAX_DESCENDANT_SESSIONS = 12
MAX_DESCENDANT_DEPTH = 3
MAX_SESSION_TREE_SIZE = 1024
_MAX_SIGNED_64 = 2**63 - 1
CONSOLIDATION_PROMPT = (
    "All authorized child analyses for this turn are now terminal. Consolidate only "
    "their already-visible results and your original analysis into one final answer. "
    "Do not invoke tools, do not spawn another agent, and do not ask a follow-up."
)


class ChildBarrierAttention(RuntimeError):
    """The remote session tree cannot safely authorize completion."""

    __slots__ = ("reason",)

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ChildSession:
    session_id: str
    parent_session_id: str
    created_at_ms: int


def iso_to_epoch_ms(value: object) -> int:
    if type(value) is not str:
        raise ChildBarrierAttention("child_barrier_turn_time_invalid")
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        raise ChildBarrierAttention("child_barrier_turn_time_invalid") from None
    if parsed.tzinfo is None:
        raise ChildBarrierAttention("child_barrier_turn_time_invalid")
    utc_value = parsed.astimezone(UTC)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = utc_value - epoch
    milliseconds = (
        delta.days * 86_400_000
        + delta.seconds * 1_000
        + delta.microseconds // 1_000
    )
    if milliseconds < 0:
        raise ChildBarrierAttention("child_barrier_turn_time_invalid")
    return milliseconds


def _session_created_ms(item: Mapping[str, Any]) -> int:
    time_value = item.get("time")
    created = time_value.get("created") if type(time_value) is dict else None
    if type(created) is not int or created < 0:
        raise ChildBarrierAttention("child_session_time_invalid")
    return created


def discover_current_turn_children(
    sessions: list[Mapping[str, Any]],
    *,
    root_session_id: str,
    turn_started_at_ms: int,
    observed_at_ms: int,
) -> tuple[ChildSession, ...]:
    """Freeze the bounded descendant tree created during this root turn."""

    try:
        validate_identifier(root_session_id, "root_session_id")
    except OpenCodeClientError:
        raise ChildBarrierAttention("child_session_tree_invalid") from None
    if (
        type(turn_started_at_ms) is not int
        or type(observed_at_ms) is not int
        or not 0 <= turn_started_at_ms <= observed_at_ms <= _MAX_SIGNED_64
    ):
        raise ChildBarrierAttention("child_barrier_turn_time_invalid")
    if type(sessions) is not list:
        raise ChildBarrierAttention("child_session_tree_invalid")
    if len(sessions) > MAX_SESSION_TREE_SIZE:
        raise ChildBarrierAttention("child_session_tree_too_large")
    indexed: dict[str, tuple[str | None, Mapping[str, Any]]] = {}
    for item in sessions:
        if type(item) is not dict:
            raise ChildBarrierAttention("child_session_tree_invalid")
        try:
            session_id = validate_identifier(item.get("id"), "session_id")
        except OpenCodeClientError:
            raise ChildBarrierAttention("child_session_tree_invalid") from None
        parent_value = item.get("parentID")
        if parent_value in (None, ""):
            parent_id = None
        else:
            try:
                parent_id = validate_identifier(parent_value, "parent_session_id")
            except OpenCodeClientError:
                raise ChildBarrierAttention("child_session_tree_invalid") from None
        if session_id in indexed:
            raise ChildBarrierAttention("child_session_tree_invalid")
        indexed[session_id] = (parent_id, item)
    if root_session_id not in indexed:
        raise ChildBarrierAttention("child_barrier_root_missing")

    descendants: list[ChildSession] = []
    for session_id, (parent_id, item) in indexed.items():
        if session_id == root_session_id:
            continue
        created_at_ms = _session_created_ms(item)
        if created_at_ms > observed_at_ms:
            raise ChildBarrierAttention("child_session_time_invalid")
        seen = {session_id}
        ancestor = parent_id
        lineage = [session_id]
        depth = 1
        while ancestor is not None:
            if ancestor in seen:
                raise ChildBarrierAttention("child_session_tree_invalid")
            seen.add(ancestor)
            if ancestor == root_session_id:
                break
            parent = indexed.get(ancestor)
            if parent is None:
                if created_at_ms >= turn_started_at_ms:
                    raise ChildBarrierAttention("child_session_tree_invalid")
                break
            lineage.append(ancestor)
            ancestor = parent[0]
            depth += 1
        if ancestor != root_session_id:
            continue
        if created_at_ms < turn_started_at_ms:
            continue
        if any(
            _session_created_ms(indexed[lineage_id][1]) < turn_started_at_ms
            for lineage_id in lineage[1:]
        ):
            raise ChildBarrierAttention("child_session_historical_branch_changed")
        if depth > MAX_DESCENDANT_DEPTH:
            raise ChildBarrierAttention("child_session_depth_exceeded")
        if type(parent_id) is not str:
            raise ChildBarrierAttention("child_session_tree_invalid")
        descendants.append(ChildSession(session_id, parent_id, created_at_ms))
    if len(descendants) > MAX_DESCENDANT_SESSIONS:
        raise ChildBarrierAttention("child_session_limit_exceeded")
    return tuple(
        sorted(descendants, key=lambda item: (item.created_at_ms, item.session_id))
    )



def canonical_review_profile(
    messages: list[Mapping[str, Any]], *, session_id: str
) -> str | None:
    """Return the one concrete canonical review marker from a child root prompt."""

    if type(messages) is not list or len(messages) > 16:
        raise ChildBarrierAttention("review_prompt_invalid")
    candidates: list[tuple[int | float, str, Mapping[str, Any]]] = []
    for item in messages:
        if type(item) is not dict or set(item) != {"info", "parts"}:
            raise ChildBarrierAttention("review_prompt_invalid")
        info = item.get("info")
        parts = item.get("parts")
        if type(info) is not dict or type(parts) is not list:
            raise ChildBarrierAttention("review_prompt_invalid")
        if info.get("role") != "user" or info.get("sessionID") != session_id:
            continue
        time_value = info.get("time")
        created = time_value.get("created") if type(time_value) is dict else None
        message_id = info.get("id")
        if type(created) not in {int, float} or type(message_id) is not str:
            raise ChildBarrierAttention("review_prompt_invalid")
        candidates.append((created, message_id, item))
    if not candidates:
        raise ChildBarrierAttention("review_prompt_missing")
    _created, _message_id, initial = min(candidates, key=lambda item: (item[0], item[1]))
    info = initial["info"]
    if info.get("agent") != CHILD_AGENT_NAME:
        # Ordinary direct child agents remain valid for non-review turns.  A marker
        # below would still fail closed if a non-canonical child attempted one.
        agent_is_child = False
    else:
        agent_is_child = True
    text_parts: list[str] = []
    for part in initial["parts"]:
        if type(part) is not dict or type(part.get("type")) is not str:
            raise ChildBarrierAttention("review_prompt_invalid")
        if part.get("type") != "text":
            continue
        text = part.get("text")
        if type(text) is not str:
            raise ChildBarrierAttention("review_prompt_invalid")
        text_parts.append(text)
    prompt = "\n".join(text_parts)
    prefix = "FUGUE_REVIEW_PROFILE:"
    marker_count = prompt.count(prefix)
    if marker_count == 0:
        return None
    if marker_count != 1 or not agent_is_child or not prompt.startswith(prefix):
        raise ChildBarrierAttention("review_profile_invalid")
    first_line = prompt.split("\n", 1)[0]
    profile = first_line.removeprefix(prefix)
    if profile not in FUGUE_REVIEW_PROFILES:
        raise ChildBarrierAttention("review_profile_invalid")
    if first_line != f"{prefix}{profile}":
        raise ChildBarrierAttention("review_profile_invalid")
    return profile

def child_set_digest(children: tuple[ChildSession, ...]) -> str:
    material = [
        {
            "created_at_ms": child.created_at_ms,
            "parent_session_id": child.parent_session_id,
            "session_id": child.session_id,
        }
        for child in sorted(
            children, key=lambda item: (item.created_at_ms, item.session_id)
        )
    ]
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def consolidation_message_id(transport_id: str, generation: int) -> str:
    validate_identifier(transport_id, "transport_id")
    if type(generation) is not int or generation <= 0:
        raise ValueError("generation is invalid")
    digest = hashlib.sha256(f"{transport_id}:{generation}:consolidate".encode()).hexdigest()
    return f"msg-consolidate-{digest[:40]}"
