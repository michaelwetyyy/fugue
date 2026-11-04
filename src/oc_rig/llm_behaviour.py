"""Closed, durable LLM selection for future OpenCode dispatch turns."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Mapping

from oc_rig.opencode_authority import (
    DEFAULT_AGENT_EFFORT,
    DEFAULT_AGENT_MODEL,
    ZERO_COST_ZEN_ROSTER,
)


SUPPORTED_EFFORTS_BY_MODEL: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {model: tuple(efforts) for model, efforts in ZERO_COST_ZEN_ROSTER}
)
SUPPORTED_MODELS = tuple(SUPPORTED_EFFORTS_BY_MODEL)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class LlmBehaviourInvalid(ValueError):
    """The requested or persisted closed-roster selection is invalid."""


class LlmBehaviourBusy(RuntimeError):
    """The scheduler is not quiescent enough to change future dispatches."""


class LlmBehaviourConflict(RuntimeError):
    """The durable selection changed while applying an update."""


@dataclass(frozen=True, slots=True)
class LlmSelection:
    model: str
    effort: str
    revision: int

    def __post_init__(self) -> None:
        if (
            not valid_pair(self.model, self.effort)
            or type(self.revision) is not int
            or self.revision < 1
        ):
            raise LlmBehaviourInvalid("LLM behaviour authority is invalid")


def valid_pair(model: object, effort: object) -> bool:
    return (
        type(model) is str
        and type(effort) is str
        and model in SUPPORTED_EFFORTS_BY_MODEL
        and effort in SUPPORTED_EFFORTS_BY_MODEL[model]
    )


def read_selection(connection: sqlite3.Connection) -> LlmSelection:
    rows = connection.execute(
        "SELECT model, effort, revision FROM llm_behaviour_settings WHERE singleton = 1"
    ).fetchall()
    if len(rows) != 1:
        raise LlmBehaviourInvalid("LLM behaviour authority is absent")
    return LlmSelection(str(rows[0][0]), str(rows[0][1]), int(rows[0][2]))


def status(connection: sqlite3.Connection) -> dict[str, object]:
    selected = read_selection(connection)
    return {
        "available": True,
        "supported_models": list(SUPPORTED_MODELS),
        "supported_efforts_by_model": {
            model: list(efforts)
            for model, efforts in SUPPORTED_EFFORTS_BY_MODEL.items()
        },
        "current_model": selected.model,
        "current_effort": selected.effort,
        "effective_model": selected.model,
        "effective_effort": selected.effort,
    }


def apply_selection(
    connection: sqlite3.Connection,
    *,
    model: object,
    effort: object,
    idempotency_id: str,
) -> dict[str, object]:
    if not valid_pair(model, effort):
        raise LlmBehaviourInvalid("unsupported LLM model and effort pair")
    busy = connection.execute(
        "SELECT count(*) FROM scheduler_work WHERE state IN ('queued','assigned')"
    ).fetchone()
    active = connection.execute(
        "SELECT count(*) FROM scheduler_assignments WHERE state = 'active'"
    ).fetchone()
    if busy is None or active is None or int(busy[0]) != 0 or int(active[0]) != 0:
        raise LlmBehaviourBusy("scheduler must be idle before changing LLM behaviour")
    selected = read_selection(connection)
    if (selected.model, selected.effort) != (model, effort):
        cursor = connection.execute(
            """UPDATE llm_behaviour_settings
               SET model = ?, effort = ?, revision = revision + 1,
                   applied_idempotency_id = ?, updated_at = ?
               WHERE singleton = 1 AND revision = ?""",
            (model, effort, idempotency_id, _now(), selected.revision),
        )
        if cursor.rowcount != 1:
            raise LlmBehaviourConflict("LLM behaviour authority changed")
    return status(connection)


def prompt_fields(connection: sqlite3.Connection) -> dict[str, object]:
    selected = read_selection(connection)
    provider, separator, model_id = selected.model.partition("/")
    if separator != "/" or provider != "opencode" or not model_id:
        raise LlmBehaviourInvalid("LLM model provider is invalid")
    return {
        "model": {"providerID": provider, "modelID": model_id},
        "variant": selected.effort,
    }


assert valid_pair(DEFAULT_AGENT_MODEL, DEFAULT_AGENT_EFFORT)
