"""Closed recovery event, timer, and action vocabularies."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class RecoveryPhase(StrEnum):
    QUEUED = "queued"
    ACTIVE = "active"
    HANDED_OFF = "handed_off"
    TOOL_FLOW = "tool_flow"
    BUSY = "busy"
    THINKING = "thinking"
    CORPSE = "corpse"
    COMPLETED = "completed"
    ATTENTION = "attention"


class RecoveryEvidence(StrEnum):
    NONE = "none"
    CALLBACK = "callback"
    CLAIM = "claim"
    COMPLETION = "completion"


class RecoveryResult(StrEnum):
    PROGRESS = "progress"
    NO_PROGRESS = "no_progress"
    TRANSIENT_FAILURE = "transient_failure"
    TERMINAL_FAILURE = "terminal_failure"


class RecoveryFailureClass(StrEnum):
    TRANSIENT = "transient"
    DETERMINISTIC = "deterministic"
    PERMISSION = "permission"
    POLICY = "policy"
    DELIVERY_UNKNOWN = "delivery_unknown"


@dataclass(frozen=True, slots=True)
class RecoveryObservationReceipt:
    target_id: str
    work_id: str
    generation: int
    phase: RecoveryPhase
    timer_id: str | None
    threshold_seconds: int | None
    circuit_state: str


@dataclass(frozen=True, slots=True)
class RecoveryTimerReceipt:
    timer_id: str
    state: str
    kind: str
    due: bool
    episode_id: str | None
    attempt: int | None
    tier: str | None
    next_timer_id: str | None


@dataclass(frozen=True, slots=True)
class RecoveryAttemptReceipt:
    episode_id: str
    attempt: int
    state: str
    next_timer_id: str | None
    circuit_state: str
