"""Closed scheduler topology and durable state values."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Lane(StrEnum):
    TENSORHOST = "tensorhost"
    HOMELAB = "homelab"
    PERSONAL = "personal"
    CONTROL = "control"
    HANDS_OFF = "hands-off"


LANES = (
    Lane.TENSORHOST,
    Lane.HOMELAB,
    Lane.PERSONAL,
    Lane.CONTROL,
    Lane.HANDS_OFF,
)


class SlotState(StrEnum):
    CLEAR = "clear"
    ASSIGNED = "assigned"


class ScheduledWorkState(StrEnum):
    QUEUED = "queued"
    ASSIGNED = "assigned"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    REJECTED = "rejected"


class AssignmentState(StrEnum):
    ACTIVE = "active"
    RELEASED = "released"


class ReleaseOutcome(StrEnum):
    REQUEUED = "requeued"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class SchedulerReservation:
    id: str
    sequence: int
    work_id: str
    work_sequence: int
    lane: Lane
    slot_id: str
    owner_id: str
    attempt: int
    fence_token: str
    scope_claim_id: str
    scope_claim_attempt: int
    scope_claim_fence: str
    state: AssignmentState
    release_outcome: ReleaseOutcome | None = None


@dataclass(frozen=True, slots=True)
class SlotSnapshot:
    id: str
    lane: Lane
    position: int
    state: SlotState
    last_used_sequence: int
    assignment_id: str | None
    work_id: str | None
    owner_id: str | None
    attempt: int | None
    fence_token: str | None


@dataclass(frozen=True, slots=True)
class WorkSnapshot:
    id: str
    sequence: int
    queue_order: int
    lane: Lane
    state: ScheduledWorkState
    admitted: bool
    policy_allowed: bool | None
    attempt: int
    assignment_id: str | None
    admission_decision_id: str | None
    scope_claim_id: str | None


@dataclass(frozen=True, slots=True)
class LaneSnapshot:
    lane: Lane
    slots: tuple[SlotSnapshot, ...]
    work: tuple[WorkSnapshot, ...]


@dataclass(frozen=True, slots=True)
class SchedulerSnapshot:
    lanes: tuple[LaneSnapshot, ...]
    assignments: tuple[SchedulerReservation, ...]
