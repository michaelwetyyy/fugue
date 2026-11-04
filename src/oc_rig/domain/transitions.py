"""State-machine rules shared by commands and persistence."""

from __future__ import annotations

from collections.abc import Mapping, Set
from enum import StrEnum

from oc_rig.domain.models import (
    ControllerRunState,
    DispatchState,
    OperationState,
    OutboxState,
    TransportState,
)


class InvalidStateTransition(ValueError):
    """Raised when an aggregate is asked to make an unsafe transition."""


TRANSITIONS: Mapping[type[StrEnum], Mapping[StrEnum, Set[StrEnum]]] = {
    ControllerRunState: {
        ControllerRunState.STARTING: {
            ControllerRunState.RUNNING,
            ControllerRunState.FAILED,
            ControllerRunState.CRASHED,
        },
        ControllerRunState.RUNNING: {
            ControllerRunState.STOPPING,
            ControllerRunState.FAILED,
            ControllerRunState.CRASHED,
        },
        ControllerRunState.STOPPING: {
            ControllerRunState.SUCCEEDED,
            ControllerRunState.FAILED,
            ControllerRunState.CRASHED,
        },
        ControllerRunState.SUCCEEDED: set(),
        ControllerRunState.FAILED: set(),
        ControllerRunState.CRASHED: set(),
    },
    OperationState: {
        OperationState.PENDING: {
            OperationState.RUNNING,
            OperationState.CANCELLED,
            OperationState.FAILED,
        },
        OperationState.RUNNING: {
            OperationState.WAITING,
            OperationState.SUCCEEDED,
            OperationState.FAILED,
            OperationState.CANCELLED,
        },
        OperationState.WAITING: {
            OperationState.RUNNING,
            OperationState.SUCCEEDED,
            OperationState.FAILED,
            OperationState.CANCELLED,
        },
        OperationState.SUCCEEDED: set(),
        OperationState.FAILED: set(),
        OperationState.CANCELLED: set(),
    },
    DispatchState: {
        DispatchState.PENDING: {
            DispatchState.DISPATCHING,
            DispatchState.CANCELLED,
        },
        DispatchState.DISPATCHING: {
            DispatchState.DISPATCHED,
            DispatchState.FAILED,
            DispatchState.CANCELLED,
        },
        DispatchState.DISPATCHED: {
            DispatchState.COMPLETED,
            DispatchState.FAILED,
        },
        DispatchState.COMPLETED: set(),
        DispatchState.FAILED: set(),
        DispatchState.CANCELLED: set(),
    },
    TransportState: {
        TransportState.PENDING: {
            TransportState.SENT,
            TransportState.FAILED,
            TransportState.ABANDONED,
        },
        TransportState.SENT: {
            TransportState.ACKNOWLEDGED,
            TransportState.FAILED,
            TransportState.ABANDONED,
        },
        TransportState.ACKNOWLEDGED: set(),
        TransportState.FAILED: set(),
        TransportState.ABANDONED: set(),
    },
    OutboxState: {
        OutboxState.PENDING: {OutboxState.DELIVERING},
        OutboxState.DELIVERING: {
            OutboxState.PENDING,
            OutboxState.DELIVERED,
            OutboxState.FAILED,
        },
        OutboxState.DELIVERED: set(),
        OutboxState.FAILED: set(),
    },
}


def require_transition(current: StrEnum, target: StrEnum) -> None:
    """Validate a transition between two values from the same state enum."""
    if type(current) is not type(target):
        raise InvalidStateTransition(
            f"cannot transition {type(current).__name__} to {type(target).__name__}"
        )
    allowed = TRANSITIONS.get(type(current), {}).get(current, set())
    if target not in allowed:
        raise InvalidStateTransition(f"invalid transition: {current.value} -> {target.value}")
