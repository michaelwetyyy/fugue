"""Domain types and invariants for the Rig controller."""

from oc_rig.domain.models import (
    ControllerRunState,
    DispatchState,
    OperationKind,
    OperationState,
    OutboxState,
    OwnershipState,
    RecoveryState,
    SettingKey,
    TransportState,
    WorkKind,
    WorkState,
)
from oc_rig.domain.transitions import InvalidStateTransition, require_transition

__all__ = [
    "ControllerRunState",
    "DispatchState",
    "InvalidStateTransition",
    "OperationKind",
    "OperationState",
    "OutboxState",
    "OwnershipState",
    "RecoveryState",
    "SettingKey",
    "TransportState",
    "WorkKind",
    "WorkState",
    "require_transition",
]
