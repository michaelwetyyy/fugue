"""SQLite persistence API for Rig controller state."""

from oc_rig.store.database import (
    CredentialDataError,
    DaemonAuthorityError,
    IdempotencyConflict,
    OwnershipConflict,
    OwnershipReceipt,
    RigStore,
    StoreError,
    StoreQuiescenceError,
    WorkReservation,
)
from oc_rig.store.runtime import PrivateRuntimeDirectory, RuntimeContainmentError
from oc_rig.store.snapshot import ReadOnlySnapshot, Snapshot

__all__ = [
    "CredentialDataError",
    "DaemonAuthorityError",
    "IdempotencyConflict",
    "OwnershipConflict",
    "OwnershipReceipt",
    "PrivateRuntimeDirectory",
    "ReadOnlySnapshot",
    "RigStore",
    "RuntimeContainmentError",
    "Snapshot",
    "StoreError",
    "StoreQuiescenceError",
    "WorkReservation",
]
