"""Closed state vocabularies stored by the controller."""

from __future__ import annotations

from enum import StrEnum


class OperationKind(StrEnum):
    DISPATCH = "dispatch"
    RECOVERY = "recovery"
    CALLBACK = "callback"
    CONTROLLER = "controller"


class WorkKind(StrEnum):
    DISPATCH = "dispatch"
    RECOVERY = "recovery"
    CALLBACK = "callback"


class WorkState(StrEnum):
    QUEUED = "queued"
    CLAIMED = "claimed"
    COMPLETED = "completed"
    REJECTED = "rejected"


class SettingKey(StrEnum):
    CONTROLLER_ENABLED = "controller_enabled"
    MAX_CONCURRENT_WORKERS = "max_concurrent_workers"
    WORKER_START_TIMEOUT_SECONDS = "worker_start_timeout_seconds"
    DEFAULT_PRIORITY = "default_priority"


class ControllerRunState(StrEnum):
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CRASHED = "crashed"


class OperationState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING = "waiting"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DispatchState(StrEnum):
    PENDING = "pending"
    DISPATCHING = "dispatching"
    DISPATCHED = "dispatched"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TransportState(StrEnum):
    PENDING = "pending"
    SENT = "sent"
    ACKNOWLEDGED = "acknowledged"
    FAILED = "failed"
    ABANDONED = "abandoned"


class OutboxState(StrEnum):
    PENDING = "pending"
    DELIVERING = "delivering"
    DELIVERED = "delivered"
    FAILED = "failed"


class OwnershipState(StrEnum):
    ACTIVE = "active"
    RELEASED = "released"


class RecoveryState(StrEnum):
    OPEN = "open"
    RECOVERED = "recovered"
    FAILED = "failed"
