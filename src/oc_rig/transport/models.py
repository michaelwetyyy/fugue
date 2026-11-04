"""Durable transport state values."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class TransportState(StrEnum):
    RESERVED = "reserved"
    PREPARED = "prepared"
    SENDING = "sending"
    ACCEPTED = "accepted"
    DELIVERY_UNKNOWN = "delivery_unknown"
    DEFINITE_FAILED = "definite_failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class TransportReceipt:
    transport_id: str
    work_id: str
    pool: str
    state: TransportState
    attempt: int
    completion_registration_id: str
    callback_registration_id: str
    acknowledgement_id: str | None = None
    error_code: str | None = None
