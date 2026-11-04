"""Trusted dual-clock abstraction used by persisted recovery timers."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class ClockReading:
    epoch: str
    wall_us: int
    monotonic_ns: int

    def __post_init__(self) -> None:
        if not self.epoch or len(self.epoch) > 128:
            raise ValueError("clock epoch is invalid")
        if type(self.wall_us) is not int or self.wall_us < 0:
            raise ValueError("wall clock must be a non-negative integer")
        if type(self.monotonic_ns) is not int or self.monotonic_ns < 0:
            raise ValueError("monotonic clock must be a non-negative integer")


class TrustedClock(Protocol):
    def read(self) -> ClockReading: ...


class SystemTrustedClock:
    """One process epoch with wall time for restart and monotonic time in-process."""

    __slots__ = ("_epoch",)

    def __init__(self) -> None:
        self._epoch = f"boot-{uuid.uuid4().hex}"

    def read(self) -> ClockReading:
        return ClockReading(self._epoch, time.time_ns() // 1_000, time.monotonic_ns())
