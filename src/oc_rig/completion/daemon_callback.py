"""Daemon-only bridge from the durable callback outbox to local Codex."""

from __future__ import annotations

import threading
import time

from oc_rig.completion.codex_callback import LocalCodexQueueAdapter
from oc_rig.completion.service import _CompletionService
from oc_rig.store.database import RigStore, _DaemonAuthority


class _DaemonLocalCodexCallbackPump:
    """Deliver one journalled callback without holding a database transaction."""

    __slots__ = (
        "_adapter",
        "_authority",
        "_capability",
        "_closed",
        "_completion",
        "_lock",
        "_store",
        "_timer",
    )

    def __init__(
        self,
        store: RigStore,
        authority: _DaemonAuthority,
        capability: object,
        completion: _CompletionService,
        adapter: LocalCodexQueueAdapter,
    ):
        if type(completion) is not _CompletionService:
            raise TypeError("exact daemon completion service required")
        if type(adapter) is not LocalCodexQueueAdapter:
            raise TypeError("exact local Codex callback adapter required")
        authority._assert_for(store)
        self._store = store
        self._authority = authority
        self._capability = capability
        self._completion = completion
        self._adapter = adapter
        self._closed = False
        self._lock = threading.RLock()
        self._timer: threading.Timer | None = None

    def _run_once_locked(self) -> bool:
        with self._store._daemon_transaction(self._authority) as connection:
            delivery = self._completion.begin_local_codex_delivery(
                self._capability, connection
            )
        if delivery is None:
            return False
        result = self._adapter.deliver(delivery.request())
        with self._store._daemon_transaction(self._authority) as connection:
            self._completion.finish_local_codex_delivery(
                self._capability,
                connection,
                delivery,
                result,
            )
        return True

    def _arm_next_locked(self) -> None:
        if self._closed or self._timer is not None:
            return
        with self._store._daemon_transaction(self._authority) as connection:
            available = self._completion.next_local_codex_available_at(
                self._capability, connection
            )
        if available is None:
            return
        delay = max((available - time.time_ns() // 1_000) / 1_000_000, 0.001)
        timer = threading.Timer(delay, self._timer_fired)
        timer.daemon = True
        self._timer = timer
        timer.start()

    def _timer_fired(self) -> None:
        with self._lock:
            self._timer = None
            if self._closed:
                return
        self.drain_ready()

    def run_once(self) -> bool:
        """Try one ready callback and arm its earliest durable retry."""

        with self._lock:
            if self._closed:
                return False
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            delivered = self._run_once_locked()
            self._arm_next_locked()
            return delivered

    def drain_ready(self, maximum: int = 16) -> int:
        """Drain one bounded wake-up batch; this is not a polling loop."""

        if type(maximum) is not int or not 1 <= maximum <= 64:
            raise ValueError("callback drain maximum must be in [1, 64]")
        with self._lock:
            if self._closed:
                return 0
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            delivered = 0
            while delivered < maximum and self._run_once_locked():
                delivered += 1
            self._arm_next_locked()
            return delivered

    def close(self) -> None:
        """Cancel the daemon-owned wake without changing durable callback state."""

        with self._lock:
            self._closed = True
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
