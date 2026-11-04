"""Daemon-private RigStore authority for OpenCode delivery reservations."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3

from oc_rig.adapters.models import AdapterDisposition, AdapterResult
from oc_rig.adapters.opencode import (
    AcquisitionState,
    AbortAcquisition,
    DeliveryAcquisition,
    DispatchRegistration,
    DurableReservation,
    LiveOpenCodeAdapter,
    LiveOpenCodeAdapterConfig,
    PersistentSession,
    ProvisionalSession,
    ReservationCandidate,
    ReservationRequest,
    SessionCleanup,
    _DAEMON_CONSTRUCTION_TOKEN,
    _expected_message_id,
)
from oc_rig.policy.models import AgentLifecycle
from oc_rig.store.database import (
    IdempotencyConflict,
    RigStore,
    StoreError,
    _DaemonAuthority,
    _identifier,
    _utc_now,
)


_TERMINAL_DELIVERY_STATES = frozenset(
    {"accepted", "delivery_unknown", "definite_failed", "cancelled"}
)


def _result(state: str, acknowledgement_id: str | None, error_code: str | None) -> AdapterResult:
    if state == "accepted" and acknowledgement_id is not None:
        return AdapterResult.accepted(acknowledgement_id)
    if state == "delivery_unknown" and error_code is not None:
        return AdapterResult.unknown(error_code)
    if state == "definite_failed" and error_code is not None:
        return AdapterResult.definite_failure(error_code)
    if state == "cancelled" and error_code is not None:
        return AdapterResult.cancelled(error_code)
    raise StoreError("persisted OpenCode outcome is incompatible")


class _RigStoreOpenCodeReservations:
    """Exact daemon capability implementing the adapter's atomic persistence port."""

    __slots__ = ("_authority", "_capability_id", "_store")

    def __new__(cls, *_args: object, **_kwargs: object) -> "_RigStoreOpenCodeReservations":
        raise PermissionError("OpenCode reservation services are created only by rigd")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("RigStore OpenCode reservations are sealed")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("RigStore OpenCode reservations are immutable")

    def _assert_authority(self) -> None:
        self._authority._assert_for(self._store)

    @staticmethod
    def _validate_request(request: ReservationRequest) -> None:
        if type(request) is not ReservationRequest:
            raise TypeError("exact ReservationRequest required")
        for value, label in (
            (request.transport_id, "transport_id"),
            (request.work_id, "work_id"),
            (request.pool, "pool"),
            (request.completion_registration_id, "completion_registration_id"),
            (request.callback_registration_id, "callback_registration_id"),
        ):
            _identifier(value, label)
        if (
            len(request.request_fingerprint) != 64
            or any(
                character not in "0123456789abcdef"
                for character in request.request_fingerprint
            )
            or len(request.candidates) > 3
            or any(type(item) is not ReservationCandidate for item in request.candidates)
            or len({item.slot_id for item in request.candidates})
            != len(request.candidates)
            or type(request.agent_lifecycle) is not AgentLifecycle
        ):
            raise ValueError("reservation request is invalid")
        if request.agent_lifecycle is AgentLifecycle.PERSISTENT:
            if request.persistent_scope_hash is not None and (
                type(request.persistent_scope_hash) is not str
                or len(request.persistent_scope_hash) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in request.persistent_scope_hash
                )
            ):
                raise ValueError("persistent scope authority is invalid")
            if (
                request.isolated_session_id is not None
                and request.persistent_scope_hash is None
            ):
                raise ValueError("persistent scope authority is absent")
        elif request.persistent_scope_hash is not None:
            raise ValueError("disposable scope authority is invalid")
        if request.isolated_session_id is not None:
            _identifier(request.isolated_session_id, "isolated_session_id")
            if request.agent_lifecycle is AgentLifecycle.DISPOSABLE and (
                request.provisional_claim_token is None
                or len(request.provisional_claim_token) != 64
                or any(c not in "0123456789abcdef" for c in request.provisional_claim_token)
            ):
                raise ValueError("provisional claim token is invalid")
        for candidate in request.candidates:
            for value, label in (
                (candidate.slot_id, "slot_id"),
                (candidate.session_id, "session_id"),
                (candidate.worker, "worker"),
            ):
                _identifier(value, label)
            if type(candidate.last_used) is not int or candidate.last_used < 0:
                raise ValueError("candidate last_used is invalid")

    @staticmethod
    def _reservation(row: sqlite3.Row) -> DurableReservation:
        outcome = (
            _result(
                str(row["delivery_state"]),
                row["acknowledgement_id"],
                row["error_code"],
            )
            if row["delivery_state"] in _TERMINAL_DELIVERY_STATES
            else None
        )
        abort_outcome = (
            _result(
                str(row["abort_disposition"]),
                None,
                row["abort_error_code"],
            )
            if row["abort_state"] == "terminal"
            else None
        )
        return DurableReservation(
            transport_id=row["transport_id"],
            work_id=row["work_id"],
            pool=row["pool"],
            request_fingerprint=row["request_fingerprint"],
            completion_registration_id=row["completion_registration_id"],
            callback_registration_id=row["callback_registration_id"],
            slot_id=row["slot_id"],
            session_id=row["session_id"],
            worker=row["worker"],
            assignment_generation=int(row["assignment_generation"]),
            prompt_message_id=row["prompt_message_id"],
            capability=row["delivery_capability"],
            isolated_session_id=row["isolated_session_id"],
            abort_capability=row["abort_capability"],
            outcome=outcome,
            abort_outcome=abort_outcome,
        )

    def acquire_delivery(
        self, request: ReservationRequest
    ) -> DeliveryAcquisition | None:
        """Atomically resolve retry or create one exact durable send intent."""

        self._assert_authority()
        self._validate_request(request)
        with self._store._daemon_transaction(self._authority) as connection:
            connection.row_factory = sqlite3.Row
            existing = connection.execute(
                "SELECT * FROM opencode_deliveries WHERE transport_id = ?",
                (request.transport_id,),
            ).fetchone()
            if existing is not None:
                if existing["request_fingerprint"] != request.request_fingerprint:
                    raise IdempotencyConflict(request.transport_id)
                state = (
                    AcquisitionState.IN_FLIGHT
                    if existing["delivery_state"] == "in_flight"
                    else AcquisitionState.TERMINAL
                )
                return DeliveryAcquisition(state, self._reservation(existing))
            if not request.candidates:
                return None
            if request.isolated_session_id is not None:
                if request.agent_lifecycle is AgentLifecycle.DISPOSABLE:
                    authority = connection.execute(
                        """SELECT 1 FROM opencode_provisional_sessions
                           WHERE transport_id = ? AND work_id = ?
                             AND request_fingerprint = ? AND session_id = ?
                             AND state = 'bound' AND claim_token = ?
                             AND julianday(claim_started_at) > julianday('now','-30 seconds')""",
                        (
                            request.transport_id, request.work_id,
                            request.request_fingerprint, request.isolated_session_id,
                            request.provisional_claim_token,
                        ),
                    ).fetchone()
                else:
                    authority = connection.execute(
                        """SELECT 1 FROM opencode_persistent_sessions
                           WHERE scope_hash = ? AND session_id = ?
                             AND state = 'active'""",
                        (
                            request.persistent_scope_hash,
                            request.isolated_session_id,
                        ),
                    ).fetchone()
                if authority is None:
                    raise StoreError("session binding authority is absent")
            now = _utc_now()
            candidates = sorted(
                request.candidates,
                key=lambda item: (item.last_used, item.slot_id),
            )
            for candidate in candidates:
                held = connection.execute(
                    """SELECT 1 FROM opencode_deliveries
                       WHERE slot_id = ? AND lease_state IN ('active','aborting')""",
                    (candidate.slot_id,),
                ).fetchone()
                if held is not None:
                    continue
                slot = connection.execute(
                    """SELECT session_id, worker, generation
                       FROM opencode_slot_generations WHERE slot_id = ?
                       ORDER BY generation DESC LIMIT 1""",
                    (candidate.slot_id,),
                ).fetchone()
                if slot is None:
                    generation = 1
                else:
                    generation = int(slot["generation"]) + 1
                    if tuple(slot[:2]) != (candidate.session_id, candidate.worker):
                        self._store._append_event(
                            connection,
                            "opencode_slot",
                            candidate.slot_id,
                            "opencode.slot.rebound",
                            {
                                "generation": generation,
                                "session_id": candidate.session_id,
                                "worker": candidate.worker,
                            },
                            now,
                        )
                connection.execute(
                    """INSERT INTO opencode_slot_generations(
                           slot_id, session_id, worker, generation, updated_at
                       ) VALUES (?, ?, ?, ?, ?)""",
                    (
                        candidate.slot_id,
                        candidate.session_id,
                        candidate.worker,
                        generation,
                        now,
                    ),
                )
                prompt_message_id = _expected_message_id(
                    request.transport_id,
                    request.isolated_session_id or candidate.session_id,
                    generation,
                )
                capability = secrets.token_hex(32)
                connection.execute(
                    """INSERT INTO opencode_deliveries(
                           transport_id, request_fingerprint, work_id, pool,
                           completion_registration_id, callback_registration_id,
                           slot_id, session_id, worker, assignment_generation,
                           prompt_message_id, delivery_capability,
                           isolated_session_id, agent_lifecycle, delivery_state,
                           lease_state, abort_state, created_at, updated_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'in_flight',
                                 'active', 'none', ?, ?)""",
                    (
                        request.transport_id,
                        request.request_fingerprint,
                        request.work_id,
                        request.pool,
                        request.completion_registration_id,
                        request.callback_registration_id,
                        candidate.slot_id,
                        candidate.session_id,
                        candidate.worker,
                        generation,
                        prompt_message_id,
                        capability,
                        request.isolated_session_id,
                        request.agent_lifecycle.value,
                        now,
                        now,
                    ),
                )
                self._store._append_event(
                    connection,
                    "opencode_delivery",
                    request.transport_id,
                    "opencode.delivery.acquired",
                    {
                        "slot_id": candidate.slot_id,
                        "session_id": request.isolated_session_id or candidate.session_id,
                        "generation": generation,
                        "completion_registration_id": request.completion_registration_id,
                        "callback_registration_id": request.callback_registration_id,
                    },
                    now,
                )
                created = connection.execute(
                    "SELECT * FROM opencode_deliveries WHERE transport_id = ?",
                    (request.transport_id,),
                ).fetchone()
                assert created is not None
                if (
                    request.isolated_session_id is not None
                    and request.agent_lifecycle is AgentLifecycle.DISPOSABLE
                ):
                    cursor = connection.execute(
                        """UPDATE opencode_provisional_sessions
                           SET state = 'consumed', claim_token = NULL,
                               claim_started_at = NULL, updated_at = ?
                           WHERE transport_id = ? AND session_id = ?
                             AND state = 'bound' AND claim_token = ?""",
                        (
                            now, request.transport_id, request.isolated_session_id,
                            request.provisional_claim_token,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise StoreError("provisional consume fence is stale")
                return DeliveryAcquisition(
                    AcquisitionState.CREATED, self._reservation(created)
                )
            return None

    def persistent_intent(
        self, request: ReservationRequest, scope_hash: str, worker: str
    ) -> PersistentSession:
        self._assert_authority()
        self._validate_request(request)
        if request.agent_lifecycle is not AgentLifecycle.PERSISTENT:
            raise ValueError("persistent lifecycle is required")
        _identifier(worker, "worker")
        if scope_hash != request.persistent_scope_hash:
            raise ValueError("persistent scope authority changed")
        title = f"fugue-persistent-{scope_hash}"
        with self._store._daemon_transaction(self._authority) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM opencode_persistent_sessions WHERE scope_hash = ?",
                (scope_hash,),
            ).fetchone()
            if row is None:
                now = _utc_now()
                connection.execute(
                    """INSERT INTO opencode_persistent_sessions(
                           scope_hash, pool, worker, title, session_id, state,
                           error, claim_token, claim_started_at, created_at, updated_at
                       ) VALUES (?, ?, ?, ?, NULL, 'intended', NULL, NULL, NULL, ?, ?)""",
                    (scope_hash, request.pool, worker, title, now, now),
                )
                return PersistentSession(
                    scope_hash, request.pool, worker, title, "intended"
                )
            if (
                row["worker"] != worker
                or row["title"] != title
                or row["state"] not in {"intended", "active"}
            ):
                raise StoreError("persistent session authority changed")
            return PersistentSession(
                row["scope_hash"], row["pool"], row["worker"], row["title"],
                row["state"], row["session_id"],
            )

    def claim_persistent(
        self, scope_hash: str, title: str
    ) -> PersistentSession | None:
        self._assert_authority()
        token = secrets.token_hex(32)
        with self._store._daemon_transaction(self._authority) as connection:
            cursor = connection.execute(
                """UPDATE opencode_persistent_sessions
                   SET claim_token = ?, claim_started_at = ?, updated_at = ?
                   WHERE scope_hash = ? AND title = ? AND state = 'intended'
                     AND (claim_token IS NULL OR
                          julianday(claim_started_at) <= julianday('now','-30 seconds'))""",
                (token, _utc_now(), _utc_now(), scope_hash, title),
            )
            if cursor.rowcount != 1:
                return None
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM opencode_persistent_sessions WHERE scope_hash = ?",
                (scope_hash,),
            ).fetchone()
            assert row is not None
            return PersistentSession(
                row["scope_hash"], row["pool"], row["worker"], row["title"],
                row["state"], row["session_id"], token,
            )

    def bind_persistent(
        self, scope_hash: str, title: str, session_id: str, claim_token: str
    ) -> PersistentSession:
        self._assert_authority()
        _identifier(session_id, "persistent_session_id")
        with self._store._daemon_transaction(self._authority) as connection:
            cursor = connection.execute(
                """UPDATE opencode_persistent_sessions
                   SET session_id = ?, state = 'active', error = NULL,
                       claim_token = NULL, claim_started_at = NULL, updated_at = ?
                   WHERE scope_hash = ? AND title = ? AND state = 'intended'
                     AND session_id IS NULL AND claim_token = ?
                     AND julianday(claim_started_at) > julianday('now','-30 seconds')""",
                (session_id, _utc_now(), scope_hash, title, claim_token),
            )
            if cursor.rowcount != 1:
                raise StoreError("persistent session bind fence is stale")
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM opencode_persistent_sessions WHERE scope_hash = ?",
                (scope_hash,),
            ).fetchone()
            assert row is not None
            return PersistentSession(
                row["scope_hash"], row["pool"], row["worker"], row["title"],
                row["state"], row["session_id"],
            )

    def claim_persistent_close(
        self, scope_hash: str
    ) -> PersistentSession | None:
        """Fence deletion of one exact retained root after every delivery releases it."""

        self._assert_authority()
        if (
            type(scope_hash) is not str
            or len(scope_hash) != 64
            or any(character not in "0123456789abcdef" for character in scope_hash)
        ):
            raise ValueError("persistent scope authority is invalid")
        token = secrets.token_hex(32)
        with self._store._daemon_transaction(self._authority) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM opencode_persistent_sessions WHERE scope_hash = ?",
                (scope_hash,),
            ).fetchone()
            if row is None:
                raise StoreError("persistent session authority is absent")
            if row["state"] in {"closed", "attention"}:
                return PersistentSession(
                    row["scope_hash"], row["pool"], row["worker"], row["title"],
                    row["state"], row["session_id"],
                )
            if row["state"] != "active" or type(row["session_id"]) is not str:
                return None
            busy = connection.execute(
                """SELECT 1 FROM opencode_deliveries
                   WHERE isolated_session_id = ?
                     AND agent_lifecycle = 'persistent'
                     AND lease_state != 'released'
                   LIMIT 1""",
                (row["session_id"],),
            ).fetchone()
            if busy is not None:
                return None
            cursor = connection.execute(
                """UPDATE opencode_persistent_sessions
                   SET claim_token = ?, claim_started_at = ?, error = NULL, updated_at = ?
                   WHERE scope_hash = ? AND state = 'active'
                     AND session_id = ?
                     AND (claim_token IS NULL OR
                          julianday(claim_started_at) <= julianday('now','-30 seconds'))""",
                (
                    token, _utc_now(), _utc_now(), scope_hash, row["session_id"],
                ),
            )
            if cursor.rowcount != 1:
                return None
            return PersistentSession(
                row["scope_hash"], row["pool"], row["worker"], row["title"],
                "active", row["session_id"], token,
            )

    def finish_persistent_close(
        self, scope_hash: str, title: str, session_id: str, claim_token: str,
        state: str, error: str | None,
    ) -> PersistentSession:
        """Commit one close result only under the exact active close claim."""

        self._assert_authority()
        if state not in {"active", "closed", "attention"}:
            raise ValueError("persistent close state is invalid")
        _identifier(session_id, "persistent_session_id")
        if type(title) is not str or not title or len(title) > 256:
            raise ValueError("persistent session title is invalid")
        if (
            type(claim_token) is not str
            or len(claim_token) != 64
            or any(character not in "0123456789abcdef" for character in claim_token)
        ):
            raise ValueError("persistent close claim is invalid")
        if state == "closed":
            if error is not None:
                raise ValueError("closed persistent session cannot retain an error")
        elif type(error) is not str or not error or len(error) > 128:
            raise ValueError("persistent close error is invalid")
        with self._store._daemon_transaction(self._authority) as connection:
            cursor = connection.execute(
                """UPDATE opencode_persistent_sessions
                   SET state = ?, error = ?, claim_token = NULL,
                       claim_started_at = NULL, updated_at = ?
                   WHERE scope_hash = ? AND title = ? AND session_id = ?
                     AND state = 'active' AND claim_token = ?""",
                (
                    state, error, _utc_now(), scope_hash, title, session_id, claim_token,
                ),
            )
            if cursor.rowcount != 1:
                raise StoreError("persistent close fence is stale")
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM opencode_persistent_sessions WHERE scope_hash = ?",
                (scope_hash,),
            ).fetchone()
            assert row is not None
            return PersistentSession(
                row["scope_hash"], row["pool"], row["worker"], row["title"],
                row["state"], row["session_id"],
            )

    def provisional_intent(self, request: ReservationRequest) -> ProvisionalSession:
        self._assert_authority()
        self._validate_request(request)
        with self._store._daemon_transaction(self._authority) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM opencode_provisional_sessions WHERE transport_id = ?",
                (request.transport_id,),
            ).fetchone()
            if row is not None:
                if (
                    row["work_id"] != request.work_id
                    or row["pool"] != request.pool
                    or row["request_fingerprint"] != request.request_fingerprint
                    or row["completion_registration_id"]
                    != request.completion_registration_id
                    or row["callback_registration_id"]
                    != request.callback_registration_id
                ):
                    raise IdempotencyConflict(request.transport_id)
                if row["state"] != "cleaned":
                    return ProvisionalSession(
                        row["transport_id"], row["title"], row["state"],
                        row["session_id"],
                    )
                connection.execute(
                    "DELETE FROM opencode_provisional_sessions WHERE transport_id = ?",
                    (request.transport_id,),
                )
            token = secrets.token_hex(16)
            title = "oc-rig-review-" + hashlib.sha256(
                f"{request.transport_id}:{token}".encode()
            ).hexdigest()[:32]
            now = _utc_now()
            connection.execute(
                """INSERT INTO opencode_provisional_sessions(
                       transport_id, work_id, pool, request_fingerprint,
                       completion_registration_id, callback_registration_id,
                       title, session_id, state, error, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'intended', NULL, ?, ?)""",
                (
                    request.transport_id, request.work_id, request.pool,
                    request.request_fingerprint, request.completion_registration_id,
                    request.callback_registration_id, title, now, now,
                ),
            )
            return ProvisionalSession(request.transport_id, title, "intended")

    def claim_provisional(
        self, request: ReservationRequest, title: str
    ) -> ProvisionalSession | None:
        self._assert_authority()
        self._validate_request(request)
        token = secrets.token_hex(32)
        with self._store._daemon_transaction(self._authority) as connection:
            cursor = connection.execute(
                """UPDATE opencode_provisional_sessions
                   SET claim_token = ?, claim_started_at = ?, updated_at = ?
                   WHERE transport_id = ? AND title = ?
                     AND state IN ('intended','bound')
                     AND (claim_token IS NULL OR
                          julianday(claim_started_at) <= julianday('now','-30 seconds'))""",
                (token, _utc_now(), _utc_now(), request.transport_id, title),
            )
            if cursor.rowcount != 1:
                return None
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM opencode_provisional_sessions WHERE transport_id = ?",
                (request.transport_id,),
            ).fetchone()
            assert row is not None
            return ProvisionalSession(
                row["transport_id"], row["title"], row["state"],
                row["session_id"], token,
            )

    def bind_provisional(
        self, request: ReservationRequest, title: str, session_id: str,
        claim_token: str,
    ) -> ProvisionalSession:
        self._assert_authority()
        self._validate_request(request)
        _identifier(session_id, "isolated_session_id")
        with self._store._daemon_transaction(self._authority) as connection:
            row = connection.execute(
                """SELECT session_id, state FROM opencode_provisional_sessions
                   WHERE transport_id = ? AND work_id = ? AND request_fingerprint = ?
                     AND title = ?""",
                (request.transport_id, request.work_id, request.request_fingerprint, title),
            ).fetchone()
            if row is None or row[1] not in {"intended", "bound"}:
                raise StoreError("provisional session authority is stale")
            if row[0] is not None and row[0] != session_id:
                raise StoreError("provisional session binding changed")
            cursor = connection.execute(
                """UPDATE opencode_provisional_sessions
                   SET session_id = ?, state = 'bound', error = NULL, updated_at = ?
                   WHERE transport_id = ? AND claim_token = ?
                     AND julianday(claim_started_at) > julianday('now','-30 seconds')""",
                (session_id, _utc_now(), request.transport_id, claim_token),
            )
            if cursor.rowcount != 1:
                raise StoreError("provisional session bind fence is stale")
            return ProvisionalSession(
                request.transport_id, title, "bound", session_id, claim_token
            )

    def mark_provisional(
        self, request: ReservationRequest, title: str, state: str, error: str | None,
        claim_token: str,
    ) -> None:
        self._assert_authority()
        if state not in {"cleanup", "cleaned", "attention"}:
            raise ValueError("provisional state is invalid")
        with self._store._daemon_transaction(self._authority) as connection:
            cursor = connection.execute(
                """UPDATE opencode_provisional_sessions
                   SET state = ?, error = ?,
                       claim_token = CASE WHEN ? = 'cleanup' THEN claim_token ELSE NULL END,
                       claim_started_at = CASE WHEN ? = 'cleanup' THEN claim_started_at ELSE NULL END,
                       updated_at = ?
                   WHERE transport_id = ? AND title = ?
                     AND state IN ('intended','bound','cleanup')
                     AND claim_token = ?
                     AND julianday(claim_started_at) > julianday('now','-30 seconds')""",
                (
                    state, error, state, state, _utc_now(), request.transport_id,
                    title, claim_token,
                ),
            )
            if cursor.rowcount != 1:
                raise StoreError("provisional session authority is stale")

    def outstanding_provisionals(
        self, limit: int
    ) -> tuple[ProvisionalSession, ...]:
        self._assert_authority()
        if type(limit) is not int or not 1 <= limit <= 32:
            raise ValueError("provisional reconciliation limit is invalid")
        with self._store._daemon_transaction(self._authority) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """SELECT transport_id, title, state, session_id
                   FROM opencode_provisional_sessions
                   WHERE state IN ('intended','bound','cleanup')
                     AND (claim_token IS NULL OR
                          julianday(claim_started_at) <= julianday('now','-30 seconds'))
                   ORDER BY created_at, transport_id LIMIT ?""",
                (limit,),
            ).fetchall()
            claimed: list[ProvisionalSession] = []
            for row in rows:
                token = secrets.token_hex(32)
                cursor = connection.execute(
                    """UPDATE opencode_provisional_sessions
                       SET claim_token = ?, claim_started_at = ?, updated_at = ?
                       WHERE transport_id = ? AND state = ?
                         AND (claim_token IS NULL OR
                              julianday(claim_started_at) <= julianday('now','-30 seconds'))""",
                    (token, _utc_now(), _utc_now(), row["transport_id"], row["state"]),
                )
                if cursor.rowcount == 1:
                    claimed.append(ProvisionalSession(
                        row["transport_id"], row["title"], row["state"],
                        row["session_id"], token,
                    ))
            return tuple(claimed)

    def bind_outstanding_provisional(
        self, transport_id: str, title: str, session_id: str, claim_token: str
    ) -> ProvisionalSession:
        self._assert_authority()
        _identifier(transport_id, "transport_id")
        _identifier(session_id, "isolated_session_id")
        with self._store._daemon_transaction(self._authority) as connection:
            cursor = connection.execute(
                """UPDATE opencode_provisional_sessions
                   SET session_id = ?, state = 'bound', error = NULL, updated_at = ?
                   WHERE transport_id = ? AND title = ? AND state = 'intended'
                     AND session_id IS NULL AND claim_token = ?
                     AND julianday(claim_started_at) > julianday('now','-30 seconds')""",
                (session_id, _utc_now(), transport_id, title, claim_token),
            )
            if cursor.rowcount != 1:
                raise StoreError("provisional reconciliation authority is stale")
            return ProvisionalSession(
                transport_id, title, "bound", session_id, claim_token
            )

    def mark_outstanding_provisional(
        self, transport_id: str, title: str, state: str, error: str | None,
        claim_token: str,
    ) -> None:
        self._assert_authority()
        if state not in {"cleaned", "attention"}:
            raise ValueError("provisional reconciliation state is invalid")
        with self._store._daemon_transaction(self._authority) as connection:
            cursor = connection.execute(
                """UPDATE opencode_provisional_sessions
                   SET state = ?, error = ?, claim_token = NULL,
                       claim_started_at = NULL, updated_at = ?
                   WHERE transport_id = ? AND title = ?
                     AND state IN ('intended','bound','cleanup')
                     AND claim_token = ?
                     AND julianday(claim_started_at) > julianday('now','-30 seconds')""",
                (state, error, _utc_now(), transport_id, title, claim_token),
            )
            if cursor.rowcount != 1:
                raise StoreError("provisional reconciliation authority is stale")

    def release_provisional_claim(
        self, transport_id: str, title: str, claim_token: str
    ) -> None:
        self._assert_authority()
        with self._store._daemon_transaction(self._authority) as connection:
            cursor = connection.execute(
                """UPDATE opencode_provisional_sessions
                   SET claim_token = NULL, claim_started_at = NULL, updated_at = ?
                   WHERE transport_id = ? AND title = ? AND claim_token = ?
                     AND state IN ('intended','bound','cleanup')""",
                (_utc_now(), transport_id, title, claim_token),
            )
            if cursor.rowcount != 1:
                raise StoreError("provisional claim release is stale")

    def record_outcome(
        self, reservation: DurableReservation, result: AdapterResult
    ) -> AdapterResult:
        self._assert_authority()
        if type(reservation) is not DurableReservation or type(result) is not AdapterResult:
            raise TypeError("exact durable outcome required")
        if result.acknowledgement_id is not None:
            _identifier(result.acknowledgement_id, "acknowledgement_id")
        if result.error_code is not None:
            _identifier(result.error_code, "error_code")
        with self._store._daemon_transaction(self._authority) as connection:
            connection.row_factory = sqlite3.Row
            row = self._exact_row(connection, reservation)
            if row["delivery_state"] != "in_flight":
                return self._reservation(row).outcome or result
            now = _utc_now()
            target = result.disposition.value
            connection.execute(
                """UPDATE opencode_deliveries
                   SET delivery_state = ?, acknowledgement_id = ?, error_code = ?,
                       updated_at = ?, finished_at = ?
                   WHERE transport_id = ? AND delivery_state = 'in_flight'""",
                (
                    target,
                    result.acknowledgement_id,
                    result.error_code,
                    now,
                    now,
                    reservation.transport_id,
                ),
            )
            if result.disposition in {
                AdapterDisposition.DEFINITE_FAILED,
                AdapterDisposition.CANCELLED,
            }:
                connection.execute(
                    """UPDATE opencode_deliveries SET lease_state = 'released'
                       WHERE transport_id = ? AND lease_state = 'active'""",
                    (reservation.transport_id,),
                )
            self._store._append_event(
                connection,
                "opencode_delivery",
                reservation.transport_id,
                f"opencode.delivery.{target}",
                {
                    "acknowledgement_id": result.acknowledgement_id,
                    "error_code": result.error_code,
                },
                now,
            )
            return result

    def acquire_abort(self, transport_id: str) -> AbortAcquisition | None:
        self._assert_authority()
        _identifier(transport_id, "transport_id")
        with self._store._daemon_transaction(self._authority) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM opencode_deliveries WHERE transport_id = ?",
                (transport_id,),
            ).fetchone()
            if row is None:
                return None
            if row["abort_state"] == "in_flight":
                return AbortAcquisition(
                    AcquisitionState.IN_FLIGHT, self._reservation(row)
                )
            if row["abort_state"] == "terminal":
                return AbortAcquisition(
                    AcquisitionState.TERMINAL, self._reservation(row)
                )
            if row["lease_state"] == "released":
                return None
            if (
                row["lease_state"] != "active"
                or row["delivery_state"] not in {"accepted", "delivery_unknown"}
            ):
                return None
            now = _utc_now()
            capability = secrets.token_hex(32)
            cursor = connection.execute(
                """UPDATE opencode_deliveries
                   SET lease_state = 'aborting', abort_state = 'in_flight',
                       abort_capability = ?, abort_started_at = ?, updated_at = ?
                   WHERE transport_id = ? AND lease_state = 'active'
                     AND abort_state = 'none'
                     AND delivery_state IN ('accepted','delivery_unknown')""",
                (capability, now, now, transport_id),
            )
            if cursor.rowcount != 1:
                raise StoreError("opencode abort acquisition lost authority")
            self._store._append_event(
                connection,
                "opencode_delivery",
                transport_id,
                "opencode.abort.acquired",
                {
                    "slot_id": row["slot_id"],
                    "generation": int(row["assignment_generation"]),
                },
                now,
            )
            acquired = connection.execute(
                "SELECT * FROM opencode_deliveries WHERE transport_id = ?",
                (transport_id,),
            ).fetchone()
            assert acquired is not None
            return AbortAcquisition(
                AcquisitionState.CREATED, self._reservation(acquired)
            )

    def revalidate_abort(self, reservation: DurableReservation) -> bool:
        self._assert_authority()
        if type(reservation) is not DurableReservation or reservation.abort_capability is None:
            return False
        with self._store._daemon_read_transaction(self._authority) as connection:
            row = connection.execute(
                """SELECT 1 FROM opencode_deliveries
                   WHERE transport_id = ? AND slot_id = ? AND session_id = ?
                     AND assignment_generation = ? AND delivery_capability = ?
                     AND abort_capability = ? AND lease_state = 'aborting'
                     AND abort_state = 'in_flight'""",
                (
                    reservation.transport_id,
                    reservation.slot_id,
                    reservation.session_id,
                    reservation.assignment_generation,
                    reservation.capability,
                    reservation.abort_capability,
                ),
            ).fetchone()
            return row is not None

    def record_abort(
        self, reservation: DurableReservation, result: AdapterResult
    ) -> AdapterResult:
        self._assert_authority()
        if type(reservation) is not DurableReservation or type(result) is not AdapterResult:
            raise TypeError("exact durable abort outcome required")
        if result.disposition is AdapterDisposition.ACCEPTED or result.error_code is None:
            raise ValueError("abort outcome is invalid")
        _identifier(result.error_code, "error_code")
        with self._store._daemon_transaction(self._authority) as connection:
            connection.row_factory = sqlite3.Row
            row = self._exact_row(connection, reservation, abort=True)
            if row["abort_state"] == "terminal":
                return self._reservation(row).abort_outcome or result
            if row["abort_state"] != "in_flight" or row["lease_state"] != "aborting":
                raise StoreError("opencode abort intent is not active")
            now = _utc_now()
            connection.execute(
                """UPDATE opencode_deliveries
                   SET abort_state = 'terminal', abort_disposition = ?,
                       abort_error_code = ?, updated_at = ?, abort_finished_at = ?
                   WHERE transport_id = ? AND abort_state = 'in_flight'
                     AND lease_state = 'aborting'""",
                (
                    result.disposition.value,
                    result.error_code,
                    now,
                    now,
                    reservation.transport_id,
                ),
            )
            if (
                result.disposition is AdapterDisposition.CANCELLED
                and reservation.isolated_session_id is not None
            ):
                # Disposable-session cleanup is guarded by the scheduler and
                # scope release join.  Keep the OpenCode lease fenced until the
                # controller commits those releases in the same transaction.
                lease_state = None
            elif result.disposition is AdapterDisposition.CANCELLED:
                lease_state = "released"
            elif result.disposition is AdapterDisposition.DEFINITE_FAILED:
                lease_state = "active"
            else:
                lease_state = None
            if lease_state is not None:
                connection.execute(
                    """UPDATE opencode_deliveries SET lease_state = ?
                       WHERE transport_id = ? AND lease_state = 'aborting'""",
                    (lease_state, reservation.transport_id),
                )
            self._store._append_event(
                connection,
                "opencode_delivery",
                reservation.transport_id,
                f"opencode.abort.{result.disposition.value}",
                {"error_code": result.error_code},
                now,
            )
            return result

    def release_completed(self, registration: DispatchRegistration) -> bool:
        """Release only the exact completed registration and current generation."""

        self._assert_authority()
        with self._store._daemon_transaction(self._authority) as connection:
            return self.release_completed_in_transaction(connection, registration)

    def release_completed_in_transaction(
        self,
        connection: sqlite3.Connection,
        registration: DispatchRegistration,
    ) -> bool:
        """Release within the caller's exact durable completion transaction."""

        self._assert_authority()
        if (
            not isinstance(connection, sqlite3.Connection)
            or not connection.in_transaction
        ):
            raise RuntimeError("an active daemon transaction is required")
        if type(registration) is not DispatchRegistration:
            raise TypeError("exact DispatchRegistration required")
        if registration.idempotency_key != registration.transport_id:
            raise ValueError("completion registration authority is invalid")
        now = _utc_now()
        completion_won_abort = connection.execute(
            """SELECT 1
               FROM opencode_deliveries AS opencode
               JOIN transport_deliveries AS delivery
                 ON delivery.id = opencode.transport_id
               JOIN transport_completion_registrations AS completion
                 ON completion.id = opencode.completion_registration_id
                AND completion.transport_id = delivery.id
               JOIN scheduler_assignments AS assignment
                 ON assignment.id = delivery.assignment_id
               JOIN scope_claims AS claim ON claim.id = delivery.scope_claim_id
               WHERE opencode.transport_id = ? AND opencode.work_id = ?
                 AND opencode.completion_registration_id = ?
                 AND opencode.callback_registration_id = ?
                 AND coalesce(opencode.isolated_session_id, opencode.session_id) = ?
                 AND opencode.assignment_generation = ?
                 AND opencode.prompt_message_id = ?
                 AND opencode.lease_state = 'aborting'
                 AND opencode.abort_state = 'in_flight'
                 AND opencode.abort_disposition IS NULL
                 AND opencode.abort_error_code IS NULL
                 AND completion.state = 'completed'
                 AND assignment.state = 'released'
                 AND assignment.release_outcome = 'completed'
                 AND claim.state = 'released'""",
            (
                registration.transport_id,
                registration.work_id,
                registration.completion_registration_id,
                registration.callback_registration_id,
                registration.session_id,
                registration.generation,
                registration.prompt_message_id,
            ),
        ).fetchone()
        if completion_won_abort is not None:
            cursor = connection.execute(
                """UPDATE opencode_deliveries
                   SET lease_state = 'released', abort_state = 'terminal',
                       abort_disposition = 'definite_failed',
                       abort_error_code = 'completion_won_abort_race',
                       abort_finished_at = ?, updated_at = ?
                   WHERE transport_id = ? AND work_id = ?
                     AND completion_registration_id = ?
                     AND callback_registration_id = ?
                     AND coalesce(isolated_session_id, session_id) = ?
                     AND assignment_generation = ? AND prompt_message_id = ?
                     AND lease_state = 'aborting' AND abort_state = 'in_flight'
                     AND abort_disposition IS NULL AND abort_error_code IS NULL
                     AND delivery_state IN ('accepted','delivery_unknown')""",
                (
                    now,
                    now,
                    registration.transport_id,
                    registration.work_id,
                    registration.completion_registration_id,
                    registration.callback_registration_id,
                    registration.session_id,
                    registration.generation,
                    registration.prompt_message_id,
                ),
            )
        else:
            cursor = connection.execute(
                """UPDATE opencode_deliveries SET lease_state = 'released', updated_at = ?
               WHERE transport_id = ? AND work_id = ?
                 AND completion_registration_id = ?
                 AND callback_registration_id = ?
                 AND coalesce(isolated_session_id, session_id) = ?
                 AND assignment_generation = ? AND prompt_message_id = ?
                 AND lease_state = 'active'
                 AND (
                     abort_state = 'none' OR
                     (abort_state = 'terminal' AND
                      abort_disposition = 'definite_failed')
                 )
                 AND delivery_state IN ('accepted','delivery_unknown')""",
                (
                    now,
                    registration.transport_id,
                    registration.work_id,
                    registration.completion_registration_id,
                    registration.callback_registration_id,
                    registration.session_id,
                    registration.generation,
                    registration.prompt_message_id,
                ),
            )
        if cursor.rowcount != 1:
            return False
        self._store._append_event(
            connection,
            "opencode_delivery",
            registration.transport_id,
            "opencode.delivery.completed",
            {
                "completion_registration_id": (
                    registration.completion_registration_id
                ),
                "generation": registration.generation,
            },
            now,
        )
        return True

    def acquire_session_cleanup(self) -> SessionCleanup | None:
        self._assert_authority()
        with self._store._daemon_transaction(self._authority) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute(
                """UPDATE opencode_deliveries SET cleanup_state = 'ambiguous',
                          cleanup_error = 'cleanup_interrupted'
                   WHERE cleanup_state = 'in_flight'"""
            )
            row = connection.execute(
                """SELECT transport_id, isolated_session_id, cleanup_attempts
                   FROM opencode_deliveries
                   WHERE cleanup_state IN ('pending','ambiguous')
                     AND agent_lifecycle = 'disposable'
                     AND cleanup_attempts < 3
                   ORDER BY updated_at, transport_id LIMIT 1"""
            ).fetchone()
            if row is None:
                return None
            attempt = int(row["cleanup_attempts"]) + 1
            connection.execute(
                """UPDATE opencode_deliveries
                   SET cleanup_state = 'in_flight', cleanup_attempts = ?,
                       cleanup_error = NULL, updated_at = ?
                   WHERE transport_id = ?
                     AND cleanup_state IN ('pending','ambiguous')""",
                (attempt, _utc_now(), row["transport_id"]),
            )
            session_id = str(row["isolated_session_id"])
            key = (
                f"{row['transport_id']}:cleanup:"
                + hashlib.sha256(session_id.encode()).hexdigest()[:16]
            )
            return SessionCleanup(str(row["transport_id"]), session_id, key, attempt)

    def record_session_cleanup(
        self, cleanup: SessionCleanup, state: str, error: str | None
    ) -> None:
        self._assert_authority()
        if type(cleanup) is not SessionCleanup or state not in {
            "succeeded", "ambiguous", "failed"
        }:
            raise TypeError("exact cleanup outcome required")
        with self._store._daemon_transaction(self._authority) as connection:
            cursor = connection.execute(
                """UPDATE opencode_deliveries
                   SET cleanup_state = ?, cleanup_error = ?, updated_at = ?
                   WHERE transport_id = ? AND isolated_session_id = ?
                     AND agent_lifecycle = 'disposable'
                     AND cleanup_state = 'in_flight'
                     AND cleanup_attempts = ?""",
                (
                    state, error, _utc_now(), cleanup.transport_id,
                    cleanup.session_id, cleanup.attempt,
                ),
            )
            if cursor.rowcount != 1:
                raise StoreError("isolated cleanup authority is stale")

    def session_cleanup_attention(self) -> bool:
        self._assert_authority()
        with self._store._daemon_read_transaction(self._authority) as connection:
            return connection.execute(
                """SELECT 1 FROM opencode_deliveries
                   WHERE cleanup_state = 'failed'
                      OR (cleanup_state = 'ambiguous' AND cleanup_attempts >= 3)
                   UNION ALL
                   SELECT 1 FROM opencode_provisional_sessions
                   WHERE state = 'attention'
                   LIMIT 1"""
            ).fetchone() is not None

    def registration_for_transport(
        self, transport_id: str
    ) -> DispatchRegistration | None:
        """Return only a monitorable exact durable registration."""

        self._assert_authority()
        _identifier(transport_id, "transport_id")
        with self._store._daemon_read_transaction(self._authority) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """SELECT * FROM opencode_deliveries
                   WHERE transport_id = ?
                     AND delivery_state IN ('in_flight','accepted','delivery_unknown')
                     AND lease_state IN ('active','aborting')""",
                (transport_id,),
            ).fetchone()
            return self._reservation(row).registration() if row is not None else None

    def monitor_registrations(self) -> tuple[DispatchRegistration, ...]:
        """Load restart-safe registrations without changing or resending delivery."""

        self._assert_authority()
        with self._store._daemon_read_transaction(self._authority) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """SELECT delivery.* FROM opencode_deliveries AS delivery
                   JOIN transport_completion_registrations AS completion
                     ON completion.id = delivery.completion_registration_id
                    AND completion.transport_id = delivery.transport_id
                   WHERE delivery.delivery_state IN (
                             'in_flight','accepted','delivery_unknown'
                         )
                     AND delivery.lease_state IN ('active','aborting')
                     AND completion.state IN ('pending','completed')
                   ORDER BY delivery.created_at, delivery.transport_id"""
            ).fetchall()
            return tuple(self._reservation(row).registration() for row in rows)

    @staticmethod
    def _exact_row(
        connection: sqlite3.Connection,
        reservation: DurableReservation,
        *,
        abort: bool = False,
    ) -> sqlite3.Row:
        row = connection.execute(
            """SELECT * FROM opencode_deliveries
               WHERE transport_id = ? AND slot_id = ? AND session_id = ?
                 AND isolated_session_id IS ?
                 AND worker = ? AND assignment_generation = ?
                 AND prompt_message_id = ? AND delivery_capability = ?""",
            (
                reservation.transport_id,
                reservation.slot_id,
                reservation.session_id,
                reservation.isolated_session_id,
                reservation.worker,
                reservation.assignment_generation,
                reservation.prompt_message_id,
                reservation.capability,
            ),
        ).fetchone()
        if (
            row is None
            or (
                abort
                and (
                    reservation.abort_capability is None
                    or row["abort_capability"] != reservation.abort_capability
                )
            )
        ):
            raise StoreError("opencode durable capability is stale")
        return row


def _create_opencode_reservations(
    store: RigStore,
    authority: _DaemonAuthority,
    capability: object,
) -> _RigStoreOpenCodeReservations:
    """Daemon-internal constructor; intentionally absent from package exports."""

    if type(store) is not RigStore or type(authority) is not _DaemonAuthority:
        raise TypeError("exact daemon store authority required")
    authority._assert_for(store)
    service = object.__new__(_RigStoreOpenCodeReservations)
    object.__setattr__(service, "_store", store)
    object.__setattr__(service, "_authority", authority)
    object.__setattr__(service, "_capability_id", id(capability))
    return service


def _create_daemon_live_opencode_adapter(
    store: RigStore,
    authority: _DaemonAuthority,
    capability: object,
    config: LiveOpenCodeAdapterConfig,
) -> LiveOpenCodeAdapter:
    """Production factory retained for a future explicit daemon integration."""

    reservations = _create_opencode_reservations(store, authority, capability)
    return LiveOpenCodeAdapter._construct(
        _DAEMON_CONSTRUCTION_TOKEN,
        config,
        reservations=reservations,
    )
