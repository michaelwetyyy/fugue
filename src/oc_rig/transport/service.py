"""Daemon-private durable transport coordinator."""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Mapping
from typing import Any

from oc_rig.adapters import (
    AdapterPort,
    AdapterRequest,
    AdapterResult,
    NoCancellation,
    PreparedAdapterPort,
    ProcessIdentity,
)
from oc_rig.completion.service import _CompletionService
from oc_rig.policy.capsule import (
    MAX_SCOPE_ENVELOPE_BYTES,
    ScopeCapsuleError,
    parse_capsule_prompt,
    parse_task_prompt,
)
from oc_rig.policy.models import AgentLifecycle
from oc_rig.policy.scanner import scan_content
from oc_rig.scheduler.models import Lane
from oc_rig.store.database import (
    IdempotencyConflict,
    OwnershipConflict,
    RigStore,
    _DaemonAuthority,
    _identifier,
    _json,
    _utc_now,
)
from oc_rig.transport.models import TransportReceipt, TransportState


MAX_TRANSPORT_PAYLOAD_BYTES = 64 * 1024
MAX_ADAPTER_OUTPUT_BYTES = 16 * 1024


class _TransportService:
    """Transport mutation surface instantiated only by the durable daemon."""

    __slots__ = (
        "store",
        "_adapter",
        "_authority",
        "_capability_id",
        "_clock",
        "_completion",
        "_completion_registration",
    )

    def __new__(cls, *_args: object, **_kwargs: object) -> "_TransportService":
        raise PermissionError("transport services are created only by rigd")

    def _assert_authority(self, capability: object) -> None:
        if id(capability) != self._capability_id:
            raise PermissionError("transport mutation requires the daemon dispatch capability")
        self._authority._assert_for(self.store)

    def prepare(
        self,
        capability: object,
        connection: sqlite3.Connection,
        *,
        idempotency_key: str,
        fingerprint: str,
        work_id: str,
        pool: Lane,
        payload: Mapping[str, Any],
        reservation_id: str | None = None,
        reservation_attempt: int | None = None,
        reservation_fence: str | None = None,
        local_codex_thread_id: str | None = None,
    ) -> TransportReceipt:
        self._assert_authority(capability)
        _identifier(idempotency_key, "idempotency_key")
        _identifier(work_id, "work_id")
        if not isinstance(pool, Lane):
            raise TypeError("pool must be a Lane")
        if "agent_lifecycle" in payload or "allow_child_agents" in payload:
            raise ValueError(
                "transport callers cannot assert admitted agent policy"
            )
        binding = (reservation_id, reservation_attempt, reservation_fence)
        if any(value is not None for value in binding):
            if any(value is None for value in binding):
                raise ValueError("reservation binding must be complete")
            _identifier(reservation_id, "reservation_id")
            _identifier(reservation_fence, "reservation_fence")
            if type(reservation_attempt) is not int or reservation_attempt <= 0:
                raise ValueError("reservation_attempt must be a positive integer")
        payload_json = _json(dict(payload))
        if len(payload_json.encode("utf-8")) > MAX_TRANSPORT_PAYLOAD_BYTES:
            raise ValueError("transport payload exceeds the bounded limit")
        existing = connection.execute(
            "SELECT * FROM transport_deliveries WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        if existing is not None:
            if existing["request_fingerprint"] != fingerprint:
                raise IdempotencyConflict(idempotency_key)
            return self._receipt(connection, existing)
        authority = connection.execute(
            """SELECT assignment.id, assignment.owner_id, assignment.attempt,
                      assignment.fence_token, work.policy_decision_id,
                      decision.scope_claim_id, decision.scope_claim_attempt,
                      decision.scope_claim_fence, decision.content_hash,
                      claim.scope_key
               FROM scheduler_work AS work
               JOIN scheduler_assignments AS assignment
                 ON assignment.id = work.active_assignment_id
                AND assignment.work_id = work.id
                AND assignment.state = 'active'
               JOIN scheduler_admission_decisions AS decision
                 ON decision.id = work.policy_decision_id
                AND decision.work_id = work.id
                AND decision.allowed = 1
               JOIN scope_claims AS claim
                 ON claim.id = decision.scope_claim_id
                AND claim.state = 'active'
                AND claim.attempt = decision.scope_claim_attempt
                AND claim.fence_token = decision.scope_claim_fence
               WHERE work.id = ? AND work.lane = ? AND work.state = 'assigned'
                 AND work.policy_allowed = 1""",
            (work_id, pool.value),
        ).fetchone()
        if authority is None:
            raise OwnershipConflict("transport requires an exact active admitted assignment")
        if reservation_id is not None and (
            authority[0], int(authority[2]), authority[3]
        ) != (reservation_id, reservation_attempt, reservation_fence):
            raise OwnershipConflict(
                "transport reservation generation does not match the active assignment"
            )
        prompt = payload.get("prompt")
        if type(prompt) is not str or scan_content(prompt).content_hash != authority[8]:
            raise OwnershipConflict(
                "transport prompt does not match the exact admitted worker instructions"
            )
        try:
            decoded_prompt = parse_capsule_prompt(prompt)
            task_prompt = (
                parse_task_prompt(prompt) if decoded_prompt is None else None
            )
        except ScopeCapsuleError:
            raise OwnershipConflict("transport scope capsule is invalid") from None
        scope_prompt = decoded_prompt or task_prompt
        if scope_prompt is not None:
            capsule_binding = (
                scope_prompt["claim_scope_hash"],
                scope_prompt["scope_capsule"]["manifest"]["scope_hash"],
            )
            if (
                capsule_binding[0] != authority[9]
                or payload.get("classification") != "PUBLIC"
                or len(prompt.encode("utf-8")) > MAX_SCOPE_ENVELOPE_BYTES
            ):
                raise OwnershipConflict(
                    "transport scope capsule does not match the admitted scope"
                )
        now = self._clock()
        transport_id = f"transport-{uuid.uuid4().hex}"
        completion_id = f"completion-registration-{uuid.uuid4().hex}"
        callback_id = f"callback-registration-{uuid.uuid4().hex}"
        route_id = f"return-route-{uuid.uuid4().hex}"
        connection.execute(
            """INSERT INTO transport_deliveries(
                   id, idempotency_key, request_fingerprint, work_id, pool,
                   assignment_id, owner_id, assignment_attempt, assignment_fence,
                   admission_decision_id, scope_claim_id, scope_claim_attempt,
                   scope_claim_fence, adapter_kind, payload_json, state,
                   created_at, updated_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                         'reserved', ?, ?)""",
            (
                transport_id,
                idempotency_key,
                fingerprint,
                work_id,
                pool.value,
                authority[0],
                authority[1],
                int(authority[2]),
                authority[3],
                authority[4],
                authority[5],
                int(authority[6]),
                authority[7],
                "disabled",
                payload_json,
                now,
                now,
            ),
        )
        if self._adapter.kind != "disabled":
            connection.execute(
                """INSERT INTO transport_adapter_selections(
                       transport_id, adapter_kind, selected_at
                   ) VALUES (?, ?, ?)""",
                (transport_id, self._adapter.kind, now),
            )
        self.store._append_event(
            connection,
            "transport",
            transport_id,
            "transport.reserved",
            {
                "work_id": work_id,
                "pool": pool.value,
                "adapter_kind": self._adapter.kind,
                "assignment_id": authority[0],
                "assignment_attempt": int(authority[2]),
                "assignment_fence": authority[3],
                "scope_claim_id": authority[5],
                "scope_claim_attempt": int(authority[6]),
                "scope_claim_fence": authority[7],
            },
            now,
        )
        connection.execute(
            """INSERT INTO transport_completion_registrations(
                   id, transport_id, work_id, assignment_id, assignment_attempt,
                   assignment_fence, registration_key, state, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
            (
                completion_id,
                transport_id,
                work_id,
                authority[0],
                int(authority[2]),
                authority[3],
                f"completion:{transport_id}",
                now,
            ),
        )
        self._completion.register_route(
            capability,
            connection,
            route_id=route_id,
            transport_id=transport_id,
            completion_registration_id=completion_id,
            work_id=work_id,
            generation=int(authority[2]),
            assignment_id=authority[0],
            assignment_fence=authority[3],
            scope_claim_id=authority[5],
            scope_claim_attempt=int(authority[6]),
            scope_claim_fence=authority[7],
        )
        if local_codex_thread_id is not None:
            self._completion.register_local_codex_route(
                capability,
                connection,
                return_route_id=route_id,
                codex_thread_id=local_codex_thread_id,
            )
        connection.execute(
            """INSERT INTO transport_callback_registrations(
                   id, transport_id, completion_registration_id,
                   return_route_id, work_id, generation, callback_key,
                   state, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
            (
                callback_id,
                transport_id,
                completion_id,
                route_id,
                work_id,
                int(authority[2]),
                f"callback:{transport_id}",
                now,
            ),
        )
        self.store._append_event(
            connection,
            "transport",
            transport_id,
            "transport.registrations.persisted",
            {
                "completion_registration_id": completion_id,
                "callback_registration_id": callback_id,
                "return_route_id": route_id,
            },
            now,
        )
        connection.execute(
            """UPDATE transport_deliveries
               SET state = 'prepared', updated_at = ?
               WHERE id = ? AND state = 'reserved'""",
            (now, transport_id),
        )
        self.store._append_event(
            connection,
            "transport",
            transport_id,
            "transport.prepared",
            {"from": "reserved", "to": "prepared"},
            now,
        )
        row = connection.execute(
            "SELECT * FROM transport_deliveries WHERE id = ?", (transport_id,)
        ).fetchone()
        assert row is not None
        return self._receipt(connection, row)

    def adapter_request(
        self,
        capability: object,
        connection: sqlite3.Connection,
        transport_id: str,
    ) -> AdapterRequest:
        self._assert_authority(capability)
        row = connection.execute(
            """SELECT delivery.id, delivery.work_id, delivery.pool,
                      delivery.payload_json, completion.id, callback.id,
                      decision.content_hash, claim.scope_key,
                      decision.agent_lifecycle, decision.allow_child_agents
               FROM transport_deliveries AS delivery
               JOIN transport_completion_registrations AS completion
                 ON completion.transport_id = delivery.id
               JOIN transport_callback_registrations AS callback
                 ON callback.transport_id = delivery.id
               JOIN scheduler_admission_decisions AS decision
                 ON decision.id = delivery.admission_decision_id
               JOIN scope_claims AS claim
                 ON claim.id = delivery.scope_claim_id
               WHERE delivery.id = ? AND delivery.state = 'prepared'
                 AND completion.state = 'pending' AND callback.state = 'pending'""",
            (transport_id,),
        ).fetchone()
        if row is None:
            raise OwnershipConflict("transport is not prepared for sending")
        capsule_scope_hash: str | None = None
        try:
            payload = json.loads(row[3])
            prompt = payload.get("prompt") if type(payload) is dict else None
            envelope = parse_capsule_prompt(prompt)
            task_envelope = (
                parse_task_prompt(prompt) if envelope is None else None
            )
            scope_envelope = envelope or task_envelope
            capsule_scope_hash = (
                scope_envelope["scope_capsule"]["manifest"]["scope_hash"]
                if scope_envelope is not None
                else None
            )
        except (json.JSONDecodeError, UnicodeError, ScopeCapsuleError):
            envelope = None
            capsule_scope_hash = None
        lifecycle = AgentLifecycle(row[8])
        allow_child_agents = bool(row[9])
        # Migration 015 cannot identify a pre-lifecycle capsule that was admitted
        # but not yet delivered because its body was not stored on the decision.
        # The exact delivery payload is authoritative at this later boundary.
        if (
            envelope is not None
            and lifecycle is AgentLifecycle.PERSISTENT
            and not allow_child_agents
        ):
            lifecycle = AgentLifecycle.DISPOSABLE
        return AdapterRequest(
            transport_id=row[0],
            work_id=row[1],
            pool=row[2],
            payload_json=row[3],
            completion_registration_id=row[4],
            callback_registration_id=row[5],
            admitted_content_hash=row[6],
            claim_scope_hash=row[7],
            capsule_scope_hash=capsule_scope_hash,
            agent_lifecycle=lifecycle,
            allow_child_agents=allow_child_agents,
        )

    def begin_attempt(
        self,
        capability: object,
        connection: sqlite3.Connection,
        transport_id: str,
        prepared: PreparedAdapterPort,
    ) -> int:
        self._assert_authority(capability)
        row = connection.execute(
            "SELECT state FROM transport_deliveries WHERE id = ?", (transport_id,)
        ).fetchone()
        if row is None or row[0] != TransportState.PREPARED.value:
            raise OwnershipConflict("transport is not prepared")
        prior = connection.execute(
            "SELECT coalesce(max(attempt_number), 0) FROM transport_attempts WHERE transport_id = ?",
            (transport_id,),
        ).fetchone()
        assert prior is not None
        attempt_number = int(prior[0]) + 1
        attempt_id = f"transport-attempt-{uuid.uuid4().hex}"
        now = self._clock()
        provenance = prepared.provenance
        executable = (
            (
                str(provenance.path),
                provenance.device,
                provenance.inode,
                provenance.mode,
                provenance.size,
                provenance.digest,
                str(provenance.source_path),
                provenance.source_device,
                provenance.source_inode,
                provenance.source_digest,
            )
            if provenance is not None
            else (None,) * 10
        )
        connection.execute(
            """INSERT INTO transport_attempts(
                   id, transport_id, attempt_number, state, executable_path,
                   executable_device, executable_inode, executable_mode,
                   executable_size, executable_digest, source_path,
                   source_device, source_inode, source_digest, started_at
               ) VALUES (?, ?, ?, 'sending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (attempt_id, transport_id, attempt_number, *executable, now),
        )
        connection.execute(
            """UPDATE transport_deliveries
               SET state = 'sending', active_attempt_id = ?, updated_at = ?
               WHERE id = ? AND state = 'prepared'""",
            (attempt_id, now, transport_id),
        )
        self.store._append_event(
            connection,
            "transport",
            transport_id,
            "transport.sending",
            {
                "attempt_id": attempt_id,
                "attempt": attempt_number,
                "executable": (
                    {
                        "path": str(provenance.path),
                        "device": provenance.device,
                        "inode": provenance.inode,
                        "mode": provenance.mode,
                        "size": provenance.size,
                        "digest": provenance.digest,
                        "source_path": str(provenance.source_path),
                        "source_device": provenance.source_device,
                        "source_inode": provenance.source_inode,
                        "source_digest": provenance.source_digest,
                    }
                    if provenance is not None
                    else None
                ),
            },
            now,
        )
        return attempt_number

    def record_process_identity(
        self,
        capability: object,
        connection: sqlite3.Connection,
        transport_id: str,
        identity: ProcessIdentity,
    ) -> None:
        """Persist supervisor-owned identity before any request byte is sent."""
        self._assert_authority(capability)
        if not isinstance(identity, ProcessIdentity):
            raise TypeError("typed process identity is required")
        _identifier(identity.token, "process_token")
        row = connection.execute(
            """SELECT active_attempt_id FROM transport_deliveries
               WHERE id = ? AND state = 'sending'""",
            (transport_id,),
        ).fetchone()
        if row is None:
            raise OwnershipConflict("transport send intent is not active")
        cursor = connection.execute(
            """UPDATE transport_attempts
               SET supervisor_pid = ?, target_pid = ?, process_token = ?
               WHERE id = ? AND state = 'sending'
                 AND supervisor_pid IS NULL AND target_pid IS NULL
                 AND process_token IS NULL""",
            (
                identity.supervisor_pid,
                identity.target_pid,
                identity.token,
                row[0],
            ),
        )
        if cursor.rowcount != 1:
            existing = connection.execute(
                """SELECT supervisor_pid, target_pid, process_token
                   FROM transport_attempts WHERE id = ?""",
                (row[0],),
            ).fetchone()
            if existing is None or tuple(existing) != (
                identity.supervisor_pid,
                identity.target_pid,
                identity.token,
            ):
                raise OwnershipConflict("process identity is already bound")
            return
        self.store._append_event(
            connection,
            "transport",
            transport_id,
            "transport.process_identity_recorded",
            {
                "attempt_id": row[0],
                "supervisor_pid": identity.supervisor_pid,
                "target_pid": identity.target_pid,
                "process_token": identity.token,
            },
            self._clock(),
        )

    def finalize(
        self,
        capability: object,
        connection: sqlite3.Connection,
        transport_id: str,
        result: AdapterResult,
    ) -> TransportReceipt:
        self._assert_authority(capability)
        row = connection.execute(
            """SELECT active_attempt_id, state FROM transport_deliveries
               WHERE id = ?""",
            (transport_id,),
        ).fetchone()
        if row is None or row[1] != TransportState.SENDING.value:
            raise OwnershipConflict("transport attempt is not active")
        attempt_id = row[0]
        active = connection.execute(
            """SELECT 1
               FROM transport_deliveries AS delivery
               JOIN scheduler_assignments AS assignment
                 ON assignment.id = delivery.assignment_id
                AND assignment.work_id = delivery.work_id
                AND assignment.attempt = delivery.assignment_attempt
                AND assignment.fence_token = delivery.assignment_fence
                AND assignment.state = 'active'
               JOIN scope_claims AS claim
                 ON claim.id = delivery.scope_claim_id
                AND claim.attempt = delivery.scope_claim_attempt
                AND claim.fence_token = delivery.scope_claim_fence
                AND claim.state = 'active'
               WHERE delivery.id = ?""",
            (transport_id,),
        ).fetchone()
        if active is None:
            result = AdapterResult.unknown(
                "stale_transport_fence",
                exit_code=result.exit_code,
                output=result.output,
                provenance=result.provenance,
                process_identity=result.process_identity,
            )
        target = TransportState(result.disposition.value)
        now = self._clock()
        if result.acknowledgement_id is not None:
            _identifier(result.acknowledgement_id, "acknowledgement_id")
        if result.error_code is not None:
            _identifier(result.error_code, "error_code")
        output_json = result.output
        if output_json is not None:
            if len(output_json.encode("utf-8")) > MAX_ADAPTER_OUTPUT_BYTES:
                raise ValueError("adapter output metadata exceeds the bounded limit")
            try:
                json.loads(output_json)
            except (json.JSONDecodeError, TypeError) as error:
                raise ValueError("adapter output must be bounded JSON") from error
        if result.process_identity is not None:
            bound = connection.execute(
                """SELECT supervisor_pid, target_pid, process_token
                   FROM transport_attempts WHERE id = ?""",
                (attempt_id,),
            ).fetchone()
            if bound is None or tuple(bound) != (
                result.process_identity.supervisor_pid,
                result.process_identity.target_pid,
                result.process_identity.token,
            ):
                raise OwnershipConflict("adapter result process identity is not durable")
        connection.execute(
            """UPDATE transport_attempts
               SET state = ?, acknowledgement_id = ?, error_code = ?,
                   exit_code = ?, output_json = ?, finished_at = ?
               WHERE id = ? AND state = 'sending'""",
            (
                target.value,
                result.acknowledgement_id,
                result.error_code,
                result.exit_code,
                output_json,
                now,
                attempt_id,
            ),
        )
        connection.execute(
            """UPDATE transport_deliveries
               SET state = ?, acknowledgement_id = ?, error_code = ?,
                   updated_at = ?, finished_at = ?
               WHERE id = ? AND state = 'sending' AND active_attempt_id = ?""",
            (
                target.value,
                result.acknowledgement_id,
                result.error_code,
                now,
                now,
                transport_id,
                attempt_id,
            ),
        )
        self.store._append_event(
            connection,
            "transport",
            transport_id,
            f"transport.{target.value}",
            {
                "attempt_id": attempt_id,
                "acknowledgement_id": result.acknowledgement_id,
                "error_code": result.error_code,
                "exit_code": result.exit_code,
            },
            now,
        )
        current = connection.execute(
            "SELECT * FROM transport_deliveries WHERE id = ?", (transport_id,)
        ).fetchone()
        assert current is not None
        return self._receipt(connection, current)

    def reconcile_startup(
        self,
        capability: object,
        connection: sqlite3.Connection,
    ) -> int:
        """Conservatively classify committed send intents; never resend them."""
        self._assert_authority(capability)
        rows = connection.execute(
            "SELECT id FROM transport_deliveries WHERE state = 'sending' ORDER BY rowid"
        ).fetchall()
        for row in rows:
            self.finalize(
                capability,
                connection,
                row[0],
                AdapterResult.unknown("daemon_restart_during_send"),
            )
        return len(rows)

    def status(
        self,
        capability: object,
        connection: sqlite3.Connection,
        work_id: str,
        pool: Lane,
    ) -> TransportReceipt | None:
        self._assert_authority(capability)
        _identifier(work_id, "work_id")
        row = connection.execute(
            """SELECT * FROM transport_deliveries
               WHERE work_id = ? AND pool = ? ORDER BY rowid DESC LIMIT 1""",
            (work_id, pool.value),
        ).fetchone()
        return self._receipt(connection, row) if row is not None else None

    def lookup_idempotent(
        self,
        capability: object,
        connection: sqlite3.Connection,
        idempotency_key: str,
        fingerprint: str,
    ) -> TransportReceipt | None:
        """Resolve durable transport before any outcome-capacity decision."""
        self._assert_authority(capability)
        row = connection.execute(
            "SELECT * FROM transport_deliveries WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        if row is None:
            return None
        if row["request_fingerprint"] != fingerprint:
            raise IdempotencyConflict(idempotency_key)
        return self._receipt(connection, row)

    def cancel(
        self,
        capability: object,
        connection: sqlite3.Connection,
        work_id: str,
        pool: Lane,
    ) -> TransportReceipt | None:
        self._assert_authority(capability)
        receipt = self.status(capability, connection, work_id, pool)
        if receipt is None or receipt.state not in {
            TransportState.RESERVED,
            TransportState.PREPARED,
        }:
            return receipt
        now = self._clock()
        connection.execute(
            """UPDATE transport_deliveries
               SET state = 'cancelled', error_code = 'cancelled_before_send',
                   updated_at = ?, finished_at = ?
               WHERE id = ? AND state IN ('reserved','prepared')""",
            (now, now, receipt.transport_id),
        )
        connection.execute(
            """UPDATE transport_completion_registrations
               SET state = 'cancelled', completed_at = ?
               WHERE transport_id = ? AND state = 'pending'""",
            (now, receipt.transport_id),
        )
        connection.execute(
            """UPDATE transport_callback_registrations
               SET state = 'cancelled', cancelled_at = ?
               WHERE transport_id = ? AND state = 'pending'""",
            (now, receipt.transport_id),
        )
        connection.execute(
            """UPDATE return_routes
               SET state = 'cancelled', cancelled_at_us = ?
               WHERE transport_id = ? AND state IN ('registered','ready')""",
            (self._completion._clock(), receipt.transport_id),
        )
        route = connection.execute(
            "SELECT id FROM return_routes WHERE transport_id = ?",
            (receipt.transport_id,),
        ).fetchone()
        if route is not None:
            self.store._append_event(
                connection,
                "return_route",
                route[0],
                "completion.route.cancelled",
                {"reason": "transport_cancelled_before_send"},
                now,
            )
        self.store._append_event(
            connection,
            "transport",
            receipt.transport_id,
            "transport.cancelled",
            {"error_code": "cancelled_before_send"},
            now,
        )
        return self.status(capability, connection, work_id, pool)

    def abort_external(
        self,
        capability: object,
        transport_id: str,
    ) -> AdapterResult | None:
        """Invoke only the explicitly injected adapter's durable abort fence."""

        self._assert_authority(capability)
        _identifier(transport_id, "transport_id")
        abort = getattr(self._adapter, "safe_abort", None)
        if not callable(abort):
            return None
        result = abort(transport_id)
        if type(result) is not AdapterResult:
            raise TypeError("adapter abort returned an invalid result")
        return result

    @staticmethod
    def _receipt(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> TransportReceipt:
        registrations = connection.execute(
            """SELECT completion.id, callback.id
               FROM transport_completion_registrations AS completion
               JOIN transport_callback_registrations AS callback
                 ON callback.transport_id = completion.transport_id
               WHERE completion.transport_id = ?""",
            (row["id"],),
        ).fetchone()
        if registrations is None:
            completion_id = callback_id = "pending-registration"
        else:
            completion_id, callback_id = registrations
        attempt = connection.execute(
            "SELECT coalesce(max(attempt_number), 0) FROM transport_attempts WHERE transport_id = ?",
            (row["id"],),
        ).fetchone()
        assert attempt is not None
        return TransportReceipt(
            transport_id=row["id"],
            work_id=row["work_id"],
            pool=row["pool"],
            state=TransportState(row["state"]),
            attempt=int(attempt[0]),
            completion_registration_id=completion_id,
            callback_registration_id=callback_id,
            acknowledgement_id=row["acknowledgement_id"],
            error_code=row["error_code"],
        )


def _create_transport(
    store: RigStore,
    authority: _DaemonAuthority,
    capability: object,
    completion: _CompletionService,
    adapter: AdapterPort,
    completion_registration: object | None = None,
) -> _TransportService:
    """Daemon-internal constructor kept outside the public package surface."""
    authority._assert_for(store)
    if not isinstance(getattr(adapter, "kind", None), str) or not callable(
        getattr(adapter, "prepare", None)
    ):
        raise TypeError("explicit AdapterPort required")
    if completion_registration is not None and not callable(completion_registration):
        raise TypeError("completion registration callback must be callable")
    service = object.__new__(_TransportService)
    service.store = store
    service._adapter = adapter
    service._authority = authority
    service._capability_id = id(capability)
    service._clock = _utc_now
    service._completion = completion
    service._completion_registration = completion_registration
    return service


def _dispatch_transport(
    service: _TransportService,
    capability: object,
    *,
    idempotency_key: str,
    fingerprint: str,
    work_id: str,
    pool: Lane,
    payload: Mapping[str, Any],
    reservation_id: str | None = None,
    reservation_attempt: int | None = None,
    reservation_fence: str | None = None,
    local_codex_thread_id: str | None = None,
) -> TransportReceipt:
    """Commit registrations and send intent around exactly one external attempt."""
    service._assert_authority(capability)
    adapter = service._adapter
    with service.store._daemon_transaction(service._authority) as connection:
        connection.row_factory = sqlite3.Row
        receipt = service.prepare(
            capability,
            connection,
            idempotency_key=idempotency_key,
            fingerprint=fingerprint,
            work_id=work_id,
            pool=pool,
            payload=payload,
            reservation_id=reservation_id,
            reservation_attempt=reservation_attempt,
            reservation_fence=reservation_fence,
            local_codex_thread_id=local_codex_thread_id,
        )
        if receipt.state is not TransportState.PREPARED:
            return receipt
        request = service.adapter_request(capability, connection, receipt.transport_id)
    try:
        prepared = adapter.prepare(request)
    except Exception:
        result = AdapterResult.definite_failure("adapter_prepare_failed")
        prepared = None
    if prepared is None:
        class _FailedPrepared:
            provenance = None

            def close(self) -> None:
                return None

        attempt_prepared: PreparedAdapterPort = _FailedPrepared()  # type: ignore[assignment]
    else:
        attempt_prepared = prepared
    try:
        with service.store._daemon_transaction(service._authority) as connection:
            connection.row_factory = sqlite3.Row
            service.begin_attempt(
                capability, connection, receipt.transport_id, attempt_prepared
            )
        if prepared is not None:
            try:
                result = prepared.send(NoCancellation())
            except Exception:
                result = AdapterResult.unknown("adapter_exception_after_send_intent")
        with service.store._daemon_transaction(service._authority) as connection:
            connection.row_factory = sqlite3.Row
            receipt = service.finalize(
                capability, connection, receipt.transport_id, result
            )
        if (
            receipt.state in {TransportState.ACCEPTED, TransportState.DELIVERY_UNKNOWN}
            and service._completion_registration is not None
        ):
            service._completion_registration(receipt.transport_id)
        return receipt
    finally:
        attempt_prepared.close()
