"""Daemon-private atomic five-lane scheduling over the Rig SQLite store."""

from __future__ import annotations

import hashlib
import json
import sqlite3

from oc_rig.policy.engine import decide_standalone_worker
from oc_rig.policy.models import AdmissionRequest
from oc_rig.scheduler.models import (
    LANES,
    AssignmentState,
    Lane,
    LaneSnapshot,
    ReleaseOutcome,
    ScheduledWorkState,
    SchedulerReservation,
    SchedulerSnapshot,
    SlotSnapshot,
    SlotState,
    WorkSnapshot,
)
from oc_rig.store.database import (
    IdempotencyConflict,
    OwnershipConflict,
    _DaemonAuthority,
    _identifier,
    _json,
    _utc_now,
)


def _scope_digest(repository: str | None, normalized_scope: tuple[str, ...]) -> str:
    material = {
        "repository": repository,
        "normalized_scope": list(normalized_scope),
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class _AdmissionEvidence:
    """Non-dataclass policy result bound to one live daemon authority."""

    __slots__ = (
        "_authority",
        "agent_lifecycle",
        "allowed",
        "allow_child_agents",
        "content_hash",
        "decision_hash",
        "policy_hash",
        "policy_version",
        "reason_codes",
        "scope_hash",
    )

    def __new__(cls, *_args: object, **_kwargs: object) -> "_AdmissionEvidence":
        raise PermissionError("admission evidence can only be issued by the engine")

    def _assert_for(self, authority: _DaemonAuthority) -> None:
        if self._authority is not authority:
            raise PermissionError("admission evidence belongs to another daemon")
        authority._assert_for(authority._store)


def _evaluate_admission(
    authority: _DaemonAuthority,
    request: AdmissionRequest,
) -> _AdmissionEvidence:
    """Evaluate raw input and issue evidence that cannot accept caller decisions."""
    if not isinstance(authority, _DaemonAuthority):
        raise PermissionError("daemon authority is required")
    if not isinstance(request, AdmissionRequest):
        raise TypeError("raw AdmissionRequest is required")
    authority._assert_for(authority._store)
    decision = decide_standalone_worker(request)
    evidence = object.__new__(_AdmissionEvidence)
    evidence._authority = authority
    evidence.agent_lifecycle = decision.agent_lifecycle.value
    evidence.allowed = decision.allowed
    evidence.allow_child_agents = decision.allow_child_agents
    evidence.content_hash = decision.content_hash
    evidence.decision_hash = decision.decision_hash
    evidence.policy_hash = decision.policy_hash
    evidence.policy_version = decision.policy_version
    evidence.reason_codes = tuple(reason.value for reason in decision.reason_codes)
    evidence.scope_hash = _scope_digest(decision.repository, decision.normalized_scope)
    return evidence


class _Scheduler:
    """Scheduler mutation surface instantiated only by the daemon controller."""

    def __new__(cls, *_args: object, **_kwargs: object) -> "_Scheduler":
        raise PermissionError("scheduler instances are created only by rigd")

    def _assert_authority(self) -> None:
        self._authority._assert_for(self.store)

    @staticmethod
    def _next_queue_order(connection: sqlite3.Connection) -> int:
        row = connection.execute(
            """UPDATE scheduler_queue_clock
               SET current_value = current_value + 1
               WHERE singleton = 1
               RETURNING current_value"""
        ).fetchone()
        if row is None:
            raise RuntimeError("scheduler queue clock is missing")
        return int(row[0])

    def enqueue(
        self,
        connection: sqlite3.Connection,
        work_id: str,
        lane: Lane,
        *,
        idempotency_key: str,
    ) -> int:
        """Queue unaudited work; only a later daemon-owned decision can admit it."""
        self._assert_authority()
        _identifier(work_id, "work_id")
        _identifier(idempotency_key, "idempotency_key")
        if not isinstance(lane, Lane):
            raise TypeError("lane must be a Lane")
        existing = connection.execute(
            """SELECT sequence, id, lane FROM scheduler_work
               WHERE idempotency_key = ?""",
            (idempotency_key,),
        ).fetchone()
        if existing is not None:
            if (existing[1], existing[2]) != (work_id, lane.value):
                raise IdempotencyConflict(idempotency_key)
            return int(existing[0])
        now = self._clock()
        queue_order = self._next_queue_order(connection)
        try:
            cursor = connection.execute(
                """INSERT INTO scheduler_work(
                       id, idempotency_key, lane, state, enqueued_at, queue_order
                   ) VALUES (?, ?, ?, 'queued', ?, ?)""",
                (work_id, idempotency_key, lane.value, now, queue_order),
            )
        except sqlite3.IntegrityError as error:
            if "scheduler_work.id" in str(error):
                raise IdempotencyConflict(work_id) from error
            raise
        sequence = int(cursor.lastrowid)
        self.store._append_event(
            connection,
            "scheduler_work",
            work_id,
            "scheduler.work.enqueued",
            {"lane": lane.value, "sequence": sequence, "queue_order": queue_order},
            now,
        )
        return sequence

    def admit(
        self,
        connection: sqlite3.Connection,
        work_id: str,
        *,
        decision_id: str,
        claim_id: str,
        evidence: _AdmissionEvidence,
        idempotency_key: str,
    ) -> bool:
        """Persist an engine decision bound to the exact current active claim."""
        self._assert_authority()
        for value, field in (
            (work_id, "work_id"),
            (decision_id, "decision_id"),
            (claim_id, "claim_id"),
            (idempotency_key, "idempotency_key"),
        ):
            _identifier(value, field)
        if not isinstance(evidence, _AdmissionEvidence):
            raise PermissionError("daemon admission evidence is required")
        evidence._assert_for(self._authority)
        claim = connection.execute(
            """SELECT scope_key, owner_operation_id, attempt, fence_token
               FROM scope_claims WHERE id = ? AND state = 'active'""",
            (claim_id,),
        ).fetchone()
        if claim is None:
            raise OwnershipConflict("scope claim is not active")
        if claim[0] != evidence.scope_hash:
            raise OwnershipConflict("scope claim does not match the admitted scope")
        work = connection.execute(
            """SELECT state, policy_decision_id, admission_idempotency_key
               FROM scheduler_work WHERE id = ?""",
            (work_id,),
        ).fetchone()
        if work is None:
            raise KeyError(work_id)
        if work[2] is not None:
            if (work[1], work[2]) != (decision_id, idempotency_key):
                raise IdempotencyConflict(idempotency_key)
            return evidence.allowed
        if work[0] != ScheduledWorkState.QUEUED.value:
            return False

        now = self._clock()
        reasons_json = _json(evidence.reason_codes)
        try:
            connection.execute(
                """INSERT INTO scheduler_admission_decisions(
                       id, work_id, policy_version, policy_hash, decision_hash,
                       content_hash, scope_hash, allowed, reasons_json,
                       agent_lifecycle, allow_child_agents,
                       scope_claim_id, scope_key, scope_owner_id,
                       scope_claim_attempt, scope_claim_fence, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    decision_id,
                    work_id,
                    evidence.policy_version,
                    evidence.policy_hash,
                    evidence.decision_hash,
                    evidence.content_hash,
                    evidence.scope_hash,
                    int(evidence.allowed),
                    reasons_json,
                    evidence.agent_lifecycle,
                    int(evidence.allow_child_agents),
                    claim_id,
                    claim[0],
                    claim[1],
                    int(claim[2]),
                    claim[3],
                    now,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise IdempotencyConflict(decision_id) from error
        if evidence.allowed:
            connection.execute(
                """UPDATE scheduler_work
                   SET scope_key = ?, scope_owner_id = ?, policy_decision_id = ?,
                       policy_allowed = 1, admission_idempotency_key = ?
                   WHERE id = ? AND state = 'queued'
                     AND admission_idempotency_key IS NULL""",
                (claim[0], claim[1], decision_id, idempotency_key, work_id),
            )
        else:
            connection.execute(
                """UPDATE scheduler_work
                   SET scope_key = ?, scope_owner_id = ?, policy_decision_id = ?,
                       policy_allowed = 0, admission_idempotency_key = ?,
                       state = 'rejected', finished_at = ?
                   WHERE id = ? AND state = 'queued'
                     AND admission_idempotency_key IS NULL""",
                (claim[0], claim[1], decision_id, idempotency_key, now, work_id),
            )
        self.store._append_event(
            connection,
            "scheduler_work",
            work_id,
            "scheduler.work.admitted",
            {
                "allowed": evidence.allowed,
                "decision_id": decision_id,
                "scope_claim_id": claim_id,
                "scope_owner_id": claim[1],
                "scope_claim_attempt": int(claim[2]),
                "scope_claim_fence": claim[3],
                "policy_version": evidence.policy_version,
                "policy_hash": evidence.policy_hash,
                "content_hash": evidence.content_hash,
                "scope_hash": evidence.scope_hash,
                "agent_lifecycle": evidence.agent_lifecycle,
                "allow_child_agents": evidence.allow_child_agents,
                "reasons": list(evidence.reason_codes),
            },
            now,
        )
        if not evidence.allowed:
            self.store._append_event(
                connection,
                "scheduler_work",
                work_id,
                "scheduler.work.rejected",
                {"decision_id": decision_id},
                now,
            )
        return evidence.allowed

    def reserve_next(
        self,
        connection: sqlite3.Connection,
        reservation_id: str,
        *,
        fence_token: str,
        work_id: str | None = None,
    ) -> SchedulerReservation | None:
        """Atomically reserve the eligible lane head, optionally bound to one work ID."""
        self._assert_authority()
        _identifier(reservation_id, "reservation_id")
        _identifier(fence_token, "fence_token")
        if work_id is not None:
            _identifier(work_id, "work_id")
        prior = connection.execute(
            self._reservation_query("WHERE assignment.id = ?"),
            (reservation_id,),
        ).fetchone()
        if prior is not None:
            if prior[8] != fence_token or (
                work_id is not None and prior[2] != work_id
            ):
                raise IdempotencyConflict(reservation_id)
            return self._reservation(prior)
        work = connection.execute(
            """WITH eligible AS (
                   SELECT candidate.sequence, candidate.queue_order,
                          candidate.id, candidate.lane, candidate.attempt,
                          decision.scope_owner_id, decision.scope_claim_id,
                          decision.scope_claim_attempt,
                          decision.scope_claim_fence
                   FROM scheduler_work AS candidate
                   JOIN scheduler_admission_decisions AS decision
                     ON decision.id = candidate.policy_decision_id
                    AND decision.work_id = candidate.id
                    AND decision.allowed = 1
                   JOIN scope_claims AS claim
                     ON claim.id = decision.scope_claim_id
                    AND claim.scope_key = decision.scope_key
                    AND claim.owner_operation_id = decision.scope_owner_id
                    AND claim.attempt = decision.scope_claim_attempt
                    AND claim.fence_token = decision.scope_claim_fence
                    AND claim.state = 'active'
                   WHERE candidate.state = 'queued'
               ), lane_heads AS (
                   SELECT lane, MIN(queue_order) AS queue_order
                   FROM eligible GROUP BY lane
               )
               SELECT candidate.sequence, candidate.queue_order, candidate.id,
                      candidate.lane, candidate.scope_owner_id,
                      candidate.attempt, candidate.scope_claim_id,
                      candidate.scope_claim_attempt,
                      candidate.scope_claim_fence
               FROM eligible AS candidate
               JOIN lane_heads
                 ON lane_heads.lane = candidate.lane
                AND lane_heads.queue_order = candidate.queue_order
               WHERE EXISTS (
                   SELECT 1 FROM scheduler_slots AS slot
                   WHERE slot.lane = candidate.lane AND slot.state = 'clear'
               )
                 AND (? IS NULL OR candidate.id = ?)
               ORDER BY candidate.queue_order, candidate.sequence
               LIMIT 1""",
            (work_id, work_id),
        ).fetchone()
        if work is None:
            return None
        slot = connection.execute(
            """SELECT id FROM scheduler_slots
               WHERE lane = ? AND state = 'clear'
               ORDER BY last_used_sequence, position
               LIMIT 1""",
            (work[3],),
        ).fetchone()
        if slot is None:
            return None
        attempt = int(work[5]) + 1
        now = self._clock()
        cursor = connection.execute(
            """INSERT INTO scheduler_assignments(
                   id, work_id, slot_id, lane, owner_id, attempt,
                   fence_token, state, assigned_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)""",
            (reservation_id, work[2], slot[0], work[3], work[4], attempt, fence_token, now),
        )
        assignment_sequence = int(cursor.lastrowid)
        work_cursor = connection.execute(
            """UPDATE scheduler_work
               SET state = 'assigned', active_assignment_id = ?,
                   attempt = ?, assigned_at = ?
               WHERE id = ? AND state = 'queued'""",
            (reservation_id, attempt, now, work[2]),
        )
        slot_cursor = connection.execute(
            """UPDATE scheduler_slots
               SET state = 'assigned', active_assignment_id = ?,
                   active_work_id = ?, owner_id = ?, attempt = ?, fence_token = ?
               WHERE id = ? AND state = 'clear'""",
            (reservation_id, work[2], work[4], attempt, fence_token, slot[0]),
        )
        if work_cursor.rowcount != 1 or slot_cursor.rowcount != 1:
            raise OwnershipConflict(f"scheduler reservation raced: {work[2]}")
        self.store._append_event(
            connection,
            "scheduler_assignment",
            reservation_id,
            "scheduler.assignment.created",
            {
                "work_id": work[2],
                "lane": work[3],
                "slot_id": slot[0],
                "owner_id": work[4],
                "attempt": attempt,
                "fence": fence_token,
                "scope_claim_id": work[6],
                "scope_claim_attempt": int(work[7]),
                "scope_claim_fence": work[8],
            },
            now,
        )
        return SchedulerReservation(
            id=reservation_id,
            sequence=assignment_sequence,
            work_id=str(work[2]),
            work_sequence=int(work[0]),
            lane=Lane(str(work[3])),
            slot_id=str(slot[0]),
            owner_id=str(work[4]),
            attempt=attempt,
            fence_token=fence_token,
            scope_claim_id=str(work[6]),
            scope_claim_attempt=int(work[7]),
            scope_claim_fence=str(work[8]),
            state=AssignmentState.ACTIVE,
        )

    def release(
        self,
        connection: sqlite3.Connection,
        reservation_id: str,
        work_id: str,
        owner_id: str,
        *,
        attempt: int,
        fence_token: str,
        outcome: ReleaseOutcome,
    ) -> bool:
        """Release only an exact active assignment; exact retries are idempotent."""
        self._assert_authority()
        for value, field in (
            (reservation_id, "reservation_id"),
            (work_id, "work_id"),
            (owner_id, "owner_id"),
            (fence_token, "fence_token"),
        ):
            _identifier(value, field)
        if type(attempt) is not int or attempt <= 0:
            raise ValueError("attempt must be a positive integer")
        if not isinstance(outcome, ReleaseOutcome):
            raise TypeError("outcome must be a ReleaseOutcome")
        row = connection.execute(
            """SELECT sequence, work_id, slot_id, lane, owner_id, attempt,
                      fence_token, state, release_outcome
               FROM scheduler_assignments WHERE id = ?""",
            (reservation_id,),
        ).fetchone()
        if row is None:
            return False
        exact = (row[1], row[4], int(row[5]), row[6]) == (
            work_id, owner_id, attempt, fence_token
        )
        if not exact:
            return False
        if row[7] == AssignmentState.RELEASED.value:
            return row[8] == outcome.value
        target = {
            ReleaseOutcome.REQUEUED: ScheduledWorkState.QUEUED,
            ReleaseOutcome.COMPLETED: ScheduledWorkState.COMPLETED,
            ReleaseOutcome.CANCELLED: ScheduledWorkState.CANCELLED,
        }[outcome]
        now = self._clock()
        connection.execute(
            """UPDATE scheduler_assignments
               SET state = 'released', release_outcome = ?, released_at = ?
               WHERE id = ? AND state = 'active'""",
            (outcome.value, now, reservation_id),
        )
        slot_cursor = connection.execute(
            """UPDATE scheduler_slots
               SET state = 'clear', active_assignment_id = NULL,
                   active_work_id = NULL, owner_id = NULL, attempt = NULL,
                   fence_token = NULL, last_used_sequence = ?
               WHERE id = ? AND state = 'assigned'
                 AND active_assignment_id = ? AND active_work_id = ?
                 AND owner_id = ? AND attempt = ? AND fence_token = ?""",
            (row[0], row[2], reservation_id, work_id, owner_id, attempt, fence_token),
        )
        if target is ScheduledWorkState.QUEUED:
            queue_order = self._next_queue_order(connection)
            work_cursor = connection.execute(
                """UPDATE scheduler_work
                   SET state = 'queued', active_assignment_id = NULL,
                       finished_at = NULL, queue_order = ?
                   WHERE id = ? AND state = 'assigned'
                     AND active_assignment_id = ? AND attempt = ?""",
                (queue_order, work_id, reservation_id, attempt),
            )
        else:
            queue_order = None
            work_cursor = connection.execute(
                """UPDATE scheduler_work
                   SET state = ?, active_assignment_id = NULL, finished_at = ?
                   WHERE id = ? AND state = 'assigned'
                     AND active_assignment_id = ? AND attempt = ?""",
                (target.value, now, work_id, reservation_id, attempt),
            )
        if slot_cursor.rowcount != 1 or work_cursor.rowcount != 1:
            raise OwnershipConflict(f"scheduler ownership mismatch: {reservation_id}")
        payload: dict[str, object] = {
            "work_id": work_id,
            "slot_id": row[2],
            "owner_id": owner_id,
            "attempt": attempt,
            "fence": fence_token,
            "outcome": outcome.value,
        }
        if queue_order is not None:
            payload["queue_order"] = queue_order
        self.store._append_event(
            connection,
            "scheduler_assignment",
            reservation_id,
            "scheduler.assignment.released",
            payload,
            now,
        )
        return True

    def cancel_queued(
        self,
        connection: sqlite3.Connection,
        work_id: str,
        *,
        idempotency_key: str,
    ) -> bool:
        self._assert_authority()
        _identifier(work_id, "work_id")
        _identifier(idempotency_key, "idempotency_key")
        row = connection.execute(
            """SELECT state, cancellation_idempotency_key
               FROM scheduler_work WHERE id = ?""",
            (work_id,),
        ).fetchone()
        if row is None:
            raise KeyError(work_id)
        if row[1] is not None:
            if row[1] != idempotency_key:
                raise IdempotencyConflict(idempotency_key)
            return True
        if row[0] != ScheduledWorkState.QUEUED.value:
            return False
        now = self._clock()
        try:
            connection.execute(
                """UPDATE scheduler_work
                   SET state = 'cancelled', finished_at = ?,
                       cancellation_idempotency_key = ?
                   WHERE id = ? AND state = 'queued'""",
                (now, idempotency_key, work_id),
            )
        except sqlite3.IntegrityError as error:
            if "cancellation_idempotency_key" in str(error):
                raise IdempotencyConflict(idempotency_key) from error
            raise
        self.store._append_event(
            connection, "scheduler_work", work_id, "scheduler.work.cancelled", {}, now
        )
        return True

    def snapshot(self) -> SchedulerSnapshot:
        with self.store._read_transaction() as connection:
            slot_rows = connection.execute(
                """SELECT id, lane, position, state, last_used_sequence,
                          active_assignment_id, active_work_id, owner_id,
                          attempt, fence_token FROM scheduler_slots"""
            ).fetchall()
            work_rows = connection.execute(
                """SELECT work.id, work.sequence, work.queue_order, work.lane,
                          work.state, work.scope_key, work.policy_allowed,
                          work.attempt, work.active_assignment_id,
                          work.policy_decision_id, decision.scope_claim_id
                   FROM scheduler_work AS work
                   LEFT JOIN scheduler_admission_decisions AS decision
                     ON decision.id = work.policy_decision_id
                   ORDER BY work.sequence"""
            ).fetchall()
            assignment_rows = connection.execute(
                self._reservation_query("ORDER BY assignment.sequence")
            ).fetchall()
        slots = tuple(
            SlotSnapshot(
                id=str(row[0]), lane=Lane(str(row[1])), position=int(row[2]),
                state=SlotState(str(row[3])), last_used_sequence=int(row[4]),
                assignment_id=row[5], work_id=row[6], owner_id=row[7],
                attempt=row[8], fence_token=row[9],
            )
            for row in sorted(slot_rows, key=lambda row: (LANES.index(Lane(str(row[1]))), row[2]))
        )
        work = tuple(
            WorkSnapshot(
                id=str(row[0]), sequence=int(row[1]), queue_order=int(row[2]),
                lane=Lane(str(row[3])), state=ScheduledWorkState(str(row[4])),
                admitted=row[5] is not None,
                policy_allowed=None if row[6] is None else bool(row[6]),
                attempt=int(row[7]), assignment_id=row[8],
                admission_decision_id=row[9], scope_claim_id=row[10],
            )
            for row in work_rows
        )
        lanes = tuple(
            LaneSnapshot(
                lane=lane,
                slots=tuple(slot for slot in slots if slot.lane is lane),
                work=tuple(item for item in work if item.lane is lane),
            )
            for lane in LANES
        )
        return SchedulerSnapshot(
            lanes=lanes,
            assignments=tuple(self._reservation(row) for row in assignment_rows),
        )

    @staticmethod
    def _reservation_query(suffix: str) -> str:
        return f"""SELECT assignment.sequence, assignment.id,
                          assignment.work_id, work.sequence, assignment.lane,
                          assignment.slot_id, assignment.owner_id,
                          assignment.attempt, assignment.fence_token,
                          assignment.state, assignment.release_outcome,
                          decision.scope_claim_id,
                          decision.scope_claim_attempt,
                          decision.scope_claim_fence
                   FROM scheduler_assignments AS assignment
                   JOIN scheduler_work AS work ON work.id = assignment.work_id
                   JOIN scheduler_admission_decisions AS decision
                     ON decision.id = work.policy_decision_id
                   {suffix}"""

    @staticmethod
    def _reservation(row: sqlite3.Row | tuple[object, ...]) -> SchedulerReservation:
        return SchedulerReservation(
            id=str(row[1]), sequence=int(row[0]), work_id=str(row[2]),
            work_sequence=int(row[3]), lane=Lane(str(row[4])), slot_id=str(row[5]),
            owner_id=str(row[6]), attempt=int(row[7]), fence_token=str(row[8]),
            scope_claim_id=str(row[11]), scope_claim_attempt=int(row[12]),
            scope_claim_fence=str(row[13]), state=AssignmentState(str(row[9])),
            release_outcome=None if row[10] is None else ReleaseOutcome(str(row[10])),
        )
