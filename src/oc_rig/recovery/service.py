"""Event-driven recovery classification and explicit persisted due timers."""

from __future__ import annotations

import sqlite3
import uuid

from oc_rig.recovery.clock import ClockReading, SystemTrustedClock, TrustedClock
from oc_rig.recovery.models import (
    RecoveryAttemptReceipt,
    RecoveryEvidence,
    RecoveryFailureClass,
    RecoveryObservationReceipt,
    RecoveryPhase,
    RecoveryResult,
    RecoveryTimerReceipt,
)
from oc_rig.store.database import (
    OwnershipConflict,
    RigStore,
    _DaemonAuthority,
    _identifier,
)


PRODUCTIVE_ACTIVE_SECONDS = 60
ZERO_OUTPUT_SECONDS = 90
UNANSWERED_SECONDS = 150
STALLED_SECONDS = 300
STALE_THINKING_SECONDS = 120
CORPSE_SECONDS = 45
MAX_RECOVERY_ATTEMPTS = 6
_RECOVERY_DELAYS = {1: 60, 2: 60, 3: 60, 4: 180, 5: 300, 6: 600}
_TERMINAL_FAILURES = {
    RecoveryFailureClass.DETERMINISTIC,
    RecoveryFailureClass.PERMISSION,
    RecoveryFailureClass.POLICY,
    RecoveryFailureClass.DELIVERY_UNKNOWN,
}


def threshold_seconds(phase: RecoveryPhase, *, productive: bool) -> int | None:
    """Return the inclusive due threshold for one explicit semantic phase."""
    if phase is RecoveryPhase.ACTIVE:
        return PRODUCTIVE_ACTIVE_SECONDS if productive else ZERO_OUTPUT_SECONDS
    if phase is RecoveryPhase.HANDED_OFF:
        return UNANSWERED_SECONDS
    if phase in {RecoveryPhase.TOOL_FLOW, RecoveryPhase.BUSY}:
        return STALLED_SECONDS
    if phase is RecoveryPhase.THINKING:
        return STALE_THINKING_SECONDS
    if phase is RecoveryPhase.CORPSE:
        return CORPSE_SECONDS
    return None


class ClockRollbackError(RuntimeError):
    """The trusted monotonic clock moved backwards within one epoch."""


class _RecoveryService:
    """Recovery mutation surface instantiated only by the durable daemon."""

    __slots__ = ("store", "_authority", "_capability_id", "_clock")

    def __new__(cls, *_args: object, **_kwargs: object) -> "_RecoveryService":
        raise PermissionError("recovery services are created only by rigd")

    def _assert_authority(self, capability: object) -> None:
        if id(capability) != self._capability_id:
            raise PermissionError("recovery mutation requires daemon capability")
        self._authority._assert_for(self.store)

    def _read_clock(self, connection: sqlite3.Connection) -> ClockReading:
        reading = self._clock.read()
        row = connection.execute(
            "SELECT clock_epoch, wall_us, mono_ns FROM recovery_clock_state WHERE singleton = 1"
        ).fetchone()
        if row is not None and row[0] == reading.epoch and reading.monotonic_ns < int(row[2]):
            raise ClockRollbackError("trusted monotonic clock moved backwards")
        connection.execute(
            """INSERT INTO recovery_clock_state(singleton, clock_epoch, wall_us, mono_ns)
               VALUES (1, ?, ?, ?)
               ON CONFLICT(singleton) DO UPDATE SET
                   clock_epoch = excluded.clock_epoch,
                   wall_us = excluded.wall_us,
                   mono_ns = excluded.mono_ns""",
            (reading.epoch, reading.wall_us, reading.monotonic_ns),
        )
        return reading

    def observe(
        self,
        capability: object,
        connection: sqlite3.Connection,
        *,
        target_id: str,
        work_id: str,
        generation: int,
        phase: RecoveryPhase,
        productive: bool,
        evidence: RecoveryEvidence,
    ) -> RecoveryObservationReceipt:
        """Persist one observation and preserve or reset one legal progression."""
        self._assert_authority(capability)
        _identifier(target_id, "target_id")
        _identifier(work_id, "work_id")
        if type(generation) is not int or generation <= 0:
            raise ValueError("generation must be a positive integer")
        if not isinstance(phase, RecoveryPhase):
            raise TypeError("phase must be a RecoveryPhase")
        if type(productive) is not bool:
            raise TypeError("productive must be a boolean")
        if not isinstance(evidence, RecoveryEvidence):
            raise TypeError("evidence must be RecoveryEvidence")
        reading = self._read_clock(connection)
        if evidence is not RecoveryEvidence.NONE and not self._evidence_exists(
            connection, work_id, generation, evidence
        ):
            raise OwnershipConflict("authoritative recovery evidence was not found")
        newest = connection.execute(
            "SELECT max(generation) FROM recovery_targets WHERE work_id = ?",
            (work_id,),
        ).fetchone()
        if newest is not None and newest[0] is not None and generation < int(newest[0]):
            raise OwnershipConflict("recovery event belongs to a stale generation")
        existing = connection.execute(
            """SELECT work_id, generation, current_timer_id, episode_id
               FROM recovery_targets WHERE target_id = ?""",
            (target_id,),
        ).fetchone()
        if existing is not None and (existing[0], int(existing[1])) != (work_id, generation):
            raise OwnershipConflict("recovery target identity is already bound")
        if newest is not None and newest[0] is not None and generation > int(newest[0]):
            stale = connection.execute(
                """SELECT target_id, current_timer_id, episode_id
                   FROM recovery_targets WHERE work_id = ? AND generation < ?""",
                (work_id, generation),
            ).fetchall()
            for stale_target, timer_id, episode_id in stale:
                self._cancel_timer(connection, timer_id, reading, "newer_generation")
                self._recover_episode(connection, episode_id, reading, "newer_generation")
                connection.execute(
                    """UPDATE recovery_targets
                       SET phase = 'completed', current_timer_id = NULL,
                           episode_id = NULL, circuit_state = 'closed', updated_at_us = ?
                       WHERE target_id = ?""",
                    (reading.wall_us, stale_target),
                )
        if existing is None:
            connection.execute(
                """INSERT INTO recovery_targets(
                       target_id, work_id, generation, phase, productive,
                       current_timer_id, episode_id, circuit_state,
                       last_observed_at_us, updated_at_us
                   ) VALUES (?, ?, ?, ?, ?, NULL, NULL, 'closed', ?, ?)""",
                (
                    target_id,
                    work_id,
                    generation,
                    phase.value,
                    int(productive),
                    reading.wall_us,
                    reading.wall_us,
                ),
            )
            old_timer = old_episode = None
        else:
            old_timer, old_episode = existing[2], existing[3]
        if old_episode is not None:
            open_episode = connection.execute(
                """SELECT attempts FROM recovery_episodes
                   WHERE id = ? AND target_id = ? AND generation = ?
                     AND state = 'open'""",
                (old_episode, target_id, generation),
            ).fetchone()
            if open_episode is None:
                old_episode = None
        else:
            open_episode = None

        authoritative = evidence in {
            RecoveryEvidence.CALLBACK,
            RecoveryEvidence.CLAIM,
            RecoveryEvidence.COMPLETION,
        }
        reset_phase = phase in {RecoveryPhase.QUEUED, RecoveryPhase.HANDED_OFF}
        circuit_state = "closed"
        effective_phase = phase
        if authoritative:
            self._cancel_timer(connection, old_timer, reading, f"evidence_{evidence.value}")
            self._recover_episode(connection, old_episode, reading, f"evidence_{evidence.value}")
            timer_id = None
            threshold = None
            effective_phase = RecoveryPhase.COMPLETED
            event_type = "recovery.evidence_override"
            episode_id = None
        elif productive or reset_phase:
            reset_reason = (
                "productive_progress" if productive else f"phase_reset_{phase.value}"
            )
            self._cancel_timer(connection, old_timer, reading, reset_reason)
            self._recover_episode(connection, old_episode, reading, reset_reason)
            episode_id = None
            threshold = threshold_seconds(phase, productive=productive)
            timer_id = None
            if threshold is not None:
                timer_id = self._schedule_timer(
                    connection,
                    target_id=target_id,
                    generation=generation,
                    episode_id=None,
                    kind="heuristic",
                    reason=self._reason(phase, productive),
                    attempt=None,
                    delay_seconds=threshold,
                    reading=reading,
                )
            event_type = "recovery.observed_reset"
        elif old_episode is not None:
            valid_timer = connection.execute(
                """SELECT id FROM recovery_timers
                   WHERE id = ? AND target_id = ? AND generation = ?
                     AND episode_id = ? AND kind = 'recovery'
                     AND state = 'scheduled'""",
                (old_timer, target_id, generation, old_episode),
            ).fetchone()
            due_attempt = connection.execute(
                """SELECT 1 FROM recovery_attempts
                   WHERE episode_id = ? AND state = 'due'""",
                (old_episode,),
            ).fetchone()
            if phase is RecoveryPhase.TOOL_FLOW and valid_timer is None:
                self._cancel_timer(connection, old_timer, reading, "tool_flow_reset")
                self._recover_episode(connection, old_episode, reading, "tool_flow_reset")
                episode_id = None
                threshold = STALLED_SECONDS
                timer_id = self._schedule_timer(
                    connection,
                    target_id=target_id,
                    generation=generation,
                    episode_id=None,
                    kind="heuristic",
                    reason="stalled_tool_flow",
                    attempt=None,
                    delay_seconds=threshold,
                    reading=reading,
                )
                event_type = "recovery.observed_reset"
            else:
                episode_id = str(old_episode)
                threshold = None
                if valid_timer is not None:
                    timer_id = str(valid_timer[0])
                    event_type = "recovery.observed_episode_preserved"
                elif due_attempt is not None:
                    timer_id = None
                    event_type = "recovery.observed_attempt_preserved"
                else:
                    assert open_episode is not None
                    next_attempt = int(open_episode[0]) + 1
                    if next_attempt > MAX_RECOVERY_ATTEMPTS:
                        connection.execute(
                            """UPDATE recovery_episodes
                               SET state = 'attention', closed_at_us = ?,
                                   attention_reason = 'no_progress_circuit_open'
                               WHERE id = ? AND state = 'open'""",
                            (reading.wall_us, old_episode),
                        )
                        timer_id = None
                        circuit_state = "open"
                        effective_phase = RecoveryPhase.ATTENTION
                        event_type = "recovery.attention_required"
                    else:
                        timer_id = self._schedule_timer(
                            connection,
                            target_id=target_id,
                            generation=generation,
                            episode_id=str(old_episode),
                            kind="recovery",
                            reason=self._reason(phase, productive=False),
                            attempt=next_attempt,
                            delay_seconds=_RECOVERY_DELAYS[next_attempt],
                            reading=reading,
                        )
                        event_type = "recovery.observed_episode_repaired"
        else:
            self._cancel_timer(connection, old_timer, reading, "observation_reset")
            episode_id = None
            threshold = threshold_seconds(phase, productive=False)
            timer_id = None
            if threshold is not None:
                timer_id = self._schedule_timer(
                    connection,
                    target_id=target_id,
                    generation=generation,
                    episode_id=None,
                    kind="heuristic",
                    reason=self._reason(phase, productive=False),
                    attempt=None,
                    delay_seconds=threshold,
                    reading=reading,
                )
            event_type = "recovery.observed"

        connection.execute(
            """UPDATE recovery_targets
               SET phase = ?, productive = ?, current_timer_id = ?,
                   episode_id = ?, circuit_state = ?,
                   last_observed_at_us = ?, updated_at_us = ?
               WHERE target_id = ?""",
            (
                effective_phase.value,
                int(productive),
                timer_id,
                episode_id,
                circuit_state,
                reading.wall_us,
                reading.wall_us,
                target_id,
            ),
        )
        self.store._append_event(
            connection,
            "recovery_target",
            target_id,
            event_type,
            {
                "work_id": work_id,
                "generation": generation,
                "phase": effective_phase.value,
                "productive": productive,
                "evidence": evidence.value,
                "timer_id": timer_id,
                "threshold_seconds": threshold,
            },
            str(reading.wall_us),
        )
        return RecoveryObservationReceipt(
            target_id,
            work_id,
            generation,
            effective_phase,
            timer_id,
            threshold,
            circuit_state,
        )

    def evidence_for_work(
        self,
        capability: object,
        connection: sqlite3.Connection,
        *,
        work_id: str,
        generation: int,
        evidence: RecoveryEvidence,
    ) -> int:
        """Apply authoritative callback/claim/completion evidence to exact targets."""
        self._assert_authority(capability)
        if evidence is RecoveryEvidence.NONE:
            raise ValueError("authoritative evidence is required")
        rows = connection.execute(
            """SELECT target_id FROM recovery_targets
               WHERE work_id = ? AND generation = ?""",
            (work_id, generation),
        ).fetchall()
        for row in rows:
            self.observe(
                capability,
                connection,
                target_id=str(row[0]),
                work_id=work_id,
                generation=generation,
                phase=RecoveryPhase.COMPLETED,
                productive=True,
                evidence=evidence,
            )
        return len(rows)

    def fire_timer(
        self,
        capability: object,
        connection: sqlite3.Connection,
        timer_id: str,
    ) -> RecoveryTimerReceipt:
        """Fire one named due event exactly once; this performs no polling."""
        self._assert_authority(capability)
        _identifier(timer_id, "timer_id")
        reading = self._read_clock(connection)
        row = connection.execute(
            """SELECT target_id, generation, episode_id, kind, reason,
                      attempt_number, state, clock_epoch, due_wall_us, due_mono_ns
               FROM recovery_timers WHERE id = ?""",
            (timer_id,),
        ).fetchone()
        if row is None:
            raise KeyError(timer_id)
        if row[6] != "scheduled":
            return self._timer_receipt(
                connection, timer_id, due=row[6] == "fired"
            )
        current = connection.execute(
            """SELECT current_timer_id FROM recovery_targets
               WHERE target_id = ? AND generation = ?""",
            (row[0], int(row[1])),
        ).fetchone()
        if current is None or current[0] != timer_id:
            self._cancel_timer(connection, timer_id, reading, "stale_timer_fence")
            return self._timer_receipt(connection, timer_id, due=False)
        due = (
            reading.monotonic_ns >= int(row[9])
            if reading.epoch == row[7]
            else reading.wall_us >= int(row[8])
        )
        if not due:
            return self._timer_receipt(connection, timer_id, due=False)
        cursor = connection.execute(
            """UPDATE recovery_timers SET state = 'fired', fired_at_us = ?
               WHERE id = ? AND state = 'scheduled'""",
            (reading.wall_us, timer_id),
        )
        if cursor.rowcount != 1:
            return self._timer_receipt(connection, timer_id, due=True)
        connection.execute(
            """UPDATE recovery_targets SET current_timer_id = NULL, updated_at_us = ?
               WHERE target_id = ? AND generation = ? AND current_timer_id = ?""",
            (reading.wall_us, row[0], int(row[1]), timer_id),
        )
        if row[3] == "heuristic":
            episode_id = f"recovery-episode-{uuid.uuid4().hex}"
            connection.execute(
                """INSERT INTO recovery_episodes(
                       id, target_id, work_id, generation, state, reason,
                       attempts, opened_at_us
                   ) SELECT ?, target_id, work_id, generation, 'open', ?, 0, ?
                     FROM recovery_targets WHERE target_id = ? AND generation = ?""",
                (episode_id, row[4], reading.wall_us, row[0], int(row[1])),
            )
            next_timer = self._schedule_timer(
                connection,
                target_id=str(row[0]),
                generation=int(row[1]),
                episode_id=episode_id,
                kind="recovery",
                reason=str(row[4]),
                attempt=1,
                delay_seconds=_RECOVERY_DELAYS[1],
                reading=reading,
            )
            connection.execute(
                """UPDATE recovery_targets
                   SET episode_id = ?, current_timer_id = ?, updated_at_us = ?
                   WHERE target_id = ? AND generation = ?""",
                (episode_id, next_timer, reading.wall_us, row[0], int(row[1])),
            )
            event_type = "recovery.episode_opened"
        else:
            assert row[2] is not None and row[5] is not None
            episode_id = str(row[2])
            attempt = int(row[5])
            tier = "fast" if attempt <= 3 else "normal"
            connection.execute(
                """INSERT INTO recovery_attempts(
                       id, episode_id, timer_id, attempt_number, tier, state,
                       reason, due_at_us
                   ) VALUES (?, ?, ?, ?, ?, 'due', ?, ?)""",
                (
                    f"recovery-attempt-{uuid.uuid4().hex}",
                    episode_id,
                    timer_id,
                    attempt,
                    tier,
                    row[4],
                    reading.wall_us,
                ),
            )
            connection.execute(
                """UPDATE recovery_episodes SET attempts = ?
                   WHERE id = ? AND state = 'open' AND attempts < ?""",
                (attempt, episode_id, attempt),
            )
            event_type = "recovery.attempt_due"
        self.store._append_event(
            connection,
            "recovery_timer",
            timer_id,
            event_type,
            {
                "target_id": row[0],
                "generation": int(row[1]),
                "episode_id": episode_id,
                "attempt": None if row[5] is None else int(row[5]),
                "reason": row[4],
            },
            str(reading.wall_us),
        )
        if row[3] == "heuristic":
            return RecoveryTimerReceipt(
                timer_id,
                "fired",
                "heuristic",
                True,
                episode_id,
                None,
                None,
                next_timer,
            )
        return self._timer_receipt(connection, timer_id, due=True)

    def record_attempt(
        self,
        capability: object,
        connection: sqlite3.Connection,
        *,
        episode_id: str,
        attempt: int,
        result: RecoveryResult,
        failure_class: RecoveryFailureClass | None,
        reason: str,
    ) -> RecoveryAttemptReceipt:
        """Record one action result and schedule only bounded safe retry classes."""
        self._assert_authority(capability)
        _identifier(episode_id, "episode_id")
        _identifier(reason, "reason")
        if type(attempt) is not int or not 1 <= attempt <= MAX_RECOVERY_ATTEMPTS:
            raise ValueError("attempt is outside the recovery budget")
        if not isinstance(result, RecoveryResult):
            raise TypeError("result must be RecoveryResult")
        if failure_class is not None and not isinstance(failure_class, RecoveryFailureClass):
            raise TypeError("failure_class must be RecoveryFailureClass")
        if result is RecoveryResult.PROGRESS and failure_class is not None:
            raise ValueError("progress cannot have a failure class")
        if result is RecoveryResult.TRANSIENT_FAILURE and failure_class is not RecoveryFailureClass.TRANSIENT:
            raise ValueError("transient result requires transient failure class")
        if result is RecoveryResult.TERMINAL_FAILURE and failure_class not in _TERMINAL_FAILURES:
            raise ValueError("terminal result requires a non-retryable failure class")
        reading = self._read_clock(connection)
        row = connection.execute(
            """SELECT attempt_row.id, attempt_row.state, episode.target_id,
                      episode.generation, episode.state
               FROM recovery_attempts AS attempt_row
               JOIN recovery_episodes AS episode ON episode.id = attempt_row.episode_id
               WHERE attempt_row.episode_id = ? AND attempt_row.attempt_number = ?""",
            (episode_id, attempt),
        ).fetchone()
        if row is None:
            raise KeyError(episode_id)
        if row[1] != "due":
            return self._attempt_receipt(connection, episode_id, attempt)
        if row[4] != "open":
            raise OwnershipConflict("recovery episode is not open")
        if result is RecoveryResult.PROGRESS:
            connection.execute(
                """UPDATE recovery_attempts
                   SET state = 'succeeded', finished_at_us = ?
                   WHERE id = ? AND state = 'due'""",
                (reading.wall_us, row[0]),
            )
            self._recover_episode(connection, episode_id, reading, reason)
            connection.execute(
                """UPDATE recovery_targets
                   SET phase = 'active', productive = 1, episode_id = NULL,
                       current_timer_id = NULL, circuit_state = 'closed', updated_at_us = ?
                   WHERE target_id = ? AND generation = ?""",
                (reading.wall_us, row[2], int(row[3])),
            )
            next_timer = None
            event_type = "recovery.progress"
        else:
            terminal = (
                result is RecoveryResult.TERMINAL_FAILURE
                or failure_class in _TERMINAL_FAILURES
                or attempt >= MAX_RECOVERY_ATTEMPTS
            )
            if terminal:
                failure = failure_class or RecoveryFailureClass.TRANSIENT
                connection.execute(
                    """UPDATE recovery_attempts
                       SET state = 'terminal', failure_class = ?, finished_at_us = ?
                       WHERE id = ? AND state = 'due'""",
                    (failure.value, reading.wall_us, row[0]),
                )
                attention = (
                    "no_progress_circuit_open"
                    if attempt >= MAX_RECOVERY_ATTEMPTS and failure not in _TERMINAL_FAILURES
                    else f"terminal_{failure.value}"
                )
                connection.execute(
                    """UPDATE recovery_episodes
                       SET state = 'attention', closed_at_us = ?, attention_reason = ?
                       WHERE id = ? AND state = 'open'""",
                    (reading.wall_us, attention, episode_id),
                )
                connection.execute(
                    """UPDATE recovery_targets
                       SET phase = 'attention', current_timer_id = NULL,
                           circuit_state = 'open', updated_at_us = ?
                       WHERE target_id = ? AND generation = ?""",
                    (reading.wall_us, row[2], int(row[3])),
                )
                next_timer = None
                event_type = "recovery.attention_required"
            else:
                state = "no_progress"
                connection.execute(
                    """UPDATE recovery_attempts
                       SET state = ?, failure_class = ?, finished_at_us = ?
                       WHERE id = ? AND state = 'due'""",
                    (
                        state,
                        None if failure_class is None else failure_class.value,
                        reading.wall_us,
                        row[0],
                    ),
                )
                next_attempt = attempt + 1
                next_timer = self._schedule_timer(
                    connection,
                    target_id=str(row[2]),
                    generation=int(row[3]),
                    episode_id=episode_id,
                    kind="recovery",
                    reason=reason,
                    attempt=next_attempt,
                    delay_seconds=_RECOVERY_DELAYS[next_attempt],
                    reading=reading,
                )
                connection.execute(
                    """UPDATE recovery_targets
                       SET current_timer_id = ?, updated_at_us = ?
                       WHERE target_id = ? AND generation = ?""",
                    (next_timer, reading.wall_us, row[2], int(row[3])),
                )
                event_type = "recovery.retry_scheduled"
        self.store._append_event(
            connection,
            "recovery_episode",
            episode_id,
            event_type,
            {
                "attempt": attempt,
                "result": result.value,
                "failure_class": None if failure_class is None else failure_class.value,
                "reason": reason,
                "next_timer_id": next_timer,
            },
            str(reading.wall_us),
        )
        return self._attempt_receipt(connection, episode_id, attempt)

    def _schedule_timer(
        self,
        connection: sqlite3.Connection,
        *,
        target_id: str,
        generation: int,
        episode_id: str | None,
        kind: str,
        reason: str,
        attempt: int | None,
        delay_seconds: int,
        reading: ClockReading,
    ) -> str:
        timer_id = f"recovery-timer-{uuid.uuid4().hex}"
        connection.execute(
            """INSERT INTO recovery_timers(
                   id, target_id, generation, episode_id, kind, reason,
                   attempt_number, state, clock_epoch, scheduled_wall_us,
                   scheduled_mono_ns, due_wall_us, due_mono_ns
               ) VALUES (?, ?, ?, ?, ?, ?, ?, 'scheduled', ?, ?, ?, ?, ?)""",
            (
                timer_id,
                target_id,
                generation,
                episode_id,
                kind,
                reason,
                attempt,
                reading.epoch,
                reading.wall_us,
                reading.monotonic_ns,
                reading.wall_us + delay_seconds * 1_000_000,
                reading.monotonic_ns + delay_seconds * 1_000_000_000,
            ),
        )
        self.store._append_event(
            connection,
            "recovery_timer",
            timer_id,
            "recovery.timer_scheduled",
            {
                "target_id": target_id,
                "generation": generation,
                "episode_id": episode_id,
                "kind": kind,
                "reason": reason,
                "attempt": attempt,
                "delay_seconds": delay_seconds,
            },
            str(reading.wall_us),
        )
        return timer_id

    @staticmethod
    def _evidence_exists(
        connection: sqlite3.Connection,
        work_id: str,
        generation: int,
        evidence: RecoveryEvidence,
    ) -> bool:
        if evidence is RecoveryEvidence.COMPLETION:
            row = connection.execute(
                """SELECT 1 FROM completion_events
                   WHERE work_id = ? AND generation = ?""",
                (work_id, generation),
            ).fetchone()
        elif evidence is RecoveryEvidence.CALLBACK:
            row = connection.execute(
                """SELECT 1
                   FROM callbacks AS callback
                   JOIN completion_events AS completion
                     ON completion.id = callback.completion_event_id
                   WHERE completion.work_id = ? AND completion.generation = ?
                     AND callback.state = 'delivered'""",
                (work_id, generation),
            ).fetchone()
        elif evidence is RecoveryEvidence.CLAIM:
            row = connection.execute(
                """SELECT 1
                   FROM scheduler_work AS work
                   JOIN scheduler_admission_decisions AS decision
                     ON decision.id = work.policy_decision_id
                    AND decision.work_id = work.id
                    AND decision.allowed = 1
                   JOIN scope_claims AS claim
                     ON claim.id = decision.scope_claim_id
                    AND claim.attempt = decision.scope_claim_attempt
                    AND claim.fence_token = decision.scope_claim_fence
                    AND claim.state IN ('active','released')
                   WHERE work.id = ? AND work.attempt = ?""",
                (work_id, generation),
            ).fetchone()
        else:
            return False
        return row is not None

    def _cancel_timer(
        self,
        connection: sqlite3.Connection,
        timer_id: str | None,
        reading: ClockReading,
        reason: str,
    ) -> None:
        if timer_id is None:
            return
        cursor = connection.execute(
            """UPDATE recovery_timers SET state = 'cancelled', cancelled_at_us = ?
               WHERE id = ? AND state = 'scheduled'""",
            (reading.wall_us, timer_id),
        )
        if cursor.rowcount:
            self.store._append_event(
                connection,
                "recovery_timer",
                timer_id,
                "recovery.timer_cancelled",
                {"reason": reason},
                str(reading.wall_us),
            )

    def _recover_episode(
        self,
        connection: sqlite3.Connection,
        episode_id: str | None,
        reading: ClockReading,
        reason: str,
    ) -> None:
        if episode_id is None:
            return
        due_attempts = connection.execute(
            """SELECT id, attempt_number FROM recovery_attempts
               WHERE episode_id = ? AND state = 'due'""",
            (episode_id,),
        ).fetchall()
        for attempt_id, attempt_number in due_attempts:
            connection.execute(
                """UPDATE recovery_attempts
                   SET state = 'cancelled', finished_at_us = ?
                   WHERE id = ? AND state = 'due'""",
                (reading.wall_us, attempt_id),
            )
            self.store._append_event(
                connection,
                "recovery_attempt",
                attempt_id,
                "recovery.attempt_cancelled",
                {"attempt": int(attempt_number), "reason": reason},
                str(reading.wall_us),
            )
        cursor = connection.execute(
            """UPDATE recovery_episodes
               SET state = 'recovered', closed_at_us = ?
               WHERE id = ? AND state = 'open'""",
            (reading.wall_us, episode_id),
        )
        if cursor.rowcount != 1:
            return
        self.store._append_event(
            connection,
            "recovery_episode",
            episode_id,
            "recovery.episode_recovered",
            {"reason": reason},
            str(reading.wall_us),
        )

    @staticmethod
    def _reason(phase: RecoveryPhase, productive: bool) -> str:
        if phase is RecoveryPhase.ACTIVE:
            return "productive_active" if productive else "zero_output"
        return {
            RecoveryPhase.HANDED_OFF: "unanswered",
            RecoveryPhase.TOOL_FLOW: "stalled_tool_flow",
            RecoveryPhase.BUSY: "frozen_busy",
            RecoveryPhase.THINKING: "stale_thinking",
            RecoveryPhase.CORPSE: "corpse",
        }.get(phase, "inactive")

    @staticmethod
    def _timer_receipt(
        connection: sqlite3.Connection,
        timer_id: str,
        *,
        due: bool,
    ) -> RecoveryTimerReceipt:
        row = connection.execute(
            """SELECT timer.state, timer.kind,
                      coalesce(timer.episode_id, target.episode_id),
                      timer.attempt_number, attempt.tier,
                      CASE WHEN timer.kind = 'heuristic' AND timer.state = 'fired'
                           THEN target.current_timer_id ELSE NULL END
               FROM recovery_timers AS timer
               JOIN recovery_targets AS target
                 ON target.target_id = timer.target_id
                AND target.generation = timer.generation
               LEFT JOIN recovery_attempts AS attempt ON attempt.timer_id = timer.id
               WHERE timer.id = ?""",
            (timer_id,),
        ).fetchone()
        if row is None:
            raise KeyError(timer_id)
        return RecoveryTimerReceipt(
            timer_id,
            str(row[0]),
            str(row[1]),
            due,
            None if row[2] is None else str(row[2]),
            None if row[3] is None else int(row[3]),
            None if row[4] is None else str(row[4]),
            None if row[5] is None else str(row[5]),
        )

    @staticmethod
    def _attempt_receipt(
        connection: sqlite3.Connection,
        episode_id: str,
        attempt: int,
    ) -> RecoveryAttemptReceipt:
        row = connection.execute(
            """SELECT attempt_row.state, target.current_timer_id,
                      target.circuit_state
               FROM recovery_attempts AS attempt_row
               JOIN recovery_episodes AS episode ON episode.id = attempt_row.episode_id
               JOIN recovery_targets AS target ON target.target_id = episode.target_id
               WHERE attempt_row.episode_id = ? AND attempt_row.attempt_number = ?""",
            (episode_id, attempt),
        ).fetchone()
        if row is None:
            raise KeyError(episode_id)
        return RecoveryAttemptReceipt(
            episode_id,
            attempt,
            str(row[0]),
            None if row[1] is None else str(row[1]),
            str(row[2]),
        )


def _create_recovery(
    store: RigStore,
    authority: _DaemonAuthority,
    capability: object,
    *,
    clock: TrustedClock | None = None,
) -> _RecoveryService:
    authority._assert_for(store)
    service = object.__new__(_RecoveryService)
    service.store = store
    service._authority = authority
    service._capability_id = id(capability)
    service._clock = clock or SystemTrustedClock()
    return service
