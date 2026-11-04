"""Daemon-owned lifecycle wrapper for the explicit OpenCode completion join."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any

from oc_rig.adapters.opencode import (
    DispatchRegistration,
    LiveOpenCodeAdapter,
    _validated_status_types,
)
from oc_rig.adapters.opencode_client import (
    SSE_READ_TIMEOUT_SECONDS,
    OpenCodeClientError,
    validate_identifier,
)
from oc_rig.completion.opencode import OpenCodeCompletion, OpenCodeCompletionMonitor
from oc_rig.completion.opencode import (
    CompletionDeferred,
    MAX_COMPLETION_MESSAGE_WINDOW,
    _assistant_final,
    _latest_assistant_segment,
    _message_outcome,
    _terminal_text,
)
from oc_rig.completion.barrier import (
    CONSOLIDATION_PROMPT,
    ChildBarrierAttention,
    canonical_review_profile,
    child_set_digest,
    consolidation_message_id,
    discover_current_turn_children,
    iso_to_epoch_ms,
)
from oc_rig.completion.models import (
    FUGUE_REVIEW_PROFILES,
    CompletionFinalResult,
    CompletionOutcome,
    FugueHandoverInvalid,
    parse_fugue_handover,
)
from oc_rig.completion.service import _CompletionService
from oc_rig.policy.capsule import ScopeCapsuleError, parse_task_prompt
from oc_rig.recovery.models import RecoveryEvidence, RecoveryPhase
from oc_rig.recovery.service import _RecoveryService
from oc_rig.store.database import OwnershipConflict, RigStore, _DaemonAuthority
from oc_rig.transcript import (
    TRANSCRIPT_MESSAGE_LIMIT,
    TranscriptProjectionInvalid,
    project_transcript_turns,
)
from oc_rig.workspace_edit import (
    WorkspaceEditIndeterminate,
    WorkspaceEditRejected,
    apply_workspace_edit_plan,
)


SLOW_RECONNECT_DELAYS_SECONDS = (5.0, 15.0, 30.0)


class _CompletionReleaseError(RuntimeError):
    """The exact completion and lease release could not commit together."""


class _WorkspaceEditApplyError(RuntimeError):
    """A workspace task completion could not pass the local write broker."""


class _DaemonOpenCodeCompletionMonitor:
    """Own one bounded monitor thread and its durable completion sink."""

    __slots__ = (
        "_adapter",
        "_authority",
        "_cancellation",
        "_capability",
        "_completion",
        "_completion_callback",
        "_cleanup_event",
        "_cleanup_thread",
        "_failure",
        "_failure_lock",
        "_monitor",
        "_recovery",
        "_store",
        "_thread",
    )

    def __init__(
        self,
        store: RigStore,
        authority: _DaemonAuthority,
        capability: object,
        completion: _CompletionService,
        recovery: _RecoveryService,
        adapter: LiveOpenCodeAdapter,
        completion_callback: Callable[[], object] | None = None,
    ):
        if type(adapter) is not LiveOpenCodeAdapter:
            raise TypeError("exact live OpenCode adapter required")
        authority._assert_for(store)
        self._store = store
        self._authority = authority
        self._capability = capability
        self._completion = completion
        self._recovery = recovery
        self._adapter = adapter
        if completion_callback is not None and not callable(completion_callback):
            raise TypeError("completion callback must be callable")
        self._completion_callback = completion_callback
        self._cleanup_event = threading.Event()
        self._cleanup_thread: threading.Thread | None = None
        self._cancellation = threading.Event()
        self._failure: str | None = None
        self._failure_lock = threading.Lock()
        self._monitor = OpenCodeCompletionMonitor(
            adapter._client,
            self._accept,
            self._session_missing,
            self._session_present,
            self._accept,
            self._session_idle_state,
        )
        self._thread: threading.Thread | None = None

    def startup_validate(self) -> None:
        """Load durable registrations and prove REST compatibility before readiness."""

        for registration in self._adapter.completion_registrations():
            self._monitor.register(registration)
        self._monitor.read_repair()
        self._adapter.pump_session_cleanup()

    def register_transport(self, transport_id: str) -> None:
        registration = self._adapter.completion_registration(transport_id)
        if registration is None:
            raise RuntimeError("accepted OpenCode dispatch lacks a durable registration")
        self._monitor.register(registration)

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("completion monitor is already started")
        self._cancellation.clear()
        thread = threading.Thread(
            target=self._run,
            name="rigd-opencode-completion",
            daemon=True,
        )
        self._thread = thread
        thread.start()
        cleanup = threading.Thread(
            target=self._cleanup_run,
            name="rigd-opencode-session-cleanup",
            daemon=True,
        )
        self._cleanup_thread = cleanup
        cleanup.start()

    def _cleanup_run(self) -> None:
        while not self._cancellation.is_set():
            self._cleanup_event.wait(30)
            self._cleanup_event.clear()
            if self._cancellation.is_set():
                return
            try:
                self._adapter.pump_session_cleanup()
            except OpenCodeClientError as error:
                self._record_failure(error.code)

    def _run(self) -> None:
        slow_failures = 0
        while not self._cancellation.is_set():
            repaired = False

            def authoritative_health() -> None:
                nonlocal repaired
                repaired = True
                self._clear_failure()

            try:
                self._monitor.run(self._cancellation, authoritative_health)
                return
            except _CompletionReleaseError:
                self._record_failure("completion_reservation_release_failed")
                return
            except _WorkspaceEditApplyError:
                self._record_failure("workspace_edit_rejected")
                return
            except OpenCodeClientError as error:
                if self._cancellation.is_set():
                    return
                self._record_failure(error.code)
            except Exception:
                self._record_failure("completion_monitor_internal_error")
                return
            if repaired:
                slow_failures = 0
            delay = SLOW_RECONNECT_DELAYS_SECONDS[
                min(slow_failures, len(SLOW_RECONNECT_DELAYS_SECONDS) - 1)
            ]
            slow_failures += 1
            if self._cancellation.wait(delay):
                return

    def _record_failure(self, reason: str) -> None:
        with self._failure_lock:
            self._failure = reason

    def _clear_failure(self) -> None:
        with self._failure_lock:
            self._failure = None

    @staticmethod
    def _session_recovery_target(registration: DispatchRegistration) -> str:
        material = (
            f"{registration.transport_id}:{registration.completion_registration_id}:"
            f"{registration.generation}:{registration.session_id}"
        ).encode()
        return f"recovery-target-session-missing-{hashlib.sha256(material).hexdigest()}"

    def _session_observation(
        self,
        registration: DispatchRegistration,
        *,
        missing: bool,
    ) -> None:
        exact = self._adapter.completion_registration(registration.transport_id)
        if exact != registration:
            return
        with self._store._daemon_transaction(self._authority) as connection:
            eligible = connection.execute(
                """SELECT completion.assignment_attempt
                   FROM opencode_deliveries AS delivery
                   JOIN transport_completion_registrations AS completion
                     ON completion.id = delivery.completion_registration_id
                    AND completion.transport_id = delivery.transport_id
                   WHERE delivery.transport_id = ? AND delivery.work_id = ?
                     AND delivery.isolated_session_id = ?
                     AND delivery.agent_lifecycle = 'disposable'
                     AND delivery.delivery_state = 'accepted'
                     AND delivery.lease_state = 'active'
                     AND delivery.abort_state = 'none'
                     AND delivery.cleanup_state = 'none'
                     AND completion.id = ? AND completion.state = 'pending'
                     AND NOT EXISTS (
                         SELECT 1 FROM completion_events AS event
                         WHERE event.work_id = delivery.work_id
                           AND event.generation = delivery.assignment_generation
                     )""",
                (
                    registration.transport_id,
                    registration.work_id,
                    registration.session_id,
                    registration.completion_registration_id,
                ),
            ).fetchone()
            if eligible is None:
                return
            completion_generation = int(eligible[0])
            self._recovery.observe(
                self._capability,
                connection,
                target_id=self._session_recovery_target(registration),
                work_id=registration.work_id,
                generation=completion_generation,
                phase=RecoveryPhase.CORPSE if missing else RecoveryPhase.ACTIVE,
                productive=not missing,
                evidence=RecoveryEvidence.NONE,
            )

    def _session_missing(self, registration: DispatchRegistration) -> None:
        self._session_observation(registration, missing=True)

    def _session_present(self, registration: DispatchRegistration) -> None:
        self._session_observation(registration, missing=False)

    def _session_idle_state(
        self, registration: DispatchRegistration, reason: str
    ) -> None:
        if reason not in {"idle_without_terminal", "idle_progress_resumed"}:
            self._record_failure("idle_recovery_reason_invalid")
            return
        exact = self._adapter.completion_registration(registration.transport_id)
        if exact != registration:
            return
        try:
            with self._store._daemon_transaction(self._authority) as connection:
                eligible = connection.execute(
                    """SELECT completion.assignment_attempt
                       FROM opencode_deliveries AS delivery
                       JOIN transport_completion_registrations AS completion
                         ON completion.id = delivery.completion_registration_id
                        AND completion.transport_id = delivery.transport_id
                       WHERE delivery.transport_id = ? AND delivery.work_id = ?
                         AND delivery.isolated_session_id = ?
                         AND delivery.agent_lifecycle = 'disposable'
                         AND delivery.delivery_state = 'accepted'
                         AND delivery.lease_state = 'active'
                         AND delivery.abort_state = 'none'
                         AND delivery.cleanup_state = 'none'
                         AND completion.id = ? AND completion.state = 'pending'
                         AND NOT EXISTS (
                             SELECT 1 FROM completion_events AS event
                             WHERE event.work_id = delivery.work_id
                               AND event.generation = completion.assignment_attempt
                         )""",
                    (
                        registration.transport_id,
                        registration.work_id,
                        registration.session_id,
                        registration.completion_registration_id,
                    ),
                ).fetchone()
                if eligible is None:
                    return
                self._recovery.observe(
                    self._capability,
                    connection,
                    target_id=self._session_recovery_target(registration),
                    work_id=registration.work_id,
                    generation=int(eligible[0]),
                    phase=(
                        RecoveryPhase.CORPSE
                        if reason == "idle_without_terminal"
                        else RecoveryPhase.ACTIVE
                    ),
                    productive=reason == "idle_progress_resumed",
                    evidence=RecoveryEvidence.NONE,
                )
        except Exception:
            self._record_failure("idle_recovery_observation_failed")

    def _accept(self, completion: OpenCodeCompletion) -> None:
        exact = self._adapter.completion_registration(completion.transport_id)
        if exact is None or exact != DispatchRegistration(
            completion.transport_id,
            completion.work_id,
            completion.registration_id,
            completion.callback_registration_id,
            completion.session_id,
            completion.generation,
            completion.prompt_message_id,
            completion.transport_id,
        ):
            raise RuntimeError("completion registration lost exact authority")
        completion = self._child_completion_gate(exact, completion)
        if completion.outcome is None:
            raise RuntimeError("child barrier returned a non-terminal trigger")
        archive_capture = (
            self._capture_transcript_archive(exact)
            if self._transcript_archive_enabled()
            else None
        )
        with self._store._daemon_transaction(self._authority) as connection:
            route = connection.execute(
                """SELECT assignment_attempt, work_id
                   FROM transport_completion_registrations
                   WHERE id = ? AND transport_id = ?""",
                (completion.registration_id, completion.transport_id),
            ).fetchone()
            if route is None or str(route[1]) != completion.work_id:
                raise RuntimeError("completion route lost exact authority")
            task_envelope = self._task_envelope(connection, completion.work_id)
            final_result = self._workspace_final_result(
                connection,
                completion,
                int(route[0]),
            )
            if task_envelope is not None and task_envelope.get("task_mode") == "agent_task":
                final_result = self._agent_task_final_result(
                    completion, int(route[0]), task_envelope
                )
            try:
                receipt = self._completion.accept(
                    self._capability,
                    connection,
                    completion_key=completion.completion_key,
                    registration_id=completion.registration_id,
                    work_id=completion.work_id,
                    generation=int(route[0]),
                    outcome=final_result.outcome,
                    final_result=final_result,
                )
            except OwnershipConflict as error:
                raise _CompletionReleaseError(
                    "exact completion finalization failed"
                ) from error
            if receipt.result_ref is None:
                raise RuntimeError("completion did not persist a durable final result")
            if archive_capture is not None:
                self._persist_transcript_archive(
                    connection,
                    exact,
                    result_ref=receipt.result_ref,
                    generation=int(route[0]),
                    capture=archive_capture,
                )
            self._recovery.evidence_for_work(
                self._capability,
                connection,
                work_id=completion.work_id,
                generation=int(route[0]),
                evidence=RecoveryEvidence.COMPLETION,
            )
            if not self._adapter.release_completed_in_transaction(connection, exact):
                raise _CompletionReleaseError("exact reservation release failed")
        if self._completion_callback is not None:
            self._completion_callback()
        self._cleanup_event.set()

    def _transcript_archive_enabled(self) -> bool:
        with self._store._daemon_transaction(self._authority) as connection:
            return connection.execute(
                """SELECT 1 FROM sqlite_master
                   WHERE type = 'table'
                     AND name = 'completed_transcript_snapshots'"""
            ).fetchone() is not None

    def _capture_transcript_archive(
        self, registration: DispatchRegistration
    ) -> tuple[str, str, int, int, int] | None:
        """Capture one bounded durable-safe root transcript before cleanup."""

        try:
            messages = self._adapter._client.messages(
                registration.session_id, limit=TRANSCRIPT_MESSAGE_LIMIT
            )
            turns, redacted = project_transcript_turns(messages, durable=True)
        except (OpenCodeClientError, TranscriptProjectionInvalid):
            return None
        document = {"turns": turns, "redacted": redacted}
        encoded = json.dumps(
            document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if not 25 <= len(encoded) <= 48 * 1024:
            return None
        return (
            encoded.decode("utf-8"),
            hashlib.sha256(encoded).hexdigest(),
            len(turns),
            len(redacted),
            time.time_ns() // 1_000,
        )

    def _persist_transcript_archive(
        self,
        connection: object,
        registration: DispatchRegistration,
        *,
        result_ref: str,
        generation: int,
        capture: tuple[str, str, int, int, int],
    ) -> None:
        slot = connection.execute(
            """SELECT slot_id FROM opencode_deliveries
               WHERE transport_id = ?
                 AND completion_registration_id = ?
                 AND work_id = ?
                 AND assignment_generation = ?""",
            (
                registration.transport_id,
                registration.completion_registration_id,
                registration.work_id,
                registration.generation,
            ),
        ).fetchone()
        if slot is None or type(slot[0]) is not str:
            raise _CompletionReleaseError("transcript archive lost slot authority")
        existing = connection.execute(
            """SELECT transport_id, work_id, generation, slot_id, session_id
               FROM completed_transcript_snapshots WHERE result_ref = ?""",
            (result_ref,),
        ).fetchone()
        expected = (
            registration.transport_id,
            registration.work_id,
            generation,
            str(slot[0]),
            registration.session_id,
        )
        if existing is not None:
            if tuple(existing) != expected:
                raise _CompletionReleaseError("transcript archive authority changed")
            return
        transcript_json, digest, turn_count, redaction_count, captured_at_us = capture
        connection.execute(
            """INSERT INTO completed_transcript_snapshots(
                   result_ref, transport_id, work_id, generation, slot_id, session_id,
                   captured_at_us, turn_count, redaction_count, transcript_json,
                   transcript_sha256
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result_ref,
                *expected,
                captured_at_us,
                turn_count,
                redaction_count,
                transcript_json,
                digest,
            ),
        )

    def _child_completion_gate(
        self,
        registration: DispatchRegistration,
        completion: OpenCodeCompletion,
    ) -> OpenCodeCompletion:
        """Authorize a root final only after its frozen child set is joined."""

        with self._store._daemon_transaction(self._authority) as connection:
            authority = connection.execute(
                """SELECT decision.allow_child_agents, delivery.created_at,
                          completion.assignment_attempt
                   FROM opencode_deliveries AS backend
                   JOIN transport_deliveries AS delivery
                     ON delivery.id = backend.transport_id
                   JOIN transport_completion_registrations AS completion
                     ON completion.id = backend.completion_registration_id
                    AND completion.transport_id = backend.transport_id
                   JOIN scheduler_admission_decisions AS decision
                     ON decision.id = delivery.admission_decision_id
                   WHERE backend.transport_id = ?
                     AND backend.completion_registration_id = ?
                     AND backend.work_id = ?
                     AND backend.assignment_generation = ?""",
                (
                    registration.transport_id,
                    registration.completion_registration_id,
                    registration.work_id,
                    registration.generation,
                ),
            ).fetchone()
            if authority is None:
                raise _CompletionReleaseError("child barrier authority is absent")
            task_envelope = self._task_envelope(connection, registration.work_id)
            if int(authority[0]) == 0:
                if completion.outcome is None:
                    raise CompletionDeferred("root_tool_calls_not_terminal")
                return completion
            turn_started_at_ms = iso_to_epoch_ms(authority[1])
            completion_generation = int(authority[2])
            existing = connection.execute(
                """SELECT state, child_set_sha256, child_count,
                          consolidation_message_id,
                          consolidation_idempotency_key,
                          authorized_assistant_message_id, turn_started_at_ms,
                          generation
                   FROM completion_child_barriers WHERE transport_id = ?""",
                (registration.transport_id,),
            ).fetchone()

        if existing is not None and str(existing[0]) == "attention":
            raise CompletionDeferred("child_barrier_attention")

        sessions = self._adapter._client.list_sessions()
        observed_at_ms = iso_to_epoch_ms(self._store_now())
        try:
            children = discover_current_turn_children(
                sessions,
                root_session_id=registration.session_id,
                turn_started_at_ms=turn_started_at_ms,
                observed_at_ms=observed_at_ms,
            )
        except ChildBarrierAttention as error:
            self._record_child_barrier_attention(registration, error.reason)
            raise CompletionDeferred(error.reason) from None
        digest = child_set_digest(children)

        if task_envelope is not None:
            if not children:
                if completion.outcome is None:
                    raise CompletionDeferred("root_tool_calls_not_terminal")
                # A controller-created task capsule may close without reviewers only
                # as an explicit failed completion.  It cannot escape as successful
                # work merely because the model ignored its mandatory review phase.
                completion = self._failed_completion(completion)
            else:
                try:
                    self._validate_review_quorum(registration, children)
                except ChildBarrierAttention as error:
                    self._record_child_barrier_attention(registration, error.reason)
                    raise CompletionDeferred(error.reason) from None

        if existing is None and not children and completion.outcome is None:
            raise CompletionDeferred("root_tool_calls_not_terminal")

        if existing is not None and (
            int(existing[6]) != turn_started_at_ms
            or int(existing[7]) != completion_generation
            or str(existing[1]) != digest
            or int(existing[2]) != len(children)
        ):
            self._record_child_barrier_attention(
                registration, "child_session_set_changed"
            )
            raise CompletionDeferred("child_session_set_changed")

        if existing is None:
            now = self._store_now()
            state = "ready" if not children else "waiting"
            authorized = completion.assistant_message_id if not children else None
            with self._store._daemon_transaction(self._authority) as connection:
                connection.execute(
                    """INSERT INTO completion_child_barriers(
                           transport_id, completion_registration_id, work_id,
                           generation, root_session_id, turn_started_at_ms,
                           child_set_sha256, child_count, state,
                           consolidation_message_id,
                           consolidation_idempotency_key,
                           authorized_assistant_message_id, attention_reason,
                           created_at, updated_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, NULL, ?, ?)""",
                    (
                        registration.transport_id,
                        registration.completion_registration_id,
                        registration.work_id,
                        completion_generation,
                        registration.session_id,
                        turn_started_at_ms,
                        digest,
                        len(children),
                        state,
                        authorized,
                        now,
                        now,
                    ),
                )
                for child in children:
                    connection.execute(
                        """INSERT INTO completion_child_sessions(
                               transport_id, child_session_id, parent_session_id,
                               created_at_ms, state,
                               terminal_assistant_message_id, updated_at
                           ) VALUES (?, ?, ?, ?, 'waiting', NULL, ?)""",
                        (
                            registration.transport_id,
                            child.session_id,
                            child.parent_session_id,
                            child.created_at_ms,
                            now,
                        ),
                    )
                self._store._append_event(
                    connection,
                    "completion_child_barrier",
                    registration.transport_id,
                    "completion.child_barrier.frozen",
                    {"child_count": len(children), "work_id": registration.work_id},
                    now,
                )
            if not children:
                return completion
            existing = ("waiting", digest, len(children), None, None, None, turn_started_at_ms)

        state = str(existing[0])
        if state == "attention":
            raise CompletionDeferred("child_barrier_attention")
        if state == "ready":
            if existing[5] != completion.assistant_message_id:
                # A child-bearing ready barrier authorizes the consolidation
                # assistant, which is reconstructed below instead.
                if int(existing[2]) == 0:
                    self._record_child_barrier_attention(
                        registration, "child_barrier_authority_changed"
                    )
                    raise CompletionDeferred("child_barrier_authority_changed")
                restored = self._consolidated_completion(
                    registration, completion, str(existing[3])
                )
                if (
                    restored is None
                    or restored.assistant_message_id != str(existing[5])
                ):
                    self._record_child_barrier_attention(
                        registration, "child_barrier_authority_changed"
                    )
                    raise CompletionDeferred("child_barrier_authority_changed")
                return restored
            else:
                return completion

        statuses = _validated_status_types(self._adapter._client.session_status())
        terminal_children: dict[str, str] = {}
        try:
            for child in children:
                terminal = self._child_terminal_assistant(child.session_id, statuses)
                if terminal is not None:
                    terminal_children[child.session_id] = terminal
        except OpenCodeClientError:
            self._record_child_barrier_attention(
                registration, "child_terminal_state_invalid"
            )
            raise CompletionDeferred("child_terminal_state_invalid") from None
        with self._store._daemon_transaction(self._authority) as connection:
            stored_children = {
                str(row[0]): (str(row[1]), row[2])
                for row in connection.execute(
                    """SELECT child_session_id, state,
                              terminal_assistant_message_id
                       FROM completion_child_sessions
                       WHERE transport_id = ?""",
                    (registration.transport_id,),
                ).fetchall()
            }
        for child in children:
            stored = stored_children.get(child.session_id)
            if stored is None:
                self._record_child_barrier_attention(
                    registration, "child_session_set_changed"
                )
                raise CompletionDeferred("child_session_set_changed")
            if (
                stored[0] == "terminal"
                and terminal_children.get(child.session_id) != stored[1]
            ):
                self._record_child_barrier_attention(
                    registration, "child_terminal_authority_changed"
                )
                raise CompletionDeferred("child_terminal_authority_changed")
        now = self._store_now()
        with self._store._daemon_transaction(self._authority) as connection:
            for child_id, assistant_id in terminal_children.items():
                connection.execute(
                    """UPDATE completion_child_sessions
                       SET state = 'terminal', terminal_assistant_message_id = ?,
                           updated_at = ?
                       WHERE transport_id = ? AND child_session_id = ?
                         AND state = 'waiting'""",
                    (assistant_id, now, registration.transport_id, child_id),
                )
            barrier = connection.execute(
                """SELECT state, consolidation_message_id,
                          consolidation_idempotency_key
                   FROM completion_child_barriers WHERE transport_id = ?""",
                (registration.transport_id,),
            ).fetchone()
            if barrier is None:
                raise _CompletionReleaseError("child barrier disappeared")
            remaining = connection.execute(
                """SELECT count(*) FROM completion_child_sessions
                   WHERE transport_id = ? AND state != 'terminal'""",
                (registration.transport_id,),
            ).fetchone()[0]
            state = str(barrier[0])
            if not remaining and state == "waiting":
                message_id = consolidation_message_id(
                    registration.transport_id, registration.generation
                )
                idempotency_key = f"{registration.transport_id}:consolidate"
                connection.execute(
                    """UPDATE completion_child_barriers
                       SET state = 'consolidation_prepared',
                           consolidation_message_id = ?,
                           consolidation_idempotency_key = ?, updated_at = ?
                       WHERE transport_id = ? AND state = 'waiting'""",
                    (message_id, idempotency_key, now, registration.transport_id),
                )
                self._store._append_event(
                    connection,
                    "completion_child_barrier",
                    registration.transport_id,
                    "completion.child_barrier.consolidation_prepared",
                    {"child_count": len(children)},
                    now,
                )
                send = True
            else:
                message_id = str(barrier[1]) if barrier[1] is not None else ""
                idempotency_key = str(barrier[2]) if barrier[2] is not None else ""
                send = False

        if remaining:
            raise CompletionDeferred("child_sessions_not_terminal")

        if state == "consolidation_prepared" and not send:
            self._record_child_barrier_attention(
                registration, "consolidation_delivery_uncertain"
            )
            raise CompletionDeferred("consolidation_delivery_uncertain")
        if send:
            try:
                self._adapter.dispatch_completion_consolidation(
                    registration,
                    message_id=message_id,
                    prompt=CONSOLIDATION_PROMPT,
                    idempotency_key=idempotency_key,
                )
            except OpenCodeClientError:
                self._record_child_barrier_attention(
                    registration, "consolidation_delivery_uncertain"
                )
                raise CompletionDeferred("consolidation_delivery_uncertain") from None
            with self._store._daemon_transaction(self._authority) as connection:
                updated = connection.execute(
                    """UPDATE completion_child_barriers
                       SET state = 'consolidation_sent', updated_at = ?
                       WHERE transport_id = ? AND state = 'consolidation_prepared'
                         AND consolidation_message_id = ?
                         AND consolidation_idempotency_key = ?""",
                    (self._store_now(), registration.transport_id, message_id, idempotency_key),
                )
                if updated.rowcount != 1:
                    raise _CompletionReleaseError(
                        "consolidation acknowledgement persistence failed"
                    )
            raise CompletionDeferred("consolidation_sent")

        if state != "consolidation_sent":
            raise CompletionDeferred("child_barrier_not_ready")
        consolidated = self._consolidated_completion(
            registration, completion, message_id
        )
        if consolidated is None:
            raise CompletionDeferred("consolidation_not_terminal")
        with self._store._daemon_transaction(self._authority) as connection:
            updated = connection.execute(
                """UPDATE completion_child_barriers
                   SET state = 'ready', authorized_assistant_message_id = ?,
                       updated_at = ?
                   WHERE transport_id = ? AND state = 'consolidation_sent'
                     AND consolidation_message_id = ?""",
                (
                    consolidated.assistant_message_id,
                    self._store_now(),
                    registration.transport_id,
                    message_id,
                ),
            )
            if updated.rowcount != 1:
                raise _CompletionReleaseError("child barrier finalization failed")
        return consolidated

    @staticmethod
    def _failed_completion(completion: OpenCodeCompletion) -> OpenCodeCompletion:
        if completion.outcome is None:
            raise ValueError("non-terminal completion cannot be converted to failure")
        return OpenCodeCompletion(
            completion.completion_key,
            completion.transport_id,
            completion.registration_id,
            completion.callback_registration_id,
            completion.work_id,
            completion.session_id,
            completion.generation,
            completion.prompt_message_id,
            CompletionOutcome.FAILED,
            completion.assistant_message_id,
            None,
        )

    def _validate_review_quorum(
        self, registration: DispatchRegistration, children: tuple[object, ...]
    ) -> None:
        if len(children) != len(FUGUE_REVIEW_PROFILES):
            raise ChildBarrierAttention("review_quorum_invalid")
        seen: set[str] = set()
        for child in children:
            session_id = getattr(child, "session_id", None)
            parent_session_id = getattr(child, "parent_session_id", None)
            if type(session_id) is not str or parent_session_id != registration.session_id:
                raise ChildBarrierAttention("review_quorum_invalid")
            try:
                messages = self._adapter._client.messages(
                    session_id, limit=MAX_COMPLETION_MESSAGE_WINDOW
                )
                profile = canonical_review_profile(messages, session_id=session_id)
            except OpenCodeClientError:
                raise ChildBarrierAttention("review_prompt_unavailable") from None
            if profile is None or profile in seen:
                raise ChildBarrierAttention("review_quorum_invalid")
            seen.add(profile)
        if seen != set(FUGUE_REVIEW_PROFILES):
            raise ChildBarrierAttention("review_quorum_invalid")

    @staticmethod
    def _task_envelope(connection: object, work_id: str) -> dict[str, object] | None:
        rows = connection.execute(
            """SELECT canonical_json FROM gui_task_submissions
               WHERE state = 'completed'
                 AND json_extract(outcome_json, '$.work_id') = ?
               LIMIT 2""",
            (work_id,),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise _CompletionReleaseError("task authority is ambiguous")
        try:
            canonical = json.loads(rows[0][0])
        except (json.JSONDecodeError, TypeError, UnicodeError) as error:
            raise _CompletionReleaseError("task authority is invalid") from error
        if (
            type(canonical) is not dict
            or set(canonical) not in (
                {"envelope", "repository", "scope"},
                {"envelope", "patch_authority", "repository", "scope"},
            )
            or type(canonical.get("envelope")) is not str
            or type(canonical.get("repository")) is not str
            or type(canonical.get("scope")) is not list
        ):
            raise _CompletionReleaseError("task authority is invalid")
        try:
            envelope = parse_task_prompt(canonical["envelope"])
        except ScopeCapsuleError as error:
            raise _CompletionReleaseError("task authority is invalid") from error
        if envelope is None or canonical["scope"] != envelope.get("scope"):
            raise _CompletionReleaseError("task authority is invalid")
        return envelope

    def _child_terminal_assistant(
        self, session_id: str, statuses: Mapping[str, str]
    ) -> str | None:
        if statuses.get(session_id, "idle") != "idle":
            return None
        if not all(
            item.get("status") in {"completed", "cancelled"}
            for item in self._adapter._client.todos(session_id)
        ):
            return None
        candidates: list[tuple[int | float, str, Mapping[str, Any]]] = []
        for item in self._adapter._client.messages(
            session_id, limit=MAX_COMPLETION_MESSAGE_WINDOW
        ):
            info = item.get("info") if type(item) is dict else None
            if (
                type(info) is not dict
                or info.get("role") != "assistant"
                or info.get("sessionID") != session_id
                or not _assistant_final(info)
            ):
                continue
            created = info.get("time", {}).get("created")
            message_id = info.get("id")
            try:
                message_id = validate_identifier(message_id, "child_message_id")
                validate_identifier(info.get("parentID"), "child_parent_message_id")
            except OpenCodeClientError:
                raise OpenCodeClientError("child_message_invalid") from None
            if type(created) not in {int, float}:
                raise OpenCodeClientError("child_message_invalid")
            candidates.append((created, message_id, info))
        if not candidates:
            return None
        _created, message_id, info = max(candidates, key=lambda item: (item[0], item[1]))
        return message_id if _message_outcome(info) is not None else None

    def _consolidated_completion(
        self,
        registration: DispatchRegistration,
        original: OpenCodeCompletion,
        message_id: str,
    ) -> OpenCodeCompletion | None:
        expected = DispatchRegistration(
            registration.transport_id,
            registration.work_id,
            registration.completion_registration_id,
            registration.callback_registration_id,
            registration.session_id,
            registration.generation,
            message_id,
            registration.idempotency_key,
        )
        terminal = _latest_assistant_segment(
            self._adapter._client.messages(
                registration.session_id, limit=MAX_COMPLETION_MESSAGE_WINDOW
            ),
            expected,
        )
        if terminal is None:
            return None
        info = terminal["info"]
        outcome = _message_outcome(info)
        if outcome is None:
            return None
        try:
            text = _terminal_text(terminal)
        except OpenCodeClientError:
            outcome = CompletionOutcome.FAILED
            text = None
        return OpenCodeCompletion(
            original.completion_key,
            original.transport_id,
            original.registration_id,
            original.callback_registration_id,
            original.work_id,
            original.session_id,
            original.generation,
            original.prompt_message_id,
            outcome,
            str(info["id"]),
            text,
        )

    def _record_child_barrier_attention(
        self, registration: DispatchRegistration, reason: str
    ) -> None:
        now = self._store_now()
        with self._store._daemon_transaction(self._authority) as connection:
            authority = connection.execute(
                """SELECT delivery.created_at, completion.assignment_attempt
                   FROM opencode_deliveries AS backend
                   JOIN transport_deliveries AS delivery
                     ON delivery.id = backend.transport_id
                   JOIN transport_completion_registrations AS completion
                     ON completion.id = backend.completion_registration_id
                    AND completion.transport_id = backend.transport_id
                   WHERE backend.transport_id = ?
                     AND backend.completion_registration_id = ?""",
                (
                    registration.transport_id,
                    registration.completion_registration_id,
                ),
            ).fetchone()
            if authority is None:
                raise _CompletionReleaseError("child barrier authority is absent")
            attention_digest = hashlib.sha256(
                f"attention:{reason}".encode("utf-8")
            ).hexdigest()
            inserted = connection.execute(
                """INSERT OR IGNORE INTO completion_child_barriers(
                       transport_id, completion_registration_id, work_id,
                       generation, root_session_id, turn_started_at_ms,
                       child_set_sha256, child_count, state,
                       consolidation_message_id,
                       consolidation_idempotency_key,
                       authorized_assistant_message_id, attention_reason,
                       created_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'attention',
                             NULL, NULL, NULL, ?, ?, ?)""",
                (
                    registration.transport_id,
                    registration.completion_registration_id,
                    registration.work_id,
                    int(authority[1]),
                    registration.session_id,
                    iso_to_epoch_ms(authority[0]),
                    attention_digest,
                    reason,
                    now,
                    now,
                ),
            )
            updated = connection.execute(
                """UPDATE completion_child_barriers
                   SET state = 'attention', attention_reason = ?, updated_at = ?
                   WHERE transport_id = ? AND state != 'attention'""",
                (reason, now, registration.transport_id),
            )
            if inserted.rowcount == 1 or updated.rowcount == 1:
                self._store._append_event(
                    connection,
                    "completion_child_barrier",
                    registration.transport_id,
                    "completion.child_barrier.attention",
                    {"reason": reason, "work_id": registration.work_id},
                    now,
                )

    @staticmethod
    def _store_now() -> str:
        from oc_rig.store.database import _utc_now

        return _utc_now()

    @staticmethod
    def _agent_task_final_result(
        completion: OpenCodeCompletion,
        generation: int,
        envelope: Mapping[str, object],
    ) -> CompletionFinalResult:
        result = completion.final_result(generation)
        if result.outcome is not CompletionOutcome.SUCCEEDED:
            return result
        try:
            handover = parse_fugue_handover(result.final_text)
        except FugueHandoverInvalid:
            return CompletionFinalResult(
                result.transport_id,
                result.work_id,
                result.completion_registration_id,
                result.callback_registration_id,
                result.session_id,
                result.generation,
                result.prompt_message_id,
                result.assistant_message_id,
                CompletionOutcome.FAILED,
                None,
            )
        scope = envelope.get("scope")
        if type(scope) is not list or any(type(item) is not str for item in scope):
            raise _CompletionReleaseError("task authority scope is invalid")
        admitted = set(scope)
        changes = handover.get("changes")
        if type(changes) is not list or any(
            type(item) is not dict or item.get("path") not in admitted
            for item in changes
        ):
            return CompletionFinalResult(
                result.transport_id,
                result.work_id,
                result.completion_registration_id,
                result.callback_registration_id,
                result.session_id,
                result.generation,
                result.prompt_message_id,
                result.assistant_message_id,
                CompletionOutcome.FAILED,
                None,
            )
        status = handover["status"]
        return CompletionFinalResult(
            result.transport_id,
            result.work_id,
            result.completion_registration_id,
            result.callback_registration_id,
            result.session_id,
            result.generation,
            result.prompt_message_id,
            result.assistant_message_id,
            (
                CompletionOutcome.SUCCEEDED
                if status == "ready"
                else CompletionOutcome.FAILED
            ),
            json.dumps(
                handover, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ),
        )

    @classmethod
    def _workspace_final_result(
        cls,
        connection: object,
        completion: OpenCodeCompletion,
        generation: int,
    ) -> CompletionFinalResult:
        final_result = completion.final_result(generation)
        workspace = cls._workspace_authority(connection, completion.work_id)
        if workspace is None or completion.outcome is not CompletionOutcome.SUCCEEDED:
            return final_result
        repository, envelope, patch_authority = workspace
        receipt_kind = "workspace_patch" if envelope.get("task_mode") == "workspace_patch" else "workspace_edit"
        try:
            receipt_text = apply_workspace_edit_plan(
                repository,
                envelope,
                completion.final_text,
                patch_authority,
            )
        except WorkspaceEditIndeterminate as error:
            raise _WorkspaceEditApplyError("workspace edit state is indeterminate") from error
        except WorkspaceEditRejected:
            return CompletionFinalResult(
                completion.transport_id,
                completion.work_id,
                completion.registration_id,
                completion.callback_registration_id,
                completion.session_id,
                generation,
                completion.prompt_message_id,
                completion.assistant_message_id,
                CompletionOutcome.FAILED,
                json.dumps(
                    {
                        receipt_kind: {
                            "applied": False,
                            "reason": "rejected",
                            "version": 1,
                        }
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        return CompletionFinalResult(
            completion.transport_id,
            completion.work_id,
            completion.registration_id,
            completion.callback_registration_id,
            completion.session_id,
            generation,
            completion.prompt_message_id,
            completion.assistant_message_id,
            completion.outcome,
            receipt_text,
        )

    @staticmethod
    def _workspace_authority(
        connection: object,
        work_id: str,
    ) -> tuple[str, dict[str, object], object] | None:
        rows = connection.execute(
            """SELECT canonical_json FROM gui_task_submissions
               WHERE state = 'completed'
                 AND json_extract(outcome_json, '$.work_id') = ?
               LIMIT 2""",
            (work_id,),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise _WorkspaceEditApplyError("workspace authority is ambiguous")
        try:
            canonical = json.loads(rows[0][0])
        except (json.JSONDecodeError, TypeError, UnicodeError) as error:
            raise _WorkspaceEditApplyError("workspace authority is invalid") from error
        if (
            type(canonical) is not dict
            or set(canonical) not in (
                {"envelope", "repository", "scope"},
                {"envelope", "patch_authority", "repository", "scope"},
            )
            or type(canonical.get("envelope")) is not str
            or type(canonical.get("repository")) is not str
            or type(canonical.get("scope")) is not list
        ):
            raise _WorkspaceEditApplyError("workspace authority is invalid")
        try:
            envelope = parse_task_prompt(canonical["envelope"])
        except ScopeCapsuleError as error:
            raise _WorkspaceEditApplyError("workspace authority is invalid") from error
        if envelope is None or envelope.get("task_mode") not in {"workspace_edit", "workspace_patch"}:
            return None
        if canonical["scope"] != envelope.get("scope"):
            raise _WorkspaceEditApplyError("workspace authority scope changed")
        patch_authority = canonical.get("patch_authority")
        if (envelope.get("task_mode") == "workspace_patch") != (patch_authority is not None):
            raise _WorkspaceEditApplyError("workspace patch authority is invalid")
        return canonical["repository"], envelope, patch_authority

    def status(self) -> Mapping[str, Any]:
        with self._failure_lock:
            failure = self._failure
        return {
            "configured": True,
            "healthy": failure is None,
            "reason": failure,
        }

    def close(self) -> None:
        self._cancellation.set()
        self._monitor.close()
        self._cleanup_event.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=SSE_READ_TIMEOUT_SECONDS + 2.0)
            if thread.is_alive():
                self._record_failure("completion_monitor_shutdown_timeout")
        cleanup, self._cleanup_thread = self._cleanup_thread, None
        if cleanup is not None and cleanup is not threading.current_thread():
            cleanup.join(timeout=2.0)
            if cleanup.is_alive():
                self._record_failure("session_cleanup_shutdown_timeout")
