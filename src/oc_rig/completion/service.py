"""Daemon-private completion join and bounded callback outbox."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from dataclasses import dataclass

from oc_rig.completion.models import (
    MAX_FINAL_RESULT_BYTES,
    CompletionFinalResult,
    CompletionOutcome,
    CompletionReceipt,
)
from oc_rig.completion.codex_callback import (
    CallbackDisposition,
    CallbackResult,
    CodexCallbackRequest,
    validate_codex_thread_id,
)
from oc_rig.scheduler.models import ReleaseOutcome
from oc_rig.scheduler.service import _Scheduler
from oc_rig.store.database import (
    IdempotencyConflict,
    OwnershipConflict,
    RigStore,
    _DaemonAuthority,
    _identifier,
    _utc_now,
)


def _wall_us() -> int:
    return time.time_ns() // 1_000


@dataclass(frozen=True, slots=True)
class CallbackDelivery:
    callback_id: str
    outbox_id: str
    return_route_id: str
    delivery_key: str
    thread_id: str
    work_id: str
    outcome: str
    result_ref: str
    attempt: int

    def request(self) -> CodexCallbackRequest:
        return CodexCallbackRequest(
            self.delivery_key,
            self.thread_id,
            self.work_id,
            self.outcome,
            self.result_ref,
        )


class _CompletionService:
    """Completion mutation surface instantiated only by the durable daemon."""

    __slots__ = ("store", "_authority", "_capability_id", "_clock", "_scheduler")

    def __new__(cls, *_args: object, **_kwargs: object) -> "_CompletionService":
        raise PermissionError("completion services are created only by rigd")

    def _assert_authority(self, capability: object) -> None:
        if id(capability) != self._capability_id:
            raise PermissionError("completion mutation requires daemon capability")
        self._authority._assert_for(self.store)

    def register_route(
        self,
        capability: object,
        connection: sqlite3.Connection,
        *,
        route_id: str,
        transport_id: str,
        completion_registration_id: str,
        work_id: str,
        generation: int,
        assignment_id: str,
        assignment_fence: str,
        scope_claim_id: str,
        scope_claim_attempt: int,
        scope_claim_fence: str,
    ) -> None:
        """Persist the disabled single-use route before transport can prepare."""
        self._assert_authority(capability)
        for value, field in (
            (route_id, "route_id"),
            (transport_id, "transport_id"),
            (completion_registration_id, "completion_registration_id"),
            (work_id, "work_id"),
            (assignment_id, "assignment_id"),
            (assignment_fence, "assignment_fence"),
            (scope_claim_id, "scope_claim_id"),
            (scope_claim_fence, "scope_claim_fence"),
        ):
            _identifier(value, field)
        if type(generation) is not int or generation <= 0:
            raise ValueError("generation must be a positive integer")
        if type(scope_claim_attempt) is not int or scope_claim_attempt <= 0:
            raise ValueError("scope claim attempt must be a positive integer")
        existing = connection.execute(
            "SELECT transport_id, work_id, generation FROM return_routes WHERE id = ?",
            (route_id,),
        ).fetchone()
        if existing is not None:
            if tuple(existing) != (transport_id, work_id, generation):
                raise IdempotencyConflict(route_id)
            return
        now = self._clock()
        connection.execute(
            """INSERT INTO return_routes(
                   id, transport_id, completion_registration_id, work_id,
                   generation, assignment_id, assignment_fence, scope_claim_id,
                   scope_claim_attempt, scope_claim_fence, route_kind, route_ref,
                   state, created_at_us
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'disabled', 'disabled',
                         'registered', ?)""",
            (
                route_id,
                transport_id,
                completion_registration_id,
                work_id,
                generation,
                assignment_id,
                assignment_fence,
                scope_claim_id,
                scope_claim_attempt,
                scope_claim_fence,
                now,
            ),
        )
        self.store._append_event(
            connection,
            "return_route",
            route_id,
            "completion.route.registered",
            {"work_id": work_id, "generation": generation, "transport_id": transport_id},
            str(now),
        )

    def register_local_codex_route(
        self,
        capability: object,
        connection: sqlite3.Connection,
        *,
        return_route_id: str,
        codex_thread_id: str,
    ) -> None:
        """Bind one private Codex thread before transport can send."""

        self._assert_authority(capability)
        _identifier(return_route_id, "return_route_id")
        thread_id = validate_codex_thread_id(codex_thread_id)
        route = connection.execute(
            "SELECT state FROM return_routes WHERE id = ?", (return_route_id,)
        ).fetchone()
        if route is None or route[0] != "registered":
            raise OwnershipConflict("local Codex route must bind a registered return route")
        existing = connection.execute(
            "SELECT thread_id FROM local_codex_return_routes WHERE return_route_id = ?",
            (return_route_id,),
        ).fetchone()
        if existing is not None:
            if existing[0] != thread_id:
                raise IdempotencyConflict(return_route_id)
            return
        now = self._clock()
        connection.execute(
            """INSERT INTO local_codex_return_routes(
                   return_route_id, thread_id, created_at_us
               ) VALUES (?, ?, ?)""",
            (return_route_id, thread_id, now),
        )
        self.store._append_event(
            connection,
            "return_route",
            return_route_id,
            "completion.local_codex_route.registered",
            {"thread_bound": True},
            str(now),
        )

    def accept(
        self,
        capability: object,
        connection: sqlite3.Connection,
        *,
        completion_key: str,
        registration_id: str,
        work_id: str,
        generation: int,
        outcome: CompletionOutcome,
        final_result: CompletionFinalResult | None = None,
    ) -> CompletionReceipt:
        """Atomically complete one exact generation and release both ownership fences."""
        self._assert_authority(capability)
        for value, field in (
            (completion_key, "completion_key"),
            (registration_id, "registration_id"),
            (work_id, "work_id"),
        ):
            _identifier(value, field)
        if type(generation) is not int or generation <= 0:
            raise ValueError("generation must be a positive integer")
        if not isinstance(outcome, CompletionOutcome):
            raise TypeError("outcome must be a CompletionOutcome")
        if final_result is not None and not isinstance(
            final_result, CompletionFinalResult
        ):
            raise TypeError("final_result must be typed")
        existing = connection.execute(
            """SELECT id, completion_key, completion_registration_id, work_id,
                      generation, outcome
               FROM completion_events
               WHERE completion_key = ? OR (work_id = ? AND generation = ?)""",
            (completion_key, work_id, generation),
        ).fetchone()
        if existing is not None:
            if tuple(existing[1:]) != (
                completion_key,
                registration_id,
                work_id,
                generation,
                outcome.value,
            ):
                raise IdempotencyConflict(completion_key)
            if final_result is not None:
                self._persist_final_result(
                    connection, str(existing[0]), completion_key, final_result
                )
            local = connection.execute(
                """SELECT 1 FROM return_routes AS route
                   JOIN local_codex_return_routes AS local
                     ON local.return_route_id = route.id
                   WHERE route.completion_registration_id = ?""",
                (registration_id,),
            ).fetchone()
            persisted = connection.execute(
                "SELECT 1 FROM completion_results WHERE completion_event_id = ?",
                (str(existing[0]),),
            ).fetchone()
            if local is not None and persisted is None:
                raise OwnershipConflict(
                    "local Codex completion requires a durable final result"
                )
            return self._receipt(connection, str(existing[0]))
        child_enabled = connection.execute(
            """SELECT 1
               FROM transport_completion_registrations AS completion
               JOIN transport_deliveries AS delivery
                 ON delivery.id = completion.transport_id
               JOIN scheduler_admission_decisions AS decision
                 ON decision.id = delivery.admission_decision_id
               WHERE completion.id = ? AND completion.work_id = ?
                 AND completion.assignment_attempt = ?
                 AND decision.allow_child_agents = 1""",
            (registration_id, work_id, generation),
        ).fetchone()
        if child_enabled is not None:
            if final_result is None:
                raise OwnershipConflict(
                    "child-enabled completion requires its authorized final result"
                )
            barrier = connection.execute(
                """SELECT 1 FROM completion_child_barriers
                   WHERE completion_registration_id = ? AND work_id = ?
                     AND generation = ? AND state = 'ready'
                     AND root_session_id = ?
                     AND authorized_assistant_message_id = ?""",
                (
                    registration_id,
                    work_id,
                    generation,
                    final_result.session_id,
                    final_result.assistant_message_id,
                ),
            ).fetchone()
            if barrier is None:
                raise OwnershipConflict(
                    "child-enabled completion lacks its exact barrier authority"
                )
        registration = connection.execute(
            """SELECT completion.id, completion.transport_id, completion.work_id,
                      completion.assignment_id, completion.assignment_attempt,
                      completion.assignment_fence, completion.state,
                      route.id, route.state, assignment.owner_id,
                      assignment.state, assignment.release_outcome,
                      route.scope_claim_id, route.scope_claim_attempt,
                      route.scope_claim_fence, claim.owner_operation_id,
                      claim.state, delivery.state
               FROM transport_completion_registrations AS completion
               JOIN transport_deliveries AS delivery
                 ON delivery.id = completion.transport_id
               JOIN return_routes AS route
                 ON route.completion_registration_id = completion.id
                AND route.transport_id = completion.transport_id
               JOIN scheduler_assignments AS assignment
                 ON assignment.id = route.assignment_id
                AND assignment.work_id = route.work_id
                AND assignment.attempt = route.generation
                AND assignment.fence_token = route.assignment_fence
               JOIN scope_claims AS claim
                 ON claim.id = route.scope_claim_id
                AND claim.attempt = route.scope_claim_attempt
                AND claim.fence_token = route.scope_claim_fence
               WHERE completion.id = ?""",
            (registration_id,),
        ).fetchone()
        if registration is None:
            raise OwnershipConflict("completion registration was not found")
        if (registration[2], int(registration[4])) != (work_id, generation):
            raise OwnershipConflict("completion generation does not match its route")
        if registration[6] == "cancelled" or registration[8] == "cancelled":
            raise OwnershipConflict("completion route is cancelled")
        if registration[17] not in {"accepted", "delivery_unknown"}:
            raise OwnershipConflict("transport state cannot accept completion")
        if registration[6] == "completed":
            raise IdempotencyConflict(completion_key)
        if final_result is None and connection.execute(
            "SELECT 1 FROM local_codex_return_routes WHERE return_route_id = ?",
            (str(registration[7]),),
        ).fetchone() is not None:
            raise OwnershipConflict(
                "local Codex completion requires a durable final result"
            )
        now = self._clock()
        completion_id = f"completion-{uuid.uuid4().hex}"
        callback_id = f"callback-{uuid.uuid4().hex}"
        outbox_id = f"outbox-{uuid.uuid4().hex}"
        delivery_key = f"delivery-{uuid.uuid4().hex}"
        connection.execute(
            """INSERT INTO completion_events(
                   id, completion_key, completion_registration_id, transport_id,
                   work_id, generation, outcome, received_at_us
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                completion_id,
                completion_key,
                registration_id,
                registration[1],
                work_id,
                generation,
                outcome.value,
                now,
            ),
        )
        if final_result is not None:
            self._persist_final_result(
                connection, completion_id, completion_key, final_result
            )
        connection.execute(
            """UPDATE transport_completion_registrations
               SET state = 'completed', completed_at = ?
               WHERE id = ? AND state = 'pending'""",
            (str(now), registration_id),
        )
        connection.execute(
            """INSERT INTO callbacks(
                   id, completion_event_id, return_route_id, delivery_key,
                   state, available_at_us, created_at_us, attention_reason
               ) VALUES (?, ?, ?, ?, 'blocked', ?, ?,
                         'awaiting_exact_release')""",
            (callback_id, completion_id, registration[7], delivery_key, now, now),
        )
        connection.execute(
            """INSERT INTO outbox(
                   id, callback_id, delivery_key, topic, aggregate_type,
                   aggregate_id, state, available_at_us, created_at_us,
                   disabled_reason
               ) VALUES (?, ?, ?, 'completion.callback.v1', 'work', ?,
                         'blocked', ?, ?, 'awaiting_exact_release')""",
            (outbox_id, callback_id, delivery_key, work_id, now, now),
        )
        self.store._append_event(
            connection,
            "completion",
            completion_id,
            "completion.accepted",
            {
                "work_id": work_id,
                "generation": generation,
                "outcome": outcome.value,
                "route_id": registration[7],
            },
            str(now),
        )
        released_assignment = self._scheduler.release(
            connection,
            str(registration[3]),
            work_id,
            str(registration[9]),
            attempt=generation,
            fence_token=str(registration[5]),
            outcome=ReleaseOutcome.COMPLETED,
        )
        if not released_assignment:
            raise OwnershipConflict("completion lost exact scheduler assignment")
        claim_state = str(registration[16])
        if claim_state == "active":
            released_scope = self.store._release_scope(
                connection,
                str(registration[12]),
                str(registration[15]),
                attempt=int(registration[13]),
                fence_token=str(registration[14]),
            )
            if not released_scope:
                raise OwnershipConflict("completion lost exact scope claim")
        elif claim_state != "released":
            raise OwnershipConflict("completion scope claim is not releasable")
        self.refresh_work(capability, connection, work_id)
        return self._receipt(connection, completion_id)

    def _persist_final_result(
        self,
        connection: sqlite3.Connection,
        completion_id: str,
        completion_key: str,
        result: CompletionFinalResult,
    ) -> str:
        for value, field in (
            (result.transport_id, "transport_id"),
            (result.work_id, "work_id"),
            (result.completion_registration_id, "completion_registration_id"),
            (result.callback_registration_id, "callback_registration_id"),
            (result.session_id, "session_id"),
            (result.prompt_message_id, "prompt_message_id"),
            (result.assistant_message_id, "assistant_message_id"),
        ):
            _identifier(value, field)
        if type(result.generation) is not int or result.generation <= 0:
            raise ValueError("final result generation is invalid")
        if not isinstance(result.outcome, CompletionOutcome):
            raise TypeError("final result outcome is invalid")
        text_sha256: str | None = None
        if result.final_text is not None:
            if type(result.final_text) is not str:
                raise TypeError("final result text is invalid")
            try:
                text_bytes = result.final_text.encode("utf-8")
            except UnicodeEncodeError:
                raise ValueError("final result text is invalid") from None
            if not 1 <= len(text_bytes) <= MAX_FINAL_RESULT_BYTES:
                raise ValueError("final result text is outside the bounded envelope")
            text_sha256 = hashlib.sha256(text_bytes).hexdigest()
        authority = connection.execute(
            """SELECT event.transport_id, event.work_id, event.generation,
                      event.outcome, event.completion_registration_id,
                      delivery.callback_registration_id,
                      coalesce(delivery.isolated_session_id, delivery.session_id),
                      delivery.prompt_message_id
               FROM completion_events AS event
               JOIN opencode_deliveries AS delivery
                 ON delivery.transport_id = event.transport_id
                AND delivery.completion_registration_id =
                    event.completion_registration_id
               WHERE event.id = ? AND event.completion_key = ?""",
            (completion_id, completion_key),
        ).fetchone()
        expected = (
            result.transport_id,
            result.work_id,
            result.generation,
            result.outcome.value,
            result.completion_registration_id,
            result.callback_registration_id,
            result.session_id,
            result.prompt_message_id,
        )
        if authority is None or tuple(authority) != expected:
            raise OwnershipConflict("final result lost exact completion authority")
        content_state = "available" if result.final_text is not None else "no_text"
        result_ref = "completion-result-" + hashlib.sha256(
            completion_key.encode("utf-8")
        ).hexdigest()
        material = {
            "assistant_message_id": result.assistant_message_id,
            "callback_registration_id": result.callback_registration_id,
            "completion_event_id": completion_id,
            "completion_key": completion_key,
            "completion_registration_id": result.completion_registration_id,
            "content_state": content_state,
            "final_text_sha256": text_sha256,
            "generation": result.generation,
            "outcome": result.outcome.value,
            "prompt_message_id": result.prompt_message_id,
            "result_ref": result_ref,
            "session_id": result.session_id,
            "transport_id": result.transport_id,
            "work_id": result.work_id,
        }
        binding_sha256 = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        row = (
            result_ref,
            completion_id,
            completion_key,
            result.transport_id,
            result.completion_registration_id,
            result.callback_registration_id,
            result.work_id,
            result.generation,
            result.session_id,
            result.prompt_message_id,
            result.assistant_message_id,
            result.outcome.value,
            content_state,
            result.final_text,
            text_sha256,
            binding_sha256,
        )
        existing = connection.execute(
            """SELECT result_ref, completion_event_id, completion_key,
                      transport_id, completion_registration_id,
                      callback_registration_id, work_id, generation, session_id,
                      prompt_message_id, assistant_message_id, outcome,
                      content_state, final_text, final_text_sha256, binding_sha256
               FROM completion_results WHERE result_ref = ?
                  OR completion_event_id = ? OR transport_id = ?""",
            (result_ref, completion_id, result.transport_id),
        ).fetchone()
        if existing is not None:
            if tuple(existing) != row:
                raise IdempotencyConflict(result_ref)
            return result_ref
        connection.execute(
            """INSERT INTO completion_results(
                   result_ref, completion_event_id, completion_key, transport_id,
                   completion_registration_id, callback_registration_id,
                   work_id, generation, session_id, prompt_message_id,
                   assistant_message_id, outcome, content_state, final_text,
                   final_text_sha256, binding_sha256, created_at_us
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (*row, self._clock()),
        )
        return result_ref

    def read_final_result(
        self,
        capability: object,
        connection: sqlite3.Connection,
        result_ref: str,
    ) -> dict[str, object]:
        self._assert_authority(capability)
        _identifier(result_ref, "result_ref")
        row = connection.execute(
            """SELECT result.result_ref, result.completion_event_id,
                      result.completion_key, result.transport_id,
                      result.completion_registration_id,
                      result.callback_registration_id, result.work_id,
                      result.generation, result.session_id,
                      result.prompt_message_id, result.assistant_message_id,
                      result.outcome, result.content_state, result.final_text,
                      result.final_text_sha256, result.binding_sha256,
                      event.transport_id, event.work_id, event.generation,
                      event.outcome, event.completion_registration_id,
                      delivery.callback_registration_id,
                      coalesce(delivery.isolated_session_id, delivery.session_id),
                      delivery.prompt_message_id
               FROM completion_results AS result
               JOIN completion_events AS event
                 ON event.id = result.completion_event_id
               JOIN opencode_deliveries AS delivery
                 ON delivery.transport_id = event.transport_id
                AND delivery.completion_registration_id =
                    event.completion_registration_id
               WHERE result.result_ref = ?""",
            (result_ref,),
        ).fetchone()
        if row is None:
            raise KeyError(result_ref)
        if (
            tuple(row[16:21]) != (row[3], row[6], row[7], row[11], row[4])
            or tuple(row[21:24]) != (row[5], row[8], row[9])
        ):
            raise OwnershipConflict("durable final result relation is invalid")
        if row[12] != "historical_unavailable":
            text_sha256 = (
                None
                if row[13] is None
                else hashlib.sha256(str(row[13]).encode("utf-8")).hexdigest()
            )
            material = {
                "assistant_message_id": row[10],
                "callback_registration_id": row[5],
                "completion_event_id": row[1],
                "completion_key": row[2],
                "completion_registration_id": row[4],
                "content_state": row[12],
                "final_text_sha256": text_sha256,
                "generation": row[7],
                "outcome": row[11],
                "prompt_message_id": row[9],
                "result_ref": row[0],
                "session_id": row[8],
                "transport_id": row[3],
                "work_id": row[6],
            }
            binding = hashlib.sha256(
                json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if text_sha256 != row[14] or binding != row[15]:
                raise OwnershipConflict("durable final result integrity failed")
        return {
            "result_ref": str(row[0]),
            "completion_event_id": str(row[1]),
            "completion_registration_id": str(row[4]),
            "callback_registration_id": str(row[5]),
            "transport_id": str(row[3]),
            "work_id": str(row[6]),
            "generation": int(row[7]),
            "session_id": str(row[8]),
            "prompt_message_id": str(row[9]),
            "assistant_message_id": row[10],
            "outcome": str(row[11]),
            "content_state": str(row[12]),
            "text": row[13],
            "text_sha256": row[14],
            "binding_sha256": row[15],
        }

    def refresh_work(
        self,
        capability: object,
        connection: sqlite3.Connection,
        work_id: str,
    ) -> int:
        """Join both exact releases and promote an exact local route once."""
        self._assert_authority(capability)
        _identifier(work_id, "work_id")
        rows = connection.execute(
            """SELECT route.id, callback.id, outbox.id, event.id, route.generation
               FROM return_routes AS route
               JOIN completion_events AS event
                 ON event.completion_registration_id = route.completion_registration_id
                AND event.work_id = route.work_id
                AND event.generation = route.generation
               JOIN callbacks AS callback ON callback.completion_event_id = event.id
               JOIN outbox ON outbox.callback_id = callback.id
               JOIN scheduler_assignments AS assignment
                 ON assignment.id = route.assignment_id
                AND assignment.work_id = route.work_id
                AND assignment.attempt = route.generation
                AND assignment.fence_token = route.assignment_fence
                AND assignment.state = 'released'
               JOIN scope_claims AS claim
                 ON claim.id = route.scope_claim_id
                AND claim.attempt = route.scope_claim_attempt
                AND claim.fence_token = route.scope_claim_fence
                AND claim.state = 'released'
               WHERE route.work_id = ? AND route.state = 'registered'
                 AND callback.state = 'blocked' AND outbox.state = 'blocked'
               ORDER BY event.received_at_us, event.id""",
            (work_id,),
        ).fetchall()
        now = self._clock()
        for route_id, callback_id, outbox_id, completion_id, generation in rows:
            connection.execute(
                """UPDATE return_routes SET state = 'ready', ready_at_us = ?
                   WHERE id = ? AND state = 'registered'""",
                (now, route_id),
            )
            local = connection.execute(
                "SELECT 1 FROM local_codex_return_routes WHERE return_route_id = ?",
                (route_id,),
            ).fetchone()
            if local is not None:
                connection.execute(
                    """UPDATE callbacks
                       SET state = 'pending', attention_reason = NULL
                       WHERE id = ? AND state = 'blocked'""",
                    (callback_id,),
                )
                connection.execute(
                    """UPDATE outbox
                       SET state = 'pending', disabled_reason = NULL
                       WHERE id = ? AND state = 'blocked'""",
                    (outbox_id,),
                )
            else:
                connection.execute(
                    """UPDATE callbacks
                       SET attention_reason = 'local_codex_route_missing'
                       WHERE id = ? AND state = 'blocked'""",
                    (callback_id,),
                )
                connection.execute(
                    """UPDATE outbox
                       SET disabled_reason = 'local_codex_route_missing'
                       WHERE id = ? AND state = 'blocked'""",
                    (outbox_id,),
                )
            self.store._append_event(
                connection,
                "completion",
                completion_id,
                "completion.delivery_blocked",
                {
                    "work_id": work_id,
                    "generation": int(generation),
                    "route_id": route_id,
                    "reason": (
                        "local_codex_callback_pending"
                        if local is not None
                        else "local_codex_route_missing"
                    ),
                },
                str(now),
            )
        return len(rows)

    def begin_local_codex_delivery(
        self,
        capability: object,
        connection: sqlite3.Connection,
    ) -> CallbackDelivery | None:
        """Journal exactly one ready local callback before external delivery."""

        self._assert_authority(capability)
        now = self._clock()
        row = connection.execute(
            """SELECT callback.id, outbox.id, callback.return_route_id,
                      callback.delivery_key, local.thread_id, event.work_id,
                      event.outcome, result.result_ref,
                      registration.id, callback.attempts
               FROM outbox
               JOIN callbacks AS callback ON callback.id = outbox.callback_id
               JOIN local_codex_return_routes AS local
                 ON local.return_route_id = callback.return_route_id
               JOIN completion_events AS event
                 ON event.id = callback.completion_event_id
               JOIN completion_results AS result
                 ON result.completion_event_id = event.id
               JOIN transport_callback_registrations AS registration
                 ON registration.transport_id = event.transport_id
                AND registration.completion_registration_id =
                    event.completion_registration_id
                AND registration.return_route_id = callback.return_route_id
               WHERE outbox.state = 'pending' AND callback.state = 'pending'
                 AND outbox.available_at_us <= ? AND callback.available_at_us <= ?
               ORDER BY outbox.available_at_us, outbox.created_at_us, outbox.id
               LIMIT 1""",
            (now, now),
        ).fetchone()
        if row is None:
            return None
        try:
            result = self.read_final_result(
                capability, connection, str(row[7])
            )
            if result["callback_registration_id"] != str(row[8]):
                raise OwnershipConflict(
                    "durable final result callback authority is invalid"
                )
        except (KeyError, OwnershipConflict):
            reason = "completion_result_integrity_failed"
            connection.execute(
                """UPDATE callbacks
                   SET state = 'attention', failure_class = 'deterministic',
                       attention_reason = ?
                   WHERE id = ? AND state = 'pending'""",
                (reason, row[0]),
            )
            connection.execute(
                """UPDATE outbox SET state = 'attention', disabled_reason = ?
                   WHERE id = ? AND state = 'pending'""",
                (reason, row[1]),
            )
            self.store._append_event(
                connection,
                "callback",
                str(row[0]),
                "callback.result_integrity_attention",
                {"result_ref": str(row[7]), "reason": reason},
                str(now),
            )
            return None
        attempt = int(row[9]) + 1
        if attempt > 3:
            raise RuntimeError("callback attempt budget is inconsistent")
        attempt_id = f"callback-attempt-{uuid.uuid4().hex}"
        connection.execute(
            """UPDATE callbacks SET state = 'delivering', attempts = ?
               WHERE id = ? AND state = 'pending'""",
            (attempt, row[0]),
        )
        connection.execute(
            """UPDATE outbox SET state = 'delivering', attempts = ?
               WHERE id = ? AND state = 'pending'""",
            (attempt, row[1]),
        )
        connection.execute(
            """INSERT INTO callback_delivery_attempts(
                   id, callback_id, attempt_number, delivery_key, state,
                   started_at_us
               ) VALUES (?, ?, ?, ?, 'delivering', ?)""",
            (attempt_id, row[0], attempt, row[3], now),
        )
        self.store._append_event(
            connection,
            "callback",
            str(row[0]),
            "callback.delivery_started",
            {"delivery_key": row[3], "attempt": attempt},
            str(now),
        )
        return CallbackDelivery(
            str(row[0]),
            str(row[1]),
            str(row[2]),
            str(row[3]),
            str(row[4]),
            str(row[5]),
            str(row[6]),
            str(row[7]),
            attempt,
        )

    def local_codex_attention_delivery(
        self,
        capability: object,
        connection: sqlite3.Connection,
        callback_id: str,
    ) -> CallbackDelivery:
        """Bind one ambiguous local Codex callback for out-of-band proof."""

        self._assert_authority(capability)
        _identifier(callback_id, "callback_id")
        row = connection.execute(
            """SELECT callback.id, outbox.id, callback.return_route_id,
                      callback.delivery_key, local.thread_id, event.work_id,
                      event.outcome, result.result_ref, callback.attempts,
                      registration.id
               FROM callbacks AS callback
               JOIN outbox ON outbox.callback_id = callback.id
                 AND outbox.delivery_key = callback.delivery_key
               JOIN return_routes AS route ON route.id = callback.return_route_id
               JOIN local_codex_return_routes AS local
                 ON local.return_route_id = callback.return_route_id
               JOIN completion_events AS event
                 ON event.id = callback.completion_event_id
               JOIN completion_results AS result
                 ON result.completion_event_id = event.id
               JOIN transport_callback_registrations AS registration
                 ON registration.transport_id = event.transport_id
                AND registration.completion_registration_id =
                    event.completion_registration_id
                AND registration.return_route_id = callback.return_route_id
               JOIN callback_delivery_attempts AS attempt
                 ON attempt.callback_id = callback.id
                AND attempt.attempt_number = callback.attempts
                AND attempt.delivery_key = callback.delivery_key
               WHERE callback.id = ? AND callback.state = 'attention'
                 AND callback.failure_class = 'delivery_unknown'
                 AND outbox.state = 'attention'
                 AND route.state = 'ready'
                 AND registration.state = 'pending'
                 AND attempt.state = 'attention'
                 AND attempt.failure_class = 'delivery_unknown'
               LIMIT 1""",
            (callback_id,),
        ).fetchone()
        if row is None:
            raise OwnershipConflict(
                "callback is not an exact ambiguous local Codex delivery"
            )
        result = self.read_final_result(capability, connection, str(row[7]))
        if result["callback_registration_id"] != str(row[9]):
            raise OwnershipConflict(
                "callback reconciliation lost durable result authority"
            )
        return CallbackDelivery(
            str(row[0]),
            str(row[1]),
            str(row[2]),
            str(row[3]),
            str(row[4]),
            str(row[5]),
            str(row[6]),
            str(row[7]),
            int(row[8]),
        )

    def reconcile_local_codex_delivery(
        self,
        capability: object,
        connection: sqlite3.Connection,
        delivery: CallbackDelivery,
        *,
        proof_kind: str,
    ) -> None:
        """Resolve one ambiguous callback only after exact positive delivery proof."""

        self._assert_authority(capability)
        if not isinstance(delivery, CallbackDelivery):
            raise TypeError("exact callback delivery required")
        if proof_kind != "codex_thread_history_exact_message":
            raise ValueError("callback reconciliation proof kind is invalid")
        row = connection.execute(
            """SELECT callback.state, callback.failure_class, callback.attempts,
                      outbox.state, route.state, registration.state,
                      attempt.state, attempt.failure_class, local.thread_id,
                      event.work_id, event.outcome, result.result_ref
               FROM callbacks AS callback
               JOIN outbox ON outbox.id = ? AND outbox.callback_id = callback.id
                 AND outbox.delivery_key = callback.delivery_key
               JOIN return_routes AS route ON route.id = callback.return_route_id
               JOIN local_codex_return_routes AS local
                 ON local.return_route_id = callback.return_route_id
               JOIN completion_events AS event
                 ON event.id = callback.completion_event_id
               JOIN completion_results AS result
                 ON result.completion_event_id = event.id
               JOIN transport_callback_registrations AS registration
                 ON registration.transport_id = event.transport_id
                AND registration.completion_registration_id =
                    event.completion_registration_id
                AND registration.return_route_id = callback.return_route_id
               JOIN callback_delivery_attempts AS attempt
                 ON attempt.callback_id = callback.id
                AND attempt.attempt_number = ?
                AND attempt.delivery_key = callback.delivery_key
               WHERE callback.id = ? AND callback.return_route_id = ?
                 AND callback.delivery_key = ?""",
            (
                delivery.outbox_id,
                delivery.attempt,
                delivery.callback_id,
                delivery.return_route_id,
                delivery.delivery_key,
            ),
        ).fetchone()
        expected = (
            "attention",
            "delivery_unknown",
            delivery.attempt,
            "attention",
            "ready",
            "pending",
            "attention",
            "delivery_unknown",
            delivery.thread_id,
            delivery.work_id,
            delivery.outcome,
            delivery.result_ref,
        )
        if row is None or tuple(row) != expected:
            raise OwnershipConflict(
                "callback reconciliation authority changed after proof"
            )
        now = self._clock()
        connection.execute(
            """INSERT INTO callback_delivery_reconciliations(
                   callback_id, attempt_number, delivery_key, proof_kind,
                   reconciled_at_us
               ) VALUES (?, ?, ?, ?, ?)""",
            (
                delivery.callback_id,
                delivery.attempt,
                delivery.delivery_key,
                proof_kind,
                now,
            ),
        )
        attempt = connection.execute(
            """UPDATE callback_delivery_attempts
               SET state = 'delivered', failure_class = NULL
               WHERE callback_id = ? AND attempt_number = ?
                 AND delivery_key = ? AND state = 'attention'
                 AND failure_class = 'delivery_unknown'""",
            (delivery.callback_id, delivery.attempt, delivery.delivery_key),
        )
        callback = connection.execute(
            """UPDATE callbacks
               SET state = 'delivered', delivered_at_us = ?, failure_class = NULL,
                   attention_reason = NULL
               WHERE id = ? AND return_route_id = ? AND delivery_key = ?
                 AND state = 'attention' AND failure_class = 'delivery_unknown'""",
            (
                now,
                delivery.callback_id,
                delivery.return_route_id,
                delivery.delivery_key,
            ),
        )
        outbox = connection.execute(
            """UPDATE outbox
               SET state = 'delivered', delivered_at_us = ?, disabled_reason = NULL
               WHERE id = ? AND callback_id = ? AND delivery_key = ?
                 AND state = 'attention'""",
            (now, delivery.outbox_id, delivery.callback_id, delivery.delivery_key),
        )
        route = connection.execute(
            """UPDATE return_routes SET state = 'consumed', consumed_at_us = ?
               WHERE id = ? AND state = 'ready'""",
            (now, delivery.return_route_id),
        )
        registration = connection.execute(
            """UPDATE transport_callback_registrations
               SET state = 'consumed', consumed_at = ?
               WHERE return_route_id = ? AND state = 'pending'""",
            (str(now), delivery.return_route_id),
        )
        if any(
            cursor.rowcount != 1
            for cursor in (attempt, callback, outbox, route, registration)
        ):
            raise OwnershipConflict(
                "callback reconciliation did not consume exact authority"
            )
        # Reconciled ``delivered`` retains the callback transport's deliberately
        # weak meaning: the exact message is proven to have entered Codex history.
        # It does not assert that the destination model rendered or consumed it.
        self.store._append_event(
            connection,
            "callback",
            delivery.callback_id,
            "callback.delivery_reconciled",
            {
                "delivery_key": delivery.delivery_key,
                "attempt": delivery.attempt,
                "proof_kind": proof_kind,
            },
            str(now),
        )

    def next_local_codex_available_at(
        self,
        capability: object,
        connection: sqlite3.Connection,
    ) -> int | None:
        """Return the earliest durable retry deadline without claiming delivery."""

        self._assert_authority(capability)
        row = connection.execute(
            """SELECT min(max(callback.available_at_us, outbox.available_at_us))
               FROM outbox
               JOIN callbacks AS callback ON callback.id = outbox.callback_id
               JOIN local_codex_return_routes AS local
                 ON local.return_route_id = callback.return_route_id
               WHERE outbox.state = 'pending' AND callback.state = 'pending'"""
        ).fetchone()
        if row is None or row[0] is None:
            return None
        return int(row[0])

    def finish_local_codex_delivery(
        self,
        capability: object,
        connection: sqlite3.Connection,
        delivery: CallbackDelivery,
        result: CallbackResult,
    ) -> None:
        """Commit a proven callback result; ambiguous sends never retry."""

        self._assert_authority(capability)
        if not isinstance(delivery, CallbackDelivery) or not isinstance(
            result, CallbackResult
        ):
            raise TypeError("exact callback delivery and result required")
        row = connection.execute(
            """SELECT callback.state, callback.attempts, outbox.state,
                      attempt.state
               FROM callbacks AS callback
               JOIN outbox ON outbox.id = ? AND outbox.callback_id = callback.id
               JOIN callback_delivery_attempts AS attempt
                 ON attempt.callback_id = callback.id
                AND attempt.attempt_number = ?
                AND attempt.delivery_key = callback.delivery_key
               WHERE callback.id = ? AND callback.return_route_id = ?
                 AND callback.delivery_key = ?""",
            (
                delivery.outbox_id,
                delivery.attempt,
                delivery.callback_id,
                delivery.return_route_id,
                delivery.delivery_key,
            ),
        ).fetchone()
        if row is None:
            raise OwnershipConflict("callback result lost exact delivery authority")
        if row[0] == "delivered" and row[2] == "delivered" and row[3] == "delivered":
            return
        if tuple(row[:3]) != ("delivering", delivery.attempt, "delivering") or row[3] != "delivering":
            raise OwnershipConflict("callback delivery is not active")
        now = self._clock()
        if result.disposition is CallbackDisposition.DELIVERED:
            connection.execute(
                """UPDATE callback_delivery_attempts
                   SET state = 'delivered', finished_at_us = ?
                   WHERE callback_id = ? AND attempt_number = ?
                     AND state = 'delivering'""",
                (now, delivery.callback_id, delivery.attempt),
            )
            connection.execute(
                """UPDATE callbacks
                   SET state = 'delivered', delivered_at_us = ?, failure_class = NULL,
                       attention_reason = NULL
                   WHERE id = ? AND state = 'delivering'""",
                (now, delivery.callback_id),
            )
            connection.execute(
                """UPDATE outbox
                   SET state = 'delivered', delivered_at_us = ?, disabled_reason = NULL
                   WHERE id = ? AND state = 'delivering'""",
                (now, delivery.outbox_id),
            )
            connection.execute(
                """UPDATE return_routes SET state = 'consumed', consumed_at_us = ?
                   WHERE id = ? AND state = 'ready'""",
                (now, delivery.return_route_id),
            )
            connection.execute(
                """UPDATE transport_callback_registrations
                   SET state = 'consumed', consumed_at = ?
                   WHERE return_route_id = ? AND state = 'pending'""",
                (str(now), delivery.return_route_id),
            )
            # A zero exit proves that ``codex queue`` accepted the message, not
            # that the destination task rendered or consumed it.  Keep the
            # internal transport terminal state, but expose only the weaker
            # fact in the activity stream.
            event = "callback.queued_for_codex"
        elif result.disposition is CallbackDisposition.TRANSIENT and delivery.attempt < 3:
            available = now + (2 ** (delivery.attempt - 1)) * 1_000_000
            connection.execute(
                """UPDATE callback_delivery_attempts
                   SET state = 'retry_scheduled', failure_class = 'transient',
                       finished_at_us = ?
                   WHERE callback_id = ? AND attempt_number = ?
                     AND state = 'delivering'""",
                (now, delivery.callback_id, delivery.attempt),
            )
            connection.execute(
                """UPDATE callbacks SET state = 'pending', available_at_us = ?
                   WHERE id = ? AND state = 'delivering'""",
                (available, delivery.callback_id),
            )
            connection.execute(
                """UPDATE outbox SET state = 'pending', available_at_us = ?
                   WHERE id = ? AND state = 'delivering'""",
                (available, delivery.outbox_id),
            )
            event = "callback.retry_scheduled"
        else:
            failure = (
                "transient"
                if result.disposition is CallbackDisposition.TRANSIENT
                else result.disposition.value
            )
            connection.execute(
                """UPDATE callback_delivery_attempts
                   SET state = 'attention', failure_class = ?, finished_at_us = ?
                   WHERE callback_id = ? AND attempt_number = ?
                     AND state = 'delivering'""",
                (failure, now, delivery.callback_id, delivery.attempt),
            )
            connection.execute(
                """UPDATE callbacks
                   SET state = 'attention', failure_class = ?, attention_reason = ?
                   WHERE id = ? AND state = 'delivering'""",
                (failure, result.reason, delivery.callback_id),
            )
            connection.execute(
                """UPDATE outbox
                   SET state = 'attention', disabled_reason = ?
                   WHERE id = ? AND state = 'delivering'""",
                (result.reason, delivery.outbox_id),
            )
            event = "callback.delivery_attention"
        self.store._append_event(
            connection,
            "callback",
            delivery.callback_id,
            event,
            {
                "delivery_key": delivery.delivery_key,
                "attempt": delivery.attempt,
                "disposition": result.disposition.value,
                "reason": result.reason,
            },
            str(now),
        )

    def reconcile_startup(
        self,
        capability: object,
        connection: sqlite3.Connection,
    ) -> int:
        """Repair safe unsent callbacks and make interrupted sends ambiguous."""
        self._assert_authority(capability)
        ready_rows = connection.execute(
            """SELECT callback.id, outbox.id, callback.delivery_key
               FROM callbacks AS callback
               JOIN outbox ON outbox.callback_id = callback.id
               JOIN return_routes AS route ON route.id = callback.return_route_id
               JOIN local_codex_return_routes AS local
                 ON local.return_route_id = route.id
               WHERE route.state = 'ready'
                 AND callback.state = 'blocked' AND outbox.state = 'blocked'
                 AND callback.attempts = 0 AND outbox.attempts = 0
                 AND NOT EXISTS (
                     SELECT 1 FROM callback_delivery_attempts AS attempt
                     WHERE attempt.callback_id = callback.id
                 )
               ORDER BY callback.created_at_us, callback.id"""
        ).fetchall()
        now = self._clock()
        for callback_id, outbox_id, delivery_key in ready_rows:
            connection.execute(
                """UPDATE callbacks
                   SET state = 'pending', attention_reason = NULL
                   WHERE id = ? AND state = 'blocked' AND attempts = 0""",
                (callback_id,),
            )
            connection.execute(
                """UPDATE outbox
                   SET state = 'pending', disabled_reason = NULL
                   WHERE id = ? AND state = 'blocked' AND attempts = 0""",
                (outbox_id,),
            )
            self.store._append_event(
                connection,
                "callback",
                str(callback_id),
                "callback.startup_promoted",
                {"delivery_key": delivery_key, "reason": "ready_local_codex_route"},
                str(now),
            )
        rows = connection.execute(
            """SELECT callback.id, outbox.id, attempt_row.id,
                      callback.delivery_key, callback.attempts
               FROM callbacks AS callback
               JOIN outbox ON outbox.callback_id = callback.id
               JOIN callback_delivery_attempts AS attempt_row
                 ON attempt_row.callback_id = callback.id
                AND attempt_row.attempt_number = callback.attempts
               WHERE callback.state = 'delivering'
                 AND outbox.state = 'delivering'
                 AND attempt_row.state = 'delivering'"""
        ).fetchall()
        for callback_id, outbox_id, attempt_id, delivery_key, attempt in rows:
            connection.execute(
                """UPDATE callback_delivery_attempts
                   SET state = 'attention', failure_class = 'delivery_unknown',
                       finished_at_us = ?
                   WHERE id = ? AND state = 'delivering'""",
                (now, attempt_id),
            )
            connection.execute(
                """UPDATE callbacks
                   SET state = 'attention', failure_class = 'delivery_unknown',
                       attention_reason = 'restart_after_delivery_start'
                   WHERE id = ? AND state = 'delivering'""",
                (callback_id,),
            )
            connection.execute(
                """UPDATE outbox
                   SET state = 'attention',
                       disabled_reason = 'delivery_unknown_after_restart'
                   WHERE id = ? AND state = 'delivering'""",
                (outbox_id,),
            )
            self.store._append_event(
                connection,
                "callback",
                callback_id,
                "callback.delivery_unknown_attention",
                {
                    "delivery_key": delivery_key,
                    "attempt": int(attempt),
                    "reason": "restart_after_delivery_start",
                },
                str(now),
            )
        return len(ready_rows) + len(rows)

    @staticmethod
    def _receipt(connection: sqlite3.Connection, completion_id: str) -> CompletionReceipt:
        row = connection.execute(
            """SELECT event.id, event.work_id, event.generation, event.outcome,
                      route.state, callback.state, callback.delivery_key,
                      result.result_ref
               FROM completion_events AS event
               JOIN return_routes AS route
                 ON route.completion_registration_id = event.completion_registration_id
               JOIN callbacks AS callback ON callback.completion_event_id = event.id
               LEFT JOIN completion_results AS result
                 ON result.completion_event_id = event.id
               WHERE event.id = ?""",
            (completion_id,),
        ).fetchone()
        if row is None:
            raise KeyError(completion_id)
        return CompletionReceipt(
            str(row[0]),
            str(row[1]),
            int(row[2]),
            CompletionOutcome(str(row[3])),
            str(row[4]),
            str(row[5]),
            str(row[6]),
            None if row[7] is None else str(row[7]),
        )


def _create_completion(
    store: RigStore,
    authority: _DaemonAuthority,
    capability: object,
    scheduler: _Scheduler | None = None,
) -> _CompletionService:
    authority._assert_for(store)
    service = object.__new__(_CompletionService)
    service.store = store
    service._authority = authority
    service._capability_id = id(capability)
    service._clock = _wall_us
    if scheduler is None:
        scheduler = object.__new__(_Scheduler)
        scheduler.store = store
        scheduler._authority = authority
        scheduler._clock = _utc_now
    elif not isinstance(scheduler, _Scheduler):
        raise TypeError("daemon scheduler required")
    scheduler._assert_authority()
    service._scheduler = scheduler
    return service
