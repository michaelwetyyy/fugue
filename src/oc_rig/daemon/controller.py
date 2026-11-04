"""Contained controller surface used before backend adapters exist."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import unicodedata
import uuid
from collections.abc import Callable, Mapping
from dataclasses import fields, is_dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from math import isfinite
from pathlib import Path
from typing import Any, Protocol

from oc_rig import __version__
from oc_rig.adapters.opencode_client import OpenCodeClient, OpenCodeClientError
from oc_rig.completion import CompletionOutcome
from oc_rig.completion.codex_callback import (
    CallbackDeliveryProof,
    CodexCallbackRequest,
    parse_local_codex_return_route,
    validate_codex_thread_id,
)
from oc_rig.domain.models import OperationKind, OperationState
from oc_rig.llm_behaviour import (
    LlmBehaviourBusy,
    LlmBehaviourConflict,
    LlmBehaviourInvalid,
    apply_selection as apply_llm_selection,
    status as llm_behaviour_status,
)
from oc_rig.policy import (
    AgentLifecycle,
    AdmissionRequest,
    ScopeCapsuleError,
    ScopeInspection,
    capsule_document,
    capture_patch_scope_capsule,
    capture_scope_capsule,
    inspect_scope,
    parse_task_prompt,
    patch_capsule_document,
    patch_private_authority,
)
from oc_rig.protocol.messages import PROTOCOL_VERSION
from oc_rig.policy.scanner import scan_content
from oc_rig.recovery import (
    RecoveryEvidence,
    RecoveryFailureClass,
    RecoveryPhase,
    RecoveryResult,
)
from oc_rig.scheduler.models import Lane, ReleaseOutcome
from oc_rig.scheduler.service import (
    _AdmissionEvidence,
    _evaluate_admission,
    _scope_digest,
)
from oc_rig.store.database import (
    IdempotencyConflict,
    OwnershipConflict,
    _identifier,
    _json,
    _utc_now,
)
from oc_rig.store.snapshot import _CockpitSnapshotProjection
from oc_rig.transport.models import TransportReceipt, TransportState
from oc_rig.transcript import (
    TRANSCRIPT_MESSAGE_LIMIT,
    TRANSCRIPT_TURN_BYTES,
    TranscriptProjectionInvalid,
    project_transcript_turns,
    validate_projected_transcript,
)
from oc_rig.transport.service import _dispatch_transport


class OperationRejected(ValueError):
    """An operation or its parameters are outside the initial safe surface."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class Controller(Protocol):
    def execute(self, operation: str, params: Mapping[str, Any]) -> Mapping[str, Any]: ...


class DurableController(Protocol):
    def execute_durable(
        self,
        idempotency_id: str,
        fingerprint: str,
        operation: str,
        params: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...


def _exact(params: Mapping[str, Any], fields: set[str]) -> None:
    if set(params) != fields:
        raise OperationRejected("invalid_params", "operation parameters do not match schema")


def _json_safe(value: Any) -> Any:
    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is float:
        if not isfinite(value):
            raise OperationRejected("invalid_snapshot", "snapshot contains a non-finite number")
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _json_safe(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise OperationRejected("invalid_snapshot", "snapshot object keys must be strings")
        return {key: _json_safe(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(child) for child in value]
    raise OperationRejected("invalid_snapshot", "snapshot contains a non-JSON value")


def _submission_identifier(base: str, purpose: str) -> str:
    _identifier(base, "submission_id")
    return f"gui-{purpose}-{hashlib.sha256(base.encode('utf-8')).hexdigest()}"


def _bounded_objective(value: object) -> str:
    if type(value) is not str:
        raise OperationRejected("invalid_params", "objective must be text")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise OperationRejected("invalid_params", "objective must be valid UTF-8") from None
    unsafe = {
        "\x00", "\x7f", "\u061c", "\u200e", "\u200f", "\u2028", "\u2029",
        "\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067",
        "\u2068", "\u2069",
    }
    if not value.strip() or size > 4096 or any(character in unsafe for character in value):
        raise OperationRejected("invalid_params", "objective is invalid or exceeds its limit")
    return value.strip()


_COMPOSER_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.IGNORECASE,
)
_TRANSCRIPT_MESSAGE_LIMIT = TRANSCRIPT_MESSAGE_LIMIT
_TRANSCRIPT_TURN_BYTES = TRANSCRIPT_TURN_BYTES


def _composer_text(value: object) -> str:
    if type(value) is not str:
        raise OperationRejected("invalid_params", "message must be text")
    normalized = unicodedata.normalize("NFC", value)
    try:
        encoded = normalized.encode("utf-8")
    except UnicodeError:
        raise OperationRejected("invalid_params", "message must be valid UTF-8") from None
    unsafe = {
        "\x00", "\x7f", "\u061c", "\u200e", "\u200f", "\u2028", "\u2029",
        "\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067",
        "\u2068", "\u2069",
    }
    if (
        not normalized.strip()
        or len(encoded) > _TRANSCRIPT_TURN_BYTES
        or normalized.count("\n") > 20
        or any(character in unsafe for character in normalized)
    ):
        raise OperationRejected("invalid_params", "message is invalid or exceeds its limit")
    if not scan_content(normalized).safe:
        raise OperationRejected("sensitive_content", "message failed the secure content policy")
    return normalized


def _uuid4(value: object) -> str:
    if type(value) is not str or _COMPOSER_UUID.fullmatch(value) is None:
        raise OperationRejected("invalid_params", "idempotency ID must be a UUIDv4")
    return value.lower()


def _transcript_turns(messages: object) -> tuple[list[dict[str, Any]], list[str]]:
    """Compatibility wrapper around the shared live transcript projection."""

    try:
        return project_transcript_turns(messages)
    except TranscriptProjectionInvalid:
        raise OperationRejected("backend_invalid", "worker transcript is invalid") from None


class InMemoryController:
    """Deterministic fake-only mutation surface owned entirely by ``rigd``."""

    def __init__(self, snapshot_provider: Callable[[], Any] | None = None):
        self._snapshot_provider = snapshot_provider
        self._memory: dict[str, Any] = {}
        self._lock = threading.RLock()

    def execute(self, operation: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        if operation == "health":
            _exact(params, set())
            return {
                "status": "ok",
                "controller": "in_memory",
                "external_dependencies": False,
            }
        if operation == "version":
            _exact(params, set())
            return {"rig_version": __version__, "protocol_version": PROTOCOL_VERSION}
        if operation == "snapshot":
            _exact(params, set())
            with self._lock:
                source = (
                    self._snapshot_provider()
                    if self._snapshot_provider is not None
                    else {"memory": dict(self._memory)}
                )
                normalized = _json_safe(source)
            if not isinstance(normalized, Mapping):
                raise OperationRejected("invalid_snapshot", "snapshot must be an object")
            return {"snapshot": normalized}
        if operation == "memory.get":
            _exact(params, {"key"})
            key = self._key(params["key"])
            with self._lock:
                return {"present": key in self._memory, "value": self._memory.get(key)}
        if operation == "memory.put":
            _exact(params, {"key", "value"})
            key = self._key(params["key"])
            value = _json_safe(params["value"])
            with self._lock:
                previous = self._memory.get(key)
                self._memory[key] = value
            return {"previous": previous, "value": value}
        if operation == "memory.increment":
            _exact(params, {"key", "amount"})
            key = self._key(params["key"])
            amount = params["amount"]
            if type(amount) is not int or not -1_000_000 <= amount <= 1_000_000:
                raise OperationRejected("invalid_params", "amount must be a bounded integer")
            with self._lock:
                current = self._memory.get(key, 0)
                if type(current) is not int:
                    raise OperationRejected("invalid_params", "stored value is not an integer")
                value = current + amount
                self._memory[key] = value
            return {"value": value}
        if operation == "memory.delete":
            _exact(params, {"key"})
            key = self._key(params["key"])
            with self._lock:
                present = key in self._memory
                previous = self._memory.pop(key, None)
            return {"deleted": present, "previous": previous}
        raise OperationRejected("unknown_operation", "operation is not recognized")

    @staticmethod
    def _key(value: Any) -> str:
        if not isinstance(value, str) or not value or len(value) > 128:
            raise OperationRejected("invalid_params", "key must be 1 to 128 characters")
        return value


class _RigController:
    """Sole durable scheduler owner behind the authenticated daemon socket."""

    def __new__(cls, *_args: object, **_kwargs: object) -> "_RigController":
        raise PermissionError("durable controllers are created only by RigDaemon")

    def cockpit_snapshot(self, capability: object) -> Mapping[str, Any]:
        """Capture on rigd's persistent connection without a request journal write."""
        self._transport._assert_authority(capability)
        with self.store._daemon_read_transaction(self._authority) as connection:
            projection = _CockpitSnapshotProjection(
                topology=self._topology,
                callback_adapter_configured=getattr(
                    self, "_callback_adapter_configured", False
                ),
            )
            snapshot = projection.capture(connection)
        backend_status = getattr(self, "_backend_status", lambda: None)()
        if not isinstance(backend_status, Mapping) or backend_status.get("healthy") is not False:
            return snapshot
        degraded = dict(snapshot)
        version = dict(degraded["snapshot_version"])
        version.pop("digest", None)
        degraded["snapshot_version"] = version
        availability = dict(degraded["availability"])
        errors = list(availability.get("errors", []))
        reason = str(backend_status.get("reason") or "completion_monitor_unavailable")
        if reason not in errors:
            errors.append(reason)
        availability.update({"status": "degraded", "errors": errors})
        degraded["availability"] = availability
        attention = dict(degraded["attention"])
        operator = dict(attention["operator_required"])
        items = list(operator.get("items", []))
        items.append(
            {
                "kind": "backend_attention",
                "id": "opencode-completion-monitor",
                "scope": "controller",
                "state": "attention",
                "reason": reason,
            }
        )
        operator.update(
            {
                "items": items,
                "total": (
                    int(operator["total"]) + 1
                    if operator.get("total_status") == "exact"
                    else None
                ),
                "lower_bound": int(operator["lower_bound"]) + 1,
            }
        )
        attention["operator_required"] = operator
        degraded["attention"] = attention
        return projection._finalize(degraded)

    def source_inbox(self, capability: object, thread_id: object) -> Mapping[str, Any]:
        """Read bounded durable completion-nudge metadata for one exact Codex thread."""

        self._transport._assert_authority(capability)
        try:
            source_id = validate_codex_thread_id(thread_id)
        except ValueError as error:
            raise OperationRejected("invalid_params", str(error)) from error
        with self.store._daemon_read_transaction(self._authority) as connection:
            rows = connection.execute(
                """WITH source_routes AS (
                       SELECT route.*
                       FROM local_codex_return_routes AS local
                       JOIN return_routes AS route ON route.id = local.return_route_id
                       WHERE local.thread_id = ?
                   ), completed_local_routes AS (
                       SELECT route_id, max(completed_at_us) AS completed_at_us
                       FROM (
                           SELECT route.id AS route_id, event.received_at_us AS completed_at_us
                           FROM source_routes AS route
                           JOIN completion_events AS event
                             ON event.work_id = route.work_id
                            AND event.generation = route.generation
                           UNION ALL
                           SELECT route.id AS route_id, result.created_at_us AS completed_at_us
                           FROM source_routes AS route
                           JOIN completion_results AS result
                             ON result.work_id = route.work_id
                            AND result.generation = route.generation
                       )
                       GROUP BY route_id
                   )
                   SELECT callback.id, route.work_id, assignment.slot_id,
                          callback.state AS callback_state,
                          outbox.state AS outbox_state,
                          callback.created_at_us,
                          callback.attention_reason, outbox.disabled_reason,
                          event.id AS event_id,
                          completion_registration.id AS completion_registration_id,
                          callback_registration.id AS callback_registration_id,
                          delivery.id AS transport_id,
                          claim.id AS scope_claim_id,
                          result.result_ref AS result_ref
                   FROM completed_local_routes AS completed
                   JOIN source_routes AS route ON route.id = completed.route_id
                   LEFT JOIN completion_events AS event
                     ON event.transport_id = route.transport_id
                    AND event.completion_registration_id = route.completion_registration_id
                    AND event.work_id = route.work_id
                    AND event.generation = route.generation
                   LEFT JOIN completion_results AS result
                     ON result.completion_event_id = event.id
                    AND result.transport_id = event.transport_id
                    AND result.completion_registration_id = event.completion_registration_id
                    AND result.work_id = event.work_id
                    AND result.generation = event.generation
                   LEFT JOIN transport_completion_registrations AS completion_registration
                     ON completion_registration.id = route.completion_registration_id
                    AND completion_registration.transport_id = route.transport_id
                    AND completion_registration.work_id = route.work_id
                    AND completion_registration.assignment_id = route.assignment_id
                    AND completion_registration.assignment_attempt = route.generation
                    AND completion_registration.assignment_fence = route.assignment_fence
                   LEFT JOIN transport_callback_registrations AS callback_registration
                     ON callback_registration.id = result.callback_registration_id
                    AND callback_registration.transport_id = route.transport_id
                    AND callback_registration.completion_registration_id = route.completion_registration_id
                    AND callback_registration.return_route_id = route.id
                    AND callback_registration.work_id = route.work_id
                    AND callback_registration.generation = route.generation
                   LEFT JOIN transport_deliveries AS delivery
                     ON delivery.id = route.transport_id
                    AND delivery.work_id = route.work_id
                    AND delivery.assignment_id = route.assignment_id
                    AND delivery.assignment_attempt = route.generation
                    AND delivery.assignment_fence = route.assignment_fence
                    AND delivery.scope_claim_id = route.scope_claim_id
                    AND delivery.scope_claim_attempt = route.scope_claim_attempt
                    AND delivery.scope_claim_fence = route.scope_claim_fence
                   LEFT JOIN scheduler_assignments AS assignment
                     ON assignment.id = route.assignment_id
                    AND assignment.work_id = route.work_id
                    AND assignment.attempt = route.generation
                    AND assignment.fence_token = route.assignment_fence
                   LEFT JOIN scope_claims AS claim
                     ON claim.id = route.scope_claim_id
                    AND claim.attempt = route.scope_claim_attempt
                    AND claim.fence_token = route.scope_claim_fence
                   LEFT JOIN callbacks AS callback
                     ON callback.completion_event_id = event.id
                    AND callback.return_route_id = route.id
                   LEFT JOIN outbox
                     ON outbox.callback_id = callback.id
                    AND outbox.delivery_key = callback.delivery_key
                    AND outbox.topic = 'completion.callback.v1'
                    AND outbox.aggregate_type = 'work'
                    AND outbox.aggregate_id = route.work_id
                   ORDER BY completed.completed_at_us DESC, route.id DESC
                   LIMIT 13""",
                (source_id,),
            ).fetchall()
        truncated = len(rows) > 12
        items: list[dict[str, Any]] = []
        state_map = {
            "blocked": "queued",
            "pending": "queued",
            "delivering": "delivering",
            "delivered": "accepted",
            "attention": "attention",
        }
        for row_index, row in enumerate(rows):
            callback_id = row["id"]
            work_id = row["work_id"]
            slot_id = row["slot_id"]
            raw_state = row["callback_state"]
            outbox_state = row["outbox_state"]
            if (
                type(callback_id) is not str
                or type(work_id) is not str
                or type(slot_id) is not str
                or type(raw_state) is not str
                or type(outbox_state) is not str
                or any(
                    type(row[field]) is not str
                    for field in (
                        "event_id",
                        "completion_registration_id",
                        "callback_registration_id",
                        "transport_id",
                        "scope_claim_id",
                        "result_ref",
                    )
                )
            ):
                raise OperationRejected(
                    "source_inbox_unavailable",
                    "source inbox durable join is incomplete",
                )
            if outbox_state != raw_state:
                raise OperationRejected(
                    "source_inbox_unavailable",
                    "source inbox callback and outbox states disagree",
                )
            state = state_map.get(raw_state)
            if state is None:
                raise OperationRejected(
                    "source_inbox_unavailable",
                    "source inbox contains an unsupported callback state",
                )
            created_at_us = row["created_at_us"]
            if type(created_at_us) is not int or created_at_us < 0:
                raise OperationRejected(
                    "source_inbox_unavailable",
                    "source inbox contains an invalid callback timestamp",
                )
            reason = None
            if state == "attention":
                reason = row["attention_reason"] or row["disabled_reason"]
                if type(reason) is not str or not reason or len(reason.encode("utf-8")) > 1024:
                    raise OperationRejected(
                        "source_inbox_unavailable",
                        "source inbox contains an invalid attention reason",
                    )
            queued_at = datetime.fromtimestamp(
                created_at_us / 1_000_000, timezone.utc
            ).isoformat(timespec="microseconds").replace("+00:00", "Z")
            item = {
                "id": _identifier(callback_id, "callback_id"),
                "kind": "completion_nudge",
                "origin": _identifier(slot_id, "slot_id"),
                "work_id": _identifier(work_id, "work_id"),
                "state": state,
                "queued_at": queued_at,
                "reason": reason,
            }
            if row_index < 12:
                items.append(item)
        return {
            "source_id": source_id,
            "items": items,
            "total": None if truncated else len(rows),
            "total_status": "capped" if truncated else "exact",
            "lower_bound": len(rows),
            "truncated": truncated,
        }

    def _opencode_client(self) -> OpenCodeClient:
        adapter = getattr(self._transport, "_adapter", None)
        client = getattr(adapter, "_client", None)
        if type(client) is not OpenCodeClient:
            raise OperationRejected("backend_unavailable", "worker backend is unavailable")
        return client

    def _active_worker_binding(
        self,
        capability: object,
        *,
        slot_id: object,
        work_id: object,
        generation: object,
        session_id: object | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> Mapping[str, Any]:
        self._transport._assert_authority(capability)
        _identifier(slot_id, "slot_id")
        _identifier(work_id, "work_id")
        if type(generation) is not int or not 1 <= generation <= 2**31 - 1:
            raise OperationRejected("invalid_params", "generation is invalid")
        if session_id is not None:
            _identifier(session_id, "session_id")
        def read(active: sqlite3.Connection) -> sqlite3.Row | tuple[Any, ...] | None:
            return active.execute(
                """SELECT coalesce(opencode.isolated_session_id, opencode.session_id),
                          opencode.worker, opencode.prompt_message_id,
                          opencode.delivery_state
                   FROM opencode_deliveries AS opencode
                   JOIN transport_deliveries AS delivery
                     ON delivery.id = opencode.transport_id
                    AND delivery.work_id = opencode.work_id
                   JOIN scheduler_assignments AS assignment
                     ON assignment.id = delivery.assignment_id
                    AND assignment.work_id = delivery.work_id
                    AND assignment.attempt = delivery.assignment_attempt
                   JOIN scheduler_work AS work
                     ON work.id = delivery.work_id
                    AND work.active_assignment_id = assignment.id
                   JOIN scheduler_slots AS slot
                     ON slot.id = assignment.slot_id
                    AND slot.active_assignment_id = assignment.id
                    AND slot.active_work_id = work.id
                   WHERE assignment.slot_id = ? AND opencode.work_id = ?
                     AND opencode.assignment_generation = ?
                     AND opencode.delivery_state IN ('accepted','delivery_unknown')
                     AND opencode.lease_state = 'active'
                     AND delivery.state IN ('accepted','delivery_unknown')
                     AND assignment.state = 'active' AND work.state = 'assigned'
                     AND slot.state = 'assigned'
                   LIMIT 1""",
                (slot_id, work_id, generation),
            ).fetchone()
        if connection is None:
            with self.store._daemon_read_transaction(self._authority) as reader:
                row = read(reader)
        else:
            row = read(connection)
        if row is None:
            raise OperationRejected("stale_binding", "worker assignment is no longer active")
        target_session = str(row[0])
        if session_id is not None and session_id != target_session:
            raise OperationRejected("stale_binding", "worker session binding changed")
        return {
            "slot_id": slot_id,
            "work_id": work_id,
            "generation": generation,
            "session_id": target_session,
            "worker": str(row[1]),
            "anchor_item_id": str(row[2]),
            "delivery_state": str(row[3]),
        }

    def worker_transcript(
        self, capability: object, params: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Fetch transient text for one exact active assignment without journalling it."""
        _exact(params, {"slot_id", "work_id", "generation"})
        binding = self._active_worker_binding(
            capability,
            slot_id=params["slot_id"],
            work_id=params["work_id"],
            generation=params["generation"],
        )
        try:
            messages = self._opencode_client().messages(
                str(binding["session_id"]), limit=_TRANSCRIPT_MESSAGE_LIMIT
            )
        except OpenCodeClientError as error:
            raise OperationRejected("backend_unavailable", error.code) from None
        turns, redacted = _transcript_turns(messages)
        now = datetime.now(timezone.utc)
        return {
            "thread_id": binding["session_id"],
            "slot_id": binding["slot_id"],
            "work_id": binding["work_id"],
            "generation": binding["generation"],
            "fetched_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "turns": turns,
            "redacted": redacted,
            "anchor_item_id": binding["anchor_item_id"],
        }

    def archived_worker_transcript(
        self, capability: object, params: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Read one immutable sanitized transcript captured at exact completion."""

        _exact(params, {"archive_id", "slot_id", "work_id", "generation"})
        try:
            archive_id = _identifier(params["archive_id"], "archive_id")
            slot_id = _identifier(params["slot_id"], "slot_id")
            work_id = _identifier(params["work_id"], "work_id")
        except (TypeError, ValueError):
            raise OperationRejected("invalid_params", "archive binding is invalid") from None
        generation = params["generation"]
        if type(generation) is not int or not 1 <= generation <= 2**31 - 1:
            raise OperationRejected("invalid_params", "archive generation is invalid")
        with self.store._daemon_read_transaction(self._authority) as connection:
            row = connection.execute(
                """SELECT archive.session_id, archive.captured_at_us,
                          archive.transcript_json, archive.transcript_sha256,
                          archive.turn_count, archive.redaction_count, result.outcome
                   FROM completed_transcript_snapshots AS archive
                   JOIN completion_results AS result
                     ON result.result_ref = archive.result_ref
                   WHERE archive.result_ref = ?
                     AND archive.slot_id = ?
                     AND archive.work_id = ?
                     AND archive.generation = ?""",
                (archive_id, slot_id, work_id, generation),
            ).fetchone()
        if row is None:
            raise OperationRejected("not_found", "archived transcript was not found")
        transcript_json = row[2]
        transcript_sha256 = row[3]
        if type(transcript_json) is not str or type(transcript_sha256) is not str:
            raise OperationRejected("constraint_violation", "archived transcript is invalid")
        try:
            encoded = transcript_json.encode("utf-8")
        except UnicodeEncodeError:
            raise OperationRejected("constraint_violation", "archived transcript is invalid") from None
        if hashlib.sha256(encoded).hexdigest() != transcript_sha256:
            raise OperationRejected("constraint_violation", "archived transcript binding changed")
        try:
            document = validate_projected_transcript(json.loads(transcript_json))
        except (json.JSONDecodeError, TranscriptProjectionInvalid):
            raise OperationRejected("constraint_violation", "archived transcript is invalid") from None
        if len(document["turns"]) != row[4] or len(document["redacted"]) != row[5]:
            raise OperationRejected("constraint_violation", "archived transcript counts changed")
        captured_at = datetime.fromtimestamp(
            int(row[1]) / 1_000_000, timezone.utc
        ).isoformat().replace("+00:00", "Z")
        return {
            "archive_id": archive_id,
            "thread_id": str(row[0]),
            "slot_id": slot_id,
            "work_id": work_id,
            "generation": generation,
            "captured_at": captured_at,
            "outcome": str(row[6]),
            "turns": document["turns"],
            "redacted": document["redacted"],
            "read_only": True,
        }

    def _submission_task_authority(
        self,
        connection: sqlite3.Connection,
        submission_id: str,
        reservation_attempt: int,
    ) -> tuple[str, str, str | None]:
        """Return exact GUI submission lifecycle, work and persistent scope authority."""

        generation = f"attempt-{reservation_attempt}"
        submission_key = _submission_identifier(
            submission_id, f"dispatch-{generation}"
        )
        work_id = _submission_identifier(submission_id, f"work-{generation}")
        submission = connection.execute(
            """SELECT state, outcome_json, canonical_json
               FROM gui_task_submissions WHERE submission_key = ?""",
            (submission_key,),
        ).fetchone()
        if submission is None:
            raise OperationRejected("not_found", "task submission was not found")
        if submission[0] != "completed" or type(submission[1]) is not str:
            raise OperationRejected("invalid_state", "task submission is not complete")
        try:
            outcome = json.loads(submission[1])
            canonical = json.loads(submission[2])
        except (TypeError, json.JSONDecodeError):
            raise OperationRejected(
                "constraint_violation", "task submission authority is invalid"
            ) from None
        if (
            type(outcome) is not dict
            or outcome.get("work_id") != work_id
            or outcome.get("state") not in {"accepted", "busy", "rejected"}
            or type(canonical) is not dict
            or set(canonical) not in (
                {"envelope", "repository", "scope"},
                {"envelope", "patch_authority", "repository", "scope"},
            )
            or type(canonical.get("envelope")) is not str
        ):
            raise OperationRejected(
                "constraint_violation", "task submission authority is invalid"
            )
        try:
            envelope = parse_task_prompt(canonical["envelope"])
        except ScopeCapsuleError:
            raise OperationRejected(
                "constraint_violation", "task submission authority is invalid"
            ) from None
        if envelope is None:
            raise OperationRejected(
                "constraint_violation", "task submission authority is invalid"
            )
        lifecycle = envelope.get("agent_lifecycle")
        if lifecycle not in {"disposable", "persistent"}:
            raise OperationRejected(
                "constraint_violation", "task submission lifecycle is invalid"
            )
        scope_hash = envelope.get("claim_scope_hash")
        if lifecycle == "persistent" and (
            type(scope_hash) is not str
            or len(scope_hash) != 64
            or any(character not in "0123456789abcdef" for character in scope_hash)
        ):
            raise OperationRejected(
                "constraint_violation", "persistent task scope authority is invalid"
            )
        return str(outcome["state"]), lifecycle, (
            str(scope_hash) if lifecycle == "persistent" else None
        )

    @staticmethod
    def _persistent_session_state(
        connection: sqlite3.Connection, scope_hash: str | None
    ) -> str | None:
        if scope_hash is None:
            return None
        row = connection.execute(
            "SELECT state FROM opencode_persistent_sessions WHERE scope_hash = ?",
            (scope_hash,),
        ).fetchone()
        if row is None or row[0] == "intended":
            return "unavailable"
        state = str(row[0])
        if state not in {"active", "closed", "attention"}:
            return "unavailable"
        return state

    def _close_persistent_submission_durable(
        self,
        capability: object,
        idempotency_id: str,
        fingerprint: str,
        params: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Explicitly close one retained GUI task session without exposing its ID."""

        self._transport._assert_authority(capability)
        _exact(params, {"submission_id", "reservation_attempt"})
        submission_id = _identifier(params["submission_id"], "submission_id")
        reservation_attempt = params["reservation_attempt"]
        if type(reservation_attempt) is not int or not 1 <= reservation_attempt <= 32:
            raise OperationRejected("invalid_params", "reservation attempt is invalid")
        expected_id = f"gui-close-{submission_id}-attempt-{reservation_attempt}"
        if idempotency_id != expected_id:
            raise OperationRejected("invalid_params", "close identity is inconsistent")

        scope_hash: str | None = None
        with self.store._daemon_transaction(self._authority) as connection:
            existing = connection.execute(
                """SELECT fingerprint, operation, ok, outcome_json
                   FROM daemon_request_outcomes WHERE idempotency_id = ?""",
                (idempotency_id,),
            ).fetchone()
            if existing is not None:
                if existing[0] != fingerprint or existing[1] != "submission.close.v1":
                    raise OperationRejected(
                        "idempotency_conflict", "persistent close identity changed"
                    )
                outcome = json.loads(existing[3])
                if bool(existing[2]):
                    return outcome
                raise OperationRejected(outcome["code"], outcome["message"])
            submission_state, lifecycle, scope_hash = self._submission_task_authority(
                connection, submission_id, reservation_attempt
            )
            if submission_state != "accepted" or lifecycle != "persistent" or scope_hash is None:
                raise OperationRejected(
                    "invalid_state", "task does not own a retained persistent session"
                )
            session_state = self._persistent_session_state(connection, scope_hash)

            def commit_terminal_outcome(result: Mapping[str, Any]) -> Mapping[str, Any]:
                reserved = connection.execute(
                    """SELECT fingerprint, operation FROM daemon_outcome_reservations
                       WHERE idempotency_id = ?""",
                    (idempotency_id,),
                ).fetchone()
                if reserved is not None and tuple(reserved) != (
                    fingerprint, "submission.close.v1"
                ):
                    raise OperationRejected(
                        "idempotency_conflict", "persistent close reservation changed"
                    )
                if reserved is None:
                    count = connection.execute(
                        """SELECT
                               (SELECT count(*) FROM daemon_request_outcomes) +
                               (SELECT count(*) FROM daemon_outcome_reservations)"""
                    ).fetchone()
                    assert count is not None
                    if int(count[0]) >= self.max_idempotency_entries:
                        raise OperationRejected(
                            "idempotency_capacity", "idempotency capacity is exhausted"
                        )
                connection.execute(
                    """INSERT INTO daemon_request_outcomes(
                           idempotency_id, fingerprint, operation, ok,
                           outcome_json, completed_at
                       ) VALUES (?, ?, 'submission.close.v1', 1, ?, ?)""",
                    (idempotency_id, fingerprint, _json(result), _utc_now()),
                )
                if reserved is not None:
                    connection.execute(
                        "DELETE FROM daemon_outcome_reservations WHERE idempotency_id = ?",
                        (idempotency_id,),
                    )
                return result

            if session_state == "closed":
                return commit_terminal_outcome({
                    "submission_id": submission_id,
                    "reservation_attempt": reservation_attempt,
                    "state": "closed",
                    "reason": None,
                })
            if session_state == "attention":
                return commit_terminal_outcome({
                    "submission_id": submission_id,
                    "reservation_attempt": reservation_attempt,
                    "state": "attention",
                    "reason": "persistent_session_attention",
                })
            if session_state != "active":
                raise OperationRejected(
                    "invalid_state", "persistent session is not available to close"
                )
            reserved = connection.execute(
                """SELECT fingerprint, operation FROM daemon_outcome_reservations
                   WHERE idempotency_id = ?""",
                (idempotency_id,),
            ).fetchone()
            if reserved is not None and tuple(reserved) != (
                fingerprint, "submission.close.v1"
            ):
                raise OperationRejected(
                    "idempotency_conflict", "persistent close reservation changed"
                )
            if reserved is None:
                count = connection.execute(
                    """SELECT
                           (SELECT count(*) FROM daemon_request_outcomes) +
                           (SELECT count(*) FROM daemon_outcome_reservations)"""
                ).fetchone()
                assert count is not None
                if int(count[0]) >= self.max_idempotency_entries:
                    raise OperationRejected(
                        "idempotency_capacity", "idempotency capacity is exhausted"
                    )
                connection.execute(
                    """INSERT INTO daemon_outcome_reservations(
                           idempotency_id, fingerprint, operation, created_at
                       ) VALUES (?, ?, 'submission.close.v1', ?)""",
                    (idempotency_id, fingerprint, _utc_now()),
                )

        adapter = getattr(self._transport, "_adapter", None)
        closer = getattr(adapter, "close_persistent_session", None)
        if not callable(closer):
            with self.store._daemon_transaction(self._authority) as connection:
                connection.execute(
                    "DELETE FROM daemon_outcome_reservations WHERE idempotency_id = ?",
                    (idempotency_id,),
                )
            raise OperationRejected(
                "backend_unavailable", "persistent session close is unavailable"
            )
        try:
            close_state = closer(scope_hash)
        except OpenCodeClientError as error:
            if error.delivery_unknown:
                close_state = "attention"
            else:
                with self.store._daemon_transaction(self._authority) as connection:
                    connection.execute(
                        "DELETE FROM daemon_outcome_reservations WHERE idempotency_id = ?",
                        (idempotency_id,),
                    )
                raise OperationRejected(
                    "backend_unavailable", "persistent session close failed safely"
                ) from error
        if close_state == "busy":
            with self.store._daemon_transaction(self._authority) as connection:
                connection.execute(
                    "DELETE FROM daemon_outcome_reservations WHERE idempotency_id = ?",
                    (idempotency_id,),
                )
            raise OperationRejected(
                "invalid_state", "persistent session is still active"
            )
        if close_state not in {"closed", "attention"}:
            raise OperationRejected(
                "constraint_violation", "persistent close returned an invalid state"
            )
        result = {
            "submission_id": submission_id,
            "reservation_attempt": reservation_attempt,
            "state": close_state,
            "reason": (
                None if close_state == "closed" else "persistent_session_attention"
            ),
        }
        with self.store._daemon_transaction(self._authority) as connection:
            current_submission_state, current_lifecycle, current_scope_hash = (
                self._submission_task_authority(
                    connection, submission_id, reservation_attempt
                )
            )
            current_session_state = self._persistent_session_state(
                connection, current_scope_hash
            )
            if (
                current_submission_state != "accepted"
                or current_lifecycle != "persistent"
                or current_scope_hash != scope_hash
                or current_session_state != close_state
            ):
                raise OperationRejected(
                    "constraint_violation", "persistent close authority changed"
                )
            reservation = connection.execute(
                """SELECT fingerprint, operation FROM daemon_outcome_reservations
                   WHERE idempotency_id = ?""",
                (idempotency_id,),
            ).fetchone()
            if reservation is None or tuple(reservation) != (
                fingerprint, "submission.close.v1"
            ):
                raise OperationRejected(
                    "constraint_violation", "persistent close reservation changed"
                )
            connection.execute(
                """INSERT INTO daemon_request_outcomes(
                       idempotency_id, fingerprint, operation, ok,
                       outcome_json, completed_at
                   ) VALUES (?, ?, 'submission.close.v1', 1, ?, ?)""",
                (idempotency_id, fingerprint, _json(result), _utc_now()),
            )
            connection.execute(
                "DELETE FROM daemon_outcome_reservations WHERE idempotency_id = ?",
                (idempotency_id,),
            )
        return result

    def submission_result(
        self, capability: object, submission_id: object, reservation_attempt: object
    ) -> Mapping[str, Any]:
        """Read one GUI-owned completion without adding request-journal pressure."""
        self._transport._assert_authority(capability)
        _identifier(submission_id, "submission_id")
        if (
            type(reservation_attempt) is not int
            or not 1 <= reservation_attempt <= 32
        ):
            raise OperationRejected("invalid_params", "reservation attempt is invalid")
        generation = f"attempt-{reservation_attempt}"
        submission_key = _submission_identifier(
            submission_id, f"dispatch-{generation}"
        )
        work_id = _submission_identifier(submission_id, f"work-{generation}")
        with self.store._daemon_read_transaction(self._authority) as connection:
            submission = connection.execute(
                """SELECT state, outcome_json FROM gui_task_submissions
                   WHERE submission_key = ?""",
                (submission_key,),
            ).fetchone()
            if submission is None:
                raise OperationRejected("not_found", "task submission was not found")
            persistent_session_state: str | None = None
            if submission[0] == "completed":
                outcome = json.loads(submission[1])
                if outcome.get("work_id") != work_id:
                    raise OperationRejected(
                        "constraint_violation", "task submission binding is invalid"
                    )
                if outcome.get("state") != "accepted":
                    return {
                        "submission_id": submission_id,
                        "reservation_attempt": reservation_attempt,
                        "state": "not_started",
                        "outcome": None,
                        "result_ref": None,
                        "text": None,
                        "persistent_session_state": None,
                    }
                _submission_state, _lifecycle, scope_hash = (
                    self._submission_task_authority(
                        connection, submission_id, reservation_attempt
                    )
                )
                persistent_session_state = self._persistent_session_state(
                    connection, scope_hash
                )
            result_ref = connection.execute(
                """SELECT result_ref FROM completion_results WHERE work_id = ?
                   ORDER BY generation DESC, created_at_us DESC LIMIT 1""",
                (work_id,),
            ).fetchone()
            result = (
                None
                if result_ref is None
                else self._completion.read_final_result(
                    capability, connection, str(result_ref[0])
                )
            )
        if result is None:
            return {
                "submission_id": submission_id,
                "reservation_attempt": reservation_attempt,
                "state": "waiting",
                "outcome": None,
                "result_ref": None,
                "text": None,
                "persistent_session_state": persistent_session_state,
            }
        return {
            "submission_id": submission_id,
            "reservation_attempt": reservation_attempt,
            "state": "completed",
            "outcome": str(result["outcome"]),
            "result_ref": str(result["result_ref"]),
            "text": (
                str(result["text"])
                if result["content_state"] == "available"
                else None
            ),
            "persistent_session_state": persistent_session_state,
        }

    def reconcile_callback_delivery(
        self,
        capability: object,
        idempotency_id: str,
        fingerprint: str,
        params: Mapping[str, Any],
        verifier: Callable[[CodexCallbackRequest], CallbackDeliveryProof],
    ) -> Mapping[str, Any]:
        """Reconcile one ambiguous callback from independently verified Codex history."""

        self._transport._assert_authority(capability)
        _exact(params, {"callback_id"})
        callback_id = _identifier(params["callback_id"], "callback_id")
        if not callable(verifier):
            raise OperationRejected(
                "callback_unavailable", "callback proof verifier is not configured"
            )

        delivery = None
        binding_rejection: OperationRejected | None = None
        with self.store._daemon_transaction(self._authority) as connection:
            existing = connection.execute(
                """SELECT fingerprint, ok, outcome_json
                   FROM daemon_request_outcomes WHERE idempotency_id = ?""",
                (idempotency_id,),
            ).fetchone()
            if existing is not None:
                if existing[0] != fingerprint:
                    raise OperationRejected(
                        "idempotency_conflict",
                        "idempotency ID was reused for a different request",
                    )
                outcome = json.loads(existing[2])
                if bool(existing[1]):
                    return outcome
                raise OperationRejected(outcome["code"], outcome["message"])
            count = connection.execute(
                "SELECT count(*) FROM daemon_request_outcomes"
            ).fetchone()
            assert count is not None
            if int(count[0]) >= self.max_idempotency_entries:
                raise OperationRejected(
                    "idempotency_capacity", "idempotency capacity is exhausted"
                )
            try:
                delivery = self._completion.local_codex_attention_delivery(
                    capability, connection, callback_id
                )
            except OwnershipConflict as error:
                binding_rejection = OperationRejected("invalid_state", str(error))
                connection.execute(
                    """INSERT INTO daemon_request_outcomes(
                           idempotency_id, fingerprint, operation, ok,
                           outcome_json, completed_at
                       ) VALUES (?, ?, 'callback.delivery.reconcile.v1', 0, ?, ?)""",
                    (
                        idempotency_id,
                        fingerprint,
                        _json(
                            {
                                "code": binding_rejection.code,
                                "message": str(binding_rejection),
                            }
                        ),
                        _utc_now(),
                    ),
                )
        if binding_rejection is not None:
            raise binding_rejection
        assert delivery is not None

        proof = verifier(delivery.request())
        if (
            type(proof) is not CallbackDeliveryProof
            or (proof.proven and proof.reason != "codex_history_exact_message")
        ):
            proof = CallbackDeliveryProof(False, "callback_proof_invalid")

        mutation_rejection: OperationRejected | None = None
        result: Mapping[str, Any] | None = None
        with self.store._daemon_transaction(self._authority) as connection:
            existing = connection.execute(
                """SELECT fingerprint, ok, outcome_json
                   FROM daemon_request_outcomes WHERE idempotency_id = ?""",
                (idempotency_id,),
            ).fetchone()
            if existing is not None:
                if existing[0] != fingerprint:
                    raise OperationRejected(
                        "idempotency_conflict",
                        "idempotency ID was reused for a different request",
                    )
                outcome = json.loads(existing[2])
                if bool(existing[1]):
                    return outcome
                raise OperationRejected(outcome["code"], outcome["message"])
            if proof.proven:
                try:
                    self._completion.reconcile_local_codex_delivery(
                        capability,
                        connection,
                        delivery,
                        proof_kind=proof.reason,
                    )
                except OwnershipConflict as error:
                    mutation_rejection = OperationRejected(
                        "ownership_conflict", str(error)
                    )
                    outcome = {
                        "code": mutation_rejection.code,
                        "message": str(mutation_rejection),
                    }
                    connection.execute(
                        """INSERT INTO daemon_request_outcomes(
                               idempotency_id, fingerprint, operation, ok,
                               outcome_json, completed_at
                           ) VALUES (?, ?, 'callback.delivery.reconcile.v1', 0, ?, ?)""",
                        (idempotency_id, fingerprint, _json(outcome), _utc_now()),
                    )
                else:
                    result = {
                        "callback_id": callback_id,
                        "reconciled": True,
                        "state": "delivered",
                        "proof": proof.reason,
                    }
            else:
                result = {
                    "callback_id": callback_id,
                    "reconciled": False,
                    "state": "attention",
                    "proof": proof.reason,
                }
            if mutation_rejection is None:
                assert result is not None
                connection.execute(
                    """INSERT INTO daemon_request_outcomes(
                           idempotency_id, fingerprint, operation, ok,
                           outcome_json, completed_at
                       ) VALUES (?, ?, 'callback.delivery.reconcile.v1', 1, ?, ?)""",
                    (idempotency_id, fingerprint, _json(result), _utc_now()),
                )
        if mutation_rejection is not None:
            raise mutation_rejection
        assert result is not None
        return result

    def execute_durable(
        self,
        capability: object,
        idempotency_id: str,
        fingerprint: str,
        operation: str,
        params: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self._transport._assert_authority(capability)
        if operation == "worker.transcript.v1":
            return self.worker_transcript(capability, params)
        if operation == "worker.transcript.archive.v1":
            return self.archived_worker_transcript(capability, params)
        if operation == "llm.behaviour.status.v1":
            _exact(params, set())
            with self.store._daemon_read_transaction(self._authority) as connection:
                try:
                    return llm_behaviour_status(connection)
                except LlmBehaviourInvalid as error:
                    raise OperationRejected("constraint_violation", str(error)) from error
        if operation == "submission.close.v1":
            return self._close_persistent_submission_durable(
                capability,
                idempotency_id,
                fingerprint,
                params,
            )
        if operation == "submission.submit.v1":
            return self._submit_task_durable(
                capability,
                idempotency_id,
                fingerprint,
                params,
            )
        if operation == "transport.dispatch.v1":
            return self._dispatch_transport_durable(
                capability,
                idempotency_id,
                fingerprint,
                params,
            )
        if operation == "transport.cancel.v1":
            try:
                return self._cancel_transport_durable(
                    capability,
                    idempotency_id,
                    fingerprint,
                    params,
                )
            except OwnershipConflict as error:
                raise OperationRejected("ownership_conflict", str(error)) from error
        prepared_rejection: OperationRejected | None = None
        prepared_scope: ScopeInspection | None = None
        try:
            admission = self._prepare_admission(operation, params)
            prepared_scope = self._prepare_scope(operation, params)
        except OperationRejected as error:
            admission = None
            prepared_rejection = error
        rejected: OperationRejected | None = None
        result: Mapping[str, Any] | None = None
        with self.store._daemon_transaction(self._authority) as connection:
            existing = connection.execute(
                """SELECT fingerprint, ok, outcome_json
                   FROM daemon_request_outcomes WHERE idempotency_id = ?""",
                (idempotency_id,),
            ).fetchone()
            if existing is not None:
                if existing[0] != fingerprint:
                    raise OperationRejected(
                        "idempotency_conflict",
                        "idempotency ID was reused for a different request",
                    )
                outcome = json.loads(existing[2])
                if bool(existing[1]):
                    return outcome
                raise OperationRejected(outcome["code"], outcome["message"])
            count = connection.execute(
                """SELECT
                       (SELECT count(*) FROM daemon_request_outcomes) +
                       (SELECT count(*) FROM daemon_outcome_reservations)"""
            ).fetchone()
            assert count is not None
            if int(count[0]) >= self.max_idempotency_entries:
                raise OperationRejected(
                    "idempotency_capacity", "idempotency capacity is exhausted"
                )
            connection.execute("SAVEPOINT request_mutation")
            try:
                if prepared_rejection is not None:
                    raise prepared_rejection
                result = self._execute(
                    capability,
                    connection,
                    operation,
                    params,
                    idempotency_id=idempotency_id,
                    admission=admission,
                    prepared_scope=prepared_scope,
                )
            except OperationRejected as error:
                rejected = error
                outcome = {"code": error.code, "message": str(error)}
                ok = 0
            except IdempotencyConflict as error:
                rejected = OperationRejected("idempotency_conflict", str(error))
                outcome = {"code": rejected.code, "message": str(rejected)}
                ok = 0
            except OwnershipConflict as error:
                rejected = OperationRejected("ownership_conflict", str(error))
                outcome = {"code": rejected.code, "message": str(rejected)}
                ok = 0
            except KeyError:
                rejected = OperationRejected("not_found", "scheduler work was not found")
                outcome = {"code": rejected.code, "message": str(rejected)}
                ok = 0
            except (TypeError, ValueError) as error:
                rejected = OperationRejected("invalid_params", str(error))
                outcome = {"code": rejected.code, "message": str(rejected)}
                ok = 0
            except sqlite3.IntegrityError:
                rejected = OperationRejected(
                    "constraint_violation", "scheduler mutation was rejected"
                )
                outcome = {"code": rejected.code, "message": str(rejected)}
                ok = 0
            else:
                outcome = dict(result)
                ok = 1
            if rejected is not None:
                connection.execute("ROLLBACK TO request_mutation")
            connection.execute("RELEASE request_mutation")
            connection.execute(
                """INSERT INTO daemon_request_outcomes(
                       idempotency_id, fingerprint, operation, ok,
                       outcome_json, completed_at
                   ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    idempotency_id,
                    fingerprint,
                    operation,
                    ok,
                    _json(outcome),
                    _utc_now(),
                ),
            )
        if rejected is not None:
            raise rejected
        assert result is not None
        return result

    def _submit_task_durable(
        self,
        capability: object,
        idempotency_id: str,
        fingerprint: str,
        params: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Admit and dispatch one GUI task without exposing controller primitives."""

        submission_fields = {
            "submission_id", "lane", "repository", "scope", "objective",
            "agent_lifecycle", "allow_child_agents", "classification", "trust",
            "reservation_attempt",
        }
        if frozenset(params) not in {
            frozenset(submission_fields),
            frozenset(submission_fields | {"workspace_edit"}),
            frozenset(submission_fields | {"workspace_patch"}),
            frozenset(submission_fields | {"return_route"}),
            frozenset(submission_fields | {"return_route", "workspace_edit"}),
            frozenset(submission_fields | {"return_route", "workspace_patch"}),
        }:
            raise OperationRejected(
                "invalid_params", "operation parameters do not match schema"
            )
        try:
            local_codex_thread_id = parse_local_codex_return_route(
                params.get("return_route")
            )
        except (TypeError, ValueError) as error:
            raise OperationRejected(
                "invalid_params", "return_route is invalid"
            ) from error
        submission_id = params["submission_id"]
        _identifier(submission_id, "submission_id")
        reservation_attempt = params["reservation_attempt"]
        if type(reservation_attempt) is not int or not 1 <= reservation_attempt <= 32:
            raise OperationRejected("invalid_params", "reservation attempt is invalid")
        if idempotency_id != f"gui-submit-{submission_id}-attempt-{reservation_attempt}":
            raise OperationRejected("invalid_params", "submission identity is inconsistent")
        try:
            lane = Lane(params["lane"])
            lifecycle = AgentLifecycle(params["agent_lifecycle"])
        except (TypeError, ValueError) as error:
            raise OperationRejected("invalid_params", "lane or lifecycle is invalid") from error
        if (
            params["allow_child_agents"] is not True
            or params["classification"] != "PUBLIC"
            or params["trust"] != "secure"
        ):
            raise OperationRejected("invalid_params", "task security policy is fixed")
        workspace_edit = params.get("workspace_edit", False)
        if type(workspace_edit) is not bool:
            raise OperationRejected("invalid_params", "workspace edit mode is invalid")
        workspace_patch = params.get("workspace_patch")
        if workspace_patch is not None and (
            type(workspace_patch) is not dict
            or set(workspace_patch) != {"line_end", "line_start"}
            or type(workspace_patch.get("line_start")) is not int
            or type(workspace_patch.get("line_end")) is not int
        ):
            raise OperationRejected("invalid_params", "workspace patch range is invalid")
        if workspace_edit and workspace_patch is not None:
            raise OperationRejected("invalid_params", "workspace modes are mutually exclusive")
        if workspace_patch is not None and lifecycle is not AgentLifecycle.DISPOSABLE:
            raise OperationRejected("invalid_params", "workspace patch requires disposable lifecycle")
        objective = _bounded_objective(params["objective"])
        generation = f"attempt-{reservation_attempt}"
        operation_id = _submission_identifier(submission_id, f"operation-{generation}")
        work_id = _submission_identifier(submission_id, f"work-{generation}")
        claim_id = _submission_identifier(submission_id, f"claim-{generation}")
        claim_key = _submission_identifier(submission_id, f"claim-key-{generation}")
        reservation_id = _submission_identifier(submission_id, f"reservation-{generation}")
        reservation_fence = _submission_identifier(submission_id, f"reservation-fence-{generation}")
        scope_fence = _submission_identifier(submission_id, f"scope-fence-{generation}")
        dispatch_id = _submission_identifier(submission_id, f"dispatch-{generation}")

        canonical: Mapping[str, Any] | None = None
        with self.store._daemon_transaction(self._authority) as connection:
            prior_submission = connection.execute(
                """SELECT request_fingerprint, canonical_json, state, outcome_json
                   FROM gui_task_submissions WHERE submission_key = ?""",
                (dispatch_id,),
            ).fetchone()
        if prior_submission is not None:
            if prior_submission[0] != fingerprint:
                raise OperationRejected(
                    "idempotency_conflict", "submission identity changed"
                )
            if prior_submission[2] == "completed":
                return json.loads(prior_submission[3])
            canonical = json.loads(prior_submission[1])
            if (
                type(canonical) is not dict
                or set(canonical) not in (
                    {"envelope", "repository", "scope"},
                    {"envelope", "patch_authority", "repository", "scope"},
                )
                or type(canonical.get("envelope")) is not str
                or type(canonical.get("repository")) is not str
                or type(canonical.get("scope")) is not list
                or any(type(item) is not str for item in canonical["scope"])
            ):
                raise OperationRejected(
                    "constraint_violation", "stored submission authority is invalid"
                )
            repository = canonical["repository"]
            scope = canonical["scope"]
            envelope = canonical["envelope"]
        else:
            inspected = inspect_scope(params["repository"], params["scope"])
            if not inspected.accepted or inspected.repository is None:
                raise OperationRejected("invalid_scope", "scope failed policy inspection")
            repository = str(inspected.repository)
            scope = [path.relative for path in inspected.paths]
            if (workspace_edit or workspace_patch is not None) and len(scope) != 1:
                raise OperationRejected(
                    "invalid_scope", "workspace write requires exactly one file"
                )
            try:
                if workspace_patch is not None:
                    capsule = capture_patch_scope_capsule(
                        repository,
                        scope,
                        workspace_patch["line_start"],
                        workspace_patch["line_end"],
                    )
                    capsule_value = patch_capsule_document(capsule)
                    claim_hash = capsule.base.claim_scope_hash
                    private_patch = patch_private_authority(capsule)
                else:
                    capsule = capture_scope_capsule(repository, scope)
                    capsule_value = capsule_document(capsule)
                    claim_hash = capsule.claim_scope_hash
                    private_patch = None
            except ValueError as error:
                raise OperationRejected(
                    "invalid_scope", "scope could not be captured as safe text files"
                ) from error
            envelope = _json(
                {
                    "agent_lifecycle": lifecycle.value,
                    "allow_child_agents": True,
                    "claim_scope_hash": claim_hash,
                    "objective": objective,
                    "scope": scope,
                    "scope_capsule": capsule_value,
                    "submission_fingerprint": fingerprint,
                    "task_mode": (
                        "workspace_patch"
                        if workspace_patch is not None
                        else "workspace_edit" if workspace_edit else "agent_task"
                    ),
                    "version": 1,
                }
            )
            if len(envelope.encode("utf-8")) > 48 * 1024:
                raise OperationRejected(
                    "invalid_params", "task envelope exceeds its limit"
                )
            canonical = {
                "envelope": envelope,
                "repository": repository,
                "scope": scope,
            }
            if private_patch is not None:
                canonical["patch_authority"] = private_patch
        admission = (
            _evaluate_admission(
                self._authority,
                AdmissionRequest(
                    repository=repository,
                    scope=scope,
                    content=envelope,
                    dispatch_kind="automated",
                    trust="secure",
                    classification="PUBLIC",
                    risk_categories=[],
                    agent_lifecycle=lifecycle,
                    allow_child_agents=True,
                ),
            )
            if prior_submission is None
            else None
        )
        scope_key = _scope_digest(repository, tuple(scope))
        dispatch_params = {
            "pool": lane.value,
            "work_id": work_id,
            "reservation_id": reservation_id,
            "reservation_attempt": 1,
            "reservation_fence": reservation_fence,
            "payload": {
                "prompt": envelope,
                "classification": "PUBLIC",
                "trust": "secure",
            },
        }
        if local_codex_thread_id is not None:
            dispatch_params["return_route"] = {
                "kind": "local_codex",
                "thread_id": local_codex_thread_id,
            }
        dispatch_fingerprint = hashlib.sha256(
            _json(dispatch_params).encode("utf-8")
        ).hexdigest()

        def gui_result(state: str) -> dict[str, object]:
            return {
                "submission_id": submission_id,
                "work_id": work_id,
                "lane": lane.value,
                "state": state,
                "agent_lifecycle": lifecycle.value,
                "child_agents": "allowed",
                "reservation_attempt": reservation_attempt,
            }

        def transport_result(outcome: Mapping[str, Any]) -> dict[str, object]:
            transport_state = str(outcome.get("state", "delivery_unknown"))
            state = (
                "busy"
                if transport_state == "definite_failed"
                and outcome.get("error_code") == "no_capacity"
                else "accepted"
                if transport_state in {"accepted", "delivery_unknown"}
                else "rejected"
            )
            return gui_result(state)

        with self.store._daemon_transaction(self._authority) as connection:
            current_submission = connection.execute(
                """SELECT request_fingerprint, canonical_json, state, outcome_json
                   FROM gui_task_submissions WHERE submission_key = ?""",
                (dispatch_id,),
            ).fetchone()
            canonical_json = _json(canonical)
            if current_submission is None:
                gui_count = connection.execute(
                    "SELECT count(*) FROM gui_task_submissions"
                ).fetchone()
                assert gui_count is not None
                if int(gui_count[0]) >= self.max_idempotency_entries:
                    raise OperationRejected(
                        "idempotency_capacity", "GUI submission capacity is exhausted"
                    )
                connection.execute(
                    """INSERT INTO gui_task_submissions(
                           submission_key, request_fingerprint, canonical_json,
                           state, outcome_json, created_at, completed_at
                       ) VALUES (?, ?, ?, 'prepared', NULL, ?, NULL)""",
                    (dispatch_id, fingerprint, canonical_json, _utc_now()),
                )
            elif (
                current_submission[0] != fingerprint
                or current_submission[1] != canonical_json
                or current_submission[2] != "prepared"
                or current_submission[3] is not None
            ):
                raise OperationRejected(
                    "idempotency_conflict", "submission authority changed"
                )
            existing_outcome = connection.execute(
                """SELECT fingerprint, operation, ok, outcome_json
                   FROM daemon_request_outcomes WHERE idempotency_id = ?""",
                (dispatch_id,),
            ).fetchone()
            if existing_outcome is not None:
                if existing_outcome[0] != dispatch_fingerprint:
                    raise OperationRejected(
                        "idempotency_conflict", "submission identity changed"
                    )
                prior = json.loads(existing_outcome[3])
                if not bool(existing_outcome[2]):
                    assignment = connection.execute(
                        """SELECT owner_id, attempt, fence_token
                           FROM scheduler_assignments WHERE id = ?""",
                        (reservation_id,),
                    ).fetchone()
                    if assignment is None or not self._scheduler.release(
                        connection,
                        reservation_id,
                        work_id,
                        str(assignment[0]),
                        attempt=int(assignment[1]),
                        fence_token=str(assignment[2]),
                        outcome=ReleaseOutcome.CANCELLED,
                    ):
                        raise OperationRejected(
                            "constraint_violation",
                            "stored submission release authority is invalid",
                        )
                    stored_claim = connection.execute(
                        """SELECT owner_operation_id, attempt, fence_token
                           FROM scope_claims WHERE id = ?""",
                        (claim_id,),
                    ).fetchone()
                    if stored_claim is None or not self.store._release_scope(
                        connection,
                        claim_id,
                        str(stored_claim[0]),
                        attempt=int(stored_claim[1]),
                        fence_token=str(stored_claim[2]),
                    ):
                        raise OperationRejected(
                            "constraint_violation",
                            "stored submission scope authority is invalid",
                        )
                    now = _utc_now()
                    connection.execute(
                        """UPDATE operations SET state = 'failed', updated_at = ?,
                                  finished_at = ?
                           WHERE id = ? AND state = 'pending'""",
                        (now, now, operation_id),
                    )
                    result = gui_result("rejected")
                    connection.execute(
                        """UPDATE gui_task_submissions
                           SET state = 'completed', outcome_json = ?, completed_at = ?
                           WHERE submission_key = ? AND state = 'prepared'""",
                        (_json(result), now, dispatch_id),
                    )
                    return result
                if existing_outcome[1] == "submission.submit.v1":
                    result = prior
                elif existing_outcome[1] == "transport.dispatch.v1":
                    result = transport_result(prior)
                else:
                    raise OperationRejected(
                        "idempotency_conflict", "submission outcome type changed"
                    )
                connection.execute(
                    """UPDATE gui_task_submissions
                       SET state = 'completed', outcome_json = ?, completed_at = ?
                       WHERE submission_key = ? AND state = 'prepared'""",
                    (_json(result), _utc_now(), dispatch_id),
                )
                return result
            existing_reservation = connection.execute(
                """SELECT fingerprint, operation FROM daemon_outcome_reservations
                   WHERE idempotency_id = ?""",
                (dispatch_id,),
            ).fetchone()
            if existing_reservation is not None and (
                existing_reservation[0] != dispatch_fingerprint
                or existing_reservation[1] != "transport.dispatch.v1"
            ):
                raise OperationRejected(
                    "idempotency_conflict", "submission reservation changed"
                )
            if existing_reservation is None:
                count = connection.execute(
                    """SELECT
                           (SELECT count(*) FROM daemon_request_outcomes) +
                           (SELECT count(*) FROM daemon_outcome_reservations)"""
                ).fetchone()
                assert count is not None
                if int(count[0]) >= self.max_idempotency_entries:
                    raise OperationRejected(
                        "idempotency_capacity", "idempotency capacity is exhausted"
                    )
                connection.execute(
                    """INSERT INTO daemon_outcome_reservations(
                           idempotency_id, fingerprint, operation, created_at
                       ) VALUES (?, ?, 'transport.dispatch.v1', ?)""",
                    (dispatch_id, dispatch_fingerprint, _utc_now()),
                )
            connection.execute("SAVEPOINT gui_submission")
            operation = connection.execute(
                "SELECT id, kind, idempotency_key FROM operations WHERE idempotency_key = ?",
                (_submission_identifier(submission_id, f"operation-key-{generation}"),),
            ).fetchone()
            if operation is None:
                self.store._create_operation(
                    connection,
                    operation_id,
                    OperationKind.DISPATCH,
                    idempotency_key=_submission_identifier(submission_id, f"operation-key-{generation}"),
                    controller_run_id=None,
                    now=_utc_now(),
                )
            elif tuple(operation) != (
                operation_id,
                OperationKind.DISPATCH.value,
                _submission_identifier(submission_id, f"operation-key-{generation}"),
            ):
                raise OperationRejected("idempotency_conflict", "submission operation changed")

            prior_claim = connection.execute(
                "SELECT coalesce(max(attempt), 0) FROM scope_claims WHERE scope_key = ?",
                (scope_key,),
            ).fetchone()
            assert prior_claim is not None
            existing_claim = connection.execute(
                "SELECT attempt FROM scope_claims WHERE idempotency_key = ?",
                (claim_key,),
            ).fetchone()
            claim_attempt = int(existing_claim[0]) if existing_claim else int(prior_claim[0]) + 1
            claim = self.store._claim_scope(
                connection,
                claim_id,
                scope_key,
                operation_id,
                attempt=claim_attempt,
                fence_token=scope_fence,
                idempotency_key=claim_key,
            )
            self._scheduler.enqueue(
                connection,
                work_id,
                lane,
                idempotency_key=_submission_identifier(submission_id, f"enqueue-{generation}"),
            )
            decision_id = _submission_identifier(
                submission_id, f"decision-{generation}"
            )
            if admission is None:
                decision = connection.execute(
                    """SELECT work_id, content_hash, scope_hash, allowed,
                              agent_lifecycle, allow_child_agents, scope_claim_id,
                              scope_key, scope_owner_id, scope_claim_attempt,
                              scope_claim_fence
                       FROM scheduler_admission_decisions WHERE id = ?""",
                    (decision_id,),
                ).fetchone()
                if decision is None or tuple(decision) != (
                    work_id,
                    scan_content(envelope).content_hash,
                    scope_key,
                    1,
                    lifecycle.value,
                    1,
                    claim.id,
                    scope_key,
                    operation_id,
                    claim.attempt,
                    claim.fence_token,
                ):
                    raise OperationRejected(
                        "constraint_violation",
                        "stored submission admission authority is invalid",
                    )
                allowed = True
            else:
                allowed = self._scheduler.admit(
                    connection,
                    work_id,
                    decision_id=decision_id,
                    claim_id=claim.id,
                    evidence=admission,
                    idempotency_key=_submission_identifier(
                        submission_id, f"admission-{generation}"
                    ),
                )
            if not allowed:
                connection.execute("ROLLBACK TO gui_submission")
                connection.execute("RELEASE gui_submission")
                result = gui_result("rejected")
                connection.execute(
                    "DELETE FROM daemon_outcome_reservations WHERE idempotency_id = ?",
                    (dispatch_id,),
                )
                connection.execute(
                    """UPDATE gui_task_submissions
                       SET state = 'completed', outcome_json = ?, completed_at = ?
                       WHERE submission_key = ? AND state = 'prepared'""",
                    (_json(result), _utc_now(), dispatch_id),
                )
                return result
            reservation = self._scheduler.reserve_next(
                connection,
                reservation_id,
                fence_token=reservation_fence,
                work_id=work_id,
            )
            if reservation is None:
                connection.execute("ROLLBACK TO gui_submission")
                connection.execute("RELEASE gui_submission")
                result = gui_result("busy")
                connection.execute(
                    "DELETE FROM daemon_outcome_reservations WHERE idempotency_id = ?",
                    (dispatch_id,),
                )
                connection.execute(
                    """UPDATE gui_task_submissions
                       SET state = 'completed', outcome_json = ?, completed_at = ?
                       WHERE submission_key = ? AND state = 'prepared'""",
                    (_json(result), _utc_now(), dispatch_id),
                )
                return result
            if (
                reservation.id,
                reservation.attempt,
                reservation.fence_token,
            ) != (reservation_id, 1, reservation_fence):
                raise OperationRejected(
                    "idempotency_conflict", "submission reservation changed"
                )
            connection.execute("RELEASE gui_submission")

        try:
            transport = self._dispatch_transport_durable(
                capability,
                dispatch_id,
                dispatch_fingerprint,
                dispatch_params,
            )
        except OperationRejected:
            with self.store._daemon_transaction(self._authority) as connection:
                self._scheduler.release(
                    connection,
                    reservation.id,
                    work_id,
                    reservation.owner_id,
                    attempt=reservation.attempt,
                    fence_token=reservation.fence_token,
                    outcome=ReleaseOutcome.CANCELLED,
                )
                self.store._release_scope(
                    connection,
                    claim.id,
                    operation_id,
                    attempt=claim.attempt,
                    fence_token=claim.fence_token,
                )
                now = _utc_now()
                connection.execute(
                    """UPDATE operations SET state = 'failed', updated_at = ?,
                              finished_at = ?
                       WHERE id = ? AND state = 'pending'""",
                    (now, now, operation_id),
                )
                result = gui_result("rejected")
                connection.execute(
                    """UPDATE gui_task_submissions
                       SET state = 'completed', outcome_json = ?, completed_at = ?
                       WHERE submission_key = ? AND state = 'prepared'""",
                    (_json(result), now, dispatch_id),
                )
            return result
        result = transport_result(transport)
        state = str(result["state"])
        if state in {"busy", "rejected"}:
            with self.store._daemon_transaction(self._authority) as connection:
                if state == "busy":
                    self._scheduler.cancel_queued(
                        connection,
                        work_id,
                        idempotency_key=_submission_identifier(
                            submission_id, f"cancel-{generation}"
                        ),
                    )
                self.store._release_scope(
                    connection,
                    claim.id,
                    operation_id,
                    attempt=claim.attempt,
                    fence_token=claim.fence_token,
                )
                now = _utc_now()
                connection.execute(
                    "UPDATE operations SET state = 'failed', updated_at = ?, finished_at = ? WHERE id = ? AND state = 'pending'",
                    (now, now, operation_id),
                )
        with self.store._daemon_transaction(self._authority) as connection:
            connection.execute(
                """UPDATE gui_task_submissions
                   SET state = 'completed', outcome_json = ?, completed_at = ?
                   WHERE submission_key = ? AND state = 'prepared'""",
                (_json(result), _utc_now(), dispatch_id),
            )
        return result

    def _dispatch_transport_durable(
        self,
        capability: object,
        idempotency_id: str,
        fingerprint: str,
        params: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Commit send intent before leaving SQLite for the adapter call."""
        rejected: OperationRejected | None = None
        result: Mapping[str, Any] | None = None
        capacity_reserved = False
        try:
            basic_fields = {"work_id", "pool", "payload"}
            binding_fields = {
                "reservation_id",
                "reservation_attempt",
                "reservation_fence",
            }
            allowed_shapes = {
                frozenset(basic_fields),
                frozenset(basic_fields | binding_fields),
                frozenset(basic_fields | {"return_route"}),
                frozenset(basic_fields | binding_fields | {"return_route"}),
            }
            if frozenset(params) not in allowed_shapes:
                raise OperationRejected(
                    "invalid_params", "operation parameters do not match schema"
                )
            if not isinstance(params["payload"], Mapping):
                raise OperationRejected("invalid_params", "payload must be an object")
            try:
                local_codex_thread_id = parse_local_codex_return_route(
                    params.get("return_route")
                )
            except (TypeError, ValueError) as error:
                raise OperationRejected(
                    "invalid_params", "return_route is invalid"
                ) from error
            try:
                pool = Lane(params["pool"])
            except (TypeError, ValueError) as error:
                raise OperationRejected("invalid_params", "pool is invalid") from error
            with self.store._daemon_transaction(self._authority) as connection:
                connection.row_factory = sqlite3.Row
                existing = connection.execute(
                    """SELECT fingerprint, ok, outcome_json
                       FROM daemon_request_outcomes WHERE idempotency_id = ?""",
                    (idempotency_id,),
                ).fetchone()
                if existing is not None:
                    if existing[0] != fingerprint:
                        raise OperationRejected(
                            "idempotency_conflict",
                            "idempotency ID was reused for a different request",
                        )
                    outcome = json.loads(existing[2])
                    if bool(existing[1]):
                        return outcome
                    raise OperationRejected(outcome["code"], outcome["message"])
                durable_transport = self._transport.lookup_idempotent(
                    capability,
                    connection,
                    idempotency_id,
                    fingerprint,
                )
                reservation = connection.execute(
                    """SELECT fingerprint FROM daemon_outcome_reservations
                       WHERE idempotency_id = ?""",
                    (idempotency_id,),
                ).fetchone()
                if reservation is not None and reservation[0] != fingerprint:
                    raise OperationRejected(
                        "idempotency_conflict",
                        "idempotency ID was reused for a different request",
                    )
                if durable_transport is None and reservation is None:
                    count = connection.execute(
                        """SELECT
                               (SELECT count(*) FROM daemon_request_outcomes) +
                               (SELECT count(*) FROM daemon_outcome_reservations)"""
                    ).fetchone()
                    assert count is not None
                    if int(count[0]) >= self.max_idempotency_entries:
                        raise OperationRejected(
                            "idempotency_capacity", "idempotency capacity is exhausted"
                        )
                    connection.execute(
                        """INSERT INTO daemon_outcome_reservations(
                               idempotency_id, fingerprint, operation, created_at
                           ) VALUES (?, ?, 'transport.dispatch.v1', ?)""",
                        (idempotency_id, fingerprint, _utc_now()),
                    )
                    capacity_reserved = True
                elif reservation is not None:
                    capacity_reserved = True
            receipt = _dispatch_transport(
                self._transport,
                capability,
                idempotency_key=idempotency_id,
                fingerprint=fingerprint,
                work_id=params["work_id"],
                pool=pool,
                payload=params["payload"],
                reservation_id=params.get("reservation_id"),
                reservation_attempt=params.get("reservation_attempt"),
                reservation_fence=params.get("reservation_fence"),
                local_codex_thread_id=local_codex_thread_id,
            )
            self._release_terminal_dispatch(capability, receipt)
            result = self._transport_result(receipt)
        except OperationRejected as error:
            rejected = error
        except IdempotencyConflict as error:
            rejected = OperationRejected("idempotency_conflict", str(error))
        except OwnershipConflict as error:
            rejected = OperationRejected("ownership_conflict", str(error))
        except (TypeError, ValueError) as error:
            rejected = OperationRejected("invalid_params", str(error))
        except sqlite3.IntegrityError:
            rejected = OperationRejected(
                "constraint_violation", "transport mutation was rejected"
            )
        outcome: Mapping[str, Any]
        if rejected is None:
            assert result is not None
            outcome = result
            ok = 1
        else:
            outcome = {"code": rejected.code, "message": str(rejected)}
            ok = 0
        with self.store._daemon_transaction(self._authority) as connection:
            prior = connection.execute(
                "SELECT fingerprint, ok, outcome_json FROM daemon_request_outcomes WHERE idempotency_id = ?",
                (idempotency_id,),
            ).fetchone()
            if prior is None:
                reservation = connection.execute(
                    """SELECT fingerprint FROM daemon_outcome_reservations
                       WHERE idempotency_id = ?""",
                    (idempotency_id,),
                ).fetchone()
                can_insert = False
                if reservation is not None:
                    if reservation[0] != fingerprint:
                        rejected = OperationRejected(
                            "idempotency_conflict",
                            "idempotency ID was reused for a different request",
                        )
                    else:
                        connection.execute(
                            "DELETE FROM daemon_outcome_reservations WHERE idempotency_id = ?",
                            (idempotency_id,),
                        )
                        can_insert = True
                elif not capacity_reserved:
                    count = connection.execute(
                        """SELECT
                               (SELECT count(*) FROM daemon_request_outcomes) +
                               (SELECT count(*) FROM daemon_outcome_reservations)"""
                    ).fetchone()
                    assert count is not None
                    can_insert = int(count[0]) < self.max_idempotency_entries
                if can_insert:
                    connection.execute(
                        """INSERT INTO daemon_request_outcomes(
                               idempotency_id, fingerprint, operation, ok,
                               outcome_json, completed_at
                           ) VALUES (?, ?, 'transport.dispatch.v1', ?, ?, ?)""",
                        (idempotency_id, fingerprint, ok, _json(outcome), _utc_now()),
                    )
            elif prior[0] != fingerprint:
                rejected = OperationRejected(
                    "idempotency_conflict",
                    "idempotency ID was reused for a different request",
                )
        if rejected is not None:
            raise rejected
        assert result is not None
        return result

    def _cancel_transport_durable(
        self,
        capability: object,
        idempotency_id: str,
        fingerprint: str,
        params: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Fence one exact live abort outside the SQLite transaction."""

        _exact(params, {"work_id", "pool"})
        try:
            pool = Lane(params["pool"])
        except (TypeError, ValueError) as error:
            raise OperationRejected("invalid_params", "pool is invalid") from error
        receipt: TransportReceipt | None = None
        release_outcome: ReleaseOutcome | None = None
        try:
            with self.store._daemon_transaction(self._authority) as connection:
                connection.row_factory = sqlite3.Row
                prior = connection.execute(
                    """SELECT fingerprint, ok, outcome_json
                       FROM daemon_request_outcomes WHERE idempotency_id = ?""",
                    (idempotency_id,),
                ).fetchone()
                if prior is not None:
                    if prior[0] != fingerprint:
                        raise OperationRejected(
                            "idempotency_conflict",
                            "idempotency ID was reused for a different request",
                        )
                    outcome = json.loads(prior[2])
                    if bool(prior[1]):
                        return outcome
                    raise OperationRejected(outcome["code"], outcome["message"])
                count = connection.execute(
                    "SELECT count(*) FROM daemon_request_outcomes"
                ).fetchone()
                assert count is not None
                if int(count[0]) >= self.max_idempotency_entries:
                    raise OperationRejected(
                        "idempotency_capacity", "idempotency capacity is exhausted"
                    )
                receipt = self._transport.status(
                    capability, connection, params["work_id"], pool
                )
                if receipt is not None and receipt.state in {
                    TransportState.RESERVED,
                    TransportState.PREPARED,
                }:
                    receipt = self._transport.cancel(
                        capability, connection, params["work_id"], pool
                    )
                if receipt is not None:
                    release_outcome = self._terminal_release_outcome(receipt)
                    if release_outcome is not None:
                        self._release_terminal_dispatch_in_transaction(
                            capability, connection, receipt, release_outcome
                        )
        except OwnershipConflict:
            if receipt is not None and release_outcome is not None:
                self._record_transport_release_attention(receipt, release_outcome)
            raise
        abort = None
        if receipt is not None and receipt.state in {
            TransportState.ACCEPTED,
            TransportState.DELIVERY_UNKNOWN,
        }:
            abort = self._transport.abort_external(
                capability, receipt.transport_id
            )
            if (
                abort is not None
                and abort.disposition.value == "cancelled"
            ):
                try:
                    with self.store._daemon_transaction(self._authority) as connection:
                        self._release_cancelled_abort_in_transaction(
                            capability, connection, receipt
                        )
                except OwnershipConflict:
                    self._record_transport_release_attention(
                        receipt, ReleaseOutcome.CANCELLED
                    )
                    raise
        result: dict[str, Any] = {
            "transport": self._transport_result(receipt) if receipt is not None else None,
            "abort": (
                None
                if abort is None
                else {
                    "disposition": abort.disposition.value,
                    "error_code": abort.error_code,
                }
            ),
        }
        with self.store._daemon_transaction(self._authority) as connection:
            connection.execute(
                """INSERT INTO daemon_request_outcomes(
                       idempotency_id, fingerprint, operation, ok,
                       outcome_json, completed_at
                   ) VALUES (?, ?, 'transport.cancel.v1', 1, ?, ?)""",
                (idempotency_id, fingerprint, _json(result), _utc_now()),
            )
        return result

    def _release_cancelled_abort_in_transaction(
        self,
        capability: object,
        connection: sqlite3.Connection,
        receipt: TransportReceipt,
    ) -> None:
        """Cancel an exact accepted dispatch after its adapter abort is durable."""

        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """SELECT delivery.assignment_id, delivery.owner_id,
                      delivery.assignment_attempt, delivery.assignment_fence,
                      delivery.scope_claim_id, delivery.scope_claim_attempt,
                      delivery.scope_claim_fence, assignment.state AS assignment_state,
                      assignment.release_outcome, work.state AS work_state,
                      claim.owner_operation_id, claim.state AS claim_state,
                      completion.state AS completion_state,
                      callback.state AS callback_state, route.id AS route_id,
                      route.state AS route_state,
                      opencode.transport_id AS opencode_transport_id,
                      opencode.lease_state AS opencode_lease_state,
                      opencode.abort_state AS opencode_abort_state,
                      opencode.abort_disposition AS opencode_abort_disposition,
                      opencode.abort_error_code AS opencode_abort_error_code
               FROM transport_deliveries AS delivery
               JOIN scheduler_assignments AS assignment
                 ON assignment.id = delivery.assignment_id
                AND assignment.work_id = delivery.work_id
               JOIN scheduler_work AS work ON work.id = delivery.work_id
               JOIN scope_claims AS claim ON claim.id = delivery.scope_claim_id
               JOIN transport_completion_registrations AS completion
                 ON completion.transport_id = delivery.id
               JOIN transport_callback_registrations AS callback
                 ON callback.transport_id = delivery.id
                AND callback.completion_registration_id = completion.id
               JOIN return_routes AS route ON route.transport_id = delivery.id
                AND route.completion_registration_id = completion.id
               LEFT JOIN opencode_deliveries AS opencode
                 ON opencode.transport_id = delivery.id
                AND opencode.work_id = delivery.work_id
               WHERE delivery.id = ? AND delivery.work_id = ?
                 AND delivery.pool = ?""",
            (receipt.transport_id, receipt.work_id, receipt.pool),
        ).fetchone()
        if row is None:
            raise OwnershipConflict(
                "cancelled abort lost its exact durable dispatch authority"
            )
        already_released = row["assignment_state"] == "released"
        if already_released:
            if (
                row["release_outcome"] != ReleaseOutcome.CANCELLED.value
                or row["work_state"] != "cancelled"
                or row["claim_state"] != "released"
            ):
                raise OwnershipConflict(
                    "cancelled abort conflicts with an existing terminal outcome"
                )
            if (
                row["completion_state"] == "cancelled"
                and row["callback_state"] == "cancelled"
                and row["route_state"] == "cancelled"
                and (
                    row["opencode_transport_id"] is None
                    or row["opencode_lease_state"] == "released"
                )
            ):
                return
        elif (
            row["assignment_state"] != "active"
            or row["work_state"] != "assigned"
            or row["claim_state"] != "active"
        ):
            raise OwnershipConflict(
                "cancelled abort cannot release non-active completion authority"
            )
        if (
            row["completion_state"] != "pending"
            or row["callback_state"] != "pending"
            or row["route_state"] not in {"registered", "ready"}
        ):
            raise OwnershipConflict(
                "cancelled abort conflicts with completion route state"
            )
        active_cancel = (
            row["opencode_lease_state"] == "aborting"
            and row["opencode_abort_state"] == "terminal"
            and row["opencode_abort_disposition"] == "cancelled"
            and row["opencode_abort_error_code"] is not None
        )
        legacy_cancel = (
            already_released
            and row["opencode_lease_state"] == "active"
            and row["opencode_abort_state"] == "terminal"
            and row["opencode_abort_disposition"] == "definite_failed"
            and row["opencode_abort_error_code"] == "abort_backend_not_active"
        )
        if (
            row["opencode_transport_id"] is not None
            and row["opencode_lease_state"] != "released"
            and not (active_cancel or legacy_cancel)
        ):
            raise OwnershipConflict(
                "cancelled abort lacks durable OpenCode release authority"
            )
        now = _utc_now()
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
            """UPDATE return_routes SET state = 'cancelled', cancelled_at_us = ?
               WHERE id = ? AND state IN ('registered','ready')""",
            (self._completion._clock(), row["route_id"]),
        )
        if not already_released:
            if not self._scheduler.release(
                connection,
                str(row["assignment_id"]),
                receipt.work_id,
                str(row["owner_id"]),
                attempt=int(row["assignment_attempt"]),
                fence_token=str(row["assignment_fence"]),
                outcome=ReleaseOutcome.CANCELLED,
            ):
                raise OwnershipConflict(
                    "cancelled abort could not release its exact assignment"
                )
            if not self.store._release_scope(
                connection,
                str(row["scope_claim_id"]),
                str(row["owner_operation_id"]),
                attempt=int(row["scope_claim_attempt"]),
                fence_token=str(row["scope_claim_fence"]),
            ):
                raise OwnershipConflict(
                    "cancelled abort could not release its exact scope claim"
                )
        if (
            row["opencode_transport_id"] is not None
            and row["opencode_lease_state"] != "released"
        ):
            cursor = connection.execute(
                """UPDATE opencode_deliveries SET lease_state = 'released', updated_at = ?
                   WHERE transport_id = ? AND lease_state IN ('active','aborting')
                     AND abort_state = 'terminal'""",
                (now, receipt.transport_id),
            )
            if cursor.rowcount != 1:
                raise OwnershipConflict(
                    "cancelled abort could not release its OpenCode lease"
                )
        self.store._append_event(
            connection,
            "return_route",
            str(row["route_id"]),
            "completion.route.cancelled",
            {"reason": "transport_abort_cancelled"},
            now,
        )
        self.store._append_event(
            connection,
            "transport",
            receipt.transport_id,
            "transport.abort.cancelled",
            {"work_id": receipt.work_id},
            now,
        )
        self._completion.refresh_work(capability, connection, receipt.work_id)

    @staticmethod
    def _transport_result(receipt: TransportReceipt) -> Mapping[str, Any]:
        return {
            "transport_id": receipt.transport_id,
            "work_id": receipt.work_id,
            "pool": receipt.pool,
            "state": receipt.state.value,
            "attempt": receipt.attempt,
            "completion_registration_id": receipt.completion_registration_id,
            "callback_registration_id": receipt.callback_registration_id,
            "acknowledgement_id": receipt.acknowledgement_id,
            "error_code": receipt.error_code,
        }

    def _release_terminal_dispatch(
        self,
        capability: object,
        receipt: TransportReceipt,
    ) -> None:
        release_outcome = self._terminal_release_outcome(receipt)
        if release_outcome is None:
            return
        try:
            with self.store._daemon_transaction(self._authority) as connection:
                self._release_terminal_dispatch_in_transaction(
                    capability, connection, receipt, release_outcome
                )
        except OwnershipConflict:
            self._record_transport_release_attention(receipt, release_outcome)
            raise

    @staticmethod
    def _terminal_release_outcome(
        receipt: TransportReceipt,
    ) -> ReleaseOutcome | None:
        release_outcome: ReleaseOutcome | None = None
        if receipt.state is TransportState.DEFINITE_FAILED:
            release_outcome = (
                ReleaseOutcome.REQUEUED
                if receipt.error_code == "no_capacity"
                else ReleaseOutcome.CANCELLED
            )
        elif receipt.state is TransportState.CANCELLED:
            release_outcome = ReleaseOutcome.CANCELLED
        return release_outcome

    def _release_terminal_dispatch_in_transaction(
        self,
        capability: object,
        connection: sqlite3.Connection,
        receipt: TransportReceipt,
        release_outcome: ReleaseOutcome,
    ) -> None:
        assignment = connection.execute(
            """SELECT assignment.id, assignment.owner_id,
                      assignment.attempt, assignment.fence_token
               FROM transport_deliveries AS delivery
               JOIN scheduler_assignments AS assignment
                 ON assignment.id = delivery.assignment_id
               WHERE delivery.id = ? AND delivery.work_id = ?""",
            (receipt.transport_id, receipt.work_id),
        ).fetchone()
        if assignment is None or not self._scheduler.release(
            connection,
            str(assignment[0]),
            receipt.work_id,
            str(assignment[1]),
            attempt=int(assignment[2]),
            fence_token=str(assignment[3]),
            outcome=release_outcome,
        ):
            raise OwnershipConflict(
                "terminal dispatch could not release its exact assignment"
            )
        self._completion.refresh_work(capability, connection, receipt.work_id)

    def _record_transport_release_attention(
        self,
        receipt: TransportReceipt,
        release_outcome: ReleaseOutcome,
    ) -> None:
        with self.store._daemon_transaction(self._authority) as connection:
            authority = connection.execute(
                """SELECT assignment_attempt FROM transport_deliveries
                   WHERE id = ? AND work_id = ?""",
                (receipt.transport_id, receipt.work_id),
            ).fetchone()
            if authority is None:
                raise OwnershipConflict(
                    "transport release attention lacks delivery authority"
                )
            generation = int(authority[0])
            payload = {
                "transport_id": receipt.transport_id,
                "work_id": receipt.work_id,
                "generation": generation,
                "state": receipt.state.value,
                "reason": "ownership_conflict",
                "release_outcome": release_outcome.value,
            }
            event_id = "transport-release-attention-" + uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{receipt.transport_id}:{generation}:{release_outcome.value}",
            ).hex
            existing = connection.execute(
                """SELECT aggregate_type, aggregate_id, event_type, payload_json
                   FROM events WHERE event_id = ?""",
                (event_id,),
            ).fetchone()
            expected = (
                "transport_release_attention",
                receipt.transport_id,
                "transport.release_ownership_conflict",
                _json(payload),
            )
            if existing is not None:
                if tuple(existing) != expected:
                    raise OwnershipConflict(
                        "transport release attention authority changed"
                    )
                return
            self.store._append_event(
                connection,
                expected[0],
                expected[1],
                expected[2],
                payload,
                _utc_now(),
                event_id=event_id,
            )

    def _prepare_admission(
        self,
        operation: str,
        params: Mapping[str, Any],
    ) -> _AdmissionEvidence | None:
        if operation != "scheduler.admit.v1":
            return None
        _exact(
            params,
            {
                "work_id",
                "claim_id",
                "repository",
                "scope",
                "content",
                "dispatch_kind",
                "trust",
                "classification",
                "risk_categories",
            },
        )
        return _evaluate_admission(
            self._authority,
            AdmissionRequest(
                repository=params["repository"],
                scope=params["scope"],
                content=params["content"],
                dispatch_kind=params["dispatch_kind"],
                trust=params["trust"],
                classification=params["classification"],
                risk_categories=params["risk_categories"],
            )
        )

    @staticmethod
    def _prepare_scope(
        operation: str,
        params: Mapping[str, Any],
    ) -> ScopeInspection | None:
        if operation != "scope.claim.v1":
            return None
        _exact(params, {"owner_operation_id", "repository", "scope"})
        inspected = inspect_scope(params["repository"], params["scope"])
        if not inspected.accepted:
            raise OperationRejected("invalid_scope", "scope failed policy inspection")
        return inspected

    def _execute(
        self,
        capability: object,
        connection: sqlite3.Connection,
        operation: str,
        params: Mapping[str, Any],
        *,
        idempotency_id: str,
        admission: _AdmissionEvidence | None,
        prepared_scope: ScopeInspection | None,
    ) -> Mapping[str, Any]:
        if operation == "health.v1":
            _exact(params, set())
            backend = getattr(self, "_backend_status", lambda: None)()
            configured = isinstance(backend, Mapping) and backend.get("configured") is True
            healthy = not configured or backend.get("healthy") is True
            return {
                "status": "ok" if healthy else "degraded",
                "controller": "sqlite",
                "external_dependencies": configured,
                "opencode": {
                    "configured": configured,
                    "monitor": "healthy" if healthy else "degraded",
                    "reason": None if healthy else backend.get("reason"),
                },
            }
        if operation == "version.v1":
            _exact(params, set())
            return {"rig_version": __version__, "protocol_version": PROTOCOL_VERSION}
        if operation == "scheduler.snapshot.v1":
            _exact(params, set())
            normalized = _json_safe(self._scheduler.snapshot())
            assert isinstance(normalized, Mapping)
            return {"snapshot": normalized}
        if operation == "llm.behaviour.apply.v1":
            _exact(params, {"model", "effort"})
            try:
                return apply_llm_selection(
                    connection,
                    model=params["model"],
                    effort=params["effort"],
                    idempotency_id=idempotency_id,
                )
            except LlmBehaviourInvalid as error:
                raise OperationRejected("invalid_params", str(error)) from error
            except LlmBehaviourBusy as error:
                raise OperationRejected("scheduler_busy", str(error)) from error
            except LlmBehaviourConflict as error:
                raise OperationRejected("ownership_conflict", str(error)) from error
        if operation == "operation.create.v1":
            _exact(params, {"operation_id", "kind"})
            _identifier(params["operation_id"], "operation_id")
            try:
                kind = OperationKind(params["kind"])
            except (TypeError, ValueError) as error:
                raise OperationRejected("invalid_params", "operation kind is invalid") from error
            self.store._create_operation(
                connection,
                params["operation_id"],
                kind,
                idempotency_key=idempotency_id,
                controller_run_id=None,
                now=_utc_now(),
            )
            return {"operation_id": params["operation_id"], "kind": kind.value}
        if operation == "submission.reject.v1":
            _exact(params, {"operation_id", "claim_id", "owner_id", "attempt", "fence_token"})
            for field in ("operation_id", "claim_id", "owner_id", "fence_token"):
                _identifier(params[field], field)
            row = connection.execute(
                """SELECT operation.state, claim.state, claim.owner_operation_id,
                          claim.attempt, claim.fence_token
                   FROM operations AS operation JOIN scope_claims AS claim
                     ON claim.id = ?
                   WHERE operation.id = ?""",
                (params["claim_id"], params["operation_id"]),
            ).fetchone()
            exact = row is not None and tuple(row[2:]) == (
                params["owner_id"], params["attempt"], params["fence_token"]
            ) and params["owner_id"] == params["operation_id"]
            if not exact or (row[0], row[1]) not in {
                (OperationState.PENDING.value, "active"),
                (OperationState.FAILED.value, "released"),
            }:
                raise OperationRejected("invalid_claim", "submission rejection fence mismatch")
            if row[0] == OperationState.PENDING.value:
                if not self.store._release_scope(
                    connection, params["claim_id"], params["owner_id"],
                    attempt=params["attempt"], fence_token=params["fence_token"],
                ):
                    raise OperationRejected("invalid_claim", "submission claim release failed")
                now = _utc_now()
                connection.execute(
                    """UPDATE operations
                       SET state = 'failed', updated_at = ?, finished_at = ?
                       WHERE id = ? AND state = 'pending'""",
                    (now, now, params["operation_id"]),
                )
                self.store._append_event(
                    connection,
                    "operation",
                    params["operation_id"],
                    "operation.state_changed",
                    {"from": "pending", "to": "failed"},
                    now,
                )
            return {
                "operation_id": params["operation_id"],
                "claim_id": params["claim_id"],
                "operation_state": "failed",
                "claim_state": "released",
            }
        if operation == "scope.claim.v1":
            assert prepared_scope is not None
            assert prepared_scope.repository is not None
            scope_key = _scope_digest(
                str(prepared_scope.repository),
                tuple(path.relative for path in prepared_scope.paths),
            )
            prior = connection.execute(
                "SELECT coalesce(max(attempt), 0) FROM scope_claims WHERE scope_key = ?",
                (scope_key,),
            ).fetchone()
            assert prior is not None
            receipt = self.store._claim_scope(
                connection,
                f"claim-{uuid.uuid4().hex}",
                scope_key,
                params["owner_operation_id"],
                attempt=int(prior[0]) + 1,
                fence_token=f"scope-fence-{uuid.uuid4().hex}",
                idempotency_key=idempotency_id,
            )
            return {
                "claim_id": receipt.id,
                "scope_hash": scope_key,
                "repository": str(prepared_scope.repository),
                "scope": [path.relative for path in prepared_scope.paths],
                "owner_id": receipt.owner_id,
                "attempt": receipt.attempt,
                "fence_token": receipt.fence_token,
            }
        if operation == "scope.release.v1":
            _exact(params, {"claim_id", "owner_id", "attempt", "fence_token"})
            released = self.store._release_scope(
                connection,
                params["claim_id"],
                params["owner_id"],
                attempt=params["attempt"],
                fence_token=params["fence_token"],
            )
            if released:
                work_rows = connection.execute(
                    "SELECT DISTINCT work_id FROM return_routes WHERE scope_claim_id = ?",
                    (params["claim_id"],),
                ).fetchall()
                for work_row in work_rows:
                    self._completion.refresh_work(capability, connection, str(work_row[0]))
            return {"released": released}
        if operation == "scheduler.enqueue.v1":
            _exact(params, {"work_id", "lane"})
            try:
                lane = Lane(params["lane"])
            except (TypeError, ValueError) as error:
                raise OperationRejected("invalid_params", "lane is invalid") from error
            sequence = self._scheduler.enqueue(
                connection,
                params["work_id"],
                lane,
                idempotency_key=idempotency_id,
            )
            return {"sequence": sequence}
        if operation == "scheduler.admit.v1":
            assert admission is not None
            allowed = self._scheduler.admit(
                connection,
                params["work_id"],
                decision_id=f"decision-{uuid.uuid4().hex}",
                claim_id=params["claim_id"],
                evidence=admission,
                idempotency_key=idempotency_id,
            )
            return {
                "allowed": allowed,
                "decision_hash": admission.decision_hash,
                "policy_version": admission.policy_version,
                "policy_hash": admission.policy_hash,
                "content_hash": admission.content_hash,
                "reason_codes": list(admission.reason_codes),
            }
        if operation == "scheduler.reserve.v1":
            if set(params) not in (set(), {"work_id"}):
                raise OperationRejected(
                    "invalid_params", "operation parameters do not match schema"
                )
            reservation = self._scheduler.reserve_next(
                connection,
                f"reservation-{uuid.uuid4().hex}",
                fence_token=f"fence-{uuid.uuid4().hex}",
                work_id=params.get("work_id"),
            )
            return {"reservation": _json_safe(reservation)}
        if operation == "scheduler.release.v1":
            _exact(
                params,
                {"reservation_id", "work_id", "owner_id", "attempt", "fence_token", "outcome"},
            )
            try:
                outcome = ReleaseOutcome(params["outcome"])
            except (TypeError, ValueError) as error:
                raise OperationRejected("invalid_params", "outcome is invalid") from error
            released = self._scheduler.release(
                connection,
                params["reservation_id"],
                params["work_id"],
                params["owner_id"],
                attempt=params["attempt"],
                fence_token=params["fence_token"],
                outcome=outcome,
            )
            if released:
                self._completion.refresh_work(
                    capability, connection, params["work_id"]
                )
            return {"released": released}
        if operation == "scheduler.cancel.v1":
            _exact(params, {"work_id"})
            cancelled = self._scheduler.cancel_queued(
                connection,
                params["work_id"],
                idempotency_key=idempotency_id,
            )
            return {"cancelled": cancelled}
        if operation == "codex.source.route.commit.v1":
            _exact(params, {"thread_id", "message_id"})
            thread_id = params["thread_id"]
            _identifier(thread_id, "thread_id")
            message_id = _uuid4(params["message_id"])
            if idempotency_id != message_id:
                raise OperationRejected(
                    "idempotency_conflict",
                    "source route idempotency must equal its message ID",
                )
            route_id = "codex-route-" + message_id
            connection.execute(
                """INSERT INTO codex_source_routes(
                       route_id, message_id, thread_id, state, idempotency_id, created_at
                   ) VALUES(?, ?, ?, 'committed', ?, ?)""",
                (route_id, message_id, thread_id, idempotency_id, _utc_now()),
            )
            return {
                "message_id": message_id,
                "route_id": route_id,
                "state": "committed",
                "thread_id": thread_id,
            }
        if operation == "worker.compose.v1":
            _exact(
                params,
                {"slot_id", "work_id", "generation", "session_id", "text"},
            )
            _uuid4(idempotency_id)
            text = _composer_text(params["text"])
            binding = self._active_worker_binding(
                capability,
                slot_id=params["slot_id"],
                work_id=params["work_id"],
                generation=params["generation"],
                session_id=params["session_id"],
                connection=connection,
            )
            if binding["delivery_state"] != "accepted":
                raise OperationRejected(
                    "delivery_uncertain",
                    "worker cannot accept another message while delivery is uncertain",
                )
            item_id = "message-" + idempotency_id.replace("-", "")
            try:
                self._opencode_client().prompt_async(
                    str(binding["session_id"]),
                    {
                        "agent": binding["worker"],
                        "messageID": item_id,
                        "parts": [{"type": "text", "text": text}],
                    },
                    idempotency_key=idempotency_id,
                )
                state = "accepted"
                reason = None
            except OpenCodeClientError as error:
                state = "uncertain" if error.delivery_unknown else "rejected"
                reason = error.code
            return {
                "thread_id": binding["session_id"],
                "slot_id": binding["slot_id"],
                "work_id": binding["work_id"],
                "generation": binding["generation"],
                "item_id": item_id,
                "state": state,
                "queued_at": _utc_now(),
                "reason": reason,
            }
        if operation == "transport.status.v1":
            _exact(params, {"work_id", "pool"})
            try:
                pool = Lane(params["pool"])
            except (TypeError, ValueError) as error:
                raise OperationRejected("invalid_params", "pool is invalid") from error
            connection.row_factory = sqlite3.Row
            receipt = self._transport.status(
                capability, connection, params["work_id"], pool
            )
            return {
                "transport": self._transport_result(receipt) if receipt is not None else None
            }
        if operation == "transport.reconcilecancelled.v1":
            _exact(params, {"work_id", "pool"})
            try:
                pool = Lane(params["pool"])
            except (TypeError, ValueError) as error:
                raise OperationRejected("invalid_params", "pool is invalid") from error
            connection.row_factory = sqlite3.Row
            receipt = self._transport.status(
                capability, connection, params["work_id"], pool
            )
            if receipt is None or receipt.state not in {
                TransportState.ACCEPTED,
                TransportState.DELIVERY_UNKNOWN,
            }:
                raise OperationRejected(
                    "invalid_state",
                    "operator cancellation reconciliation requires an accepted transport",
                )
            authority = connection.execute(
                """SELECT assignment.state AS assignment_state,
                          assignment.release_outcome, work.state AS work_state,
                          claim.state AS claim_state, opencode.lease_state,
                          opencode.abort_state, opencode.abort_disposition,
                          opencode.abort_error_code
                   FROM transport_deliveries AS delivery
                   JOIN scheduler_assignments AS assignment
                     ON assignment.id = delivery.assignment_id
                   JOIN scheduler_work AS work ON work.id = delivery.work_id
                   JOIN scope_claims AS claim ON claim.id = delivery.scope_claim_id
                   JOIN opencode_deliveries AS opencode
                     ON opencode.transport_id = delivery.id
                    AND opencode.work_id = delivery.work_id
                   WHERE delivery.id = ? AND delivery.work_id = ?
                     AND delivery.pool = ?""",
                (receipt.transport_id, receipt.work_id, receipt.pool),
            ).fetchone()
            active_authority = authority is not None and (
                authority["assignment_state"] == "active"
                and authority["release_outcome"] is None
                and authority["work_state"] == "assigned"
                and authority["claim_state"] == "active"
            )
            released_authority = authority is not None and (
                authority["assignment_state"] == "released"
                and authority["release_outcome"] == ReleaseOutcome.CANCELLED.value
                and authority["work_state"] == "cancelled"
                and authority["claim_state"] == "released"
            )
            if not active_authority and not released_authority:
                raise OperationRejected(
                    "ownership_conflict",
                    "operator cancellation lacks exact active or cancelled authority",
                )
            if authority["lease_state"] == "released" and released_authority:
                pass
            elif (
                authority["lease_state"] == "aborting"
                and authority["abort_state"] == "in_flight"
                and authority["abort_disposition"] is None
                and authority["abort_error_code"] is None
            ):
                now = _utc_now()
                cursor = connection.execute(
                    """UPDATE opencode_deliveries
                       SET abort_state = 'terminal',
                           abort_disposition = 'cancelled',
                           abort_error_code = 'operator_cancelled_after_idle_snapshot',
                           abort_finished_at = ?, updated_at = ?
                       WHERE transport_id = ? AND lease_state = 'aborting'
                         AND abort_state = 'in_flight'""",
                    (now, now, receipt.transport_id),
                )
                if cursor.rowcount != 1:
                    raise OperationRejected(
                        "ownership_conflict",
                        "operator cancellation abort authority changed",
                    )
            elif (
                released_authority
                and authority["lease_state"] == "active"
                and authority["abort_state"] == "terminal"
                and authority["abort_disposition"] == "definite_failed"
                and authority["abort_error_code"] == "abort_backend_not_active"
            ):
                cursor = connection.execute(
                    """UPDATE opencode_deliveries
                       SET lease_state = 'released', updated_at = ?
                       WHERE transport_id = ? AND lease_state = 'active'
                         AND abort_state = 'terminal'
                         AND abort_disposition = 'definite_failed'
                         AND abort_error_code = 'abort_backend_not_active'""",
                    (_utc_now(), receipt.transport_id),
                )
                if cursor.rowcount != 1:
                    raise OperationRejected(
                        "ownership_conflict",
                        "operator cancellation legacy abort authority changed",
                    )
            else:
                raise OperationRejected(
                    "invalid_state",
                    "operator cancellation transport is not safely reconcilable",
                )
            self._release_cancelled_abort_in_transaction(
                capability, connection, receipt
            )
            return {
                "reconciled": True,
                "transport": self._transport_result(receipt),
            }
        if operation == "transport.cancel.v1":
            _exact(params, {"work_id", "pool"})
            try:
                pool = Lane(params["pool"])
            except (TypeError, ValueError) as error:
                raise OperationRejected("invalid_params", "pool is invalid") from error
            connection.row_factory = sqlite3.Row
            receipt = self._transport.cancel(
                capability, connection, params["work_id"], pool
            )
            return {
                "transport": self._transport_result(receipt) if receipt is not None else None
            }
        if operation == "completion.accept.v1":
            _exact(
                params,
                {
                    "completion_key",
                    "registration_id",
                    "work_id",
                    "generation",
                    "outcome",
                },
            )
            try:
                outcome = CompletionOutcome(params["outcome"])
            except (TypeError, ValueError) as error:
                raise OperationRejected(
                    "invalid_params", "completion outcome is invalid"
                ) from error
            receipt = self._completion.accept(
                capability,
                connection,
                completion_key=params["completion_key"],
                registration_id=params["registration_id"],
                work_id=params["work_id"],
                generation=params["generation"],
                outcome=outcome,
            )
            self._recovery.evidence_for_work(
                capability,
                connection,
                work_id=params["work_id"],
                generation=params["generation"],
                evidence=RecoveryEvidence.COMPLETION,
            )
            normalized = _json_safe(receipt)
            assert isinstance(normalized, Mapping)
            return dict(normalized)
        if operation == "completion.result.v1":
            _exact(params, {"result_ref"})
            return self._completion.read_final_result(
                capability, connection, params["result_ref"]
            )
        if operation == "recovery.observe.v1":
            _exact(
                params,
                {
                    "target_id",
                    "work_id",
                    "generation",
                    "phase",
                    "productive",
                    "evidence",
                },
            )
            try:
                phase = RecoveryPhase(params["phase"])
                evidence = RecoveryEvidence(params["evidence"])
            except (TypeError, ValueError) as error:
                raise OperationRejected(
                    "invalid_params", "recovery observation is invalid"
                ) from error
            receipt = self._recovery.observe(
                capability,
                connection,
                target_id=params["target_id"],
                work_id=params["work_id"],
                generation=params["generation"],
                phase=phase,
                productive=params["productive"],
                evidence=evidence,
            )
            normalized = _json_safe(receipt)
            assert isinstance(normalized, Mapping)
            return dict(normalized)
        if operation == "recovery.timer.fire.v1":
            _exact(params, {"timer_id"})
            receipt = self._recovery.fire_timer(
                capability, connection, params["timer_id"]
            )
            normalized = _json_safe(receipt)
            assert isinstance(normalized, Mapping)
            return dict(normalized)
        if operation == "recovery.attempt.record.v1":
            _exact(
                params,
                {
                    "episode_id",
                    "attempt",
                    "result",
                    "failure_class",
                    "reason",
                },
            )
            try:
                recovery_result = RecoveryResult(params["result"])
                failure = (
                    None
                    if params["failure_class"] is None
                    else RecoveryFailureClass(params["failure_class"])
                )
            except (TypeError, ValueError) as error:
                raise OperationRejected(
                    "invalid_params", "recovery result classification is invalid"
                ) from error
            receipt = self._recovery.record_attempt(
                capability,
                connection,
                episode_id=params["episode_id"],
                attempt=params["attempt"],
                result=recovery_result,
                failure_class=failure,
                reason=params["reason"],
            )
            normalized = _json_safe(receipt)
            assert isinstance(normalized, Mapping)
            return dict(normalized)
        raise OperationRejected("unknown_operation", "operation is not recognized")
