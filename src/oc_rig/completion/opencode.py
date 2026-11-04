"""SSE-driven OpenCode completion join with final REST reconciliation."""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass
from threading import Event, RLock, Timer
from time import monotonic
from typing import Any, Callable, Mapping

from oc_rig.adapters.opencode import DispatchRegistration, _validated_status_types
from oc_rig.adapters.opencode_client import (
    MAX_SSE_RECONNECTS,
    OpenCodeClient,
    OpenCodeClientError,
    SSEEvent,
    SSEProtocolError,
    validate_identifier,
)
from oc_rig.completion.models import (
    MAX_FINAL_RESULT_BYTES,
    CompletionFinalResult,
    CompletionOutcome,
)


MAX_TRACKED_EVENT_IDS = 4096
MAX_READ_REPAIR_REGISTRATIONS = 11
# The backend endpoint is bounded to sixteen records. Authority remains the
# exact durable prompt parent; this larger window is not a latest-text rule.
MAX_COMPLETION_MESSAGE_WINDOW = 16
RECONNECT_DELAYS_SECONDS = (0.0, 0.25, 0.5, 1.0)
STABLE_CONNECTION_SECONDS = 1.0
MAX_FINAL_RESULT_PARTS = 256
IDLE_WITHOUT_TERMINAL_GRACE_SECONDS = 30.0
_NON_TEXT_PART_TYPES = frozenset({
    "agent", "compaction", "file", "patch", "reasoning", "retry", "snapshot",
    "step-finish", "step-start", "subtask", "tool",
})


@dataclass(frozen=True, slots=True)
class OpenCodeCompletion:
    completion_key: str
    transport_id: str
    registration_id: str
    callback_registration_id: str
    work_id: str
    session_id: str
    generation: int
    prompt_message_id: str
    outcome: CompletionOutcome | None
    assistant_message_id: str
    final_text: str | None

    def final_result(self, completion_generation: int) -> CompletionFinalResult:
        if type(completion_generation) is not int or completion_generation <= 0:
            raise ValueError("completion generation is invalid")
        if self.outcome is None:
            raise ValueError("child-barrier trigger is not a final result")
        return CompletionFinalResult(
            self.transport_id,
            self.work_id,
            self.registration_id,
            self.callback_registration_id,
            self.session_id,
            completion_generation,
            self.prompt_message_id,
            self.assistant_message_id,
            self.outcome,
            self.final_text,
        )


CompletionSink = Callable[[OpenCodeCompletion], None]
BarrierSink = Callable[[OpenCodeCompletion], None]
MissingSessionSink = Callable[[DispatchRegistration], None]
PresentSessionSink = Callable[[DispatchRegistration], None]
IdleStateSink = Callable[[DispatchRegistration, str], None]


@dataclass(slots=True)
class _Pending:
    registration: DispatchRegistration
    assistant_final: bool = False
    idle: bool = False
    delivered: bool = False
    missing_reported: bool = False
    idle_timer: Timer | None = None
    idle_token: object | None = None
    idle_reported: bool = False


class CompletionDeferred(RuntimeError):
    """A durable child barrier intentionally deferred root completion."""


def _installed_event(event: SSEEvent) -> tuple[str, Mapping[str, Any]]:
    """Decode the exact OpenCode 1.18.20 project-scoped ``/event`` payload.

    The installed server exposes two different streams: ``/event`` emits the
    event object directly for the server's bound project directory, while
    ``/global/event`` wraps events for multiple projects.  The client connects
    only to the scoped endpoint, so accepting the global wrapper here would
    discard the endpoint's directory boundary.
    """

    payload = event.json()
    if type(payload) is not dict:
        raise SSEProtocolError("backend_event_incompatible")
    standard = (
        set(payload) == {"id", "type", "properties"}
        and payload.get("type") != "sync"
        and type(payload.get("properties")) is dict
    )
    sync = (
        set(payload) == {"id", "type", "syncEvent"}
        and payload.get("type") == "sync"
        and type(payload.get("syncEvent")) is dict
    )
    if type(payload.get("type")) is not str or not (standard or sync):
        raise SSEProtocolError("backend_event_incompatible")
    try:
        event_id = validate_identifier(payload.get("id"), "event_id")
    except OpenCodeClientError:
        raise SSEProtocolError("backend_event_incompatible") from None
    return event_id, payload


def _session_id(properties: Mapping[str, Any]) -> str | None:
    value = properties.get("sessionID")
    return value if type(value) is str else None


def _session_info_id(properties: Mapping[str, Any]) -> str:
    if set(properties) not in ({"info"}, {"info", "sessionID"}):
        raise SSEProtocolError("backend_event_incompatible")
    info = properties.get("info")
    if type(info) is not dict:
        raise SSEProtocolError("backend_event_incompatible")
    try:
        session_id = validate_identifier(info.get("id"), "session_id")
        if "sessionID" in properties:
            outer = validate_identifier(properties.get("sessionID"), "session_id")
            if outer != session_id:
                raise SSEProtocolError("backend_event_incompatible")
    except OpenCodeClientError:
        raise SSEProtocolError("backend_event_incompatible") from None
    return session_id


def _status_type(properties: Mapping[str, Any]) -> str | None:
    value = properties.get("status")
    return value.get("type") if type(value) is dict else None


def _message_info(properties: Mapping[str, Any]) -> Mapping[str, Any] | None:
    info = properties.get("info")
    return info if type(info) is dict else None


def _validated_message_update(properties: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(properties) != {"info", "sessionID"}:
        raise SSEProtocolError("backend_event_incompatible")
    message = _message_info(properties)
    outer_session_id = _session_id(properties)
    inner_session_id = _session_id(message) if message is not None else None
    try:
        outer_session_id = validate_identifier(outer_session_id, "session_id")
        inner_session_id = validate_identifier(inner_session_id, "session_id")
        validate_identifier(
            message.get("id") if message is not None else None,
            "message_id",
        )
    except OpenCodeClientError:
        raise SSEProtocolError("backend_event_incompatible") from None
    if outer_session_id != inner_session_id or message is None:
        raise SSEProtocolError("backend_event_incompatible")
    role = message.get("role")
    if role not in {"user", "assistant"}:
        raise SSEProtocolError("backend_event_incompatible")
    if role == "assistant":
        try:
            validate_identifier(message.get("parentID"), "parent_message_id")
        except OpenCodeClientError:
            raise SSEProtocolError("backend_event_incompatible") from None
    return message


def _parent_id(message: Mapping[str, Any]) -> str | None:
    value = message.get("parentID")
    return value if type(value) is str else None


def _assistant_final(message: Mapping[str, Any]) -> bool:
    if message.get("role") != "assistant":
        return False
    time_value = message.get("time")
    return (
        type(time_value) is dict
        and type(time_value.get("completed")) in {int, float}
        and time_value["completed"] >= 0
    )


def _message_outcome(message: Mapping[str, Any]) -> CompletionOutcome | None:
    if message.get("error") is not None or message.get("finish") in {"error", "failed"}:
        return CompletionOutcome.FAILED
    if message.get("finish") in {"cancelled", "abort"}:
        return CompletionOutcome.CANCELLED
    if message.get("finish") == "stop":
        return CompletionOutcome.SUCCEEDED
    if message.get("finish") in {None, "tool-calls", "unknown"}:
        return None
    return CompletionOutcome.FAILED


def _latest_assistant_segment(
    messages: list[Mapping[str, Any]],
    registration: DispatchRegistration,
) -> Mapping[str, Any] | None:
    """Select the installed server's latest completed assistant generation.

    OpenCode 1.18.20 creates one assistant message per tool-loop generation;
    every generation remains a sibling of the original user prompt.  Its own
    latest-message comparison orders those siblings by ``time.created`` and
    then by message ID.  REST list order is not authority here because retries
    and test doubles may duplicate or reorder records.
    """

    unique: dict[str, Mapping[str, Any]] = {}
    order: dict[str, tuple[float, str]] = {}
    for item in messages:
        if set(item) != {"info", "parts"} or type(item.get("info")) is not dict:
            return None
        if type(item.get("parts")) is not list:
            return None
        message = item["info"]
        if (
            type(message) is not dict
            or message.get("role") != "assistant"
            or _parent_id(message) != registration.prompt_message_id
            or _session_id(message) != registration.session_id
            or not _assistant_final(message)
        ):
            continue
        time_value = message.get("time")
        created = time_value.get("created") if type(time_value) is dict else None
        if type(created) not in {int, float} or created < 0:
            return None
        try:
            message_id = validate_identifier(message.get("id"), "message_id")
        except OpenCodeClientError:
            return None
        existing = unique.get(message_id)
        if existing is not None:
            if existing != item:
                return None
            continue
        unique[message_id] = item
        order[message_id] = (created, message_id)
    if not unique:
        return None
    latest_id = max(order, key=order.__getitem__)
    return unique[latest_id]


def _terminal_text(segment: Mapping[str, Any]) -> str | None:
    info = segment["info"]
    parts = segment["parts"]
    if type(info) is not dict or type(parts) is not list or len(parts) > MAX_FINAL_RESULT_PARTS:
        raise SSEProtocolError("backend_message_parts_incompatible")
    text_parts: list[str] = []
    for part in parts:
        if type(part) is not dict or type(part.get("type")) is not str:
            raise SSEProtocolError("backend_message_parts_incompatible")
        part_type = part["type"]
        if part_type != "text":
            if part_type not in _NON_TEXT_PART_TYPES:
                raise SSEProtocolError("backend_message_parts_incompatible")
            continue
        if not {"type", "text"}.issubset(part) or not set(part).issubset({
            "id", "sessionID", "messageID", "type", "text", "synthetic",
            "ignored", "time", "metadata",
        }):
            raise SSEProtocolError("backend_message_parts_incompatible")
        text = part.get("text")
        if type(text) is not str:
            raise SSEProtocolError("backend_message_parts_incompatible")
        for field, expected in (
            ("sessionID", info.get("sessionID")),
            ("messageID", info.get("id")),
        ):
            if field in part and part[field] != expected:
                raise SSEProtocolError("backend_message_parts_incompatible")
        if "id" in part:
            try:
                validate_identifier(part["id"], "part_id")
            except OpenCodeClientError:
                raise SSEProtocolError("backend_message_parts_incompatible") from None
        if any(
            field in part and type(part[field]) is not bool
            for field in ("synthetic", "ignored")
        ) or (
            "time" in part and type(part["time"]) is not dict
        ) or (
            "metadata" in part and type(part["metadata"]) is not dict
        ):
            raise SSEProtocolError("backend_message_parts_incompatible")
        if part.get("synthetic") is True or part.get("ignored") is True:
            continue
        text_parts.append(text)
    text = "".join(text_parts)
    if not text:
        return None
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError:
        raise SSEProtocolError("backend_message_text_invalid") from None
    if (
        len(encoded) > MAX_FINAL_RESULT_BYTES
        or "\x00" in text
        or any(ord(character) < 0x20 and character not in "\t\n\r" for character in text)
    ):
        raise SSEProtocolError("backend_message_text_invalid")
    return text


def _todos_clear(todos: list[Mapping[str, Any]]) -> bool:
    return all(item.get("status") in {"completed", "cancelled"} for item in todos)


def _completion_status_types(statuses: Mapping[str, Any]) -> dict[str, str]:
    try:
        return _validated_status_types(statuses)
    except OpenCodeClientError:
        raise SSEProtocolError("backend_status_incompatible") from None


def _listed_session_ids(sessions: list[Mapping[str, Any]]) -> set[str]:
    session_ids = [item.get("id") for item in sessions]
    if any(type(session_id) is not str for session_id in session_ids):
        raise SSEProtocolError("backend_sessions_incompatible")
    if len(session_ids) != len(set(session_ids)):
        raise SSEProtocolError("backend_sessions_incompatible")
    return set(session_ids)


class OpenCodeCompletionMonitor:
    """Consume backend events; never poll for completion.

    Bounded REST read-repair occurs only at stream connection seams.  During a
    connected stream, REST reconciliation occurs only after the SSE stream has
    supplied both sides of the assistant-final/idle gate.  REST state is the
    final authority in either case.
    """

    __slots__ = (
        "client", "sink", "missing_sink", "present_sink", "barrier_sink",
        "idle_state_sink",
        "_pending", "_seen", "_seen_order", "_cursor", "_lock",
    )

    def __init__(
        self,
        client: OpenCodeClient,
        sink: CompletionSink,
        missing_sink: MissingSessionSink | None = None,
        present_sink: PresentSessionSink | None = None,
        barrier_sink: BarrierSink | None = None,
        idle_state_sink: IdleStateSink | None = None,
    ):
        if not isinstance(client, OpenCodeClient):
            raise TypeError("OpenCodeClient required")
        if not callable(sink):
            raise TypeError("completion sink required")
        if missing_sink is not None and not callable(missing_sink):
            raise TypeError("missing session sink must be callable")
        if present_sink is not None and not callable(present_sink):
            raise TypeError("present session sink must be callable")
        if barrier_sink is not None and not callable(barrier_sink):
            raise TypeError("child barrier sink must be callable")
        if idle_state_sink is not None and not callable(idle_state_sink):
            raise TypeError("idle state sink must be callable")
        self.client = client
        self.sink = sink
        self.missing_sink = missing_sink
        self.present_sink = present_sink
        self.barrier_sink = barrier_sink
        self.idle_state_sink = idle_state_sink
        self._pending: dict[str, _Pending] = {}
        self._seen: set[str] = set()
        self._seen_order: deque[str] = deque()
        self._cursor: str | None = None
        self._lock = RLock()

    @property
    def cursor(self) -> str | None:
        with self._lock:
            return self._cursor

    def register(self, registration: DispatchRegistration) -> None:
        with self._lock:
            self._register(registration)

    def _register(self, registration: DispatchRegistration) -> None:
        if not isinstance(registration, DispatchRegistration):
            raise TypeError("DispatchRegistration required")
        existing = self._pending.get(registration.prompt_message_id)
        if existing is not None:
            if existing.registration != registration:
                raise ValueError("completion_registration_conflict")
            return
        if sum(not item.delivered for item in self._pending.values()) >= MAX_READ_REPAIR_REGISTRATIONS:
            raise ValueError("completion_registration_limit")
        for pending in self._pending.values():
            if (
                not pending.delivered
                and pending.registration.session_id == registration.session_id
                and pending.registration.generation == registration.generation
                and pending.registration.prompt_message_id != registration.prompt_message_id
            ):
                raise ValueError("session_generation_already_registered")
        self._pending[registration.prompt_message_id] = _Pending(registration)

    def unregister(self, registration: DispatchRegistration) -> None:
        """Remove only the exact pre-send registration after a definite failure."""

        with self._lock:
            self._unregister(registration)

    def _unregister(self, registration: DispatchRegistration) -> None:

        if not isinstance(registration, DispatchRegistration):
            raise TypeError("DispatchRegistration required")
        pending = self._pending.get(registration.prompt_message_id)
        if pending is not None and not pending.delivered:
            if pending.registration != registration:
                raise ValueError("completion_registration_conflict")
            self._cancel_idle_grace(pending)
            del self._pending[registration.prompt_message_id]

    def consume(self, event: SSEEvent) -> None:
        with self._lock:
            self._consume(event)

    def _consume(self, event: SSEEvent) -> None:
        event_id, payload = _installed_event(event)
        if not self._accept_event_id(event_id):
            return
        event_type = payload.get("type")
        if event_type == "sync":
            return
        properties = payload["properties"]
        if event_type == "server.connected":
            if properties:
                raise SSEProtocolError("backend_event_incompatible")
            return
        if event_type == "session.idle":
            if set(properties) != {"sessionID"} or _session_id(properties) is None:
                raise SSEProtocolError("backend_event_incompatible")
            session_id = _session_id(properties)
            for pending in self._pending.values():
                registration = pending.registration
                if not pending.delivered and registration.session_id == session_id:
                    pending.idle = True
        elif event_type == "session.status":
            if (
                set(properties) != {"sessionID", "status"}
                or _session_id(properties) is None
                or _status_type(properties) not in {"idle", "busy", "retry"}
            ):
                raise SSEProtocolError("backend_event_incompatible")
            status = _status_type(properties)
            session_id = _session_id(properties)
            for pending in self._pending.values():
                registration = pending.registration
                if not pending.delivered and registration.session_id == session_id:
                    pending.idle = status == "idle"
                    if status != "idle":
                        self._cancel_idle_grace(pending, resumed=True)
        elif event_type == "message.updated":
            message = _validated_message_update(properties)
            if _assistant_final(message):
                parent_id = _parent_id(message)
                pending = self._pending.get(parent_id or "")
                if pending is not None and not pending.delivered:
                    registration = pending.registration
                    if (
                        _session_id(message) == registration.session_id
                        # The prompt ID is derived from and validated against the
                        # durable assignment generation before dispatch.
                        and parent_id == registration.prompt_message_id
                    ):
                        pending.assistant_final = True
        elif event_type == "session.deleted":
            session_id = _session_info_id(properties)
            for pending in self._pending.values():
                if not pending.delivered and pending.registration.session_id == session_id:
                    self._cancel_idle_grace(pending)
                    self._report_missing(pending)
        elif event_type in {"session.created", "session.updated"}:
            session_id = _session_info_id(properties)
            for pending in self._pending.values():
                if not pending.delivered and pending.registration.session_id == session_id:
                    self._report_present(pending)
        self._reconcile_ready()

    def _cancel_idle_grace(self, pending: _Pending, *, resumed: bool = False) -> None:
        timer, pending.idle_timer = pending.idle_timer, None
        pending.idle_token = None
        if timer is not None:
            timer.cancel()
        if resumed and pending.idle_reported:
            if self.idle_state_sink is not None:
                self.idle_state_sink(
                    pending.registration, "idle_progress_resumed"
                )
            pending.idle_reported = False

    def _arm_idle_grace(self, pending: _Pending) -> None:
        if (
            self.idle_state_sink is None
            or pending.delivered
            or not pending.idle
            or pending.idle_timer is not None
            or pending.idle_reported
        ):
            return
        token = object()
        timer = Timer(
            IDLE_WITHOUT_TERMINAL_GRACE_SECONDS,
            self._idle_grace_expired,
            args=(pending.registration, token),
        )
        timer.daemon = True
        pending.idle_token = token
        pending.idle_timer = timer
        timer.start()

    def _idle_grace_expired(
        self, registration: DispatchRegistration, token: object
    ) -> None:
        with self._lock:
            pending = self._pending.get(registration.prompt_message_id)
            if (
                pending is None
                or pending.registration != registration
                or pending.delivered
                or not pending.idle
                or pending.idle_token is not token
            ):
                return
            pending.idle_timer = None
            pending.idle_token = None
            session_ids = _listed_session_ids(self.client.list_sessions())
            if registration.session_id not in session_ids:
                self._report_missing(pending)
                return
            status_types = _completion_status_types(self.client.session_status())
            if status_types.get(registration.session_id, "idle") != "idle":
                pending.idle = False
                self._cancel_idle_grace(pending, resumed=True)
                return
            if not _todos_clear(self.client.todos(registration.session_id)):
                return
            unresolved = self._process_idle_pending(
                pending,
                session_ids=session_ids,
                status_types=status_types,
                arm_grace=False,
            )
            if (
                unresolved
                and self.idle_state_sink is not None
                and self._pending.get(registration.prompt_message_id) is pending
            ):
                self.idle_state_sink(registration, "idle_without_terminal")
                pending.idle_reported = True

    def close(self) -> None:
        """Cancel only this monitor's bounded idle deadlines."""

        with self._lock:
            for pending in self._pending.values():
                self._cancel_idle_grace(pending)

    def _report_missing(self, pending: _Pending) -> None:
        if pending.missing_reported:
            return
        if self.missing_sink is not None:
            self.missing_sink(pending.registration)
        pending.missing_reported = True

    def _report_present(self, pending: _Pending) -> None:
        if not pending.missing_reported:
            return
        if self.present_sink is not None:
            self.present_sink(pending.registration)
        pending.missing_reported = False

    def _accept_event_id(self, event_id: str) -> bool:
        if event_id in self._seen:
            return False
        self._seen.add(event_id)
        self._seen_order.append(event_id)
        while len(self._seen_order) > MAX_TRACKED_EVENT_IDS:
            self._seen.discard(self._seen_order.popleft())
        self._cursor = event_id
        return True

    def read_repair(self) -> None:
        """Bounded one-shot REST repair used only at stream connection seams."""

        with self._lock:
            self._read_repair()

    def _read_repair(self) -> None:
        pending = [item for item in self._pending.values() if not item.delivered]
        if len(pending) > MAX_READ_REPAIR_REGISTRATIONS:
            raise SSEProtocolError("completion_registration_limit")
        if not pending:
            return
        session_ids = _listed_session_ids(self.client.list_sessions())
        statuses = self.client.session_status()
        status_types = _completion_status_types(statuses)
        for item in pending:
            self._process_idle_pending(
                item,
                session_ids=session_ids,
                status_types=status_types,
            )

    def _reconcile_ready(self) -> None:
        ready = [
            item for item in self._pending.values()
            if not item.delivered and item.idle
        ]
        if not ready:
            return
        if len(ready) > MAX_READ_REPAIR_REGISTRATIONS:
            raise SSEProtocolError("completion_registration_limit")
        session_ids = _listed_session_ids(self.client.list_sessions())
        statuses = self.client.session_status()
        status_types = _completion_status_types(statuses)
        for pending in ready:
            self._process_idle_pending(
                pending,
                session_ids=session_ids,
                status_types=status_types,
            )

    def _process_idle_pending(
        self,
        pending: _Pending,
        *,
        session_ids: set[str],
        status_types: Mapping[str, str],
        arm_grace: bool = True,
    ) -> bool:
        """Reconcile one idle registration and report whether it is unresolved."""

        registration = pending.registration
        if registration.session_id not in session_ids:
            self._cancel_idle_grace(pending)
            self._report_missing(pending)
            return False
        self._report_present(pending)
        if status_types.get(registration.session_id, "idle") != "idle":
            pending.idle = False
            self._cancel_idle_grace(pending, resumed=True)
            return False
        pending.idle = True
        completion = self._reconcile(
            registration,
            session_ids=session_ids,
            status_types=status_types,
        )
        unresolved = completion is None
        if completion is not None:
            sink = self.barrier_sink if completion.outcome is None else self.sink
            if sink is None:
                unresolved = True
            else:
                try:
                    sink(completion)
                except CompletionDeferred as error:
                    unresolved = str(error) == "root_tool_calls_not_terminal"
                else:
                    self._cancel_idle_grace(pending)
                    pending.assistant_final = True
                    pending.delivered = True
                    self._pending.pop(registration.prompt_message_id, None)
                    return False
        if unresolved:
            if arm_grace:
                self._arm_idle_grace(pending)
            return True
        self._cancel_idle_grace(pending)
        return False

    def _reconcile(
        self,
        registration: DispatchRegistration,
        *,
        session_ids: set[str] | None = None,
        status_types: Mapping[str, str] | None = None,
    ) -> OpenCodeCompletion | None:
        session_ids = (
            session_ids
            if session_ids is not None
            else _listed_session_ids(self.client.list_sessions())
        )
        if registration.session_id not in session_ids:
            pending = self._pending.get(registration.prompt_message_id)
            if pending is not None:
                self._report_missing(pending)
            return None
        status_types = (
            status_types
            if status_types is not None
            else _completion_status_types(self.client.session_status())
        )
        if status_types.get(registration.session_id, "idle") != "idle":
            return None
        todos = self.client.todos(registration.session_id)
        if not _todos_clear(todos):
            return None
        terminal = _latest_assistant_segment(
                self.client.messages(
                    registration.session_id,
                    limit=MAX_COMPLETION_MESSAGE_WINDOW,
                ),
            registration,
        )
        if terminal is None:
            return None
        terminal_info = terminal["info"]
        outcome = _message_outcome(terminal_info)
        barrier_trigger = outcome is None and terminal_info.get("finish") == "tool-calls"
        if outcome is None and not barrier_trigger:
            return None
        if barrier_trigger:
            final_text = None
        else:
            try:
                final_text = _terminal_text(terminal)
            except SSEProtocolError as error:
                if error.code != "backend_message_text_invalid":
                    raise
                outcome = CompletionOutcome.FAILED
                final_text = None
        digest = hashlib.sha256(
            (
                f"{registration.completion_registration_id}:"
                f"{registration.session_id}:{registration.generation}:"
                f"{registration.prompt_message_id}"
            ).encode()
        ).hexdigest()
        return OpenCodeCompletion(
            completion_key=f"opencode-completion-{digest}",
            transport_id=registration.transport_id,
            registration_id=registration.completion_registration_id,
            callback_registration_id=registration.callback_registration_id,
            work_id=registration.work_id,
            session_id=registration.session_id,
            generation=registration.generation,
            prompt_message_id=registration.prompt_message_id,
            outcome=outcome,
            assistant_message_id=str(terminal_info["id"]),
            final_text=final_text,
        )

    def run(
        self,
        cancellation: Event,
        health_sink: Callable[[], None] | None = None,
    ) -> None:
        if health_sink is not None and not callable(health_sink):
            raise TypeError("health sink required")
        consecutive_failures = 0
        while not cancellation.is_set():
            delay = RECONNECT_DELAYS_SECONDS[
                min(consecutive_failures, len(RECONNECT_DELAYS_SECONDS) - 1)
            ]
            if delay and cancellation.wait(delay):
                return
            stream_started: float | None = None
            try:
                self.read_repair()
                if health_sink is not None:
                    health_sink()
                if cancellation.is_set():
                    return
                stream_started = monotonic()
                for event in self.client.event_stream(cancellation):
                    self.consume(event)
                    if cancellation.is_set():
                        return
            except SSEProtocolError:
                raise
            except OpenCodeClientError:
                if cancellation.is_set():
                    return
                stable = (
                    stream_started is not None
                    and monotonic() - stream_started >= STABLE_CONNECTION_SECONDS
                )
                consecutive_failures = 0 if stable else consecutive_failures + 1
                if consecutive_failures > MAX_SSE_RECONNECTS:
                    raise OpenCodeClientError("sse_retries_exhausted")
                continue
            if cancellation.is_set():
                return
            stable = (
                stream_started is not None
                and monotonic() - stream_started >= STABLE_CONNECTION_SECONDS
            )
            consecutive_failures = 0 if stable else consecutive_failures + 1
            if consecutive_failures > MAX_SSE_RECONNECTS:
                raise OpenCodeClientError("sse_retries_exhausted")
