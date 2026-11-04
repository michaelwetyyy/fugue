"""Fail-closed normalization for deterministic cockpit views."""

from __future__ import annotations

import unicodedata
import math
from collections.abc import Iterable, Mapping
from typing import Any


LANES = (
    ("tensorhost", "TensorHost", "⬢", 3),
    ("homelab", "Home Lab", "⌂", 3),
    ("personal", "Personal", "◇", 3),
    ("control", "Control", "◆", 3),
    ("hands-off", "Hands-off", "⛔", 1),
)
MAX_ITEMS = 64
MAX_INPUT_SCAN = 256
MAX_ERRORS = 64
MAX_TEXT = 160
SIGNED_64_MAX = 2**63 - 1
_TURN_FIELDS = {"turn_id", "ordinal", "state", "occurred_at", "token_count"}
_FORBIDDEN_TURN_FIELDS = {
    "content",
    "text",
    "message",
    "messages",
    "prompt",
    "output",
    "transcript",
}
_EXPLICIT_UNAVAILABLE_FIELDS = {
    "state",
    "registration_state",
    "route_state",
    "callback_state",
    "phase",
    "circuit_state",
    "episode_state",
    "timer_state",
}
_DIRECTIONAL_CONTROLS = {
    "\u061c",
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}


def safe_text(value: object, *, limit: int = MAX_TEXT) -> str:
    """Make untrusted labels inert while preserving ordinary Unicode."""
    if not isinstance(value, str):
        return "unavailable"
    output: list[str] = []
    for character in value:
        category = unicodedata.category(character)
        if (
            character in _DIRECTIONAL_CONTROLS
            or category in {"Cc", "Cs"}
            or character in {"\u2028", "\u2029"}
        ):
            output.append(f"\\u{ord(character):04x}")
        else:
            output.append(character)
        if sum(len(part) for part in output) >= limit:
            break
    result = "".join(output)
    if len(result) > limit:
        result = result[:limit]
    if len(value) > len(output):
        result = result[: max(0, limit - 1)] + "…"
    return result or "unavailable"


def _integer(value: object, default: int = 0) -> int:
    return (
        value
        if type(value) is int and 0 <= value <= SIGNED_64_MAX
        else default
    )


def _is_i64(value: object, *, nullable: bool = False) -> bool:
    return (nullable and value is None) or (
        type(value) is int and 0 <= value <= SIGNED_64_MAX
    )


def _is_text(value: object, *, nullable: bool = False) -> bool:
    return (nullable and value is None) or isinstance(value, str)


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _bounded_items(value: object) -> Iterable[object]:
    if isinstance(value, (str, bytes, bytearray, Mapping)) or not isinstance(
        value, Iterable
    ):
        return ()
    items: list[object] = []
    for index, item in enumerate(value):
        if index >= MAX_INPUT_SCAN:
            break
        items.append(item)
    return items


def _collection_item_fields(
    attention: str | None,
    item: Mapping[str, Any],
) -> tuple[tuple[str, ...], set[str]] | None:
    if attention == "automatic":
        return (
            (
                "kind", "id", "target_id", "work_id", "generation", "state",
                "reason", "attempts",
            ),
            {"generation", "attempts"},
        )
    if attention == "operator":
        if "scope" in item:
            if item.get("scope") != "controller":
                return None
            return (("kind", "id", "scope", "state", "reason"), set())
        return (
            ("kind", "id", "work_id", "generation", "state", "reason"),
            {"generation"},
        )
    return (
        (
            "work_id", "sequence", "queue_order", "lane", "state", "policy",
            "attempt", "enqueued_at",
        ),
        {"sequence", "queue_order", "attempt"},
    )


def _require_fields(
    value: object,
    fields: set[str],
    path: str,
    errors: list[str],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        errors.append(f"{path} must be an object")
        return {}
    missing = fields - set(value)
    if missing:
        errors.append(f"{path} missing: {','.join(sorted(missing))}")
    return value


def _component_schema(
    value: object,
    fields: set[str],
    path: str,
    errors: list[str],
) -> Mapping[str, Any]:
    component = _require_fields(value, {"status", *fields}, path, errors)
    if component and component.get("status") not in {
        "available",
        "unavailable",
        "disabled",
    }:
        errors.append(f"{path}.status is invalid")
    return component


def _collection_schema(
    value: object,
    path: str,
    errors: list[str],
    *,
    attention: str | None = None,
) -> None:
    section = _require_fields(
        value,
        {
            "status",
            "items",
            "total",
            "total_status",
            "lower_bound",
            "truncated",
        },
        path,
        errors,
    )
    if not section:
        return
    if section.get("status") not in {"available", "unavailable"}:
        errors.append(f"{path}.status is invalid")
    if not isinstance(section.get("items"), list):
        errors.append(f"{path}.items must be an array")
    if section.get("total_status") not in {"exact", "capped", "unknown"}:
        errors.append(f"{path}.total_status is invalid")
    total_status = section.get("total_status")
    total = section.get("total")
    if total_status == "exact" and not _is_i64(total):
        errors.append(f"{path}.total must be signed-64 for an exact total")
    if total_status != "exact" and total is not None:
        errors.append(f"{path}.total must be null unless exact")
    if not _is_i64(section.get("lower_bound")):
        errors.append(f"{path}.lower_bound is not signed-64")
    if type(section.get("truncated")) is not bool:
        errors.append(f"{path}.truncated must be boolean")
    items = section.get("items")
    if isinstance(items, list):
        for index, raw in enumerate(items[:MAX_INPUT_SCAN]):
            source = _mapping(raw)
            shape = _collection_item_fields(attention, source)
            if shape is None:
                errors.append(f"{path}.items[{index}].scope is invalid")
                continue
            fields, integer_fields = shape
            required = set(fields)
            item = _require_fields(raw, required, f"{path}.items[{index}]", errors)
            persistent_attention = (
                attention == "operator"
                and item.get("kind") == "persistent_session_attention"
            )
            if persistent_attention and set(item) != required:
                errors.append(f"{path}.items[{index}] has unexpected persistent attention fields")
            for field in integer_fields.intersection(item):
                if not _is_i64(item.get(field)):
                    errors.append(f"{path}.items[{index}].{field} is not signed-64")
            for field in required - integer_fields:
                nullable = attention is not None and field == "reason"
                if persistent_attention and field == "work_id":
                    if item.get(field) is not None:
                        errors.append(f"{path}.items[{index}].work_id must be null")
                    continue
                if not _is_text(item.get(field), nullable=nullable):
                    errors.append(f"{path}.items[{index}].{field} must be text")
            if persistent_attention and item.get("generation") != 0:
                errors.append(f"{path}.items[{index}].generation must equal zero")


def _turn_schema(value: object, path: str, errors: list[str]) -> None:
    turns = _require_fields(
        value,
        {"status", "reason", "limit", "items", "content_included"},
        path,
        errors,
    )
    if not turns:
        return
    if turns.get("status") not in {"available", "unavailable"}:
        errors.append(f"{path}.status is invalid")
    if turns.get("limit") != 2:
        errors.append(f"{path}.limit must equal 2")
    if not isinstance(turns.get("items"), list):
        errors.append(f"{path}.items must be an array")
    if turns.get("content_included") is not False:
        errors.append(f"{path}.content_included must be false")
    items = turns.get("items")
    if isinstance(items, list):
        if len(items) > 2:
            errors.append(f"{path}.items exceeds the two-turn limit")
        for index, raw in enumerate(items[:3]):
            item = _require_fields(raw, _TURN_FIELDS, f"{path}.items[{index}]", errors)
            if _FORBIDDEN_TURN_FIELDS.intersection(item):
                errors.append(f"{path}.items[{index}] contains transcript content")
            for field in ("ordinal", "token_count"):
                if not _is_i64(item.get(field)):
                    errors.append(f"{path}.items[{index}].{field} is not signed-64")
            for field in ("turn_id", "state", "occurred_at"):
                if not _is_text(item.get(field)):
                    errors.append(f"{path}.items[{index}].{field} must be text")


def _metric_schema(value: object, path: str, errors: list[str]) -> None:
    metric = _require_fields(value, {"status"}, path, errors)
    if not metric:
        return
    status = metric.get("status")
    if status == "available":
        missing = {"source", "value"} - set(metric)
        if missing:
            errors.append(f"{path} missing: {','.join(sorted(missing))}")
        sample = metric.get("value")
        bounded = (
            type(sample) is int and 0 <= sample <= SIGNED_64_MAX
        ) or (
            type(sample) is float
            and math.isfinite(sample)
            and 0 <= sample <= SIGNED_64_MAX
        )
        if metric.get("source") != "durable_samples" or not bounded:
            errors.append(f"{path} lacks a finite bounded durable sample")
    elif status == "unavailable":
        if not isinstance(metric.get("reason"), str):
            errors.append(f"{path}.reason must be text when unavailable")
    else:
        errors.append(f"{path}.status is invalid")


def _schema_errors(source: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    top = _require_fields(
        source,
        {
            "projection_version",
            "snapshot_version",
            "availability",
            "topology",
            "slots",
            "worker_graph",
            "queue",
            "attention",
            "metrics",
            "recent_turns",
            "refresh",
        },
        "snapshot",
        errors,
    )
    if not top:
        return errors
    version = _require_fields(
        source.get("snapshot_version"),
        {"event_sequence", "migration_version", "digest"},
        "snapshot_version",
        errors,
    )
    availability = _require_fields(
        source.get("availability"), {"status", "errors"}, "availability", errors
    )
    unavailable_snapshot = availability.get("status") in {"unavailable", "degraded"}
    if version and not _is_i64(
        version.get("event_sequence"), nullable=unavailable_snapshot
    ):
        errors.append("snapshot_version.event_sequence is not signed-64")
    if version and not isinstance(version.get("migration_version"), str):
        errors.append("snapshot_version.migration_version must be text")
    if availability and availability.get("status") not in {
        "available",
        "degraded",
        "unavailable",
    }:
        errors.append("availability.status is invalid")
    if availability and not isinstance(availability.get("errors"), list):
        errors.append("availability.errors must be an array")
    elif availability:
        for index, error in enumerate(availability.get("errors", [])[:MAX_ERRORS]):
            if not isinstance(error, str):
                errors.append(f"availability.errors[{index}] must be text")
    topology = _require_fields(
        source.get("topology"),
        {"lanes", "expected_slots", "observed_slots", "observed_status"},
        "topology",
        errors,
    )
    if topology and not isinstance(topology.get("lanes"), list):
        errors.append("topology.lanes must be an array")
    if topology and topology.get("expected_slots") not in {11, 13}:
        errors.append("topology.expected_slots must equal 11 or 13")
    if topology and not _is_i64(
        topology.get("observed_slots"), nullable=unavailable_snapshot
    ):
        errors.append("topology.observed_slots is not signed-64")
    if topology and topology.get("observed_status") not in {"exact", "capped", "unknown"}:
        errors.append("topology.observed_status is invalid")
    if not unavailable_snapshot and topology and topology.get("observed_status") != "exact":
        errors.append("topology.observed_status must be exact when available")
    if not isinstance(source.get("slots"), list):
        errors.append("slots must be an array")
    else:
        for index, raw in enumerate(source["slots"][:14]):
            slot = _require_fields(
                raw,
                {"slot_id", "lane", "position", "state", "assignment_id", "work_id"},
                f"slots[{index}]",
                errors,
            )
            if slot and not _is_i64(slot.get("position")):
                errors.append(f"slots[{index}].position is not signed-64")
            if slot and slot.get("state") not in {"clear", "assigned", "unavailable"}:
                errors.append(f"slots[{index}].state is invalid")
            for field in ("slot_id", "lane"):
                if slot and not _is_text(slot.get(field)):
                    errors.append(f"slots[{index}].{field} must be text")
            for field in ("assignment_id", "work_id"):
                if slot and not _is_text(slot.get(field), nullable=True):
                    errors.append(f"slots[{index}].{field} must be text or null")
    graph = _require_fields(
        source.get("worker_graph"), {"workers", "edges"}, "worker_graph", errors
    )
    if graph and not isinstance(graph.get("workers"), list):
        errors.append("worker_graph.workers must be an array")
    if graph and not isinstance(graph.get("edges"), list):
        errors.append("worker_graph.edges must be an array")
    elif graph:
        for index, raw in enumerate(graph.get("edges", [])[:MAX_INPUT_SCAN]):
            edge = _require_fields(
                raw, {"from", "to", "kind"}, f"worker_graph.edges[{index}]", errors
            )
            for field in ("from", "to", "kind"):
                if edge and not _is_text(edge.get(field)):
                    errors.append(f"worker_graph.edges[{index}].{field} must be text")
    workers = graph.get("workers", []) if graph else []
    if isinstance(workers, list):
        for index, raw in enumerate(workers[:14]):
            path = f"worker_graph.workers[{index}]"
            worker = _require_fields(
                raw,
                {
                    "slot_id", "lane", "position", "slot_state", "display_name",
                    "session", "pane", "work_id", "agent_lifecycle", "owner_id", "assignment_id",
                    "attempt", "transport", "completion", "recovery", "recent_turns",
                },
                path,
                errors,
            )
            if not worker:
                continue
            if not _is_i64(worker.get("position")):
                errors.append(f"{path}.position is not signed-64")
            if not _is_i64(worker.get("attempt"), nullable=True):
                errors.append(f"{path}.attempt is not signed-64")
            if worker.get("slot_state") not in {"clear", "assigned", "unavailable"}:
                errors.append(f"{path}.slot_state is invalid")
            for field in ("slot_id", "lane", "slot_state", "display_name"):
                if not _is_text(worker.get(field)):
                    errors.append(f"{path}.{field} must be text")
            for field in ("work_id", "owner_id", "assignment_id"):
                if not _is_text(worker.get(field), nullable=True):
                    errors.append(f"{path}.{field} must be text or null")
            lifecycle = worker.get("agent_lifecycle")
            if lifecycle is not None and lifecycle not in {"disposable", "persistent"}:
                errors.append(f"{path}.agent_lifecycle is invalid")
            if worker.get("slot_state") == "assigned" and lifecycle is None:
                errors.append(f"{path}.agent_lifecycle is missing for assigned work")
            if worker.get("slot_state") != "assigned" and lifecycle is not None:
                errors.append(f"{path}.agent_lifecycle exists without assigned work")
            session = _component_schema(
                worker.get("session"), {"ref"}, f"{path}.session", errors
            )
            pane = _component_schema(
                worker.get("pane"), {"ref"}, f"{path}.pane", errors
            )
            if session and not _is_text(session.get("ref"), nullable=True):
                errors.append(f"{path}.session.ref must be text or null")
            if pane and not _is_text(pane.get("ref"), nullable=True):
                errors.append(f"{path}.pane.ref must be text or null")
            transport = _component_schema(
                worker.get("transport"),
                {
                    "reason", "id", "state", "generation",
                    "acknowledgement_id", "error_code", "adapter",
                },
                f"{path}.transport",
                errors,
            )
            if transport and not _is_i64(transport.get("generation"), nullable=True):
                errors.append(f"{path}.transport.generation is not signed-64")
            if transport:
                for field in ("reason", "id", "acknowledgement_id", "error_code"):
                    if not _is_text(transport.get(field), nullable=True):
                        errors.append(f"{path}.transport.{field} must be text or null")
                if not _is_text(transport.get("state")):
                    errors.append(f"{path}.transport.state must be text")
            if transport:
                adapter = _component_schema(
                    transport.get("adapter"),
                    {"kind", "reason"},
                    f"{path}.transport.adapter",
                    errors,
                )
                for field in ("kind", "reason"):
                    if adapter and not _is_text(adapter.get(field), nullable=True):
                        errors.append(
                            f"{path}.transport.adapter.{field} must be text or null"
                        )
            completion = _component_schema(
                worker.get("completion"),
                {
                    "reason", "id", "registration_state", "route_state",
                    "callback_state", "callback_adapter",
                },
                f"{path}.completion",
                errors,
            )
            if completion:
                for field in (
                    "reason", "id", "registration_state", "route_state", "callback_state"
                ):
                    if not _is_text(completion.get(field), nullable=field in {"reason", "id"}):
                        errors.append(f"{path}.completion.{field} has invalid type")
                callback_adapter = _component_schema(
                    completion.get("callback_adapter"),
                    {"reason"},
                    f"{path}.completion.callback_adapter",
                    errors,
                )
                if callback_adapter and not _is_text(
                    callback_adapter.get("reason"), nullable=True
                ):
                    errors.append(
                        f"{path}.completion.callback_adapter.reason must be text or null"
                    )
            recovery = _component_schema(
                worker.get("recovery"),
                {
                    "reason", "target_id", "phase", "circuit_state",
                    "episode_state", "timer_state",
                },
                f"{path}.recovery",
                errors,
            )
            if recovery:
                for field in (
                    "reason", "target_id", "phase", "circuit_state",
                    "episode_state", "timer_state",
                ):
                    if not _is_text(recovery.get(field), nullable=field in {"reason", "target_id"}):
                        errors.append(f"{path}.recovery.{field} has invalid type")
            _turn_schema(worker.get("recent_turns"), f"{path}.recent_turns", errors)
    _collection_schema(source.get("queue"), "queue", errors)
    attention = _require_fields(
        source.get("attention"),
        {"automatic_recovery", "operator_required"},
        "attention",
        errors,
    )
    if attention:
        _collection_schema(
            attention.get("automatic_recovery"),
            "attention.automatic_recovery",
            errors,
            attention="automatic",
        )
        _collection_schema(
            attention.get("operator_required"),
            "attention.operator_required",
            errors,
            attention="operator",
        )
    metrics = _require_fields(
        source.get("metrics"), {"token_total", "token_rate_5m"}, "metrics", errors
    )
    if metrics:
        _metric_schema(metrics.get("token_total"), "metrics.token_total", errors)
        _metric_schema(metrics.get("token_rate_5m"), "metrics.token_rate_5m", errors)
    _turn_schema(source.get("recent_turns"), "recent_turns", errors)
    refresh = _require_fields(
        source.get("refresh"), {"mode", "polling"}, "refresh", errors
    )
    if refresh and (refresh.get("mode"), refresh.get("polling")) != (
        "explicit",
        "disabled",
    ):
        errors.append("refresh must be explicit with polling disabled")
    return errors[:MAX_ERRORS]


def _component(value: object, fields: tuple[str, ...]) -> dict[str, Any]:
    source = _mapping(value)
    status = safe_text(source.get("status"))
    malformed_value = any(
        field in source
        and source.get(field) is not None
        and not isinstance(source.get(field), str)
        and not _is_i64(source.get(field))
        for field in fields
    )
    if (
        status not in {"available", "unavailable", "disabled"}
        or any(field not in source for field in fields)
        or malformed_value
    ):
        status = "unavailable"
    result: dict[str, Any] = {"status": status}
    for field in fields:
        child = source.get(field)
        if _is_i64(child):
            result[field] = child
        elif child is None:
            result[field] = (
                "unavailable" if field in _EXPLICIT_UNAVAILABLE_FIELDS else None
            )
        else:
            result[field] = safe_text(child)
    return result


def _recent_turns(value: object) -> dict[str, Any]:
    source = _mapping(value)
    items: list[dict[str, Any]] = []
    malformed = not (
        {"status", "reason", "limit", "items", "content_included"}.issubset(source)
        and source.get("status") in {"available", "unavailable"}
        and source.get("limit") == 2
        and isinstance(source.get("items"), list)
        and source.get("content_included") is False
    )
    unsafe = bool(source.get("content_included", False))
    for raw in _bounded_items(source.get("items")):
        if len(items) >= 2:
            malformed = True
            break
        item = _mapping(raw)
        if _FORBIDDEN_TURN_FIELDS.intersection(item):
            unsafe = True
            continue
        if not _TURN_FIELDS.issubset(item):
            malformed = True
            continue
        normalized: dict[str, Any] = {}
        for field in sorted(_TURN_FIELDS):
            child = item.get(field)
            if _is_i64(child):
                normalized[field] = child
            elif isinstance(child, str):
                normalized[field] = safe_text(child)
        if set(normalized) == _TURN_FIELDS:
            items.append(normalized)
        else:
            malformed = True
    if unsafe:
        return {
            "status": "unavailable",
            "reason": "unsafe_turn_payload_rejected",
            "limit": 2,
            "items": [],
            "content_included": False,
        }
    if malformed:
        return {
            "status": "unavailable",
            "reason": "malformed_turn_metadata_rejected",
            "limit": 2,
            "items": [],
            "content_included": False,
        }
    status = "available" if items else "unavailable"
    return {
        "status": status,
        "reason": (
            None if items else safe_text(source.get("reason", "metadata_not_recorded"))
        ),
        "limit": 2,
        "items": items,
        "content_included": False,
    }


def _empty_worker(slot_id: str, lane: str, position: int) -> dict[str, Any]:
    unavailable = {"status": "unavailable", "reason": "missing_worker_state"}
    return {
        "slot_id": slot_id,
        "lane": lane,
        "position": position,
        "slot_state": "unavailable",
        "display_name": f"session:unavailable · {slot_id}",
        "session": {"status": "unavailable", "ref": None},
        "pane": {"status": "unavailable", "ref": None},
        "work_id": None,
        "agent_lifecycle": None,
        "owner_id": None,
        "assignment_id": None,
        "attempt": None,
        "transport": {
            **unavailable,
            "id": None,
            "state": "unavailable",
            "generation": None,
            "acknowledgement_id": None,
            "error_code": None,
            "adapter": {
                "status": "unavailable",
                "kind": None,
                "reason": "missing_worker_state",
            },
        },
        "completion": {
            **unavailable,
            "id": None,
            "registration_state": "unavailable",
            "route_state": "unavailable",
            "callback_state": "unavailable",
            "callback_adapter": {"status": "unavailable", "reason": "unavailable"},
        },
        "recovery": {
            **unavailable,
            "target_id": None,
            "phase": "unavailable",
            "circuit_state": "unavailable",
            "episode_state": "unavailable",
            "timer_state": "unavailable",
        },
        "recent_turns": _recent_turns(None),
    }


def _normalize_worker(
    raw: object,
    *,
    slot_id: str,
    lane: str,
    position: int,
) -> dict[str, Any]:
    source = _mapping(raw)
    if not source:
        return _empty_worker(slot_id, lane, position)
    slot_state = safe_text(source.get("slot_state"))
    if slot_state not in {"clear", "assigned"}:
        slot_state = "unavailable"
    session = _component(source.get("session"), ("ref",))
    pane = _component(source.get("pane"), ("ref",))
    work_id = None if source.get("work_id") is None else safe_text(source.get("work_id"))
    agent_lifecycle = source.get("agent_lifecycle")
    if agent_lifecycle not in {"disposable", "persistent"}:
        agent_lifecycle = None
    if slot_state != "assigned":
        agent_lifecycle = None
    display = safe_text(source.get("display_name"))
    if display == "unavailable":
        display = f"{session.get('ref') or 'session:unavailable'} · {work_id or slot_id}"
    transport_source = _mapping(source.get("transport"))
    transport = _component(
        transport_source,
        ("reason", "id", "state", "generation", "acknowledgement_id", "error_code"),
    )
    transport["adapter"] = _component(
        transport_source.get("adapter"), ("kind", "reason")
    )
    completion_source = _mapping(source.get("completion"))
    completion = _component(
        completion_source,
        (
            "reason",
            "id",
            "registration_state",
            "route_state",
            "callback_state",
        ),
    )
    completion["callback_adapter"] = _component(
        completion_source.get("callback_adapter"), ("reason",)
    )
    recovery = _component(
        source.get("recovery"),
        (
            "reason",
            "target_id",
            "phase",
            "circuit_state",
            "episode_state",
            "timer_state",
        ),
    )
    return {
        "slot_id": slot_id,
        "lane": lane,
        "position": position,
        "slot_state": slot_state,
        "display_name": display,
        "session": session,
        "pane": pane,
        "work_id": work_id,
        "agent_lifecycle": agent_lifecycle,
        "owner_id": (
            None if source.get("owner_id") is None else safe_text(source.get("owner_id"))
        ),
        "assignment_id": (
            None
            if source.get("assignment_id") is None
            else safe_text(source.get("assignment_id"))
        ),
        "attempt": (
            source.get("attempt")
            if _is_i64(source.get("attempt"))
            else None
        ),
        "transport": transport,
        "completion": completion,
        "recovery": recovery,
        "recent_turns": _recent_turns(source.get("recent_turns")),
    }


def _normalize_collection(
    value: object, *, attention: str | None = None
) -> dict[str, Any]:
    source = _mapping(value)
    required = {
        "status",
        "items",
        "total",
        "total_status",
        "lower_bound",
        "truncated",
    }
    valid_section = (
        bool(source)
        and required.issubset(source)
        and source.get("status") in {"available", "unavailable"}
        and isinstance(source.get("items"), list)
        and source.get("total_status") in {"exact", "capped", "unknown"}
        and _is_i64(source.get("lower_bound"))
        and type(source.get("truncated")) is bool
    )
    items: list[dict[str, Any]] = []
    for raw in _bounded_items(source.get("items")):
        item = _mapping(raw)
        shape = _collection_item_fields(attention, item)
        if shape is None:
            valid_section = False
            continue
        fields, integer_fields = shape
        persistent_attention = (
            attention == "operator"
            and item.get("kind") == "persistent_session_attention"
        )
        if not set(fields).issubset(item) or (
            persistent_attention and set(item) != set(fields)
        ):
            valid_section = False
            continue
        if persistent_attention and (
            item.get("work_id") is not None or item.get("generation") != 0
        ):
            valid_section = False
            continue
        normalized: dict[str, Any] = {}
        for field in fields:
            child = item.get(field)
            if field in integer_fields and _is_i64(child):
                normalized[field] = child
            elif field not in integer_fields and child is None and (
                (attention is not None and field == "reason")
                or (persistent_attention and field == "work_id")
            ):
                normalized[field] = None
            elif field not in integer_fields and isinstance(child, str):
                normalized[field] = safe_text(child)
            else:
                valid_section = False
                normalized = {}
                break
        if not normalized:
            continue
        items.append(normalized)
    if attention is not None:
        items.sort(
            key=lambda item: (
                str(item.get("scope") or ""),
                str(item.get("work_id") or ""),
                str(item.get("kind") or ""),
                str(item.get("id") or ""),
            )
        )
    else:
        items.sort(
            key=lambda item: (
                _integer(item.get("queue_order"), 2**63 - 1),
                _integer(item.get("sequence"), 2**63 - 1),
                str(item.get("work_id") or ""),
            )
        )
    items = items[:MAX_ITEMS]
    total_status = source.get("total_status") if valid_section else "unknown"
    total = (
        max(_integer(source.get("total")), len(items))
        if total_status == "exact" and _is_i64(source.get("total"))
        else None
    )
    lower_bound = (
        max(_integer(source.get("lower_bound")), len(items))
        if valid_section
        else len(items)
    )
    return {
        "status": source.get("status") if valid_section else "unavailable",
        "items": items,
        "total": total,
        "total_status": total_status,
        "lower_bound": lower_bound,
        "truncated": (
            bool(source.get("truncated"))
            if valid_section
            else False
        ),
    }


def _partition_callback_attention(
    value: object,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Partition callbacks before display capping and prove exactness explicitly."""
    source = _mapping(value)
    raw_items = source.get("items")
    bounded_items = list(_bounded_items(raw_items))
    source_length = len(raw_items) if isinstance(raw_items, list) else -1
    complete = (
        source.get("status") == "available"
        and source.get("total_status") == "exact"
        and source.get("truncated") is False
        and _is_i64(source.get("total"))
        and _is_i64(source.get("lower_bound"))
        and source.get("total") == source.get("lower_bound") == source_length
        and source_length == len(bounded_items)
    )
    delivery_items = [
        item
        for item in bounded_items
        if _mapping(item).get("kind") == "callback_attention"
    ]
    operator_items = [
        item
        for item in bounded_items
        if _mapping(item).get("kind") != "callback_attention"
    ]

    def collection(items: list[object]) -> dict[str, Any]:
        internally_truncated = len(items) > MAX_ITEMS
        if complete:
            status = "available"
            total: int | None = len(items)
            total_status = "exact"
            lower_bound = len(items)
            truncated = internally_truncated
        else:
            status = "unavailable"
            total = None
            total_status = (
                "capped"
                if source.get("status") == "available"
                and (
                    source.get("total_status") == "capped"
                    or source.get("truncated") is True
                    or source_length > len(bounded_items)
                )
                else "unknown"
            )
            lower_bound = min(len(items), MAX_ITEMS)
            truncated = bool(source.get("truncated")) or internally_truncated
        return _normalize_collection(
            {
                "status": status,
                "items": items,
                "total": total,
                "total_status": total_status,
                "lower_bound": lower_bound,
                "truncated": truncated,
            },
            attention="operator",
        )

    return collection(delivery_items), collection(operator_items)


def _metric(value: object) -> dict[str, Any]:
    source = _mapping(value)
    sample = source.get("value")
    bounded_numeric = (
        type(sample) is int and 0 <= sample <= SIGNED_64_MAX
    ) or (
        type(sample) is float
        and math.isfinite(sample)
        and 0 <= sample <= SIGNED_64_MAX
    )
    if (
        source.get("status") == "available"
        and source.get("source") == "durable_samples"
        and bounded_numeric
    ):
        return {"status": "available", "source": "durable_samples", "value": sample}
    return {
        "status": "unavailable",
        "reason": safe_text(source.get("reason", "no_durable_token_samples")),
    }


def normalize_snapshot(value: object) -> dict[str, Any]:
    """Return a bounded exact-topology view, visibly degrading malformed input."""
    source = _mapping(value)
    errors: list[str] = []
    if not source:
        errors.append("snapshot is missing or is not an object")
    else:
        errors.extend(_schema_errors(source))
    if source.get("projection_version") != 1:
        errors.append("projection version is missing or unsupported")

    raw_workers = _mapping(source.get("worker_graph")).get("workers")
    workers_by_slot: dict[str, Mapping[str, Any]] = {}
    duplicate_workers: set[str] = set()
    for raw in _bounded_items(raw_workers):
        worker = _mapping(raw)
        slot_id = worker.get("slot_id")
        if isinstance(slot_id, str):
            if slot_id in workers_by_slot:
                duplicate_workers.add(slot_id)
            else:
                workers_by_slot[slot_id] = worker

    raw_slots: dict[str, Mapping[str, Any]] = {}
    duplicate_slots: set[str] = set()
    for raw in _bounded_items(source.get("slots")):
        slot = _mapping(raw)
        slot_id = slot.get("slot_id")
        if isinstance(slot_id, str):
            if slot_id in raw_slots:
                duplicate_slots.add(slot_id)
            else:
                raw_slots[slot_id] = slot

    topology = _mapping(source.get("topology"))
    slot_count = topology.get("expected_slots")
    if slot_count not in {11, 13}:
        slot_count = 13
    lane_counts = {
        lane_id: (1 if slot_count == 11 and lane_id == "control" else count)
        for lane_id, _label, _symbol, count in LANES
    }
    expected_slot_ids = {
        f"{lane_id}-{position}"
        for lane_id, _label, _symbol, _count in LANES
        for position in range(1, lane_counts[lane_id] + 1)
    }
    expected_lanes = [lane_id for lane_id, _label, _symbol, _count in LANES]
    if (
        topology.get("expected_slots") != slot_count
        or topology.get("observed_slots") != slot_count
        or topology.get("lanes") != expected_lanes
    ):
        errors.append(f"topology does not report exactly {slot_count} slots")
    if set(raw_slots) != expected_slot_ids:
        errors.append("slot identities do not match the fixed topology")
    if set(workers_by_slot) != expected_slot_ids:
        errors.append("worker graph does not cover the fixed topology")
    if duplicate_slots:
        errors.append("duplicate slot identities were rejected")
    if duplicate_workers:
        errors.append("duplicate worker identities were rejected")

    lanes: list[dict[str, Any]] = []
    normalized_workers: list[dict[str, Any]] = []
    for lane_id, label, symbol, _count in LANES:
        lane_slots: list[dict[str, Any]] = []
        for position in range(1, lane_counts[lane_id] + 1):
            slot_id = f"{lane_id}-{position}"
            slot = raw_slots.get(slot_id, {})
            if not slot:
                errors.append(f"missing slot {slot_id}")
            elif slot.get("lane") != lane_id or slot.get("position") != position:
                errors.append(f"identity mismatch for slot {slot_id}")
            state = safe_text(slot.get("state")) if slot else "unavailable"
            if state not in {"clear", "assigned"}:
                state = "unavailable"
                if slot:
                    errors.append(f"invalid state for slot {slot_id}")
            raw_worker = workers_by_slot.get(slot_id)
            if raw_worker is None:
                errors.append(f"missing worker state for slot {slot_id}")
            elif (
                raw_worker.get("lane") != lane_id
                or raw_worker.get("position") != position
            ):
                errors.append(f"identity mismatch for worker {slot_id}")
            worker = _normalize_worker(
                raw_worker,
                slot_id=slot_id,
                lane=lane_id,
                position=position,
            )
            if state != "unavailable":
                worker["slot_state"] = state
            lane_slots.append(
                {
                    "slot_id": slot_id,
                    "position": position,
                    "state": state,
                    "display_name": worker["display_name"],
                }
            )
            normalized_workers.append(worker)
        lanes.append(
            {
                "id": lane_id,
                "label": label,
                "symbol": symbol,
                "slots": lane_slots,
            }
        )

    version_source = _mapping(source.get("snapshot_version"))
    digest = version_source.get("digest")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        digest = "unavailable"
        errors.append("snapshot digest is missing or invalid")
    availability_source = _mapping(source.get("availability"))
    source_errors = availability_source.get("errors")
    for error in _bounded_items(source_errors):
        if len(errors) >= MAX_ERRORS:
            break
        errors.append(safe_text(error))
    attention_source = _mapping(source.get("attention"))
    metrics_source = _mapping(source.get("metrics"))
    edges: list[dict[str, str]] = []
    for worker in normalized_workers:
        for target, kind in (
            (worker.get("work_id"), "runs"),
            (_mapping(worker.get("transport")).get("id"), "transport"),
            (_mapping(worker.get("completion")).get("id"), "completion"),
            (_mapping(worker.get("recovery")).get("target_id"), "recovery"),
        ):
            if isinstance(target, str) and target != "unavailable":
                edges.append({"from": worker["slot_id"], "to": target, "kind": kind})
    edges.sort(key=lambda edge: (edge["from"], edge["kind"], edge["to"]))
    source_edges = []
    for raw in _bounded_items(_mapping(source.get("worker_graph")).get("edges")):
        edge = _mapping(raw)
        if all(isinstance(edge.get(field), str) for field in ("from", "to", "kind")):
            # Descendant delegation edges belong to the richer lifecycle graph.
            # This terminal projection intentionally normalizes only root worker
            # relationships, so those edges must not make an otherwise exact
            # snapshot look degraded merely because retained child metadata is
            # present.
            if edge["kind"] == "delegates":
                continue
            source_edges.append(
                {"from": edge["from"], "to": edge["to"], "kind": edge["kind"]}
            )
    source_edges.sort(key=lambda edge: (edge["from"], edge["kind"], edge["to"]))
    if source_edges != edges:
        errors.append("worker graph edges do not match worker relationships")
    errors = errors[:MAX_ERRORS]
    if not source or availability_source.get("status") == "unavailable":
        status = "unavailable"
    elif errors or availability_source.get("status") != "available":
        status = "degraded"
    else:
        status = "available"
    delivery_attention, operator_attention = _partition_callback_attention(
        attention_source.get("operator_required")
    )
    return {
        "projection_version": 1,
        "snapshot_version": {
            "event_sequence": (
                version_source.get("event_sequence")
                if _is_i64(version_source.get("event_sequence"))
                else None
            ),
            "migration_version": safe_text(
                version_source.get("migration_version"), limit=80
            ),
            "digest": safe_text(digest, limit=64),
        },
        "availability": {"status": status, "errors": errors},
        "legend": [
            {"id": lane_id, "label": label, "symbol": symbol}
            for lane_id, label, symbol, _count in LANES
        ],
        "lanes": lanes,
        "worker_graph": {"workers": normalized_workers, "edges": edges},
        "queue": _normalize_collection(source.get("queue")),
        "attention": {
            "automatic_recovery": _normalize_collection(
                attention_source.get("automatic_recovery"), attention="automatic"
            ),
            "delivery_attention": delivery_attention,
            "operator_required": operator_attention,
        },
        "metrics": {
            "token_total": _metric(metrics_source.get("token_total")),
            "token_rate_5m": _metric(metrics_source.get("token_rate_5m")),
        },
        "recent_turns": _recent_turns(source.get("recent_turns")),
        "refresh": {"mode": "explicit", "polling": "disabled"},
    }
