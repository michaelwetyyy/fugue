"""Deterministic JSON, compact cockpit, and diagnostic renderers."""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Mapping
from typing import Any

from oc_rig.cockpit.view import normalize_snapshot, safe_text


def render_json(snapshot: object) -> str:
    """Render normalized JSON with stable ordering and escaped controls."""
    return json.dumps(
        normalize_snapshot(snapshot),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def render_details(snapshot: object) -> str:
    """Render every normalized diagnostic field as readable deterministic JSON."""
    return json.dumps(
        normalize_snapshot(snapshot),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2,
    ) + "\n"


def _width(value: str) -> int:
    return sum(
        0
        if unicodedata.combining(character)
        else 2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1
        for character in value
    )


def _clip(value: object, width: int) -> str:
    text = safe_text(value, limit=1000)
    if _width(text) <= width:
        return text
    if width <= 1:
        return "…"[:width]
    output: list[str] = []
    used = 0
    for character in text:
        character_width = (
            0
            if unicodedata.combining(character)
            else 2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1
        )
        if used + character_width > width - 1:
            break
        output.append(character)
        used += character_width
    return "".join(output) + "…"


def _collection_total(section: Mapping[str, Any]) -> str:
    if section.get("total_status") == "exact":
        return str(section.get("total"))
    if section.get("total_status") == "capped":
        return f"≥{section.get('lower_bound')}"
    return "unknown"


def _agent_name(worker: Mapping[str, Any]) -> str:
    """Return a human label without exposing legacy session-based display names."""
    display_name = safe_text(worker.get("display_name"))
    if " · " in display_name:
        display_name = safe_text(worker.get("slot_id"))
    return display_name or safe_text(worker.get("slot_id")) or "unavailable"


def _label(value: object, *, fallback: str = "unknown") -> str:
    """Render one optional compact-view field without leaking Python ``None``."""
    if type(value) is int:
        return str(value)
    return fallback if value is None else (safe_text(value) or fallback)


def _metric_label(metric: Mapping[str, Any], *, suffix: str = "") -> str:
    """Render one durable metric or an explicit privacy-safe unavailable reason."""

    if metric.get("status") == "available":
        value = metric.get("value")
        if type(value) is int:
            rendered = f"{value:,}"
        elif type(value) is float:
            rendered = f"{value:,.1f}"
        else:
            return "unavailable"
        return rendered + suffix
    reason = safe_text(metric.get("reason")).replace("_", " ")
    return f"unavailable ({reason})"


def _component_warning(worker: Mapping[str, Any]) -> list[str]:
    """Return exceptional worker diagnostics worth promoting in compact mode."""
    if worker.get("slot_state") != "assigned":
        return []
    warnings: list[str] = []
    transport = worker.get("transport")
    if isinstance(transport, Mapping):
        state = transport.get("state")
        error = transport.get("error_code")
        if transport.get("status") == "unavailable":
            warnings.append("transport unavailable")
        elif error is not None or state in {
            "definite_failed", "failed", "cancelled", "attention",
        }:
            suffix = f" ({safe_text(error)})" if error is not None else ""
            warnings.append(f"transport {safe_text(state)}{suffix}")
    completion = worker.get("completion")
    if isinstance(completion, Mapping):
        if completion.get("status") == "unavailable":
            warnings.append("completion unavailable")
        else:
            for field in ("registration_state", "route_state", "callback_state"):
                value = completion.get(field)
                if isinstance(value, str) and value in {
                    "failed", "blocked", "attention",
                }:
                    component = field.removesuffix("_state")
                    warnings.append(f"completion {component} {safe_text(value)}")
    recovery = worker.get("recovery")
    if isinstance(recovery, Mapping):
        if recovery.get("status") == "unavailable":
            warnings.append("recovery unavailable")
        else:
            exceptional = {
                "phase": {"corpse", "attention"},
                "circuit_state": {"open"},
                "episode_state": {"failed", "attention", "exhausted"},
                "timer_state": {"failed", "attention"},
            }
            for field, states in exceptional.items():
                value = recovery.get(field)
                if value in states:
                    component = field.removesuffix("_state")
                    warnings.append(f"recovery {component} {safe_text(value)}")
    return warnings


_STATUS_MARKERS = {
    "clear": "○",
    "assigned": "●",
    "queued": "◆",
    "unavailable": "⚠",
    "automatic": "⚠",
    "operator": "⚠",
}

_STATUS_COLOURS = {
    "clear": "\x1b[36m",
    "assigned": "\x1b[32m",
    "queued": "\x1b[33m",
    "unavailable": "\x1b[31m",
    "automatic": "\x1b[33m",
    "operator": "\x1b[31m",
}


def _colour_status_marker(value: str, state: str | None) -> str:
    """Colour one renderer-owned marker without styling snapshot text."""
    if state not in _STATUS_MARKERS:
        return value
    marker = _STATUS_MARKERS[state]
    offset = len(value) - len(value.lstrip(" "))
    if not value.startswith(marker, offset):
        return value
    return (
        value[:offset]
        + _STATUS_COLOURS[state]
        + marker
        + "\x1b[0m"
        + value[offset + len(marker) :]
    )


def render_terminal(snapshot: object, *, width: int = 100, ansi: bool = False) -> str:
    """Render a display-width-bounded view with optional trusted-marker colour."""
    if type(ansi) is not bool:
        raise TypeError("ansi must be a boolean")
    if type(width) is not int or not 24 <= width <= 240:
        raise ValueError("width must be between 24 and 240 columns")
    view = normalize_snapshot(snapshot)
    lines: list[str] = []

    def emit(value: object = "", *, state: str | None = None) -> None:
        plain = _clip(value, width) if value else ""
        lines.append(_colour_status_marker(plain, state) if ansi else plain)

    availability = view["availability"]
    status = availability["status"]
    status_label = "ready" if status == "available" else status
    if status == "available":
        emit(f"Fugue · {status_label}")
    else:
        emit(f"⚠ Fugue · {status_label}", state="unavailable")
    emit("Legend: ○ idle · ● active · ◆ queued · ⚠ issue")
    if availability["errors"]:
        emit("Warnings")
        for error in availability["errors"]:
            emit(f"  ⚠ {error}", state="unavailable")
    emit()
    graph = view["worker_graph"]
    workers = {
        worker["slot_id"]: worker for worker in graph["workers"]
    }
    work_by_slot: dict[str, list[str]] = {}
    for edge in graph["edges"]:
        if edge.get("kind") == "runs":
            work_by_slot.setdefault(str(edge.get("from")), []).append(
                safe_text(edge.get("to"))
            )
    queue = view["queue"]
    queued_lanes = {
        safe_text(item.get("lane"))
        for item in queue["items"]
        if item.get("lane") is not None
    }
    markers = {key: _STATUS_MARKERS[key] for key in ("clear", "assigned", "queued", "unavailable")}
    active_groups: list[tuple[Mapping[str, Any], list[tuple[Mapping[str, Any], Mapping[str, Any], list[str], list[str]]]]] = []
    emit("ORCHESTRATORS")
    for lane in view["lanes"]:
        lane_slots = [
            (slot, workers[slot["slot_id"]]) for slot in lane["slots"]
        ]
        if any(slot["state"] == "unavailable" for slot, _worker in lane_slots):
            lane_state = "unavailable"
        elif any(slot["state"] == "assigned" for slot, _worker in lane_slots):
            lane_state = "assigned"
        elif safe_text(lane.get("id")) in queued_lanes:
            lane_state = "queued"
        else:
            lane_state = "clear"
        emit(
            f"  {markers[lane_state]} {lane['label']}",
            state=lane_state,
        )
        active: list[tuple[Mapping[str, Any], Mapping[str, Any], list[str], list[str]]] = []
        for slot in lane["slots"]:
            worker = workers[slot["slot_id"]]
            slot_state = slot["state"] if slot["state"] in markers else "unavailable"
            work_ids = work_by_slot.get(slot["slot_id"], [])
            warnings = _component_warning(worker)
            if slot_state != "clear" or work_ids or warnings:
                active.append((slot, worker, work_ids, warnings))
        if active:
            active_groups.append((lane, active))

    emit()
    emit("WORKER GRAPH")
    if not active_groups:
        emit("  (no active workers)")
    for lane, active in active_groups:
        emit(f"  {lane['label']}")
        for slot, worker, work_ids, warnings in active:
            slot_state = slot["state"] if slot["state"] in markers else "unavailable"
            emit(
                f"    {markers[slot_state]} {_agent_name(worker)}",
                state=slot_state,
            )
            for work_id in work_ids:
                emit(f"      ↳ {work_id}")
            for warning in warnings:
                emit(f"      ⚠ {warning}", state="unavailable")

    emit()
    queue_suffix = " · truncated" if queue["truncated"] else ""
    emit(f"DISPATCH QUEUE ({_collection_total(queue)}){queue_suffix}")
    if queue["status"] == "unavailable":
        emit("  ⚠ unavailable", state="unavailable")
    elif not queue["items"]:
        emit("  empty")
    for item in queue["items"]:
        emit(
            f"  ◆ #{_label(item.get('queue_order'))} "
            f"{_label(item.get('lane'))} {_label(item.get('work_id'))} "
            f"[{_label(item.get('policy'))}]",
            state="queued",
        )

    attention_sections = [
        (key, label, view["attention"][key])
        for key, label in (
        ("automatic_recovery", "automatic recovery"),
        ("delivery_attention", "delivery attention"),
        ("operator_required", "operator required"),
        )
    ]
    emit()
    attention_state = (
        "operator"
        if (
            view["attention"]["operator_required"]["status"] == "unavailable"
            or view["attention"]["operator_required"]["items"]
        )
        else "automatic"
        if (
            view["attention"]["automatic_recovery"]["status"] == "unavailable"
            or view["attention"]["automatic_recovery"]["items"]
            or view["attention"]["delivery_attention"]["status"] == "unavailable"
            or view["attention"]["delivery_attention"]["items"]
        )
        else None
    )
    if attention_state is None:
        emit("ATTENTION")
    else:
        emit("⚠ ATTENTION", state=attention_state)
    attention_problem = False
    for key, label, section in attention_sections:
        item_state = "operator" if key == "operator_required" else "automatic"
        suffix = " · truncated" if section["truncated"] else ""
        emit(f"  {label}: {_collection_total(section)}{suffix}")
        if section["status"] == "unavailable":
            attention_problem = True
            emit("    ⚠ unavailable", state=item_state)
        for item in section["items"]:
            attention_problem = True
            subject = _label(item.get("work_id") or item.get("scope") or item.get("id"))
            emit(
                f"    ⚠ {subject} · {_label(item.get('kind'))} · "
                f"{_label(item.get('state'))} · {_label(item.get('reason'))}",
                state=item_state,
            )
    if not attention_problem:
        emit("  ✓ nothing stalled, nothing needs you")

    emit()
    emit("METRICS")
    emit(f"  Tokens total: {_metric_label(view['metrics']['token_total'])}")
    emit(
        "  Token rate (5m): "
        + _metric_label(view["metrics"]["token_rate_5m"], suffix=" tok/min")
    )

    emit()
    emit("RECENT ACTIVITY")
    recent = view["recent_turns"]
    if recent["status"] == "unavailable":
        reason = safe_text(recent.get("reason")).replace("_", " ")
        emit(f"  unavailable ({reason})")
    elif not recent["items"]:
        emit("  no recorded turns")
    for item in recent["items"]:
        emit(
            f"  #{_label(item.get('ordinal'))} {_label(item.get('state'))} · "
            f"{_label(item.get('token_count'))} tok · {_label(item.get('occurred_at'))}"
        )
    return "\n".join(lines) + "\n"
