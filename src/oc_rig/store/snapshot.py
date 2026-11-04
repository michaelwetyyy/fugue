"""Strictly read-only, immutable state snapshots."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Mapping

from oc_rig.adapters.opencode import OpenCodeTopology
from oc_rig.store.database import RigStore


_TABLES = (
    "settings",
    "controller_runs",
    "operations",
    "session_bindings",
    "scope_claims",
    "dispatches",
    "transport_attempts",
    "transport_deliveries",
    "transport_completion_registrations",
    "transport_callback_registrations",
    "daemon_outcome_reservations",
    "completion_events",
    "completion_child_barriers",
    "completion_child_sessions",
    "callbacks",
    "return_routes",
    "outbox",
    "callback_delivery_attempts",
    "callback_delivery_reconciliations",
    "recovery_episodes",
    "recovery_targets",
    "recovery_timers",
    "recovery_attempts",
    "recovery_clock_state",
    "pane_bindings",
    "work_queue",
    "events",
)

_LANES = ("tensorhost", "homelab", "personal", "control", "hands-off")
_MAX_COLLECTION_ITEMS = 8
_MAX_GRAPH_SUBAGENTS = 48
_MAX_TEXT_CODEPOINTS = 80
_DEFAULT_DEADLINE_SECONDS = 0.2
_DEFAULT_MAX_VM_STEPS = 1_000_000
_PROGRESS_GRANULARITY = 100
_SIGNED_64_MAX = 2**63 - 1
_CANONICAL_MIGRATIONS = (
    (
        "001_initial.sql",
        "4dabc3649afabbaac442791867d57f577c50ea3c2489ef2da37e388b32ab9fe3",
    ),
    (
        "002_queue_and_fences.sql",
        "8521f817ba6e5a71fad3c40737dfe15056c574c8a1b20628e30dc21a68ae34f3",
    ),
    (
        "003_scheduler.sql",
        "07273db4c04c9f9e69c524462777d6de6fa9ed90f7e4e331fbb705b711d10f81",
    ),
    (
        "004_scheduler_authority.sql",
        "b03d18188aade06545258819cac822b70a5f4c8160f5950a70e072dbce81f656",
    ),
    (
        "005_transport.sql",
        "ea2840ed55b403721059fccd508fe8fa03eef23e553fdfae866da88d63cf243a",
    ),
    (
        "006_completion_recovery.sql",
        "d570c78241c52fa1b72e5519381103e263e37f90b746dfc20015bc3846efe02c",
    ),
    (
        "007_disabled_callback_recovery.sql",
        "d015c6b9d3aee94a99776f8087bddd0a54889d4ddc83eb9914e1d5a4f553f53b",
    ),
    (
        "008_opencode_delivery.sql",
        "1599d092ec8cfaa95b325a4647117c9160ad9c94c256c6372e8f511dc54ff060",
    ),
    (
        "009_transport_adapter_selection.sql",
        "11ddd4611066653e1faac7cd59baeb86a33d1dbac755152db8d190cad4feacab",
    ),
    (
        "010_local_codex_callbacks.sql",
        "643cf3d9afcf6bd5a21ba342f35757cab4d67f6781d629ca31a10aae7bf14ec5",
    ),
    (
        "011_isolated_review_sessions.sql",
        "f02d4f94716c04267d1bec8fdc29159dbf614384a039f531385f4c6483d9a546",
    ),
    (
        "012_isolated_session_cleanup.sql",
        "17f5ed2fc42afd2b82c195eb9dcd82b1c7c257ba28cee4808a24ebcb0e11b8a1",
    ),
    (
        "013_provisional_review_sessions.sql",
        "342060580224c98655d3585c9806b97d4d2f56bfad308e10825a18b63a553e86",
    ),
    (
        "014_durable_completion_results.sql",
        "0f9e8e0a2bac066718d053e5a06ea2f1b12bfb3d9e44cc86ff2760c79f5795a3",
    ),
    (
        "015_agent_lifecycle.sql",
        "a7083d4568d32aa3dca13848082c0a65c40c4d0041745678227f6432cad597af",
    ),
    (
        "016_cancelled_session_cleanup.sql",
        "9aa3d3d6050d866abf82917ecb5834bedd4c5621dacca895974869d41e9b6b7f",
    ),
    (
        "017_child_completion_barrier.sql",
        "71613d11afafec91b591edd51d2ce4db4dd6e5e493b637cb9f5acd06f60d1406",
    ),
    (
        "018_llm_behaviour.sql",
        "28911e0e88e3e770b67e6c5f31d8195457a538f51f8b915f3cdcd3cf041518a8",
    ),
    (
        "019_control_pool_expansion.sql",
        "f6a373df296390984ce0a93b5168fba1db821ddc31a13c22e0327fff2ab45f52",
    ),
    (
        "020_codex_source_routes.sql",
        "47688897a5f9ef35b15eaf4ef3a9cf3406e64cfcd9d6317e6d29596f10d7fad9",
    ),
    (
        "021_slot_session_rebind.sql",
        "8035a0f3e1e0d878e47135fca5eb430cbcad8876ba66e6fdd37bed0bcdd9785a",
    ),
    (
        "022_child_barrier_generation.sql",
        "81e34119c520301d5e2b4e9413a7e81e01e2facbd60d17bf48b5ac07a92c4c46",
    ),
    (
        "023_descendant_budget.sql",
        "0b3a409459fa83f190c88a46cc7f77cf1c22bfe247a33c93a01f117cae9e3574",
    ),
    (
        "024_completed_transcript_archive.sql",
        "7403ae615b4ab1830ab18ddb5428f57a55eaabfbe87ab09d8a793844ba4077ff",
    ),
    (
        "025_callback_delivery_reconciliation.sql",
        "a0780e59e6defb105d7b2b59e42748f82cd5d4bb8ffb84d6b396b68ccebf4742",
    ),
    (
        "026_source_inbox_read_indexes.sql",
        "8a952ae367e6633ad21426a62bcafb277033a08e2e1098413afb86af99081133",
    ),
    (
        "027_persistent_session_close.sql",
        "bd76baf14e65710cd97afcb79abdebb642a75ffe365587948cd2e6dac575e521",
    ),
)
_PROVISIONAL_TABLE_SQL = """CREATE TABLE opencode_provisional_sessions (
    transport_id TEXT PRIMARY KEY,
    work_id TEXT NOT NULL,
    pool TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    completion_registration_id TEXT NOT NULL,
    callback_registration_id TEXT NOT NULL,
    title TEXT NOT NULL UNIQUE,
    session_id TEXT UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('intended','bound','cleanup','consumed','cleaned','attention')),
    error TEXT,
    claim_token TEXT,
    claim_started_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)"""
_PROVISIONAL_TRIGGER_SQL = """CREATE TRIGGER opencode_provisional_binding_is_immutable
BEFORE UPDATE OF session_id ON opencode_provisional_sessions
WHEN OLD.session_id IS NOT NULL AND NEW.session_id IS NOT OLD.session_id
BEGIN
    SELECT RAISE(ABORT, 'provisional isolated session binding is immutable');
END"""
_PROVISIONAL_SCHEMA = (
    (
        "index", "sqlite_autoindex_opencode_provisional_sessions_1",
        "opencode_provisional_sessions", None,
    ),
    (
        "index", "sqlite_autoindex_opencode_provisional_sessions_2",
        "opencode_provisional_sessions", None,
    ),
    (
        "index", "sqlite_autoindex_opencode_provisional_sessions_3",
        "opencode_provisional_sessions", None,
    ),
    (
        "table", "opencode_provisional_sessions",
        "opencode_provisional_sessions", _PROVISIONAL_TABLE_SQL,
    ),
    (
        "trigger", "opencode_provisional_binding_is_immutable",
        "opencode_provisional_sessions", _PROVISIONAL_TRIGGER_SQL,
    ),
)


class ProjectionBudgetExceeded(RuntimeError):
    """The read projection exceeded its deterministic work budget."""


class ProjectionDataInvalid(RuntimeError):
    """The durable projection contained an invalid bounded value."""


@dataclass(slots=True)
class _ProjectionBudget:
    deadline_ns: int
    max_vm_steps: int
    vm_steps: int = 0
    exhausted: bool = False

    def progress(self) -> int:
        self.vm_steps += _PROGRESS_GRANULARITY
        if self.vm_steps > self.max_vm_steps or time.monotonic_ns() > self.deadline_ns:
            self.exhausted = True
            return 1
        return 0

    def check(self) -> None:
        if self.exhausted or time.monotonic_ns() > self.deadline_ns:
            self.exhausted = True
            raise ProjectionBudgetExceeded("cockpit_projection_budget_exhausted")


@dataclass(frozen=True, slots=True)
class Snapshot:
    """An immutable materialization of all public controller state tables."""

    tables: Mapping[str, tuple[Mapping[str, Any], ...]]

    def rows(self, table: str) -> tuple[Mapping[str, Any], ...]:
        return self.tables[table]


class ReadOnlySnapshot:
    """Capture state through a live store's identity-bound read connection."""

    def __init__(self, store: RigStore):
        if not isinstance(store, RigStore):
            raise TypeError("ReadOnlySnapshot requires a live RigStore")
        self._store = store
        self._database_identity = store._database_identity
        self._serialization_lock = store._serialization_lock

    def capture(self) -> Snapshot:
        with self._serialization_lock:
            self._store.runtime.assert_open_identity(self._database_identity)
            database = self._store.path.resolve(strict=True)
            self._store.runtime.assert_open_identity(self._database_identity)
            uri = f"{database.as_uri()}?mode=ro"
            connection = sqlite3.connect(uri, uri=True, isolation_level=None)
            connection.row_factory = sqlite3.Row
            try:
                self._store.runtime.assert_open_identity(self._database_identity)
                connection.execute("PRAGMA query_only = ON")
                if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
                    raise RuntimeError("SQLite query-only mode was not enabled")
                connection.execute("BEGIN")
                materialized: dict[str, tuple[Mapping[str, Any], ...]] = {}
                for table in _TABLES:
                    order_by = (
                        "sequence" if table in {"events", "work_queue"} else "rowid"
                    )
                    rows = connection.execute(
                        f'SELECT * FROM "{table}" ORDER BY {order_by}'
                    ).fetchall()
                    materialized[table] = tuple(
                        MappingProxyType(self._public_row(table, dict(row)))
                        for row in rows
                    )
                self._store.runtime.assert_open_identity(self._database_identity)
                connection.rollback()
            finally:
                connection.close()
        return Snapshot(MappingProxyType(materialized))

    @staticmethod
    def _public_row(table: str, row: dict[str, Any]) -> dict[str, Any]:
        """Keep dispatch payload and adapter output outside public projections."""
        private_columns = {
            "transport_deliveries": {"payload_json"},
            "transport_attempts": {"output_json"},
        }.get(table, set())
        for column in private_columns:
            if row.get(column) is not None:
                row[column] = "<redacted>"
        return row


class _CockpitSnapshotProjection:
    """Build a bounded cockpit projection on rigd's existing DB transaction."""

    def __init__(
        self,
        *,
        topology: OpenCodeTopology | None = None,
        callback_adapter_configured: bool = False,
        include_agent_lifecycle: bool = True,
        deadline_seconds: float = _DEFAULT_DEADLINE_SECONDS,
        max_vm_steps: int = _DEFAULT_MAX_VM_STEPS,
    ):
        if topology is not None and type(topology) is not OpenCodeTopology:
            raise TypeError("validated OpenCodeTopology required")
        if type(callback_adapter_configured) is not bool:
            raise TypeError("callback adapter configured state must be boolean")
        if type(include_agent_lifecycle) is not bool:
            raise TypeError("agent lifecycle projection switch must be boolean")
        if (
            type(deadline_seconds) not in {int, float}
            or not 0 < deadline_seconds <= 5
        ):
            raise ValueError("deadline_seconds must be between 0 and 5")
        if type(max_vm_steps) is not int or not 1 <= max_vm_steps <= _SIGNED_64_MAX:
            raise ValueError("max_vm_steps must be a positive signed-64 integer")
        self.deadline_seconds = float(deadline_seconds)
        self.max_vm_steps = max_vm_steps
        self.topology = topology
        self.callback_adapter_configured = callback_adapter_configured
        self.include_agent_lifecycle = include_agent_lifecycle

    @staticmethod
    def _text(value: object, *, limit: int = _MAX_TEXT_CODEPOINTS) -> str | None:
        if not isinstance(value, str):
            return None
        if len(value) <= limit:
            return value
        return value[: max(0, limit - 1)] + "…"

    @staticmethod
    def _lookup_identity(value: object) -> str | None:
        """Preserve durable identifiers exactly; only rendered copies are bounded."""
        return value if isinstance(value, str) else None

    @staticmethod
    def _integer(value: object) -> int:
        if type(value) is not int or not 0 <= value <= _SIGNED_64_MAX:
            raise ProjectionDataInvalid("cockpit_projection_invalid_durable_integer")
        return value

    @staticmethod
    def _unavailable(reason: str) -> dict[str, object]:
        return {"status": "unavailable", "reason": reason}

    @staticmethod
    def _event_timestamp(value: object) -> str:
        if isinstance(value, str) and value:
            if value.isdigit():
                value = int(value)
            else:
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    return "1970-01-01T00:00:00Z"
                if parsed.tzinfo is None:
                    return "1970-01-01T00:00:00Z"
                return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")
        if type(value) is int and 0 <= value <= _SIGNED_64_MAX:
            return datetime.fromtimestamp(value / 1_000_000, UTC).isoformat().replace("+00:00", "Z")
        return "1970-01-01T00:00:00Z"

    @classmethod
    def _callback_reason(cls, callback: sqlite3.Row | None) -> str | None:
        if callback is None:
            return None
        durable = cls._text(callback["disabled_reason"]) or cls._text(
            callback["attention_reason"]
        )
        if durable != "callback_adapter_disabled":
            return durable
        if cls._text(callback["route_state"]) == "registered":
            return "awaiting_exact_release"
        if callback["local_route_id"] is None:
            return "local_codex_route_missing"
        return None

    def _recent_activity(
        self,
        connection: sqlite3.Connection,
        budget: _ProjectionBudget,
    ) -> dict[str, Any]:
        """Project a bounded metadata-only activity window and agent recency index."""

        rows = connection.execute(
            """SELECT sequence, aggregate_type, aggregate_id, event_type,
                      payload_json, occurred_at
               FROM events ORDER BY sequence DESC LIMIT 200"""
        ).fetchall()
        budget.check()
        assignment_by_id: dict[str, tuple[str, str]] = {}
        slot_by_work: dict[str, str] = {}
        for row in connection.execute(
            """SELECT id, work_id, slot_id FROM scheduler_assignments
               ORDER BY sequence DESC LIMIT 200"""
        ).fetchall():
            work_id = str(row["work_id"])
            assignment_by_id[str(row["id"])] = (work_id, str(row["slot_id"]))
            slot_by_work.setdefault(work_id, str(row["slot_id"]))
        budget.check()
        work_by_transport = {
            str(row["id"]): str(row["work_id"])
            for row in connection.execute(
                """SELECT id, work_id FROM transport_deliveries
                   ORDER BY created_at DESC LIMIT 200"""
            ).fetchall()
        }
        work_by_route = {
            str(row["id"]): str(row["work_id"])
            for row in connection.execute(
                """SELECT id, work_id FROM return_routes
                   ORDER BY created_at_us DESC LIMIT 200"""
            ).fetchall()
        }
        work_by_completion = {
            str(row["id"]): str(row["work_id"])
            for row in connection.execute(
                """SELECT id, work_id FROM completion_events
                   ORDER BY received_at_us DESC LIMIT 200"""
            ).fetchall()
        }
        work_by_callback = {
            str(row["id"]): str(row["work_id"])
            for row in connection.execute(
                """SELECT callback.id, completion.work_id
                   FROM callbacks AS callback
                   JOIN completion_events AS completion
                     ON completion.id = callback.completion_event_id
                   ORDER BY callback.created_at_us DESC LIMIT 200"""
            ).fetchall()
        }
        source_by_work = {
            str(row["work_id"]): str(row["thread_id"])
            for row in connection.execute(
                """SELECT route.work_id, local.thread_id
                   FROM local_codex_return_routes AS local
                   JOIN return_routes AS route ON route.id = local.return_route_id
                   ORDER BY local.created_at_us DESC LIMIT 200"""
            ).fetchall()
        }
        budget.check()

        agent_recency: dict[str, tuple[int, str]] = {}
        items: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(str(row["payload_json"]))
            except (TypeError, ValueError):
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            aggregate_type = str(row["aggregate_type"])
            aggregate_id = str(row["aggregate_id"])
            work_id = payload.get("work_id") if isinstance(payload.get("work_id"), str) else None
            slot_id = payload.get("slot_id") if isinstance(payload.get("slot_id"), str) else None
            if aggregate_type == "scheduler_work":
                work_id = aggregate_id
            elif aggregate_type == "scheduler_assignment":
                assignment = assignment_by_id.get(aggregate_id)
                if assignment is not None:
                    work_id, slot_id = assignment
            elif aggregate_type in {"transport", "opencode_delivery", "completion_child_barrier"}:
                work_id = work_by_transport.get(aggregate_id, work_id)
            elif aggregate_type == "return_route":
                work_id = work_by_route.get(aggregate_id, work_id)
            elif aggregate_type == "completion":
                work_id = work_by_completion.get(aggregate_id, work_id)
            elif aggregate_type == "callback":
                work_id = work_by_callback.get(aggregate_id, work_id)
            if slot_id is None and work_id is not None:
                slot_id = slot_by_work.get(work_id)
            source_id = source_by_work.get(work_id) if work_id is not None else None
            event_type = self._text(row["event_type"]) or "event"
            sequence = self._integer(row["sequence"])
            occurred_at = self._event_timestamp(row["occurred_at"])
            callback_flow = event_type.startswith(("completion.", "callback."))
            if callback_flow:
                origin = slot_id or "fugue"
                destination = f"source:{source_id}" if source_id else "source"
            else:
                origin = f"source:{source_id}" if source_id else "source"
                destination = slot_id or "fugue"
            for agent_id in (slot_id, f"source:{source_id}" if source_id else None):
                if agent_id is not None and agent_id not in agent_recency:
                    agent_recency[agent_id] = (sequence, occurred_at)
            if len(items) < 12:
                items.append(
                    {
                        "sequence": sequence,
                        "event_type": event_type,
                        "origin": origin,
                        "destination": destination,
                        "occurred_at": occurred_at,
                    }
                )
        return {
            "status": "available",
            "window_events": 200,
            "agents": [
                {
                    "agent_id": agent_id,
                    "last_sequence": details[0],
                    "last_occurred_at": details[1],
                }
                for agent_id, details in sorted(
                    agent_recency.items(), key=lambda item: (-item[1][0], item[0])
                )[:64]
            ],
            "items": list(reversed(items)),
            "content_included": False,
        }

    def capture(self, connection: sqlite3.Connection) -> Mapping[str, Any]:
        """Capture on an already-open transaction; paths are never accepted."""
        if not isinstance(connection, sqlite3.Connection) or not connection.in_transaction:
            raise RuntimeError("an active rigd SQLite transaction is required")
        budget = _ProjectionBudget(
            deadline_ns=time.monotonic_ns()
            + int(self.deadline_seconds * 1_000_000_000),
            max_vm_steps=self.max_vm_steps,
        )
        prior_row_factory = connection.row_factory
        connection.row_factory = sqlite3.Row
        connection.set_progress_handler(budget.progress, _PROGRESS_GRANULARITY)
        try:
            try:
                projection = self._capture_transaction(connection, budget)
            except ProjectionBudgetExceeded:
                projection = self._degraded("cockpit_projection_budget_exhausted")
            except ProjectionDataInvalid as error:
                projection = self._degraded(str(error))
            except sqlite3.OperationalError:
                if not budget.exhausted:
                    raise
                projection = self._degraded("cockpit_projection_budget_exhausted")
        finally:
            connection.set_progress_handler(None, 0)
            connection.row_factory = prior_row_factory
        return self._finalize(projection)

    @staticmethod
    def _finalize(projection: Mapping[str, Any]) -> Mapping[str, Any]:
        digest_material = json.dumps(
            projection,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        version = dict(projection["snapshot_version"])
        version["digest"] = hashlib.sha256(digest_material).hexdigest()
        result = dict(projection)
        result["snapshot_version"] = version
        return result

    def _capture_transaction(
        self,
        connection: sqlite3.Connection,
        budget: _ProjectionBudget,
    ) -> dict[str, Any]:
        event_row = connection.execute(
            "SELECT sequence FROM events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        budget.check()
        migration_row = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1"
        ).fetchone()
        budget.check()
        provisional_attention_available = self._provisional_attention_available(
            connection,
            None if migration_row is None else migration_row[0],
            budget,
        )
        migration_version = None if migration_row is None else str(migration_row[0])
        expected_slot_count = (
            13
            if migration_version is not None
            and migration_version >= "019_control_pool_expansion.sql"
            else 11
        )

        slot_rows = connection.execute(
            """SELECT id, lane, position, state, active_assignment_id,
                      active_work_id, owner_id, attempt, fence_token
               FROM scheduler_slots
               ORDER BY CASE lane
                   WHEN 'tensorhost' THEN 0 WHEN 'homelab' THEN 1
                   WHEN 'personal' THEN 2 WHEN 'control' THEN 3 ELSE 4 END,
                   position, id LIMIT 14"""
        ).fetchmany(14)
        budget.check()
        slots: list[dict[str, Any]] = []
        workers: list[dict[str, Any]] = []
        edges: list[dict[str, str]] = []
        for row in slot_rows[:expected_slot_count]:
            budget.check()
            slot = {
                "slot_id": self._text(row["id"]),
                "lane": self._text(row["lane"]),
                "position": self._integer(row["position"]),
                "state": self._text(row["state"]),
                "assignment_id": self._lookup_identity(row["active_assignment_id"]),
                "work_id": self._lookup_identity(row["active_work_id"]),
            }
            slots.append(slot)
            worker = self._worker(connection, row, budget)
            workers.append(worker)
            for target, kind in (
                (worker.get("work_id"), "runs"),
                (worker.get("transport", {}).get("id"), "transport"),
                (worker.get("completion", {}).get("id"), "completion"),
                (worker.get("recovery", {}).get("target_id"), "recovery"),
            ):
                if isinstance(target, str):
                    edges.append(
                        {
                            "from": str(worker["slot_id"]),
                            "to": target,
                            "kind": kind,
                        }
                    )

        subagents: list[dict[str, Any]] = []
        if self.include_agent_lifecycle and migration_version is not None and migration_version >= "017_child_completion_barrier.sql":
            child_rows = connection.execute(
                """WITH ranked_children AS (
                       SELECT child.child_session_id, child.parent_session_id,
                              child.state, child.updated_at, barrier.work_id,
                              backend.slot_id, backend.assignment_generation,
                              (
                                  SELECT MAX(latest.assignment_generation)
                                  FROM opencode_deliveries AS latest
                                  WHERE latest.slot_id = backend.slot_id
                                    AND latest.delivery_state = 'accepted'
                              ) AS latest_parent_generation,
                              ROW_NUMBER() OVER (
                                  PARTITION BY backend.slot_id,
                                               child.child_session_id
                                  ORDER BY backend.assignment_generation DESC,
                                           child.updated_at DESC,
                                           child.transport_id DESC
                              ) AS contact_rank
                       FROM completion_child_sessions AS child
                       JOIN completion_child_barriers AS barrier
                         ON barrier.transport_id = child.transport_id
                       JOIN opencode_deliveries AS backend
                         ON backend.transport_id = child.transport_id
                   )
                   SELECT child_session_id, parent_session_id, state,
                          updated_at, work_id, slot_id, assignment_generation
                   FROM ranked_children
                   WHERE contact_rank = 1
                     AND (
                         state = 'waiting'
                         OR latest_parent_generation IS NULL
                         OR latest_parent_generation - assignment_generation < 2
                     )
                   ORDER BY updated_at DESC, child_session_id
                   LIMIT ?""",
                (_MAX_GRAPH_SUBAGENTS + 1,),
            ).fetchmany(_MAX_GRAPH_SUBAGENTS + 1)
            budget.check()
            visible_child_rows = child_rows[:_MAX_GRAPH_SUBAGENTS]
            child_identities = {
                str(row["child_session_id"]): self._lookup_identity(
                    row["child_session_id"]
                )
                for row in visible_child_rows
            }
            for row in visible_child_rows:
                child_id = child_identities.get(str(row["child_session_id"]))
                parent_slot_id = self._text(row["slot_id"])
                if child_id is None or parent_slot_id is None:
                    continue
                parent_session_id = self._lookup_identity(row["parent_session_id"])
                subagents.append(
                    {
                        "id": child_id,
                        "parent_session_id": parent_session_id,
                        "parent_slot_id": parent_slot_id,
                        "parent_work_id": self._lookup_identity(row["work_id"]),
                        "state": self._text(row["state"]) or "waiting",
                        "updated_at": self._text(row["updated_at"]) or "unavailable",
                    }
                )
                edges.append(
                    {
                        "from": child_identities.get(
                            str(row["parent_session_id"])
                        ) or parent_slot_id,
                        "to": child_id,
                        "kind": "delegates",
                    }
                )

        queue_rows = connection.execute(
            """SELECT id, sequence, queue_order, lane, state, policy_allowed,
                      attempt, enqueued_at
               FROM scheduler_work WHERE state = 'queued'
               ORDER BY queue_order, sequence, id LIMIT ?""",
            (_MAX_COLLECTION_ITEMS + 1,),
        ).fetchmany(_MAX_COLLECTION_ITEMS + 1)
        budget.check()
        queue_truncated = len(queue_rows) > _MAX_COLLECTION_ITEMS
        queue_items = [
            {
                "work_id": self._lookup_identity(row["id"]),
                "sequence": self._integer(row["sequence"]),
                "queue_order": self._integer(row["queue_order"]),
                "lane": self._text(row["lane"]),
                "state": self._text(row["state"]),
                "policy": (
                    "pending"
                    if row["policy_allowed"] is None
                    else "allowed" if bool(row["policy_allowed"]) else "rejected"
                ),
                "attempt": self._integer(row["attempt"]),
                "enqueued_at": self._text(row["enqueued_at"]),
            }
            for row in queue_rows[:_MAX_COLLECTION_ITEMS]
        ]

        automatic, automatic_truncated = self._automatic_attention(
            connection, budget
        )
        operator, operator_truncated = self._operator_attention(
            connection, budget, provisional_attention_available
        )
        topology_errors: list[str] = []
        if len(slot_rows) != expected_slot_count:
            topology_errors.append(
                f"durable_topology_is_not_exactly_{expected_slot_count}_slots"
            )
        worker_graph: dict[str, Any] = {
            "workers": workers,
            "edges": sorted(
                edges,
                key=lambda edge: (edge["from"], edge["kind"], edge["to"]),
            ),
        }
        if self.include_agent_lifecycle:
            worker_graph["subagents"] = subagents
        recent_activity = (
            self._recent_activity(connection, budget)
            if self.include_agent_lifecycle
            else None
        )
        transcript_archive = None
        if (
            self.include_agent_lifecycle
            and migration_version is not None
            and migration_version >= "024_completed_transcript_archive.sql"
        ):
            archive_rows = connection.execute(
                """SELECT archive.result_ref, archive.slot_id, archive.work_id,
                          archive.generation, result.outcome, archive.captured_at_us,
                          archive.turn_count, archive.redaction_count
                   FROM completed_transcript_snapshots AS archive
                   JOIN completion_results AS result
                     ON result.result_ref = archive.result_ref
                   ORDER BY archive.captured_at_us DESC, archive.result_ref DESC
                   LIMIT 13"""
            ).fetchmany(13)
            budget.check()
            archive_truncated = len(archive_rows) > 12
            archive_items = [
                {
                    "archive_id": self._lookup_identity(row["result_ref"]),
                    "slot_id": self._text(row["slot_id"]),
                    "work_id": self._lookup_identity(row["work_id"]),
                    "generation": self._integer(row["generation"]),
                    "outcome": self._text(row["outcome"]),
                    "captured_at_us": self._integer(row["captured_at_us"]),
                    "turn_count": self._integer(row["turn_count"]),
                    "redaction_count": self._integer(row["redaction_count"]),
                }
                for row in archive_rows[:12]
            ]
            transcript_archive = {
                "status": "available",
                "items": archive_items,
                "total": len(archive_items) if not archive_truncated else None,
                "total_status": "exact" if not archive_truncated else "capped",
                "lower_bound": len(archive_items) + int(archive_truncated),
                "truncated": archive_truncated,
                "content_included": False,
            }
        projection = {
            "projection_version": 1,
            "snapshot_version": {
                "event_sequence": (
                    0 if event_row is None else self._integer(event_row[0])
                ),
                "migration_version": (
                    "unavailable" if migration_row is None else self._text(migration_row[0])
                ),
            },
            "availability": {
                "status": "available" if not topology_errors else "degraded",
                "errors": topology_errors,
            },
            "topology": {
                "lanes": list(_LANES),
                "expected_slots": expected_slot_count,
                "observed_slots": min(len(slot_rows), expected_slot_count),
                "observed_status": (
                    "exact" if len(slot_rows) == expected_slot_count else "capped"
                ),
            },
            "slots": slots,
            "worker_graph": worker_graph,
            "queue": {
                "status": "available",
                "items": queue_items,
                "total": len(queue_items) if not queue_truncated else None,
                "total_status": "exact" if not queue_truncated else "capped",
                "lower_bound": len(queue_items) + int(queue_truncated),
                "truncated": queue_truncated,
            },
            "attention": {
                "automatic_recovery": {
                    "status": "available",
                    "items": automatic,
                    "total": len(automatic) if not automatic_truncated else None,
                    "total_status": "exact" if not automatic_truncated else "capped",
                    "lower_bound": len(automatic) + int(automatic_truncated),
                    "truncated": automatic_truncated,
                },
                "operator_required": {
                    "status": "available",
                    "items": operator,
                    "total": len(operator) if not operator_truncated else None,
                    "total_status": "exact" if not operator_truncated else "capped",
                    "lower_bound": len(operator) + int(operator_truncated),
                    "truncated": operator_truncated,
                },
            },
            "metrics": {
                "token_total": self._unavailable("no_durable_token_samples"),
                "token_rate_5m": self._unavailable("no_durable_token_samples"),
            },
            "recent_turns": {
                "status": "unavailable",
                "reason": "privacy_safe_turn_metadata_not_recorded",
                "limit": 2,
                "items": [],
                "content_included": False,
            },
            "refresh": {"mode": "explicit", "polling": "disabled"},
        }
        if recent_activity is not None:
            projection["recent_activity"] = recent_activity
        if transcript_archive is not None:
            projection["transcript_archive"] = transcript_archive
        return projection

    def _degraded(self, reason: str) -> dict[str, Any]:
        slots: list[dict[str, Any]] = []
        workers: list[dict[str, Any]] = []
        lane_sizes = {"tensorhost": 3, "homelab": 3, "personal": 3,
                      "control": 3, "hands-off": 1}
        for lane in _LANES:
            for position in range(1, lane_sizes[lane] + 1):
                slot_id = f"{lane}-{position}"
                slots.append(
                    {
                        "slot_id": slot_id,
                        "lane": lane,
                        "position": position,
                        "state": "unavailable",
                        "assignment_id": None,
                        "work_id": None,
                    }
                )
                workers.append(self._unavailable_worker(slot_id, lane, position, reason))
        unavailable_collection = {
            "status": "unavailable",
            "items": [],
            "total": None,
            "total_status": "unknown",
            "lower_bound": 0,
            "truncated": False,
        }
        projection = {
            "projection_version": 1,
            "snapshot_version": {
                "event_sequence": None,
                "migration_version": "unavailable",
            },
            "availability": {"status": "unavailable", "errors": [reason]},
            "topology": {
                "lanes": list(_LANES),
                "expected_slots": 13,
                "observed_slots": None,
                "observed_status": "unknown",
            },
            "slots": slots,
            "worker_graph": {
                "workers": workers,
                **({"subagents": []} if self.include_agent_lifecycle else {}),
                "edges": [],
            },
            "queue": dict(unavailable_collection),
            "attention": {
                "automatic_recovery": dict(unavailable_collection),
                "operator_required": dict(unavailable_collection),
            },
            "metrics": {
                "token_total": self._unavailable(reason),
                "token_rate_5m": self._unavailable(reason),
            },
            "recent_turns": {
                "status": "unavailable",
                "reason": reason,
                "limit": 2,
                "items": [],
                "content_included": False,
            },
            "refresh": {"mode": "explicit", "polling": "disabled"},
        }
        if self.include_agent_lifecycle:
            projection["recent_activity"] = {
                "status": "unavailable",
                "window_events": 200,
                "agents": [],
                "items": [],
                "content_included": False,
            }
        return projection

    def _unavailable_worker(
        self,
        slot_id: str,
        lane: str,
        position: int,
        reason: str,
    ) -> dict[str, Any]:
        worker = {
            "slot_id": slot_id,
            "lane": lane,
            "position": position,
            "slot_state": "unavailable",
            "display_name": f"session:unavailable · {slot_id}",
            "session": {"status": "unavailable", "ref": None},
            "pane": {"status": "unavailable", "ref": None},
            "work_id": None,
            "source_id": None,
            "agent_lifecycle": None,
            "owner_id": None,
            "assignment_id": None,
            "attempt": None,
            "transport": {
                "status": "unavailable",
                "reason": reason,
                "id": None,
                "state": "unavailable",
                "generation": None,
                "acknowledgement_id": None,
                "error_code": None,
                "adapter": {
                    "status": "unavailable",
                    "kind": None,
                    "reason": reason,
                },
            },
            "completion": {
                "status": "unavailable",
                "reason": reason,
                "id": None,
                "registration_state": "unavailable",
                "route_state": "unavailable",
                "callback_state": "unavailable",
                "callback_adapter": {"status": "unavailable", "reason": reason},
            },
            "recovery": {
                "status": "unavailable",
                "reason": reason,
                "target_id": None,
                "phase": "unavailable",
                "circuit_state": "unavailable",
                "episode_state": "unavailable",
                "timer_state": "unavailable",
            },
            "recent_turns": {
                "status": "unavailable",
                "reason": reason,
                "limit": 2,
                "items": [],
                "content_included": False,
            },
        }
        if not self.include_agent_lifecycle:
            worker.pop("agent_lifecycle")
            worker.pop("source_id")
        return worker

    def _worker(
        self,
        connection: sqlite3.Connection,
        slot: sqlite3.Row,
        budget: _ProjectionBudget,
    ) -> dict[str, Any]:
        budget.check()
        slot_id = self._text(slot["id"]) or "unavailable"
        raw_work_id = self._lookup_identity(slot["active_work_id"])
        raw_owner_id = self._lookup_identity(slot["owner_id"])
        display_work_id = self._text(raw_work_id)
        agent_lifecycle = None
        if raw_work_id is not None and self.include_agent_lifecycle:
            lifecycle = connection.execute(
                """SELECT agent_lifecycle
                   FROM scheduler_admission_decisions
                   WHERE work_id = ? ORDER BY id DESC LIMIT 1""",
                (raw_work_id,),
            ).fetchone()
            budget.check()
            if lifecycle is not None:
                candidate = self._text(lifecycle["agent_lifecycle"])
                if candidate in {"disposable", "persistent"}:
                    agent_lifecycle = candidate
        session = None
        pane = None
        if raw_owner_id is not None:
            session = connection.execute(
                """SELECT id, session_ref FROM session_bindings
                   WHERE operation_id = ? AND state = 'active'
                   ORDER BY bound_at DESC, id LIMIT 1""",
                (raw_owner_id,),
            ).fetchone()
            budget.check()
            if session is not None:
                pane = connection.execute(
                    """SELECT pane_ref FROM pane_bindings
                       WHERE session_binding_id = ? AND state = 'active'
                       ORDER BY bound_at DESC, id LIMIT 1""",
                    (session["id"],),
                ).fetchone()
                budget.check()
        session_ref = self._text(session["session_ref"]) if session is not None else None
        pane_ref = self._text(pane["pane_ref"]) if pane is not None else None
        if raw_work_id is not None:
            execution_session = connection.execute(
                """SELECT coalesce(opencode.isolated_session_id, opencode.session_id)
                             AS session_ref
                   FROM opencode_deliveries AS opencode
                   JOIN transport_deliveries AS delivery
                     ON delivery.id = opencode.transport_id
                    AND delivery.work_id = opencode.work_id
                   JOIN scheduler_assignments AS assignment
                     ON assignment.id = delivery.assignment_id
                    AND assignment.work_id = delivery.work_id
                    AND assignment.attempt = delivery.assignment_attempt
                   WHERE assignment.slot_id = ? AND opencode.work_id = ?
                     AND opencode.delivery_state IN ('accepted','delivery_unknown')
                     AND opencode.lease_state = 'active'
                     AND assignment.state = 'active'
                   ORDER BY delivery.assignment_attempt DESC, delivery.id DESC
                   LIMIT 1""",
                (slot_id, raw_work_id),
            ).fetchone()
            budget.check()
            if execution_session is not None:
                session_ref = self._text(execution_session["session_ref"])
        configured_session_ref = None
        if raw_work_id is None and self.topology is not None:
            configured_slot = next(
                (
                    member
                    for members in self.topology.pools.values()
                    for member in members
                    if member.slot_id == slot_id
                ),
                None,
            )
            if configured_slot is not None:
                configured_session_ref = configured_slot.session_id
                session_ref = configured_session_ref
        display_name = (
            f"{session_ref or 'session:unavailable'} · {display_work_id or slot_id}"
            if raw_work_id is not None
            else f"{session_ref or 'session:unavailable'} · {slot_id}"
        )

        transport = None
        source_id = None
        active_assignment_id = self._lookup_identity(slot["active_assignment_id"])
        active_attempt = None if slot["attempt"] is None else self._integer(slot["attempt"])
        active_fence = self._lookup_identity(slot["fence_token"])
        if (
            raw_work_id is not None
            and active_assignment_id is not None
            and isinstance(active_attempt, int)
            and active_fence is not None
            and raw_owner_id is not None
        ):
            transport = connection.execute(
                """SELECT delivery.id, delivery.state,
                          coalesce(selection.adapter_kind, delivery.adapter_kind)
                              AS adapter_kind,
                          delivery.assignment_attempt,
                          delivery.acknowledgement_id, delivery.error_code,
                          opencode.assignment_generation AS opencode_generation
                   FROM transport_deliveries AS delivery
                   JOIN scheduler_assignments AS assignment
                     ON assignment.id = delivery.assignment_id
                    AND assignment.work_id = delivery.work_id
                    AND assignment.slot_id = ?
                    AND assignment.owner_id = delivery.owner_id
                    AND assignment.attempt = delivery.assignment_attempt
                    AND assignment.fence_token = delivery.assignment_fence
                    AND assignment.state = 'active'
                   JOIN scheduler_work AS work
                     ON work.id = delivery.work_id
                    AND work.state = 'assigned'
                    AND work.active_assignment_id = assignment.id
                   LEFT JOIN transport_adapter_selections AS selection
                     ON selection.transport_id = delivery.id
                   LEFT JOIN opencode_deliveries AS opencode
                     ON opencode.transport_id = delivery.id
                    AND opencode.work_id = delivery.work_id
                   WHERE delivery.work_id = ?
                     AND delivery.assignment_id = ?
                     AND delivery.assignment_attempt = ?
                     AND delivery.assignment_fence = ?
                     AND delivery.owner_id = ?
                   LIMIT 1""",
                (
                    slot_id,
                    raw_work_id,
                    active_assignment_id,
                    active_attempt,
                    active_fence,
                    raw_owner_id,
                ),
            ).fetchone()
            budget.check()
        transport_view: dict[str, Any]
        completion_view: dict[str, Any]
        configured_idle = raw_work_id is None and configured_session_ref is not None
        if transport is None:
            transport_view = {
                "status": "available" if configured_idle else "unavailable",
                "reason": None if configured_idle else "no_durable_transport",
                "id": None,
                "state": "idle" if configured_idle else "unavailable",
                "generation": None,
                "acknowledgement_id": None,
                "error_code": None,
                "adapter": {
                    "status": "available" if configured_idle else "unavailable",
                    "kind": "opencode-http-sse-v1" if configured_idle else None,
                    "reason": None if configured_idle else "no_durable_transport",
                },
            }
            completion_view = {
                "status": "available" if configured_idle else "unavailable",
                "reason": (
                    None if configured_idle else "no_durable_completion_registration"
                ),
                "id": None,
                "registration_state": (
                    "not-applicable" if configured_idle else "unavailable"
                ),
                "route_state": "not-applicable" if configured_idle else "unavailable",
                "callback_state": "not-applicable" if configured_idle else "unavailable",
                "callback_adapter": {
                    "status": (
                        "available" if self.callback_adapter_configured else "disabled"
                    ),
                    "reason": (
                        None
                        if self.callback_adapter_configured
                        else "callback_adapter_disabled"
                    ),
                },
            }
            generation = (
                None
                if slot["attempt"] is None
                else self._integer(slot["attempt"])
            )
        else:
            transport_id = transport["id"]
            completion = connection.execute(
                """SELECT id, state FROM transport_completion_registrations
                   WHERE transport_id = ? LIMIT 1""",
                (transport_id,),
            ).fetchone()
            budget.check()
            route = connection.execute(
                """SELECT route.id, route.state, route.route_kind,
                          local.thread_id AS source_id
                   FROM return_routes AS route
                   LEFT JOIN local_codex_return_routes AS local
                     ON local.return_route_id = route.id
                   WHERE route.transport_id = ? LIMIT 1""",
                (transport_id,),
            ).fetchone()
            budget.check()
            if route is not None:
                source_id = self._lookup_identity(route["source_id"])
            callback = connection.execute(
                """SELECT callback.state, callback.attention_reason,
                          outbox.disabled_reason, route.state AS route_state,
                          local.return_route_id AS local_route_id
                   FROM callbacks AS callback
                   JOIN return_routes AS route ON route.id = callback.return_route_id
                   LEFT JOIN outbox ON outbox.callback_id = callback.id
                   LEFT JOIN local_codex_return_routes AS local
                     ON local.return_route_id = route.id
                   WHERE route.transport_id = ? LIMIT 1""",
                (transport_id,),
            ).fetchone()
            budget.check()
            transport_view = {
                "status": "available",
                "reason": None,
                "id": self._lookup_identity(transport_id),
                "state": self._text(transport["state"]) or "unavailable",
                "generation": self._integer(
                    transport["opencode_generation"]
                    if transport["opencode_generation"] is not None
                    else transport["assignment_attempt"]
                ),
                "acknowledgement_id": self._text(transport["acknowledgement_id"]),
                "error_code": self._text(transport["error_code"]),
                "adapter": {
                    "status": (
                        "disabled"
                        if (self._text(transport["adapter_kind"]) or "disabled")
                        == "disabled"
                        else "available"
                    ),
                    "kind": self._text(transport["adapter_kind"]) or "disabled",
                    "reason": (
                        "transport_adapter_disabled"
                        if (self._text(transport["adapter_kind"]) or "disabled")
                        == "disabled"
                        else None
                    ),
                },
            }
            completion_view = {
                "status": "available" if completion is not None else "unavailable",
                "reason": None if completion is not None else "missing_registration",
                "id": self._lookup_identity(completion["id"]) if completion is not None else None,
                "registration_state": (
                    self._text(completion["state"]) if completion is not None else "unavailable"
                ),
                "route_state": self._text(route["state"]) if route is not None else "unavailable",
                "callback_state": (
                    self._text(callback["state"]) if callback is not None else "unavailable"
                ),
                "callback_adapter": {
                    "status": (
                        "available" if self.callback_adapter_configured else "disabled"
                    ),
                    "reason": (
                        self._callback_reason(callback)
                        if self.callback_adapter_configured and callback is not None
                        else (
                            None
                            if self.callback_adapter_configured
                            else "callback_adapter_disabled"
                        )
                    ),
                },
            }
            generation = self._integer(transport["assignment_attempt"])

        recovery = None
        if raw_work_id is not None and isinstance(generation, int):
            recovery = connection.execute(
                """SELECT target.target_id, target.phase, target.circuit_state,
                          episode.state AS episode_state, timer.state AS timer_state
                   FROM recovery_targets AS target
                   LEFT JOIN recovery_episodes AS episode ON episode.id = target.episode_id
                   LEFT JOIN recovery_timers AS timer ON timer.id = target.current_timer_id
                   WHERE target.work_id = ? AND target.generation = ? LIMIT 1""",
                (raw_work_id, generation),
            ).fetchone()
            budget.check()
        recovery_view = (
            {
                "status": "available" if configured_idle else "unavailable",
                "reason": (
                    None if configured_idle else "no_durable_recovery_observation"
                ),
                "target_id": None,
                "phase": "not-applicable" if configured_idle else "unavailable",
                "circuit_state": (
                    "not-applicable" if configured_idle else "unavailable"
                ),
                "episode_state": (
                    "not-applicable" if configured_idle else "unavailable"
                ),
                "timer_state": (
                    "not-applicable" if configured_idle else "unavailable"
                ),
            }
            if recovery is None
            else {
                "status": "available",
                "reason": None,
                "target_id": self._lookup_identity(recovery["target_id"]),
                "phase": self._text(recovery["phase"]) or "unavailable",
                "circuit_state": self._text(recovery["circuit_state"]) or "unavailable",
                "episode_state": self._text(recovery["episode_state"]) or "unavailable",
                "timer_state": self._text(recovery["timer_state"]) or "unavailable",
            }
        )
        worker = {
            "slot_id": slot_id,
            "lane": self._text(slot["lane"]) or "unavailable",
            "position": self._integer(slot["position"]),
            "slot_state": self._text(slot["state"]) or "unavailable",
            "display_name": display_name,
            "session": {
                "status": "available" if session_ref is not None else "unavailable",
                "ref": session_ref,
            },
            "pane": {
                "status": "available" if pane_ref is not None else "unavailable",
                "ref": pane_ref,
            },
            "work_id": raw_work_id,
            "source_id": source_id,
            "agent_lifecycle": agent_lifecycle,
            "owner_id": raw_owner_id,
            "assignment_id": self._lookup_identity(slot["active_assignment_id"]),
            "attempt": (
                None if slot["attempt"] is None else self._integer(slot["attempt"])
            ),
            "transport": transport_view,
            "completion": completion_view,
            "recovery": recovery_view,
            "recent_turns": {
                "status": "unavailable",
                "reason": "privacy_safe_turn_metadata_not_recorded",
                "limit": 2,
                "items": [],
                "content_included": False,
            },
        }
        if not self.include_agent_lifecycle:
            worker.pop("agent_lifecycle")
            worker.pop("source_id")
        return worker

    def _automatic_attention(
        self,
        connection: sqlite3.Connection,
        budget: _ProjectionBudget,
    ) -> tuple[list[dict[str, Any]], bool]:
        rows = connection.execute(
            """SELECT id, target_id, work_id, generation, state, reason, attempts
               FROM recovery_episodes WHERE state = 'open'
               ORDER BY opened_at_us, id LIMIT ?""",
            (_MAX_COLLECTION_ITEMS + 1,),
        ).fetchmany(_MAX_COLLECTION_ITEMS + 1)
        budget.check()
        return (
            [
                {
                    "kind": "recovery_episode",
                    "id": self._text(row["id"]),
                    "target_id": self._text(row["target_id"]),
                    "work_id": self._text(row["work_id"]),
                    "generation": self._integer(row["generation"]),
                    "state": self._text(row["state"]),
                    "reason": self._text(row["reason"]),
                    "attempts": self._integer(row["attempts"]),
                }
                for row in rows[:_MAX_COLLECTION_ITEMS]
            ],
            len(rows) > _MAX_COLLECTION_ITEMS,
        )

    @staticmethod
    def _provisional_attention_available(
        connection: sqlite3.Connection,
        migration_version: object,
        budget: _ProjectionBudget,
    ) -> bool:
        migrations = tuple(
            tuple(row) for row in connection.execute(
                "SELECT version, checksum FROM schema_migrations ORDER BY version"
            ).fetchall()
        )
        budget.check()
        schema = tuple(
            tuple(row) for row in connection.execute(
                """SELECT type, name, tbl_name, sql FROM sqlite_master
                   WHERE tbl_name = 'opencode_provisional_sessions'
                      OR name = 'opencode_provisional_sessions'
                   ORDER BY type, name"""
            ).fetchall()
        )
        budget.check()
        historical_authority = _CANONICAL_MIGRATIONS[:10]
        cleanup_authority = _CANONICAL_MIGRATIONS[:12]
        provisional_authority = _CANONICAL_MIGRATIONS[:13]
        completion_authority = _CANONICAL_MIGRATIONS[:14]
        lifecycle_authority = _CANONICAL_MIGRATIONS[:15]
        cancelled_authority = _CANONICAL_MIGRATIONS[:16]
        barrier_authority = _CANONICAL_MIGRATIONS[:17]
        llm_authority = _CANONICAL_MIGRATIONS[:18]
        topology_authority = _CANONICAL_MIGRATIONS[:19]
        current_authority = _CANONICAL_MIGRATIONS
        if migrations in {historical_authority, cleanup_authority}:
            if migration_version != migrations[-1][0] or schema:
                raise ProjectionDataInvalid(
                    "cockpit_projection_provisional_schema_authority_invalid"
                )
            return False
        if (
            migrations not in {
                provisional_authority,
                completion_authority,
                lifecycle_authority,
                cancelled_authority,
                barrier_authority,
                llm_authority,
                topology_authority,
                current_authority,
            }
            or migration_version != migrations[-1][0]
            or schema != _PROVISIONAL_SCHEMA
        ):
            raise ProjectionDataInvalid(
                "cockpit_projection_provisional_schema_authority_invalid"
            )
        return True

    def _operator_attention(
        self,
        connection: sqlite3.Connection,
        budget: _ProjectionBudget,
        provisional_attention_available: bool,
    ) -> tuple[list[dict[str, Any]], bool]:
        entries: list[dict[str, Any]] = []
        queries = [
            (
                "recovery_attention",
                """SELECT id, work_id, generation, state, attention_reason AS reason
                   FROM recovery_episodes WHERE state = 'attention'
                   ORDER BY closed_at_us, id LIMIT ?""",
            ),
            (
                "callback_attention",
                """SELECT callback.id, completion.work_id, completion.generation,
                          callback.state, coalesce(callback.attention_reason,
                          outbox.disabled_reason) AS reason
                   FROM callbacks AS callback
                   JOIN completion_events AS completion
                     ON completion.id = callback.completion_event_id
                   LEFT JOIN outbox ON outbox.callback_id = callback.id
                   WHERE callback.state = 'attention'
                      OR (callback.state = 'blocked' AND coalesce(
                          callback.attention_reason, outbox.disabled_reason
                      ) = 'local_codex_route_missing')
                   ORDER BY callback.created_at_us, callback.id LIMIT ?""",
            ),
            (
                "transport_release_attention",
                """SELECT aggregate_id AS id,
                          json_extract(payload_json, '$.work_id') AS work_id,
                          json_extract(payload_json, '$.generation') AS generation,
                          json_extract(payload_json, '$.state') AS state,
                          json_extract(payload_json, '$.reason') AS reason
                   FROM events
                   WHERE aggregate_type = 'transport_release_attention'
                     AND event_type = 'transport.release_ownership_conflict'
                   ORDER BY sequence, event_id LIMIT ?""",
            ),
        ]
        if provisional_attention_available:
            queries.append(
                (
                    "provisional_session_attention",
                    """SELECT transport_id AS id, work_id, 0 AS generation,
                              state, error AS reason
                       FROM opencode_provisional_sessions
                       WHERE state = 'attention'
                       ORDER BY updated_at, transport_id LIMIT ?""",
                )
            )
        persistent_attention_available = connection.execute(
            """SELECT 1 FROM sqlite_master
               WHERE type = 'table' AND name = 'opencode_persistent_sessions'"""
        ).fetchone() is not None
        budget.check()
        if persistent_attention_available:
            queries.append(
                (
                    "persistent_session_attention",
                    """SELECT printf('persistent-%d', rowid) AS id,
                              NULL AS work_id, 0 AS generation, state, error AS reason
                       FROM opencode_persistent_sessions
                       WHERE state = 'attention'
                       ORDER BY updated_at, rowid LIMIT ?""",
                )
            )
        child_barrier_available = connection.execute(
            """SELECT 1 FROM sqlite_master
               WHERE type = 'table' AND name = 'completion_child_barriers'"""
        ).fetchone() is not None
        budget.check()
        if child_barrier_available:
            queries.append(
                (
                    "child_completion_attention",
                    """SELECT transport_id AS id, work_id, generation,
                              state, attention_reason AS reason
                       FROM completion_child_barriers
                       WHERE state = 'attention'
                       ORDER BY updated_at, transport_id LIMIT ?""",
                )
            )
        truncated = False
        for kind, query in queries:
            budget.check()
            remaining = _MAX_COLLECTION_ITEMS - len(entries)
            if remaining <= 0:
                row = connection.execute(query, (1,)).fetchone()
                budget.check()
                if row is not None:
                    truncated = True
                continue
            rows = connection.execute(query, (remaining + 1,)).fetchmany(remaining + 1)
            budget.check()
            if len(rows) > remaining:
                truncated = True
            entries.extend(
                {
                    "kind": kind,
                    "id": self._text(row["id"]),
                    "work_id": self._text(row["work_id"]),
                    "generation": self._integer(row["generation"]),
                    "state": self._text(row["state"]),
                    "reason": self._text(row["reason"]),
                }
                for row in rows[:remaining]
            )
        entries.sort(
            key=lambda item: (
                str(item.get("work_id") or ""),
                str(item.get("kind") or ""),
                str(item.get("id") or ""),
            )
        )
        return entries, truncated
