from __future__ import annotations

import copy
import json
import math
import sqlite3
import tempfile
import unittest
import unicodedata
from contextlib import closing
from pathlib import Path

from oc_rig.adapters.opencode import OpenCodeSlot, OpenCodeTopology
from oc_rig.cockpit import (
    normalize_snapshot,
    render_details,
    render_json,
    render_terminal,
)
from oc_rig.store import PrivateRuntimeDirectory, RigStore
from oc_rig.store.snapshot import _CockpitSnapshotProjection


def _display_width(value: str) -> int:
    return sum(
        0
        if unicodedata.combining(character)
        else 2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1
        for character in value
    )


class CockpitRenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name).resolve()
        root.chmod(0o700)
        store = RigStore(PrivateRuntimeDirectory(root / "state", root))
        store.initialize()
        with closing(sqlite3.connect(store.path, isolation_level=None)) as connection:
            connection.execute("BEGIN")
            self.snapshot = dict(_CockpitSnapshotProjection().capture(connection))
            connection.rollback()

    def test_clean_snapshot_keeps_operational_sections_visible(self) -> None:
        output = render_terminal(self.snapshot, width=100)
        self.assertIn("Fugue · ready", output)
        self.assertIn("Legend: ○ idle · ● active · ◆ queued · ⚠ issue", output)
        for label in ("TensorHost", "Home Lab", "Personal", "Control", "Hands-off"):
            self.assertIn(f"○ {label}", output)
        self.assertEqual(output.count("  ○ "), 5)
        self.assertIn("WORKER GRAPH\n  (no active workers)", output)
        self.assertIn("DISPATCH QUEUE (0)\n  empty", output)
        self.assertIn("ATTENTION", output)
        self.assertIn("automatic recovery: 0", output)
        self.assertIn("delivery attention: 0", output)
        self.assertIn("operator required: 0", output)
        self.assertIn("✓ nothing stalled, nothing needs you", output)
        self.assertIn("METRICS", output)
        self.assertIn("Tokens total: unavailable", output)
        self.assertIn("Token rate (5m): unavailable", output)
        self.assertIn("RECENT ACTIVITY", output)
        for hidden in (
            "session:",
            "transport=",
            "completion=",
            "recovery=",
            "Refresh:",
            "polling:",
            "ANSI:",
            "slots",
        ):
            self.assertNotIn(hidden, output)
        self.assertNotIn("\x1b", output)

    def test_interactive_colour_styles_only_renderer_owned_status_markers(self) -> None:
        coloured = render_terminal(self.snapshot, width=100, ansi=True)
        plain = render_terminal(self.snapshot, width=100, ansi=False)
        self.assertIn("\x1b[36m○\x1b[0m TensorHost", coloured)
        for code in ("\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[36m", "\x1b[0m"):
            coloured = coloured.replace(code, "")
        self.assertEqual(coloured, plain)

    def test_terminal_collapses_configured_clear_slots_under_worker_graph(self) -> None:
        sizes = {
            "tensorhost": 3,
            "homelab": 3,
            "personal": 3,
            "control": 3,
            "hands-off": 1,
        }
        counter = 0
        pools: dict[str, tuple[OpenCodeSlot, ...]] = {}
        for lane, size in sizes.items():
            members = []
            for position in range(1, size + 1):
                counter += 1
                members.append(
                    OpenCodeSlot(
                        f"{lane}-{position}",
                        f"configured-session-{counter}",
                        "secure-worker",
                    )
                )
            pools[lane] = tuple(members)
        root = Path(self.temporary.name).resolve()
        store = RigStore(PrivateRuntimeDirectory(root / "configured-state", root))
        store.initialize()
        with closing(sqlite3.connect(store.path, isolation_level=None)) as connection:
            connection.execute("BEGIN")
            snapshot = dict(
                _CockpitSnapshotProjection(
                    topology=OpenCodeTopology(pools)
                ).capture(connection)
            )
            connection.rollback()
        output = render_terminal(snapshot, width=100)
        for lane, size in sizes.items():
            for position in range(1, size + 1):
                self.assertNotIn(f"  ○ {lane}-{position}", output)
        self.assertNotIn("configured-session-1", output)
        self.assertNotIn("transport", output)
        self.assertIn("WORKER GRAPH\n  (no active workers)", output)

    def test_retained_delegate_edges_do_not_degrade_root_worker_projection(self) -> None:
        value = copy.deepcopy(self.snapshot)
        value["worker_graph"]["edges"].append(
            {"from": "tensorhost-1", "to": "child-session-1", "kind": "delegates"}
        )

        normalized = normalize_snapshot(value)

        self.assertEqual(normalized["availability"]["status"], "available")
        self.assertNotIn(
            "worker graph edges do not match worker relationships",
            normalized["availability"]["errors"],
        )
        self.assertEqual(normalized["worker_graph"]["edges"], [])

    def test_active_worker_shows_agent_and_work_relationship_only(self) -> None:
        active = copy.deepcopy(self.snapshot)
        active["slots"][0]["state"] = "assigned"
        worker = active["worker_graph"]["workers"][0]
        worker["slot_state"] = "assigned"
        worker["display_name"] = "research-agent"
        worker["work_id"] = "work-42"
        active["worker_graph"]["edges"] = [
            {"from": "tensorhost-1", "to": "work-42", "kind": "runs"},
            {"from": "tensorhost-1", "to": "transport-secret", "kind": "transport"},
        ]

        output = render_terminal(active, width=100)
        self.assertIn("● research-agent", output)
        self.assertIn("↳ work-42", output)
        self.assertNotIn("transport-secret", output)

    def test_completion_warning_states_do_not_substring_match(self) -> None:
        active = copy.deepcopy(self.snapshot)
        active["slots"][0]["state"] = "assigned"
        worker = active["worker_graph"]["workers"][0]
        worker["slot_state"] = "assigned"
        worker["completion"]["status"] = "available"
        worker["completion"]["registration_state"] = "unblocked"
        worker["completion"]["route_state"] = "not-failing"
        worker["completion"]["callback_state"] = "delivered"

        output = render_terminal(active, width=100)
        self.assertNotIn("completion registration", output)
        self.assertNotIn("completion route", output)

        worker["completion"]["registration_state"] = "blocked"
        output = render_terminal(active, width=100)
        self.assertIn("completion registration blocked", output)

    def test_nonempty_queue_and_clean_attention_are_both_visible(self) -> None:
        queued = copy.deepcopy(self.snapshot)
        queued["queue"]["items"] = [
            {
                "work_id": "work-queued",
                "sequence": 2,
                "queue_order": 1,
                "lane": "personal",
                "state": "queued",
                "policy": "allowed",
                "attempt": 0,
                "enqueued_at": "t",
            }
        ]
        queued["queue"].update(total=1, lower_bound=1)

        output = render_terminal(queued, width=100)
        self.assertIn("DISPATCH QUEUE (1)", output)
        self.assertIn("◆ #1 personal work-queued [allowed]", output)
        self.assertIn("◆ Personal", output)
        self.assertIn("ATTENTION", output)
        self.assertIn("✓ nothing stalled, nothing needs you", output)

    def test_nonempty_attention_is_prominent(self) -> None:
        attention = copy.deepcopy(self.snapshot)
        section = attention["attention"]["operator_required"]
        section["items"] = [
            {
                "kind": "backend_attention",
                "id": "backend-1",
                "scope": "controller",
                "state": "attention",
                "reason": "backend_degraded",
            }
        ]
        section.update(total=1, lower_bound=1)

        output = render_terminal(attention, width=100)
        self.assertIn("⚠ ATTENTION", output)
        self.assertIn("operator required: 1", output)
        self.assertIn("controller · backend_attention · attention · backend_degraded", output)
        self.assertIn("automatic recovery: 0", output)

    def test_callback_failure_is_delivery_attention_not_operator_required(self) -> None:
        attention = copy.deepcopy(self.snapshot)
        section = attention["attention"]["operator_required"]
        section["items"] = [
            {
                "kind": "callback_attention",
                "id": "callback-1",
                "work_id": "work-1",
                "generation": 1,
                "state": "attention",
                "reason": "codex_nonzero_exit_7",
            }
        ]
        section.update(total=1, lower_bound=1)

        output = render_terminal(attention, width=100)
        self.assertIn("⚠ ATTENTION", output)
        self.assertIn("delivery attention: 1", output)
        self.assertIn("operator required: 0", output)
        self.assertIn(
            "work-1 · callback_attention · attention · codex_nonzero_exit_7",
            output,
        )

        coloured = render_terminal(attention, width=100, ansi=True)
        self.assertIn("\x1b[33m⚠\x1b[0m ATTENTION", coloured)
        self.assertNotIn("\x1b[31m⚠\x1b[0m ATTENTION", coloured)

    def test_degraded_and_unavailable_sections_remain_prominent(self) -> None:
        degraded = copy.deepcopy(self.snapshot)
        del degraded["metrics"]
        degraded_output = render_terminal(degraded, width=80)
        self.assertIn("⚠ Fugue · degraded", degraded_output)
        self.assertIn("Warnings", degraded_output)

        output = render_terminal({}, width=80)
        self.assertIn("⚠ Fugue · unavailable", output)
        self.assertIn("Warnings", output)
        self.assertIn("⚠ snapshot is missing or is not an object", output)
        self.assertIn("DISPATCH QUEUE (unknown)", output)
        self.assertIn("⚠ unavailable", output)
        self.assertIn("⚠ ATTENTION", output)

    def test_details_has_exact_normalized_diagnostic_parity(self) -> None:
        details = render_details(self.snapshot)
        self.assertEqual(json.loads(details), normalize_snapshot(self.snapshot))
        self.assertIn('"session"', details)
        self.assertIn('"transport"', details)
        self.assertIn('"refresh"', details)

    def test_hostile_snapshot_text_is_inert_unicode_safe_and_width_bounded(self) -> None:
        hostile = copy.deepcopy(self.snapshot)
        hostile["slots"][0]["state"] = "assigned"
        hostile["worker_graph"]["workers"][0]["slot_state"] = "assigned"
        hostile["worker_graph"]["workers"][0]["display_name"] = (
            "会話\u202e\x1b[2J\nFORGEDabc" * 20
        )
        hostile["queue"]["items"] = [
            {
                "work_id": "bad\x1b]0;title\x07\nline",
                "sequence": 1,
                "queue_order": 1,
                "lane": "tensorhost",
                "state": "queued",
                "policy": "pending",
                "attempt": 0,
                "enqueued_at": "t",
            }
        ]
        hostile["queue"]["total"] = 1
        output = render_terminal(hostile, width=48)
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\u202e", output)
        self.assertIn("\\u001b", output)
        self.assertIn("\\u202e", output)
        self.assertTrue(all(_display_width(line) <= 48 for line in output.splitlines()))
        encoded = render_json(hostile)
        self.assertNotIn("\x1b", encoded)
        self.assertIn("\\\\u001b", encoded)
        json.loads(encoded)

    def test_huge_snapshot_is_deterministically_truncated_under_frame_budget(self) -> None:
        huge = copy.deepcopy(self.snapshot)
        huge_items = [
            {
                "work_id": f"work-{index:05d}",
                "sequence": index,
                "queue_order": index,
                "lane": "control",
                "state": "queued",
                "policy": "pending",
                "attempt": 0,
                "enqueued_at": "t" * 1000,
            }
            for index in range(10_000)
        ]
        huge["queue"] = {
            "status": "available",
            "items": huge_items,
            "total": None,
            "total_status": "capped",
            "lower_bound": 10_000,
            "truncated": True,
        }
        normalized = normalize_snapshot(huge)
        self.assertEqual(len(normalized["queue"]["items"]), 64)
        self.assertTrue(normalized["queue"]["truncated"])
        self.assertEqual(normalized["queue"]["items"][0]["work_id"], "work-00000")
        self.assertEqual(normalized["queue"]["items"][-1]["work_id"], "work-00063")
        encoded = render_json(huge).encode("utf-8")
        self.assertLess(len(encoded), 64 * 1024)
        self.assertEqual(encoded, render_json(huge).encode("utf-8"))

    def test_missing_fields_fail_closed_with_five_lanes_and_thirteen_slots(self) -> None:
        normalized = normalize_snapshot({})
        self.assertEqual(normalized["availability"]["status"], "unavailable")
        self.assertEqual(len(normalized["lanes"]), 5)
        self.assertEqual(sum(len(lane["slots"]) for lane in normalized["lanes"]), 13)
        self.assertTrue(
            all(
                slot["state"] == "unavailable"
                for lane in normalized["lanes"]
                for slot in lane["slots"]
            )
        )
        self.assertIn("Warnings", render_terminal({}, width=80))

    def test_tokens_require_durable_samples_and_turns_reject_content(self) -> None:
        value = copy.deepcopy(self.snapshot)
        value["metrics"] = {
            "token_total": {"status": "available", "value": 999},
            "token_rate_5m": {
                "status": "available",
                "source": "durable_samples",
                "value": 12.5,
            },
        }
        value["recent_turns"] = {
            "status": "available",
            "reason": None,
            "content_included": False,
            "items": [
                {"turn_id": "safe-1", "state": "completed", "ordinal": 1},
                {"turn_id": "unsafe", "content": "private transcript"},
                {"turn_id": "safe-2", "state": "active", "ordinal": 2},
            ],
        }
        normalized = normalize_snapshot(value)
        self.assertEqual(normalized["metrics"]["token_total"]["status"], "unavailable")
        self.assertEqual(normalized["metrics"]["token_rate_5m"]["value"], 12.5)
        self.assertEqual(normalized["recent_turns"]["status"], "unavailable")
        self.assertEqual(normalized["recent_turns"]["items"], [])
        self.assertNotIn("private transcript", render_json(value))

    def test_durable_metrics_and_recent_turn_metadata_are_visible(self) -> None:
        value = copy.deepcopy(self.snapshot)
        value["metrics"] = {
            "token_total": {
                "status": "available",
                "source": "durable_samples",
                "value": 12500,
            },
            "token_rate_5m": {
                "status": "available",
                "source": "durable_samples",
                "value": 42.5,
            },
        }
        value["recent_turns"] = {
            "status": "available",
            "reason": None,
            "content_included": False,
            "limit": 2,
            "items": [
                {
                    "turn_id": "turn-safe-1",
                    "state": "completed",
                    "ordinal": 7,
                    "occurred_at": "2026-09-01T22:00:00Z",
                    "token_count": 321,
                }
            ],
        }
        output = render_terminal(value, width=100)
        self.assertIn("Tokens total: 12,500", output)
        self.assertIn("Token rate (5m): 42.5 tok/min", output)
        self.assertIn("#7 completed · 321 tok · 2026-09-01T22:00:00Z", output)
        self.assertNotIn("turn-safe-1", output)

    def test_every_required_section_and_worker_component_fails_closed(self) -> None:
        for section in ("queue", "attention", "metrics", "topology", "recent_turns"):
            with self.subTest(section=section):
                value = copy.deepcopy(self.snapshot)
                del value[section]
                normalized = normalize_snapshot(value)
                self.assertEqual(normalized["availability"]["status"], "degraded")
                self.assertTrue(
                    any(section in error for error in normalized["availability"]["errors"])
                )
                if section == "queue":
                    self.assertEqual(normalized["queue"]["status"], "unavailable")

        for component in (
            "session",
            "pane",
            "transport",
            "completion",
            "recovery",
            "recent_turns",
        ):
            with self.subTest(component=component):
                value = copy.deepcopy(self.snapshot)
                del value["worker_graph"]["workers"][0][component]
                normalized = normalize_snapshot(value)
                worker = normalized["worker_graph"]["workers"][0]
                self.assertEqual(normalized["availability"]["status"], "degraded")
                self.assertTrue(
                    any(component in error for error in normalized["availability"]["errors"])
                )
                if component in {"transport", "completion", "recovery"}:
                    self.assertEqual(worker[component]["status"], "unavailable")

        value = copy.deepcopy(self.snapshot)
        value["worker_graph"]["workers"].pop()
        normalized = normalize_snapshot(value)
        self.assertEqual(normalized["availability"]["status"], "degraded")
        self.assertTrue(
            any("worker graph" in error for error in normalized["availability"]["errors"])
        )

    def test_every_worker_body_and_graph_edge_is_validated(self) -> None:
        required_worker_fields = {
            "slot_id", "lane", "position", "slot_state", "display_name",
            "session", "pane", "work_id", "agent_lifecycle", "owner_id", "assignment_id",
            "attempt", "transport", "completion", "recovery", "recent_turns",
        }
        for field in sorted(required_worker_fields):
            with self.subTest(field=field):
                value = copy.deepcopy(self.snapshot)
                del value["worker_graph"]["workers"][0][field]
                normalized = normalize_snapshot(value)
                self.assertEqual(normalized["availability"]["status"], "degraded")
                self.assertTrue(
                    any(field in error for error in normalized["availability"]["errors"])
                )

        value = copy.deepcopy(self.snapshot)
        value["worker_graph"]["workers"][0]["transport"]["generation"] = math.inf
        normalized = normalize_snapshot(value)
        self.assertEqual(normalized["availability"]["status"], "degraded")
        self.assertEqual(
            normalized["worker_graph"]["workers"][0]["transport"]["status"],
            "unavailable",
        )

        value = copy.deepcopy(self.snapshot)
        value["worker_graph"]["edges"] = [{"from": 3, "to": "work", "kind": "runs"}]
        normalized = normalize_snapshot(value)
        self.assertEqual(normalized["availability"]["status"], "degraded")
        self.assertTrue(
            any("edges" in error for error in normalized["availability"]["errors"])
        )

        stale_lifecycle = copy.deepcopy(self.snapshot)
        stale_lifecycle["worker_graph"]["workers"][1]["agent_lifecycle"] = "persistent"
        normalized = normalize_snapshot(stale_lifecycle)
        self.assertEqual(normalized["availability"]["status"], "degraded")
        self.assertIsNone(
            normalized["worker_graph"]["workers"][1]["agent_lifecycle"]
        )

    def test_queue_attention_and_topology_metadata_fail_closed(self) -> None:
        mutations = (
            ("queue item", lambda value: value["queue"]["items"].append({})),
            (
                "automatic attention item",
                lambda value: value["attention"]["automatic_recovery"]["items"].append({}),
            ),
            (
                "operator attention item",
                lambda value: value["attention"]["operator_required"]["items"].append({}),
            ),
            (
                "topology status",
                lambda value: value["topology"].__setitem__("observed_status", "unknown"),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                value = copy.deepcopy(self.snapshot)
                mutate(value)
                normalized = normalize_snapshot(value)
                self.assertEqual(normalized["availability"]["status"], "degraded")

    def test_unbounded_and_nonfinite_numbers_degrade_without_renderer_failure(self) -> None:
        for invalid in (2**1000, -(2**1000), math.nan, math.inf, -math.inf):
            with self.subTest(value=repr(invalid)):
                value = copy.deepcopy(self.snapshot)
                value["snapshot_version"]["event_sequence"] = invalid
                value["queue"]["lower_bound"] = invalid
                value["queue"]["items"] = [
                    {
                        "work_id": "work-invalid",
                        "sequence": invalid,
                        "queue_order": invalid,
                        "lane": "control",
                        "state": "queued",
                        "policy": "pending",
                        "attempt": invalid,
                        "enqueued_at": "t",
                    }
                ]
                value["metrics"] = {
                    "token_total": {
                        "status": "available",
                        "source": "durable_samples",
                        "value": invalid,
                    },
                    "token_rate_5m": {
                        "status": "available",
                        "source": "durable_samples",
                        "value": invalid,
                    },
                }
                normalized = normalize_snapshot(value)
                self.assertEqual(normalized["availability"]["status"], "degraded")
                self.assertIsNone(normalized["snapshot_version"]["event_sequence"])
                self.assertEqual(
                    normalized["metrics"]["token_total"]["status"], "unavailable"
                )
                json_output = render_json(value)
                terminal_output = render_terminal(value, width=80)
                json.loads(json_output)
                self.assertNotIn("\x1b", terminal_output)


if __name__ == "__main__":
    unittest.main()
