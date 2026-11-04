from __future__ import annotations

import hashlib
import json
import sqlite3
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from oc_rig.adapters.opencode import DispatchRegistration
from oc_rig.adapters.opencode_client import OpenCodeClient
from oc_rig.completion.daemon_monitor import _DaemonOpenCodeCompletionMonitor
from oc_rig.transcript import project_transcript_turns
from oc_rig.daemon.controller import (
    OperationRejected,
    _RigController,
    _composer_text,
    _transcript_turns,
    _uuid4,
)


class _Transport:
    def _assert_authority(self, capability: object) -> None:
        if capability != "authority":
            raise PermissionError


class _Store:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    @contextmanager
    def _daemon_read_transaction(self, _authority: object):
        yield self.connection


def _controller_with_binding() -> _RigController:
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE opencode_deliveries(
          transport_id TEXT, work_id TEXT, slot_id TEXT, assignment_generation INTEGER,
          isolated_session_id TEXT, session_id TEXT, worker TEXT, prompt_message_id TEXT,
          delivery_state TEXT, lease_state TEXT
        );
        CREATE TABLE transport_deliveries(
          id TEXT, work_id TEXT, assignment_attempt INTEGER, assignment_id TEXT, state TEXT
        );
        CREATE TABLE scheduler_assignments(
          id TEXT, work_id TEXT, slot_id TEXT, attempt INTEGER, state TEXT
        );
        CREATE TABLE scheduler_work(id TEXT, active_assignment_id TEXT, state TEXT);
        CREATE TABLE scheduler_slots(
          id TEXT, active_assignment_id TEXT, active_work_id TEXT, state TEXT
        );
        INSERT INTO opencode_deliveries VALUES(
          'transport-1','work-1','homelab-1',3,'isolated-1','persistent-1',
          'secure-worker','prompt-1','accepted','active'
        );
        INSERT INTO transport_deliveries VALUES(
          'transport-1','work-1',1,'assignment-1','accepted'
        );
        INSERT INTO scheduler_assignments VALUES(
          'assignment-1','work-1','homelab-1',1,'active'
        );
        INSERT INTO scheduler_work VALUES('work-1','assignment-1','assigned');
        INSERT INTO scheduler_slots VALUES(
          'homelab-1','assignment-1','work-1','assigned'
        );
        """
    )
    controller = object.__new__(_RigController)
    controller._transport = _Transport()
    controller._authority = object()
    controller.store = _Store(connection)
    return controller


class WorkerTranscriptTests(unittest.TestCase):
    def test_binding_requires_exact_active_slot_work_generation_and_session(self) -> None:
        controller = _controller_with_binding()
        self.addCleanup(controller.store.connection.close)
        binding = controller._active_worker_binding(
            "authority", slot_id="homelab-1", work_id="work-1", generation=3
        )
        self.assertEqual(binding["session_id"], "isolated-1")
        self.assertEqual(binding["anchor_item_id"], "prompt-1")
        with self.assertRaisesRegex(OperationRejected, "session binding changed"):
            controller._active_worker_binding(
                "authority",
                slot_id="homelab-1",
                work_id="work-1",
                generation=3,
                session_id="persistent-1",
            )
        with self.assertRaisesRegex(OperationRejected, "no longer active"):
            controller._active_worker_binding(
                "authority", slot_id="homelab-1", work_id="work-1", generation=4
            )

    def test_binding_keeps_scheduler_slot_separate_from_execution_slot(self) -> None:
        controller = _controller_with_binding()
        self.addCleanup(controller.store.connection.close)
        controller.store.connection.execute(
            "UPDATE scheduler_assignments SET slot_id = 'control-3' WHERE id = 'assignment-1'"
        )
        controller.store.connection.execute(
            "UPDATE scheduler_slots SET id = 'control-3' WHERE id = 'homelab-1'"
        )

        binding = controller._active_worker_binding(
            "authority", slot_id="control-3", work_id="work-1", generation=3
        )

        self.assertEqual(binding["slot_id"], "control-3")
        self.assertEqual(binding["session_id"], "isolated-1")
        with self.assertRaisesRegex(OperationRejected, "no longer active"):
            controller._active_worker_binding(
                "authority", slot_id="homelab-1", work_id="work-1", generation=3
            )

    def test_projection_keeps_text_and_redacts_reasoning_and_tools(self) -> None:
        turns, redacted = _transcript_turns(
            [
                {
                    "info": {"role": "user", "time": {"created": 1}},
                    "parts": [{"type": "text", "text": "bounded question"}],
                },
                {
                    "info": {"role": "assistant", "finish": "stop"},
                    "parts": [
                        {"type": "reasoning", "text": "private chain"},
                        {"type": "tool", "input": {"secret": "must not escape"}},
                        {"type": "text", "text": "bounded answer"},
                    ],
                },
            ]
        )
        self.assertEqual([turn["preview"] for turn in turns], ["bounded question", "bounded answer"])
        self.assertEqual([turn["state"] for turn in turns], ["committed", "committed"])
        self.assertEqual(len(redacted), 2)
        self.assertNotIn("private chain", repr((turns, redacted)))
        self.assertNotIn("must not escape", repr((turns, redacted)))

        bounded, _ = _transcript_turns(
            [{
                "info": {"role": "assistant", "finish": "stop"},
                "parts": [{"type": "text", "text": "é" * 2_000}],
            }]
        )
        self.assertLessEqual(len(bounded[0]["preview"].encode("utf-8")), 2_000)
        self.assertTrue(bounded[0]["preview"].endswith("…"))

    def test_durable_projection_redacts_secret_text_without_overredacting_risk_words(self) -> None:
        turns, redacted = project_transcript_turns(
            [
                {
                    "info": {"role": "user", "time": {"created": 1}},
                    "parts": [{"type": "text", "text": "production rollout notes"}],
                },
                {
                    "info": {"role": "assistant", "finish": "stop"},
                    "parts": [{"type": "text", "text": "password=do-not-persist"}],
                },
            ],
            durable=True,
        )
        self.assertEqual(turns[0]["preview"], "production rollout notes")
        self.assertEqual(turns[1]["preview"], "[redacted from archived transcript]")
        self.assertIn("messages[1].text", redacted)
        self.assertNotIn("do-not-persist", repr((turns, redacted)))

    def test_completion_capture_sanitizes_before_persistence(self) -> None:
        class Client:
            @staticmethod
            def messages(session_id: str, *, limit: int):
                self.assertEqual(session_id, "isolated-archive")
                self.assertEqual(limit, 16)
                return [
                    {
                        "info": {"role": "user", "time": {"created": 1}},
                        "parts": [{"type": "text", "text": "bounded request"}],
                    },
                    {
                        "info": {"role": "assistant", "finish": "stop"},
                        "parts": [
                            {"type": "reasoning", "text": "private chain"},
                            {"type": "text", "text": "password=do-not-persist"},
                        ],
                    },
                ]

        class Adapter:
            _client = Client()

        monitor = object.__new__(_DaemonOpenCodeCompletionMonitor)
        monitor._adapter = Adapter()  # type: ignore[assignment]
        registration = DispatchRegistration(
            "transport-archive", "work-archive", "completion-archive",
            "callback-archive", "isolated-archive", 4, "prompt-archive",
            "transport-archive",
        )

        capture = monitor._capture_transcript_archive(registration)

        self.assertIsNotNone(capture)
        transcript_json, digest, turn_count, redaction_count, captured_at_us = capture  # type: ignore[misc]
        document = json.loads(transcript_json)
        self.assertEqual(document["turns"][0]["preview"], "bounded request")
        self.assertEqual(document["turns"][1]["preview"], "[redacted from archived transcript]")
        self.assertNotIn("private chain", transcript_json)
        self.assertNotIn("do-not-persist", transcript_json)
        self.assertEqual(hashlib.sha256(transcript_json.encode("utf-8")).hexdigest(), digest)
        self.assertEqual(turn_count, 2)
        self.assertGreaterEqual(redaction_count, 2)
        self.assertGreater(captured_at_us, 0)

    def test_archive_sql_requires_exact_completion_and_is_immutable(self) -> None:
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.executescript(
            """
            PRAGMA foreign_keys = ON;
            CREATE TABLE transport_deliveries(id TEXT PRIMARY KEY);
            CREATE TABLE completion_results(
                result_ref TEXT PRIMARY KEY,
                transport_id TEXT,
                work_id TEXT,
                generation INTEGER,
                session_id TEXT
            );
            CREATE TABLE opencode_deliveries(transport_id TEXT, slot_id TEXT);
            INSERT INTO transport_deliveries VALUES ('transport-1');
            INSERT INTO completion_results VALUES (
                'result-1','transport-1','work-1',1,'session-1'
            );
            INSERT INTO opencode_deliveries VALUES ('transport-1','homelab-1');
            """
        )
        connection.executescript(
            Path("src/oc_rig/store/migrations/024_completed_transcript_archive.sql").read_text(encoding="utf-8")
        )
        document = json.dumps(
            {"turns": [], "redacted": []},
            sort_keys=True,
            separators=(",", ":"),
        )
        values = (
            "result-1", "transport-1", "work-1", 1, "homelab-1", "session-1",
            1, 0, 0, document, hashlib.sha256(document.encode()).hexdigest(),
        )
        connection.execute(
            """INSERT INTO completed_transcript_snapshots(
                   result_ref, transport_id, work_id, generation, slot_id, session_id,
                   captured_at_us, turn_count, redaction_count, transcript_json,
                   transcript_sha256
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            values,
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE completed_transcript_snapshots SET captured_at_us = 2 WHERE result_ref = 'result-1'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "DELETE FROM completed_transcript_snapshots WHERE result_ref = 'result-1'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "exact completion authority"):
            connection.execute(
                """INSERT INTO completed_transcript_snapshots(
                       result_ref, transport_id, work_id, generation, slot_id, session_id,
                       captured_at_us, turn_count, redaction_count, transcript_json,
                       transcript_sha256
                   ) VALUES ('result-2','transport-1','work-1',1,'wrong-slot','session-1',1,0,0,?,?)""",
                (document, hashlib.sha256(document.encode()).hexdigest()),
            )

    def test_archived_transcript_is_exact_read_only_and_hash_bound(self) -> None:
        controller = _controller_with_binding()
        self.addCleanup(controller.store.connection.close)
        connection = controller.store.connection
        connection.executescript(
            """
            CREATE TABLE completion_results(result_ref TEXT, outcome TEXT);
            CREATE TABLE completed_transcript_snapshots(
                result_ref TEXT, session_id TEXT, captured_at_us INTEGER,
                transcript_json TEXT, transcript_sha256 TEXT, turn_count INTEGER,
                redaction_count INTEGER, slot_id TEXT, work_id TEXT, generation INTEGER
            );
            """
        )
        document = {
            "turns": [
                {
                    "seq": 0,
                    "role": "agent",
                    "kind": "text",
                    "preview": "bounded final",
                    "state": "committed",
                }
            ],
            "redacted": ["messages[0].parts[0]"],
        }
        encoded = json.dumps(
            document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        connection.execute(
            "INSERT INTO completion_results VALUES ('completion-result-1', 'succeeded')"
        )
        connection.execute(
            "INSERT INTO completed_transcript_snapshots VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                "completion-result-1",
                "isolated-1",
                1_700_000_000_000_000,
                encoded.decode("utf-8"),
                hashlib.sha256(encoded).hexdigest(),
                1,
                1,
                "homelab-1",
                "work-1",
                1,
            ),
        )

        result = controller.execute_durable(
            "authority",
            "archive-read",
            "a" * 64,
            "worker.transcript.archive.v1",
            {
                "archive_id": "completion-result-1",
                "slot_id": "homelab-1",
                "work_id": "work-1",
                "generation": 1,
            },
        )

        self.assertTrue(result["read_only"])
        self.assertEqual(result["thread_id"], "isolated-1")
        self.assertEqual(result["turns"], document["turns"])
        self.assertNotIn("anchor_item_id", result)
        with self.assertRaisesRegex(OperationRejected, "not found"):
            controller.archived_worker_transcript(
                "authority",
                {
                    "archive_id": "completion-result-1",
                    "slot_id": "homelab-1",
                    "work_id": "other-work",
                    "generation": 1,
                },
            )
        connection.execute(
            "UPDATE completed_transcript_snapshots SET transcript_sha256 = ?",
            ("0" * 64,),
        )
        with self.assertRaisesRegex(OperationRejected, "binding changed"):
            controller.archived_worker_transcript(
                "authority",
                {
                    "archive_id": "completion-result-1",
                    "slot_id": "homelab-1",
                    "work_id": "work-1",
                    "generation": 1,
                },
            )

    def test_transcript_read_bypasses_durable_outcome_journalling(self) -> None:
        controller = _controller_with_binding()
        self.addCleanup(controller.store.connection.close)
        client = object.__new__(OpenCodeClient)
        controller._transport._adapter = SimpleNamespace(_client=client)
        with patch.object(
            OpenCodeClient,
            "messages",
            return_value=[
                {
                    "info": {"role": "assistant", "finish": "stop"},
                    "parts": [{"type": "text", "text": "bounded answer"}],
                }
            ],
        ) as messages:
            result = controller.execute_durable(
                "authority",
                "read-idempotency",
                "f" * 64,
                "worker.transcript.v1",
                {"slot_id": "homelab-1", "work_id": "work-1", "generation": 3},
            )
        self.assertEqual(result["thread_id"], "isolated-1")
        self.assertEqual(result["turns"][0]["preview"], "bounded answer")
        messages.assert_called_once_with("isolated-1", limit=16)
        with self.assertRaises(sqlite3.OperationalError):
            controller.store.connection.execute("SELECT * FROM daemon_request_outcomes")

    def test_composer_is_uuid_bound_bounded_and_policy_scanned(self) -> None:
        value = "123e4567-e89b-42d3-a456-426614174000"
        self.assertEqual(_uuid4(value), value)
        self.assertEqual(_composer_text("Cafe\u0301"), "Café")
        with self.assertRaisesRegex(OperationRejected, "secure content policy"):
            _composer_text("password=do-not-send-this")
        with self.assertRaises(OperationRejected):
            _uuid4("not-a-uuid")


if __name__ == "__main__":
    unittest.main()
