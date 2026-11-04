from __future__ import annotations

import json
import unittest

from oc_rig.completion.daemon_monitor import _DaemonOpenCodeCompletionMonitor
from oc_rig.completion.models import (
    FUGUE_HANDOVER_SCHEMA,
    FUGUE_REVIEW_PROFILES,
    MAX_FUGUE_HANDOVER_BYTES,
    CompletionOutcome,
    FugueHandoverInvalid,
    parse_fugue_handover,
)
from oc_rig.completion.opencode import OpenCodeCompletion


def handover(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": FUGUE_HANDOVER_SCHEMA,
        "status": "ready",
        "summary": "Bounded proposal is ready for Codex review.",
        "changes": [
            {
                "path": "src/component.py",
                "diff": "@@ -1 +1 @@\n-old\n+new",
            }
        ],
        "reviews": {profile: "pass" for profile in FUGUE_REVIEW_PROFILES},
        "unresolved": [],
        "codex_actions": ["run local tests"],
    }
    value.update(updates)
    return value


class FugueHandoverTests(unittest.TestCase):
    def test_valid_handover_is_detached_and_closed(self) -> None:
        source = handover()
        parsed = parse_fugue_handover(json.dumps(source))

        self.assertEqual(parsed, source)
        self.assertIsNot(parsed, source)
        self.assertEqual(set(parsed["reviews"]), set(FUGUE_REVIEW_PROFILES))

    def test_handover_rejects_shape_quorum_path_and_ready_unresolved(self) -> None:
        cases = []
        extra = handover(extra="no")
        cases.append((extra, "handover_shape_invalid"))
        missing_review = handover(
            reviews={profile: "pass" for profile in FUGUE_REVIEW_PROFILES[:-1]}
        )
        cases.append((missing_review, "handover_reviews_invalid"))
        traversal = handover(
            changes=[{"path": "../escape.py", "diff": "@@ -1 +1 @@\n-a\n+b"}]
        )
        cases.append((traversal, "handover_change_path_invalid"))
        full_file = handover(
            changes=[{"path": "src/component.py", "diff": "--- a/src/component.py"}]
        )
        cases.append((full_file, "handover_change_diff_invalid"))
        malformed_hunk = handover(
            changes=[{
                "path": "src/component.py",
                "diff": "@@ -1 +1 @@\nold without a diff prefix",
            }]
        )
        cases.append((malformed_hunk, "handover_change_diff_invalid"))
        no_change_hunk = handover(
            changes=[{"path": "src/component.py", "diff": "@@ -1 +1 @@\n context"}]
        )
        cases.append((no_change_hunk, "handover_change_diff_invalid"))
        unresolved = handover(unresolved=["still broken"])
        cases.append((unresolved, "handover_ready_has_unresolved"))

        for value, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(
                FugueHandoverInvalid, reason
            ):
                parse_fugue_handover(json.dumps(value))

    def test_handover_has_independent_24kib_limit(self) -> None:
        value = handover(summary="x" * MAX_FUGUE_HANDOVER_BYTES)
        with self.assertRaisesRegex(FugueHandoverInvalid, "handover_size_invalid"):
            parse_fugue_handover(json.dumps(value))

    def test_agent_task_result_is_canonical_and_scope_bound(self) -> None:
        raw = json.dumps(handover(), indent=2)
        completion = OpenCodeCompletion(
            "completion-key",
            "transport",
            "registration",
            "callback",
            "work",
            "session",
            1,
            "prompt",
            CompletionOutcome.SUCCEEDED,
            "assistant",
            raw,
        )
        result = _DaemonOpenCodeCompletionMonitor._agent_task_final_result(
            completion, 1, {"scope": ["src/component.py"]}
        )

        self.assertIs(result.outcome, CompletionOutcome.SUCCEEDED)
        self.assertEqual(
            result.final_text,
            json.dumps(
                parse_fugue_handover(raw),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )

        escaped = handover(
            changes=[{"path": "src/other.py", "diff": "@@ -1 +1 @@\n-a\n+b"}]
        )
        rejected = _DaemonOpenCodeCompletionMonitor._agent_task_final_result(
            OpenCodeCompletion(
                "completion-key-2",
                "transport",
                "registration",
                "callback",
                "work",
                "session",
                1,
                "prompt",
                CompletionOutcome.SUCCEEDED,
                "assistant-2",
                json.dumps(escaped),
            ),
            1,
            {"scope": ["src/component.py"]},
        )
        self.assertIs(rejected.outcome, CompletionOutcome.FAILED)
        self.assertIsNone(rejected.final_text)

    def test_nonready_valid_handover_closes_as_failed_but_remains_readable(self) -> None:
        value = handover(status="attention", unresolved=["needs Codex decision"])
        completion = OpenCodeCompletion(
            "completion-key",
            "transport",
            "registration",
            "callback",
            "work",
            "session",
            1,
            "prompt",
            CompletionOutcome.SUCCEEDED,
            "assistant",
            json.dumps(value),
        )
        result = _DaemonOpenCodeCompletionMonitor._agent_task_final_result(
            completion, 1, {"scope": ["src/component.py"]}
        )
        self.assertIs(result.outcome, CompletionOutcome.FAILED)
        self.assertIsNotNone(result.final_text)


if __name__ == "__main__":
    unittest.main()
