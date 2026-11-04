from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from oc_rig.route_cli import main


class RouteCliTests(unittest.TestCase):
    ROOT = Path("/private/verified/oc-rig-v2")
    THREAD_ID = "123e4567-e89b-12d3-a456-426614174000"

    def test_review_forwards_only_fixed_public_scope_capsule_arguments(self) -> None:
        with patch("oc_rig.route_cli.cli.main", return_value=0) as client:
            status = main(
                [
                    str(self.ROOT),
                    self.THREAD_ID,
                    "review",
                    "tensorhost",
                    "/private/repository",
                    "--scope",
                    "src/review.py",
                    "--profile",
                    "correctness",
                    "--profile",
                    "security",
                    "--idempotency-id",
                    "review-fixed-1",
                ]
            )

        self.assertEqual(status, 0)
        forwarded = client.call_args.args[0]
        self.assertEqual(
            forwarded[:6],
            [
                "--socket",
                str(self.ROOT / "runtime/socket-boundary/socket/rig.sock"),
                "--approved-root",
                str(self.ROOT / "runtime/socket-boundary"),
                "--identity-profile",
                "local-user",
            ],
        )
        self.assertIn("--include-scope", forwarded)
        self.assertEqual(forwarded[-4:], ["--classification", "PUBLIC", "--trust", "secure"])
        self.assertNotIn("--prompt", forwarded)
        self.assertNotIn("--risk-category", forwarded)
        self.assertIn("--codex-thread-id", forwarded)
        self.assertEqual(forwarded[forwarded.index("--codex-thread-id") + 1], self.THREAD_ID)

    def test_review_requires_callback_identity_before_calling_client(self) -> None:
        with patch("oc_rig.route_cli.cli.main") as client, self.assertRaises(SystemExit):
            main(
                [
                    str(self.ROOT), "-", "review", "tensorhost", "/private/repository",
                    "--scope", "review.py", "--profile", "correctness",
                    "--idempotency-id", "review-fixed-2",
                ]
            )
        client.assert_not_called()

    def test_task_forwards_one_fixed_no_tool_proposal(self) -> None:
        with patch("oc_rig.route_cli.cli.main", return_value=0) as client:
            status = main(
                [
                    str(self.ROOT), self.THREAD_ID, "task", "control",
                    "/private/repository", "--scope", "src/app.tsx",
                    "--scope", "src/settings.tsx", "--objective",
                    "Design a bounded settings-page patch.", "--lifecycle",
                    "persistent", "--idempotency-id", "task-fixed-1",
                    "--reservation-attempt", "2",
                ]
            )

        self.assertEqual(status, 0)
        forwarded = client.call_args.args[0]
        self.assertEqual(
            forwarded[:7],
            [
                "--socket",
                str(self.ROOT / "runtime/socket-boundary/socket/rig.sock"),
                "--approved-root",
                str(self.ROOT / "runtime/socket-boundary"),
                "--identity-profile",
                "local-user",
                "proposal-submit",
            ],
        )
        self.assertIn("--objective", forwarded)
        self.assertIn("--agent-lifecycle", forwarded)
        self.assertIn("persistent", forwarded)
        self.assertEqual(
            forwarded[forwarded.index("--reservation-attempt") + 1], "2"
        )
        self.assertIn("--codex-thread-id", forwarded)
        self.assertNotIn("--classification", forwarded)
        self.assertNotIn("--trust", forwarded)
        self.assertNotIn("--risk-category", forwarded)
        self.assertNotIn("--workspace-edit", forwarded)

    def test_work_forwards_one_brokered_direct_workspace_task(self) -> None:
        with patch("oc_rig.route_cli.cli.main", return_value=0) as client:
            status = main(
                [
                    str(self.ROOT), self.THREAD_ID, "work", "control",
                    "/private/repository", "--scope", "src/app.tsx",
                    "--objective", "Implement the bounded UI change.",
                    "--lifecycle", "disposable", "--idempotency-id",
                    "work-fixed-1",
                ]
            )

        self.assertEqual(status, 0)
        forwarded = client.call_args.args[0]
        self.assertIn("proposal-submit", forwarded)
        self.assertIn("--workspace-edit", forwarded)
        self.assertIn("--codex-thread-id", forwarded)
        self.assertNotIn("--classification", forwarded)
        self.assertNotIn("--trust", forwarded)

        with patch("oc_rig.route_cli.cli.main") as rejected, self.assertRaises(SystemExit):
            main(
                [
                    str(self.ROOT), self.THREAD_ID, "work", "control",
                    "/private/repository", "--scope", "src/app.tsx",
                    "--scope", "src/styles.css", "--objective", "Change both.",
                    "--lifecycle", "disposable", "--idempotency-id", "work-fixed-2",
                ]
            )
        rejected.assert_not_called()

    def test_patch_forwards_one_disposable_line_window(self) -> None:
        with patch("oc_rig.route_cli.cli.main", return_value=0) as client:
            status = main(
                [
                    str(self.ROOT), self.THREAD_ID, "patch", "personal",
                    "/private/repository", "--scope", "src/large.tsx",
                    "--lines", "220:280", "--objective", "Edit the pool renderer.",
                    "--lifecycle", "disposable", "--idempotency-id", "patch-fixed-1",
                ]
            )

        self.assertEqual(status, 0)
        forwarded = client.call_args.args[0]
        self.assertIn("proposal-submit", forwarded)
        self.assertEqual(
            forwarded[forwarded.index("--workspace-patch") + 1], "220:280"
        )
        self.assertNotIn("--workspace-edit", forwarded)

        invalid = (
            "0:2", "4:3", "1:9999999",
        )
        for line_range in invalid:
            with self.subTest(line_range=line_range), patch(
                "oc_rig.route_cli.cli.main"
            ) as rejected, self.assertRaises(SystemExit):
                main(
                    [
                        str(self.ROOT), self.THREAD_ID, "patch", "personal",
                        "/private/repository", "--scope", "src/large.tsx",
                        "--lines", line_range, "--objective", "Edit it.",
                        "--lifecycle", "disposable", "--idempotency-id", "patch-fixed-2",
                    ]
                )
            rejected.assert_not_called()
        with patch("oc_rig.route_cli.cli.main") as rejected, self.assertRaises(SystemExit):
            main(
                [
                    str(self.ROOT), self.THREAD_ID, "patch", "personal",
                    "/private/repository", "--scope", "src/large.tsx",
                    "--lines", "1:2", "--objective", "Edit it.",
                    "--lifecycle", "persistent", "--idempotency-id", "patch-fixed-3",
                ]
            )
        rejected.assert_not_called()

    def test_generic_mutations_and_policy_overrides_are_not_in_grammar(self) -> None:
        rejected = (
            [str(self.ROOT), self.THREAD_ID, "dispatch", "tensorhost", "work"],
            [str(self.ROOT), self.THREAD_ID, "cancel-transport", "tensorhost", "work"],
            [str(self.ROOT), self.THREAD_ID, "review", "tensorhost", "/private/repository",
             "--scope", "review.py", "--profile", "correctness",
             "--idempotency-id", "review-fixed-3", "--prompt", "change it"],
            [str(self.ROOT), self.THREAD_ID, "review", "tensorhost", "/private/repository",
             "--scope", "review.py", "--profile", "correctness",
             "--idempotency-id", "review-fixed-4", "--classification", "SENSITIVE"],
            [str(self.ROOT), self.THREAD_ID, "task", "control", "/private/repository",
             "--scope", "app.tsx", "--objective", "change it", "--lifecycle",
             "persistent", "--idempotency-id", "task-fixed-2", "--trust", "insecure"],
            [str(self.ROOT), self.THREAD_ID, "task", "control", "/private/repository",
             "--scope", "app.tsx", "--objective", "change it", "--lifecycle",
             "persistent", "--idempotency-id", "task-fixed-3",
             "--reservation-attempt", "0"],
            [str(self.ROOT), self.THREAD_ID, "--socket", "/tmp/attacker.sock", "status"],
        )
        for arguments in rejected:
            with self.subTest(arguments=arguments), patch(
                "oc_rig.route_cli.cli.main"
            ) as client, self.assertRaises(SystemExit):
                main(arguments)
            client.assert_not_called()

    def test_reads_use_only_the_verified_deployment_connection(self) -> None:
        with patch("oc_rig.route_cli.cli.main", return_value=0) as client:
            self.assertEqual(main([str(self.ROOT), "-", "result", "result-1"]), 0)
        self.assertEqual(
            client.call_args.args[0],
            [
                "--socket", str(self.ROOT / "runtime/socket-boundary/socket/rig.sock"),
                "--approved-root", str(self.ROOT / "runtime/socket-boundary"),
                "--identity-profile", "local-user",
                "completion-result", "result-1",
            ],
        )


if __name__ == "__main__":
    unittest.main()
