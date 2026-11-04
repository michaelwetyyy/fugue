from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from tools.worker_runner import (
    CommandOutcome,
    ConfigurationError,
    MacOSSandboxExecAdapter,
    PacketRejected,
    RepositoryRejected,
    RunnerConfig,
    WorkerRunner,
)


class RecordingAdapter:
    def __init__(self) -> None:
        self.requests = []

    def execute(self, request, cancellation):
        self.requests.append(request)
        return CommandOutcome(returncode=0)


class WorkerRunnerPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.allowed = self.root / "allowed"
        self.repository = self.allowed / "repository"
        self.repository.mkdir(parents=True)
        self.executable = self.root / "fake-worker"
        self.executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.executable.chmod(0o700)
        self.packet = {
            "task_id": "policy-test",
            "classification": "development",
            "instructions": "Return a synthetic result without network access.",
            "scope": ["placeholder.txt"],
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def runner(self, adapter: RecordingAdapter, **changes) -> WorkerRunner:
        values = {
            "runtime_root": self.root / "runtime",
            "allowed_repository_roots": (self.allowed,),
            "armed": True,
            "executable": self.executable,
        }
        values.update(changes)
        return WorkerRunner(
            RunnerConfig(**values),
            adapter,
        )

    def test_disarmed_runner_never_calls_adapter_or_creates_runtime(self) -> None:
        adapter = RecordingAdapter()
        runner = self.runner(adapter, armed=False)

        with self.assertRaisesRegex(ConfigurationError, "disarmed"):
            runner.run(self.packet, self.repository)

        self.assertEqual(adapter.requests, [])
        self.assertFalse((self.root / "runtime").exists())

    def test_missing_executable_never_calls_adapter(self) -> None:
        adapter = RecordingAdapter()
        runner = self.runner(adapter, executable=None)

        with self.assertRaisesRegex(ConfigurationError, "explicit executable"):
            runner.run(self.packet, self.repository)

        self.assertEqual(adapter.requests, [])

    def test_sensitive_classification_and_secret_fields_fail_before_io(self) -> None:
        cases = (
            {**self.packet, "classification": "confidential"},
            {**self.packet, "metadata": {"api_key": "example"}},
            {**self.packet, "instructions": "Use token=not-a-real-token"},
            {
                **self.packet,
                "instructions": "-----BEGIN PRIVATE KEY----- synthetic",
            },
        )

        for index, packet in enumerate(cases):
            with self.subTest(index=index):
                adapter = RecordingAdapter()
                with self.assertRaises(PacketRejected):
                    self.runner(adapter).run(packet, self.repository)
                self.assertEqual(adapter.requests, [])
                self.assertFalse((self.root / "runtime").exists())

    def test_repository_outside_allowlist_is_rejected_before_adapter(self) -> None:
        outside = self.root / "outside" / "repository"
        outside.mkdir(parents=True)
        adapter = RecordingAdapter()

        with self.assertRaisesRegex(RepositoryRejected, "outside"):
            self.runner(adapter).run(self.packet, outside)

        self.assertEqual(adapter.requests, [])

    def test_symlink_cannot_escape_repository_allowlist(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        linked = self.allowed / "linked-repository"
        linked.symlink_to(outside, target_is_directory=True)
        adapter = RecordingAdapter()

        with self.assertRaisesRegex(RepositoryRejected, "outside"):
            self.runner(adapter).run(self.packet, linked)

        self.assertEqual(adapter.requests, [])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are required")
    def test_runtime_root_may_not_resolve_inside_repository(self) -> None:
        adapter = RecordingAdapter()
        runtime = self.repository / "runtime"

        with self.assertRaisesRegex(ConfigurationError, "inside the repository"):
            self.runner(adapter, runtime_root=runtime).run(self.packet, self.repository)

        self.assertEqual(adapter.requests, [])

    def test_macos_sandbox_adapter_rejects_executable_override(self) -> None:
        shim = self.root / "sandbox-exec-shim"
        shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        shim.chmod(0o700)

        with self.assertRaises(TypeError):
            MacOSSandboxExecAdapter(sandbox_executable=shim)  # type: ignore[call-arg]

        with self.assertRaises(TypeError):
            WorkerRunner(  # type: ignore[call-arg]
                RunnerConfig(
                    runtime_root=self.root / "runtime",
                    allowed_repository_roots=(self.allowed,),
                    armed=True,
                    executable=self.executable,
                ),
                RecordingAdapter(),
                object(),
            )

    def test_scope_rejects_absolute_traversal_and_git_paths(self) -> None:
        cases = (
            [],
            [""],
            ["/absolute.txt"],
            ["../escape.txt"],
            ["nested/../../escape.txt"],
            ["./relative.txt"],
            [".git/config"],
        )

        for scope in cases:
            with self.subTest(scope=scope):
                adapter = RecordingAdapter()
                packet = {**self.packet, "scope": scope}
                with self.assertRaises(PacketRejected):
                    self.runner(adapter).run(packet, self.repository)
                self.assertEqual(adapter.requests, [])

    def test_scope_rejects_symlink_escape_before_adapter(self) -> None:
        outside = self.root / "outside-scope"
        outside.mkdir()
        (self.repository / "escape-link").symlink_to(outside, target_is_directory=True)
        adapter = RecordingAdapter()
        packet = {**self.packet, "scope": ["escape-link/escaped.txt"]}

        with self.assertRaisesRegex(PacketRejected, "symlink"):
            self.runner(adapter).run(packet, self.repository)

        self.assertEqual(adapter.requests, [])


if __name__ == "__main__":
    unittest.main()
