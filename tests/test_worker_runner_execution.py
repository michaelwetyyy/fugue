from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.worker_runner import (
    CancellationToken,
    PacketRejected,
    RepositoryRejected,
    RunnerConfig,
    SubprocessCommandAdapter,
    WorkerRunner,
)


class WorkerRunnerExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.allowed = self.root / "repositories"
        self.repository = self.allowed / "worktree"
        self.repository.mkdir(parents=True)
        subprocess.run(["/usr/bin/git", "init", "-q", str(self.repository)], check=True)
        subprocess.run(
            ["/usr/bin/git", "-C", str(self.repository), "config", "user.name", "Test"],
            check=True,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.repository),
                "config",
                "user.email",
                "test@example.invalid",
            ],
            check=True,
        )
        tracked = self.repository / "tracked.txt"
        tracked.write_text("unchanged\n", encoding="utf-8")
        subprocess.run(["/usr/bin/git", "-C", str(self.repository), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["/usr/bin/git", "-C", str(self.repository), "commit", "-qm", "fixture"],
            check=True,
        )
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.runtime = self.root / "runtime"
        self.packet = {
            "task_id": "execution-test",
            "classification": "synthetic",
            "instructions": "Inspect the isolated environment and exit.",
            "scope": ["tracked.txt"],
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def executable(self, name: str, body: str, *, acknowledge: bool = True) -> Path:
        path = self.bin / name
        acknowledgement = ': > "$OC_RIG_STARTUP_ACK"\n' if acknowledge else ""
        path.write_text(
            "#!/bin/sh\nset -eu\n" + acknowledgement + body,
            encoding="utf-8",
        )
        path.chmod(0o700)
        return path

    def runner(self, executable: Path, **changes) -> WorkerRunner:
        values = {
            "runtime_root": self.runtime,
            "allowed_repository_roots": (self.allowed,),
            "armed": True,
            "executable": executable,
            "timeout_seconds": 2.0,
            "startup_timeout_seconds": 5.0,
            "port": 54321,
            "namespace": "test-namespace",
        }
        values.update(changes)
        return WorkerRunner(
            RunnerConfig(**values),
            SubprocessCommandAdapter(terminate_grace_seconds=0.1),
        )

    def test_fake_executable_receives_only_isolated_environment(self) -> None:
        executable = self.executable(
            "inspect-environment",
            """
            test -f "$OC_RIG_TASK_PACKET"
            test "$HOME" = "$OC_RIG_RUN_DIRECTORY/home"
            test "$XDG_STATE_HOME" = "$OC_RIG_RUN_DIRECTORY/state"
            test "$XDG_CACHE_HOME" = "$OC_RIG_RUN_DIRECTORY/cache"
            test "$XDG_CONFIG_HOME" = "$OC_RIG_RUN_DIRECTORY/config"
            test "$TMPDIR" = "$OC_RIG_RUN_DIRECTORY/tmp"
            test "$OC_RIG_PORT" = "54321"
            test "$OC_RIG_NAMESPACE" = "test-namespace"
            test -z "${AMBIENT_WORKER_RUNNER_SENTINEL-}"
            printf 'home=%s\\nrepo=%s\\n' "$HOME" "$PWD"
            env | sort > "$OC_RIG_OUTPUT_DIR/environment.txt"
            printf isolated > "$HOME/fake-home-write"
            """,
        )
        outside = self.root / "outside-sentinel"
        outside.write_text("preserve", encoding="utf-8")
        old_sentinel = os.environ.get("AMBIENT_WORKER_RUNNER_SENTINEL")
        os.environ["AMBIENT_WORKER_RUNNER_SENTINEL"] = "must-not-leak"
        try:
            result = self.runner(executable).run(
                self.packet, self.repository, run_id="isolation-run"
            )
        finally:
            if old_sentinel is None:
                os.environ.pop("AMBIENT_WORKER_RUNNER_SENTINEL", None)
            else:
                os.environ["AMBIENT_WORKER_RUNNER_SENTINEL"] = old_sentinel

        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(outside.read_text(encoding="utf-8"), "preserve")
        self.assertTrue((result.run_directory / "home" / "fake-home-write").is_file())
        environment = (
            result.run_directory / "output" / "environment.txt"
        ).read_text(encoding="utf-8")
        self.assertNotIn("AMBIENT_WORKER_RUNNER_SENTINEL", environment)
        self.assertNotIn(str(Path.home()), environment)
        status = subprocess.run(
            ["/usr/bin/git", "-C", str(self.repository), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(status.stdout, "")

    def test_result_and_provenance_are_atomically_captured(self) -> None:
        executable = self.executable(
            "emit-result",
            "printf 'synthetic stdout\\n'\nprintf 'synthetic stderr\\n' >&2\nexit 7\n",
        )

        result = self.runner(executable).run(
            self.packet, self.repository, run_id="atomic-run"
        )
        document = json.loads(result.result_path.read_text(encoding="utf-8"))
        stdout = (result.run_directory / "output" / "stdout.bin").read_bytes()
        stderr = (result.run_directory / "output" / "stderr.bin").read_bytes()

        self.assertEqual(result.status, "failed")
        self.assertEqual(document["status"], "failed")
        self.assertTrue(document["startup_acknowledged"])
        self.assertFalse(document["startup_timed_out"])
        self.assertEqual(document["returncode"], 7)
        self.assertEqual(document["provenance"]["repository"], str(self.repository.resolve()))
        self.assertEqual(document["provenance"]["executable"], str(executable.resolve()))
        self.assertEqual(document["provenance"]["port"], 54321)
        self.assertEqual(document["provenance"]["namespace"], "test-namespace")
        self.assertEqual(
            document["provenance"]["stdout_sha256"], hashlib.sha256(stdout).hexdigest()
        )
        self.assertEqual(
            document["provenance"]["stderr_sha256"], hashlib.sha256(stderr).hexdigest()
        )
        self.assertEqual(stdout, b"synthetic stdout\n")
        self.assertEqual(stderr, b"synthetic stderr\n")
        self.assertEqual(list(result.run_directory.rglob("*.tmp")), [])
        for path in (result.result_path, result.run_directory / "state" / "task-packet.json"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(result.run_directory.stat().st_mode), 0o700)

    def test_dirty_repository_is_rejected_before_worker_launch(self) -> None:
        marker = self.root / "worker-launched"
        executable = self.executable(
            "must-not-launch",
            f"printf launched > {str(marker)!r}\n",
        )
        (self.repository / "untracked.txt").write_text("dirty\n", encoding="utf-8")

        with self.assertRaisesRegex(RepositoryRejected, "clean Git worktree"):
            self.runner(executable).run(
                self.packet, self.repository, run_id="dirty-repository"
            )

        self.assertFalse(marker.exists())

    def test_timeout_terminates_process_group_and_records_result(self) -> None:
        executable = self.executable(
            "wait-forever",
            """
            echo $$ > "$OC_RIG_OUTPUT_DIR/worker.pid"
            trap 'exit 0' TERM INT
            while :; do sleep 10; done
            """,
        )

        result = self.runner(executable, timeout_seconds=0.5).run(
            self.packet, self.repository, run_id="timeout-run"
        )
        document = json.loads(result.result_path.read_text(encoding="utf-8"))
        pid = int(
            (result.run_directory / "output" / "worker.pid").read_text(encoding="utf-8")
        )

        self.assertEqual(result.status, "timed_out")
        self.assertTrue(document["startup_acknowledged"])
        self.assertFalse(document["startup_timed_out"])
        self.assertTrue(document["timed_out"])
        self.assertFalse(document["cancelled"])
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_missing_startup_acknowledgement_fails_closed(self) -> None:
        executable = self.executable(
            "missing-startup-ack",
            "printf 'ran without acknowledgement\\n'\n",
            acknowledge=False,
        )

        result = self.runner(executable).run(
            self.packet,
            self.repository,
            run_id="missing-startup-ack",
        )
        document = json.loads(result.result_path.read_text(encoding="utf-8"))

        self.assertEqual(result.status, "startup_failed")
        self.assertFalse(document["startup_acknowledged"])
        self.assertFalse(document["startup_timed_out"])
        self.assertEqual(
            document["startup_error"],
            "process exited before startup acknowledgement",
        )

    def test_startup_timeout_terminates_unacknowledged_process_group(self) -> None:
        runner = self.runner(
            Path("/bin/sh"),
            executable_args=(
                "-c",
                'echo $$ > "$OC_RIG_OUTPUT_DIR/startup-worker.pid"; '
                "trap 'exit 0' TERM INT; while :; do sleep 10; done",
            ),
            startup_timeout_seconds=0.3,
            timeout_seconds=5.0,
        )

        result = runner.run(
            self.packet,
            self.repository,
            run_id="startup-timeout-run",
        )
        document = json.loads(result.result_path.read_text(encoding="utf-8"))
        pid = int(
            (
                result.run_directory / "output" / "startup-worker.pid"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(result.status, "startup_timed_out")
        self.assertFalse(document["startup_acknowledged"])
        self.assertTrue(document["startup_timed_out"])
        self.assertFalse(document["timed_out"])
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_sandbox_enforces_declared_scope_and_host_containment(self) -> None:
        declared = self.repository / "declared.txt"
        declared.write_text("before\n", encoding="utf-8")
        external_directory = self.root / "symlink-target"
        external_directory.mkdir()
        (self.repository / "escape-link").symlink_to(
            external_directory,
            target_is_directory=True,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.repository),
                "add",
                "declared.txt",
                "escape-link",
            ],
            check=True,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.repository),
                "commit",
                "-qm",
                "containment inputs",
            ],
            check=True,
        )

        outside_scope = self.repository / "outside-scope.txt"
        runtime_outside_run = self.runtime / "outside-run.txt"
        symlink_escape = self.repository / "escape-link" / "escaped.txt"
        unrelated_host = self.root / "unrelated-host.txt"
        unrelated_read = self.root / "unrelated-read.txt"
        unrelated_read.write_text("must not be readable\n", encoding="utf-8")
        home_target = Path.home() / f".oc-rig-v2-containment-{os.getpid()}"
        self.assertFalse(home_target.exists())

        executable = self.executable(
            "containment-probe",
            """
            allowed=$1
            outside_scope=$2
            runtime_outside=$3
            symlink_escape=$4
            unrelated_host=$5
            home_target=$6
            repo_outside_read=$7
            unrelated_read=$8
            printf 'allowed scoped write\n' > "$allowed"
            for denied in "$outside_scope" "$runtime_outside" "$symlink_escape" "$unrelated_host" "$home_target"; do
                if printf 'sandbox escape\n' > "$denied"; then
                    exit 71
                fi
            done
            for denied_read in "$repo_outside_read" "$unrelated_read"; do
                if /bin/cat "$denied_read" >/dev/null 2>&1; then
                    exit 72
                fi
            done
            """,
        )
        packet = {**self.packet, "scope": ["declared.txt"]}
        runner = self.runner(
            executable,
            executable_args=(
                str(declared),
                str(outside_scope),
                str(runtime_outside_run),
                str(symlink_escape),
                str(unrelated_host),
                str(home_target),
                str(self.repository / "tracked.txt"),
                str(unrelated_read),
            ),
        )

        result = runner.run(
            packet,
            self.repository,
            run_id="containment-run",
        )

        self.assertEqual(result.status, "succeeded")
        self.assertEqual(declared.read_text(encoding="utf-8"), "allowed scoped write\n")
        self.assertFalse(outside_scope.exists())
        self.assertFalse(runtime_outside_run.exists())
        self.assertFalse(symlink_escape.exists())
        self.assertFalse(unrelated_host.exists())
        self.assertFalse(home_target.exists())
        profile = (
            result.run_directory / "state" / "worker-sandbox.sb"
        ).read_text(encoding="utf-8")
        self.assertIn("(deny default)", profile)
        self.assertIn(str(Path.home() / ".config" / "opencode"), profile)

    def test_declared_file_hardlinked_to_host_file_is_rejected(self) -> None:
        external = self.root / "external-hardlink.txt"
        external.write_text("external remains unchanged\n", encoding="utf-8")
        declared = self.repository / "declared-hardlink.txt"
        os.link(external, declared)
        self._commit_paths("external hardlink input", declared)
        executable = self.executable(
            "hardlink-file-probe",
            "printf 'mutated by worker\n' > \"$1\"\n",
        )
        packet = {**self.packet, "scope": ["declared-hardlink.txt"]}

        with self.assertRaisesRegex(PacketRejected, "multi-link"):
            self.runner(executable, executable_args=(str(declared),)).run(
                packet,
                self.repository,
                run_id="hardlink-file-run",
            )

        self.assertEqual(
            external.read_text(encoding="utf-8"),
            "external remains unchanged\n",
        )
        self.assertFalse(self.runtime.exists())

    def test_nested_hardlink_in_declared_directory_is_rejected(self) -> None:
        external = self.root / "external-nested-hardlink.txt"
        external.write_text("nested external remains unchanged\n", encoding="utf-8")
        scoped_directory = self.repository / "scoped-directory"
        nested = scoped_directory / "nested"
        nested.mkdir(parents=True)
        linked = nested / "linked.txt"
        os.link(external, linked)
        self._commit_paths("nested hardlink input", scoped_directory)
        executable = self.executable(
            "hardlink-directory-probe",
            "printf 'mutated by worker\n' > \"$1\"\n",
        )
        packet = {**self.packet, "scope": ["scoped-directory"]}

        with self.assertRaisesRegex(PacketRejected, "multi-link"):
            self.runner(executable, executable_args=(str(linked),)).run(
                packet,
                self.repository,
                run_id="hardlink-directory-run",
            )

        self.assertEqual(
            external.read_text(encoding="utf-8"),
            "nested external remains unchanged\n",
        )
        self.assertFalse(self.runtime.exists())

    def test_same_repository_out_of_scope_hardlink_alias_is_rejected(self) -> None:
        declared = self.repository / "declared-alias.txt"
        declared.write_text("repository aliases remain unchanged\n", encoding="utf-8")
        outside_alias = self.repository / "outside-alias.txt"
        os.link(declared, outside_alias)
        self._commit_paths("same repository hardlink input", declared, outside_alias)
        executable = self.executable(
            "hardlink-repository-probe",
            "printf 'mutated by worker\n' > \"$1\"\n",
        )
        packet = {**self.packet, "scope": ["declared-alias.txt"]}

        with self.assertRaisesRegex(PacketRejected, "multi-link"):
            self.runner(executable, executable_args=(str(declared),)).run(
                packet,
                self.repository,
                run_id="hardlink-repository-run",
            )

        expected = "repository aliases remain unchanged\n"
        self.assertEqual(declared.read_text(encoding="utf-8"), expected)
        self.assertEqual(outside_alias.read_text(encoding="utf-8"), expected)
        self.assertFalse(self.runtime.exists())

    def test_ambient_sandbox_exec_shim_is_never_selected(self) -> None:
        shim_directory = self.root / "shim-bin"
        shim_directory.mkdir()
        shim_marker = self.root / "shim-ran"
        shim = shim_directory / "sandbox-exec"
        shim.write_text(
            f"#!/bin/sh\nprintf shim > {str(shim_marker)!r}\nexit 99\n",
            encoding="utf-8",
        )
        shim.chmod(0o700)
        executable = self.executable("pinned-sandbox-probe", "printf pinned\n")
        original_path = os.environ.get("PATH")
        os.environ["PATH"] = f"{shim_directory}:{original_path or ''}"
        try:
            result = self.runner(executable).run(
                self.packet,
                self.repository,
                run_id="pinned-sandbox-run",
            )
        finally:
            if original_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = original_path

        document = json.loads(result.result_path.read_text(encoding="utf-8"))
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(
            document["provenance"]["sandbox_argv"][0],
            "/usr/bin/sandbox-exec",
        )
        self.assertFalse(shim_marker.exists())

    def _commit_paths(self, message: str, *paths: Path) -> None:
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.repository),
                "add",
                *[str(path.relative_to(self.repository)) for path in paths],
            ],
            check=True,
        )
        subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(self.repository),
                "commit",
                "-qm",
                message,
            ],
            check=True,
        )

    def test_cancellation_prevents_worker_process_launch(self) -> None:
        marker = self.root / "cancelled-worker-launched"
        executable = self.executable(
            "cancelled-worker",
            f"printf launched > {str(marker)!r}\n",
        )
        token = CancellationToken()

        class CancelBeforeWorkerAdapter(SubprocessCommandAdapter):
            def execute(adapter_self, request, cancellation):
                if request.argv[0] != "/usr/bin/git":
                    cancellation.cancel()
                return super().execute(request, cancellation)

        runner = WorkerRunner(
            RunnerConfig(
                runtime_root=self.runtime,
                allowed_repository_roots=(self.allowed,),
                armed=True,
                executable=executable,
                timeout_seconds=2,
            ),
            CancelBeforeWorkerAdapter(),
        )
        result = runner.run(
            self.packet,
            self.repository,
            cancellation=token,
            run_id="cancel-run",
        )
        document = json.loads(result.result_path.read_text(encoding="utf-8"))

        self.assertEqual(result.status, "cancelled")
        self.assertTrue(document["cancelled"])
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
