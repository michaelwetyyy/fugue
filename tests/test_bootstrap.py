from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from oc_rig import __version__
from oc_rig.cli import main
from oc_rig.runtime import RuntimeDirectories


class BootstrapTests(unittest.TestCase):
    def test_version_is_declared(self) -> None:
        self.assertEqual(__version__, "0.1.0.dev0")

    def test_runtime_paths_are_calculated_without_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            home = Path(temporary_directory) / "example-home"
            before = set(Path(temporary_directory).iterdir())
            paths = RuntimeDirectories.for_home(home)

            self.assertEqual(
                paths.state,
                home / "Library" / "Application Support" / "oc-rig",
            )
            self.assertEqual(paths.cache, home / "Library" / "Caches" / "oc-rig")
            self.assertEqual(paths.logs, home / "Library" / "Logs" / "oc-rig")
            self.assertEqual(set(Path(temporary_directory).iterdir()), before)

    def test_cli_reports_version_without_live_integration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            home = Path(temporary_directory) / "home"
            working_directory = Path(temporary_directory) / "work"
            home.mkdir()
            working_directory.mkdir()
            before = sorted(
                path.relative_to(temporary_directory)
                for path in Path(temporary_directory).rglob("*")
            )
            completed = subprocess.run(
                [sys.executable, "-m", "oc_rig.cli", "--version"],
                check=True,
                capture_output=True,
                text=True,
                cwd=working_directory,
                env={"HOME": str(home), "PYTHONPATH": str(Path.cwd() / "src")},
            )
            after = sorted(
                path.relative_to(temporary_directory)
                for path in Path(temporary_directory).rglob("*")
            )

        self.assertEqual(completed.stdout.strip(), "rigctl 0.1.0.dev0")
        self.assertEqual(completed.stderr, "")
        self.assertEqual(after, before)

    def test_cli_main_is_inert_without_arguments(self) -> None:
        stdout = StringIO()
        stderr = StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main([])

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
