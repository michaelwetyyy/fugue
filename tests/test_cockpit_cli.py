from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from oc_rig.cli import main
from oc_rig.store import PrivateRuntimeDirectory, RigStore
from oc_rig.store.snapshot import _CockpitSnapshotProjection


class CockpitCliTests(unittest.TestCase):
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

    def test_cockpit_and_status_are_one_shot_plain_renderers(self) -> None:
        calls = 0
        snapshot = self.snapshot

        class OneShotClient:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def refresh(self) -> dict[str, object]:
                nonlocal calls
                calls += 1
                return snapshot

        for command in ("cockpit", "status"):
            stdout = StringIO()
            with patch("oc_rig.cli.CockpitClient", OneShotClient), redirect_stdout(stdout):
                result = main(
                    [
                        "--socket",
                        "/unused/rig.sock",
                        "--identity-profile",
                        "local-user",
                        command,
                        "--width",
                        "60",
                        "--no-ansi",
                    ]
                )
            self.assertEqual(result, 0)
            self.assertIn("Fugue · ready", stdout.getvalue())
            self.assertNotIn("Refresh:", stdout.getvalue())
            self.assertNotIn("\x1b", stdout.getvalue())
        self.assertEqual(calls, 2)

    def test_details_flag_returns_complete_normalized_projection(self) -> None:
        snapshot = self.snapshot

        class OneShotClient:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def refresh(self) -> dict[str, object]:
                return snapshot

        stdout = StringIO()
        with patch("oc_rig.cli.CockpitClient", OneShotClient), redirect_stdout(stdout):
            result = main(
                [
                    "--socket",
                    "/unused/rig.sock",
                    "--identity-profile",
                    "local-user",
                    "cockpit",
                    "--details",
                ]
            )
        self.assertEqual(result, 0)
        value = json.loads(stdout.getvalue())
        self.assertEqual(value["refresh"], {"mode": "explicit", "polling": "disabled"})
        self.assertIn("session", value["worker_graph"]["workers"][0])

    def test_json_renderer_is_explicit_and_machine_readable(self) -> None:
        snapshot = self.snapshot

        class OneShotClient:
            def __init__(self, *_args: object, **_kwargs: object):
                pass

            def refresh(self) -> dict[str, object]:
                return snapshot

        stdout = StringIO()
        with patch("oc_rig.cli.CockpitClient", OneShotClient), redirect_stdout(stdout):
            result = main(
                [
                    "--socket",
                    "/unused/rig.sock",
                    "--identity-profile",
                    "local-user",
                    "cockpit",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(result, 0)
        value = json.loads(stdout.getvalue())
        self.assertEqual(value["projection_version"], 1)
        self.assertEqual(value["refresh"], {"mode": "explicit", "polling": "disabled"})


if __name__ == "__main__":
    unittest.main()
