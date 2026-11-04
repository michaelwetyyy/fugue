from __future__ import annotations

import unittest
from pathlib import Path


class SourceRuntimeSeparationTests(unittest.TestCase):
    def test_tracked_tree_contains_no_runtime_artifacts(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        ignored_directories = {".git", "__pycache__", ".pytest_cache"}
        forbidden_names = {
            ".env",
            "rig.db",
            "rig.db-shm",
            "rig.db-wal",
            "rig.pid",
        }
        forbidden_suffixes = {".db", ".sqlite", ".sqlite3", ".pid", ".log"}

        artifacts = []
        for path in repository.rglob("*"):
            relative = path.relative_to(repository)
            if any(part in ignored_directories for part in relative.parts):
                continue
            if path.is_file() and (
                path.name in forbidden_names or path.suffix in forbidden_suffixes
            ):
                artifacts.append(str(relative))

        self.assertEqual(
            artifacts,
            [],
            "runtime artifacts must be written outside the source checkout",
        )


if __name__ == "__main__":
    unittest.main()
