from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from oc_rig.migration.release import build_release_artifact, verify_release_artifact
from tests.test_migration_rehearsal import rewrite_release


REPOSITORY = Path(__file__).resolve().parents[1]


class ReleaseLicenseTests(unittest.TestCase):
    def test_license_is_covered_by_wheel_metadata_record_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = build_release_artifact(REPOSITORY, Path(directory))
            with zipfile.ZipFile(artifact.wheel) as archive:
                name = next(n for n in archive.namelist() if n.endswith('/licenses/LICENSE'))
                prefix = name.removesuffix('licenses/LICENSE')
                license_bytes = archive.read(name)
                self.assertEqual(license_bytes, (REPOSITORY / 'LICENSE').read_bytes())
                self.assertIn(b'License-File: LICENSE\n', archive.read(prefix + 'METADATA'))
                self.assertIn(name.encode(), archive.read(prefix + 'RECORD'))
            manifest = json.loads(artifact.manifest.read_text())
            item = next(member for member in manifest['members'] if member['path'] == name)
            self.assertEqual(item['sha256'], hashlib.sha256(license_bytes).hexdigest())
            self.assertEqual(item['size'], len(license_bytes))

    def test_missing_license_is_not_accepted_as_a_current_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = build_release_artifact(REPOSITORY, Path(directory))

            def remove_license(members: dict[str, bytes]) -> None:
                name = next(n for n in members if n.endswith('/licenses/LICENSE'))
                del members[name]

            rewrite_release(artifact, remove_license, rebuild_record=True)
            with self.assertRaisesRegex(ValueError, 'dist-info membership'):
                verify_release_artifact(artifact.wheel, artifact.manifest)


if __name__ == '__main__':
    unittest.main()
