from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from oc_rig.policy.capsule import (
    MAX_SCOPE_FILE_BYTES,
    MAX_SCOPE_FILES,
    ScopeCapsuleError,
    _read_file_once,
    capsule_document,
    capture_patch_scope_capsule,
    capture_scope_capsule,
    patch_capsule_document,
    patch_private_authority,
    parse_task_prompt,
    validate_capsule_envelope,
    validate_patch_capsule_envelope,
    validate_task_envelope,
)


class ScopeCapsuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name).resolve() / "source-root-private"
        self.repository.mkdir()

    def write(self, relative: str, content: str = "first line\nsecond line\n") -> Path:
        path = self.repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def assert_rejected(self, paths: object, code: str) -> None:
        with self.assertRaises(ScopeCapsuleError) as caught:
            capture_scope_capsule(str(self.repository), paths)
        self.assertEqual(caught.exception.code, code)

    def test_exact_files_are_deterministic_content_bound_and_line_addressable(self) -> None:
        second = self.write("zeta.py", "one\ntwo\nthree")
        first = self.write("alpha/readme.md", "heading\nbody\n")
        originals = {first: first.read_bytes(), second: second.read_bytes()}

        capsule = capture_scope_capsule(
            str(self.repository), ["zeta.py", "alpha/readme.md"]
        )
        document = capsule_document(capsule)
        envelope = {
            "claim_scope_hash": capsule.claim_scope_hash,
            "review_profiles": ["correctness", "security"],
            "scope": ["alpha/readme.md", "zeta.py"],
            "scope_capsule": document,
            "task_mode": "read_only_review",
            "version": 2,
        }

        self.assertEqual(
            validate_capsule_envelope(envelope),
            (capsule.claim_scope_hash, capsule.scope_hash),
        )
        self.assertEqual([item["path"] for item in document["files"]], envelope["scope"])
        self.assertEqual(document["files"][0]["line_start"], 1)
        self.assertEqual(document["files"][0]["line_end"], 2)
        self.assertEqual(document["files"][1]["line_end"], 3)
        serialized = json.dumps(envelope, sort_keys=True)
        self.assertNotIn(str(self.repository), serialized)
        self.assertNotIn(self.repository.name, serialized)
        for path, content in originals.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertEqual(
            capsule,
            capture_scope_capsule(
                str(self.repository), ["alpha/readme.md", "zeta.py"]
            ),
        )

    def test_patch_capsule_discloses_only_the_admitted_window(self) -> None:
        self.write("large.ts", "private prefix\neditable one\neditable two\nprivate suffix\n")
        capsule = capture_patch_scope_capsule(
            str(self.repository), ["large.ts"], 2, 3
        )
        document = patch_capsule_document(capsule)
        envelope = {
            "claim_scope_hash": capsule.base.claim_scope_hash,
            "review_profiles": ["correctness"],
            "scope": ["large.ts"],
            "scope_capsule": document,
            "task_mode": "read_only_review",
            "version": 2,
        }

        self.assertEqual(document["files"][0]["content"], "editable one\neditable two\n")
        self.assertNotIn("private prefix", json.dumps(document))
        self.assertIn("private prefix", patch_private_authority(capsule)["content"])
        self.assertEqual(
            validate_patch_capsule_envelope(envelope)[0],
            capsule.base.claim_scope_hash,
        )
        task = {
            "agent_lifecycle": "disposable",
            "allow_child_agents": True,
            "claim_scope_hash": capsule.base.claim_scope_hash,
            "objective": "Edit the admitted lines.",
            "scope": ["large.ts"],
            "scope_capsule": document,
            "submission_fingerprint": "d" * 64,
            "task_mode": "workspace_patch",
            "version": 1,
        }
        self.assertIsNotNone(validate_task_envelope(task))
        self.assertEqual(
            parse_task_prompt(json.dumps(task, sort_keys=True, separators=(",", ":"))),
            task,
        )
        with self.assertRaisesRegex(ScopeCapsuleError, "scope_task_invalid"):
            validate_task_envelope({**task, "agent_lifecycle": "persistent"})

    def test_patch_capsule_rejects_invalid_ranges_and_window_tampering(self) -> None:
        self.write("large.ts", "one\ntwo\nthree\n")
        for start, end in ((0, 1), (2, 1), (1, 999), (True, 1)):
            with self.subTest(start=start, end=end), self.assertRaises(ScopeCapsuleError):
                capture_patch_scope_capsule(str(self.repository), ["large.ts"], start, end)
        capsule = capture_patch_scope_capsule(str(self.repository), ["large.ts"], 2, 2)
        document = patch_capsule_document(capsule)
        document["files"][0]["content"] = "tampered\n"
        envelope = {
            "claim_scope_hash": capsule.base.claim_scope_hash,
            "review_profiles": ["correctness"],
            "scope": ["large.ts"],
            "scope_capsule": document,
            "task_mode": "read_only_review",
            "version": 2,
        }
        with self.assertRaisesRegex(ScopeCapsuleError, "scope_patch_capsule_invalid"):
            validate_patch_capsule_envelope(envelope)

    def test_unsafe_path_forms_and_bounds_are_rejected_before_open(self) -> None:
        cases = (
            (["../escape"], "scope_path_traversal"),
            ([".git/config"], "scope_git_admin"),
            (["alpha", "ALPHA"], "scope_path_collision"),
            (["alpha", "alpha/child"], "scope_path_prefix_ambiguity"),
            (["/absolute"], "scope_path_traversal"),
            (["a/" * 32 + "leaf"], "scope_path_depth_exceeded"),
            (["a" * 1025], "scope_path_invalid"),
            ([f"file-{index}" for index in range(MAX_SCOPE_FILES + 1)], "scope_file_count_exceeded"),
            (["line\nbreak.py"], "scope_path_invalid"),
            (["tab\tpath.py"], "scope_path_invalid"),
        )
        for paths, code in cases:
            with self.subTest(code=code):
                self.assert_rejected(paths, code)

    def test_missing_directory_symlink_hardlink_and_special_files_are_rejected(self) -> None:
        self.assert_rejected(["missing"], "scope_file_open_failed")
        (self.repository / "directory").mkdir()
        self.assert_rejected(["directory"], "scope_file_non_regular")

        source = self.write("source.txt", "safe\n")
        if hasattr(os, "symlink"):
            (self.repository / "link").symlink_to(source)
            self.assert_rejected(["link"], "scope_file_symlink")
        if hasattr(os, "link"):
            os.link(source, self.repository / "hardlink")
            self.assert_rejected(["source.txt"], "scope_file_hardlink")
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.repository / "fifo")
            self.assert_rejected(["fifo"], "scope_file_non_regular")

    def test_binary_secret_entropy_and_per_file_size_are_rejected(self) -> None:
        cases: tuple[tuple[str, bytes, str], ...] = (
            ("nul.bin", b"safe\x00text", "scope_file_binary"),
            ("utf8.bin", b"\xff\xfe", "scope_file_not_utf8"),
            ("secret.txt", b"token=synthetic-secret", "scope_file_sensitive"),
            (
                "private.pem",
                b"-----BEGIN PRIVATE KEY-----\nfixture\n",
                "scope_file_sensitive",
            ),
            (
                "entropy.txt",
                b"A1b2C3d4E5f6G7h8I9j0K_lMnOpQrStUvWxYz",
                "scope_file_high_entropy",
            ),
            (
                "large.txt",
                b"x" * (MAX_SCOPE_FILE_BYTES + 1),
                "scope_file_size_exceeded",
            ),
        )
        for name, content, code in cases:
            with self.subTest(name=name):
                (self.repository / name).write_bytes(content)
                self.assert_rejected([name], code)

        self.write("safe.txt", "bounded\n")
        self.assert_rejected(
            ["A1b2C3d4E5f6G7h8I9j0K_lMnOpQrStUvWxYz.txt"],
            "scope_file_high_entropy",
        )

    def test_repository_path_in_content_is_rejected_before_serialization(self) -> None:
        self.write(
            "path.txt",
            f"source root: {str(self.repository).upper()}\n",
        )
        self.assert_rejected(["path.txt"], "scope_file_repository_path")

    def test_split_secret_like_text_shows_scanner_is_only_defense_in_depth(self) -> None:
        self.write("split.py", 'value = "tok" + "en=fixture"\n')
        capsule = capture_scope_capsule(str(self.repository), ["split.py"])
        self.assertEqual(capsule.files[0].relative, "split.py")

    def test_many_source_identifiers_do_not_exhaust_the_bounded_scanner(self) -> None:
        source = "\n".join(
            f"const ordinaryIdentifierNumber{index:03d} = componentValueNumber{index:03d};"
            for index in range(160)
        )
        self.write("component.tsx", source + "\n")

        capsule = capture_scope_capsule(str(self.repository), ["component.tsx"])

        self.assertEqual(capsule.files[0].relative, "component.tsx")

    def test_line_scanning_still_rejects_embedded_secret_material(self) -> None:
        self.write(
            "component.tsx",
            "\n".join(
                ["const ordinaryComponentName = true;"] * 80
                + ['const access_token = "synthetic-secret-value";']
            ),
        )

        self.assert_rejected(["component.tsx"], "scope_file_sensitive")

    def test_repository_replacement_cannot_mix_capture_roots(self) -> None:
        first = self.write("one.txt", "one\n")
        self.write("two.txt", "two\n")
        moved = self.repository.with_name("source-root-moved")
        original_read = __import__(
            "oc_rig.policy.capsule", fromlist=["_read_stable_file"]
        )._read_stable_file
        calls = 0

        def replacing_read(root: int, relative: str):
            nonlocal calls
            snapshot = original_read(root, relative)
            calls += 1
            if calls == 1:
                self.repository.rename(moved)
                self.repository.mkdir()
                self.repository.joinpath("one.txt").write_text("replacement\n")
                self.repository.joinpath("two.txt").write_text("replacement\n")
            return snapshot

        with patch(
            "oc_rig.policy.capsule._read_stable_file",
            side_effect=replacing_read,
        ):
            self.assert_rejected(["one.txt", "two.txt"], "scope_root_race")
        self.assertEqual(moved.joinpath(first.name).read_text(encoding="utf-8"), "one\n")

    def test_reopen_inode_ctime_size_or_hash_change_fails_closed(self) -> None:
        path = self.write("race.txt", "before\n")
        calls = 0

        def racing_read(repository: int, relative: str):
            nonlocal calls
            calls += 1
            result = _read_file_once(repository, relative)
            if calls == 1:
                path.write_text("after with different bytes\n", encoding="utf-8")
            return result

        with patch("oc_rig.policy.capsule._read_file_once", side_effect=racing_read):
            self.assert_rejected(["race.txt"], "scope_file_race")

    def test_manifest_or_content_tampering_is_rejected(self) -> None:
        self.write("one.txt", "review me\n")
        capsule = capture_scope_capsule(str(self.repository), ["one.txt"])
        envelope = {
            "claim_scope_hash": capsule.claim_scope_hash,
            "review_profiles": ["correctness"],
            "scope": ["one.txt"],
            "scope_capsule": capsule_document(capsule),
            "task_mode": "read_only_review",
            "version": 2,
        }
        envelope["scope_capsule"]["files"][0]["content"] = "tampered\n"
        with self.assertRaisesRegex(ScopeCapsuleError, "scope_capsule_invalid"):
            validate_capsule_envelope(envelope)

    def test_capsule_markers_and_numeric_metadata_require_exact_types(self) -> None:
        self.write("one.txt", "review me\n")
        capsule = capture_scope_capsule(str(self.repository), ["one.txt"])
        envelope = {
            "claim_scope_hash": capsule.claim_scope_hash,
            "review_profiles": ["correctness"],
            "scope": ["one.txt"],
            "scope_capsule": capsule_document(capsule),
            "task_mode": "read_only_review",
            "version": 2,
        }
        malformed = (
            {**envelope, "version": 2.0},
            {**envelope, "version": 1},
            {
                **envelope,
                "scope_capsule": {
                    **envelope["scope_capsule"],
                    "manifest": {
                        **envelope["scope_capsule"]["manifest"],
                        "file_count": True,
                    },
                },
            },
        )
        for document in malformed:
            with self.subTest(version=document["version"]):
                with self.assertRaisesRegex(
                    ScopeCapsuleError, "scope_capsule_invalid"
                ):
                    validate_capsule_envelope(document)

    def test_task_envelope_is_canonical_bound_and_rescanned(self) -> None:
        self.write("component.tsx", "export const Component = () => null;\n")
        capsule = capture_scope_capsule(str(self.repository), ["component.tsx"])
        envelope = {
            "agent_lifecycle": "persistent",
            "allow_child_agents": True,
            "claim_scope_hash": capsule.claim_scope_hash,
            "objective": "Return a bounded implementation proposal.",
            "scope": ["component.tsx"],
            "scope_capsule": capsule_document(capsule),
            "submission_fingerprint": "a" * 64,
            "task_mode": "agent_task",
            "version": 1,
        }
        encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":"))

        self.assertEqual(
            validate_task_envelope(envelope),
            (capsule.claim_scope_hash, capsule.scope_hash),
        )
        self.assertEqual(parse_task_prompt(encoded), envelope)
        workspace = {**envelope, "task_mode": "workspace_edit"}
        self.assertEqual(
            validate_task_envelope(workspace),
            (capsule.claim_scope_hash, capsule.scope_hash),
        )
        with self.assertRaisesRegex(ScopeCapsuleError, "scope_task_invalid"):
            parse_task_prompt(encoded + "\n")
        with self.assertRaisesRegex(
            ScopeCapsuleError, "scope_task_objective_unsafe"
        ):
            validate_task_envelope(
                {**envelope, "objective": "token=synthetic-secret-value"}
            )


if __name__ == "__main__":
    unittest.main()
