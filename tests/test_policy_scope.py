from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from oc_rig.policy import ReasonCode, inspect_scope


class ExactScopePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.repository = self.root / "repository"
        self.repository.mkdir()
        (self.repository / "alpha").mkdir()
        (self.repository / "alpha" / "one.txt").write_text("one\n", encoding="utf-8")
        (self.repository / "alphabet").mkdir()
        (self.repository / "alphabet" / "two.txt").write_text("two\n", encoding="utf-8")

    def assert_rejected(self, scope: object, reason: ReasonCode) -> None:
        result = inspect_scope(self.repository, scope)
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason_codes, (reason,))

    def test_normalizes_sort_order_and_preserves_component_boundaries(self) -> None:
        result = inspect_scope(
            self.repository,
            ["alphabet/two.txt", "new/output.txt", "alpha/one.txt"],
        )

        self.assertTrue(result.accepted)
        self.assertEqual(
            tuple(path.relative for path in result.paths),
            ("alpha/one.txt", "alphabet/two.txt", "new/output.txt"),
        )

    def test_absolute_traversal_git_and_ambiguous_characters_are_rejected(self) -> None:
        cases = (
            (["/etc/passwd"], ReasonCode.SCOPE_ABSOLUTE),
            (["C:/Windows/System32"], ReasonCode.SCOPE_ABSOLUTE),
            (["../escape"], ReasonCode.SCOPE_TRAVERSAL),
            (["nested/../../escape"], ReasonCode.SCOPE_TRAVERSAL),
            (["./alpha"], ReasonCode.SCOPE_TRAVERSAL),
            (["alpha//one.txt"], ReasonCode.SCOPE_TRAVERSAL),
            ([".git/config"], ReasonCode.SCOPE_GIT_ADMIN),
            (["alpha/.GIT/config"], ReasonCode.SCOPE_GIT_ADMIN),
            (["alpha\\one.txt"], ReasonCode.SCOPE_INVALID_ENTRY),
            (["alpha/\u200bone.txt"], ReasonCode.SCOPE_INVALID_ENTRY),
        )
        for scope, reason in cases:
            with self.subTest(scope=scope):
                self.assert_rejected(scope, reason)

    def test_duplicate_unicode_case_collision_and_prefix_ambiguity_are_rejected(self) -> None:
        cases = (
            (["alpha/one.txt", "alpha/one.txt"], ReasonCode.SCOPE_COLLISION),
            (["alpha/one.txt", "ALPHA/ONE.TXT"], ReasonCode.SCOPE_COLLISION),
            (["alpha/one.txt", "\uff41\uff4c\uff50\uff48\uff41/one.txt"], ReasonCode.SCOPE_COLLISION),
            (["alpha", "alpha/one.txt"], ReasonCode.SCOPE_PREFIX_AMBIGUITY),
        )
        for scope, reason in cases:
            with self.subTest(scope=scope):
                self.assert_rejected(scope, reason)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are required")
    def test_symlink_leaf_ancestor_and_directory_descendant_are_rejected(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (self.repository / "escape").symlink_to(outside, target_is_directory=True)
        self.assert_rejected(["escape/file.txt"], ReasonCode.SCOPE_SYMLINK)

        linked_file = self.repository / "linked-file"
        linked_file.symlink_to(self.repository / "alpha" / "one.txt")
        self.assert_rejected(["linked-file"], ReasonCode.SCOPE_SYMLINK)

        directory = self.repository / "contains-link"
        directory.mkdir()
        (directory / "child").symlink_to(outside, target_is_directory=True)
        self.assert_rejected(["contains-link"], ReasonCode.SCOPE_SYMLINK)

    @unittest.skipUnless(hasattr(os, "link"), "hardlinks are required")
    def test_hardlink_leaf_and_directory_descendant_are_rejected(self) -> None:
        source = self.root / "outside-file"
        source.write_text("outside\n", encoding="utf-8")
        os.link(source, self.repository / "hardlinked")
        self.assert_rejected(["hardlinked"], ReasonCode.SCOPE_HARDLINK)

        directory = self.repository / "contains-hardlink"
        directory.mkdir()
        os.link(source, directory / "child")
        self.assert_rejected(["contains-hardlink"], ReasonCode.SCOPE_HARDLINK)

    def test_non_directory_ancestor_and_special_node_are_rejected(self) -> None:
        (self.repository / "plain-file").write_text("plain\n", encoding="utf-8")
        self.assert_rejected(
            ["plain-file/child"],
            ReasonCode.SCOPE_NON_REGULAR,
        )

        fifo = self.repository / "fifo"
        os.mkfifo(fifo)
        self.assert_rejected(["fifo"], ReasonCode.SCOPE_NON_REGULAR)


if __name__ == "__main__":
    unittest.main()
