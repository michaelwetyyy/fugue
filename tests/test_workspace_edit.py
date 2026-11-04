from __future__ import annotations

import hashlib
import json
import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import oc_rig.workspace_edit as workspace_edit_module
from oc_rig.policy import (
    capsule_document,
    capture_patch_scope_capsule,
    capture_scope_capsule,
    patch_capsule_document,
    patch_private_authority,
)
from oc_rig.workspace_edit import (
    WorkspaceEditIndeterminate,
    WorkspaceEditRejected,
    apply_workspace_edit_plan,
)


@unittest.skipUnless(sys.platform == "darwin", "workspace edit swap requires macOS")
class WorkspaceEditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name).resolve()
        self.first = self.repository / "first.txt"
        self.second = self.repository / "nested" / "second.txt"
        self.second.parent.mkdir()
        self.first.write_text("before one\n", encoding="utf-8")
        self.second.write_text("before two\n", encoding="utf-8")
        capsule = capture_scope_capsule(
            str(self.repository), ["first.txt", "nested/second.txt"]
        )
        self.envelope = {
            "agent_lifecycle": "disposable",
            "allow_child_agents": True,
            "claim_scope_hash": capsule.claim_scope_hash,
            "objective": "Apply the requested bounded edits.",
            "scope": ["first.txt", "nested/second.txt"],
            "task_mode": "workspace_edit",
            "scope_capsule": capsule_document(capsule),
            "submission_fingerprint": "a" * 64,
            "version": 1,
        }
        self.hashes = {
            item.relative: item.content_hash for item in capsule.files
        }

    def plan(self, *edits: tuple[str, str]) -> str:
        return json.dumps(
            {
                "version": 1,
                "summary": "Apply the requested bounded edits.",
                "edits": [
                    {
                        "path": path,
                        "before_sha256": self.hashes[path],
                        "content": content,
                    }
                    for path, content in edits
                ],
            }
        )

    def patch_case(self) -> tuple[Path, dict[str, object], dict[str, object], str]:
        target = self.repository / "large.ts"
        target.write_text("prefix\nold one\nold two\nsuffix\n", encoding="utf-8")
        capsule = capture_patch_scope_capsule(
            str(self.repository), ["large.ts"], 2, 3
        )
        envelope = {
            "agent_lifecycle": "disposable",
            "allow_child_agents": True,
            "claim_scope_hash": capsule.base.claim_scope_hash,
            "objective": "Replace the admitted function body.",
            "scope": ["large.ts"],
            "task_mode": "workspace_patch",
            "scope_capsule": patch_capsule_document(capsule),
            "submission_fingerprint": "c" * 64,
            "version": 1,
        }
        authority = patch_private_authority(capsule)
        plan = json.dumps(
            {
                "version": 1,
                "summary": "Replace only the admitted lines.",
                "edits": [
                    {
                        "path": "large.ts",
                        "before_sha256": capsule.base.files[0].content_hash,
                        "line_start": 2,
                        "line_end": 3,
                        "before_text_sha256": capsule.window_hash,
                        "replacement": "new one\nnew two\nnew three\n",
                    }
                ],
            }
        )
        return target, envelope, authority, plan

    def test_patch_applies_only_admitted_window_and_is_idempotent(self) -> None:
        target, envelope, authority, plan = self.patch_case()

        first = apply_workspace_edit_plan(
            str(self.repository), envelope, plan, authority
        )
        second = apply_workspace_edit_plan(
            str(self.repository), envelope, plan, authority
        )

        self.assertEqual(first, second)
        self.assertEqual(
            target.read_text(encoding="utf-8"),
            "prefix\nnew one\nnew two\nnew three\nsuffix\n",
        )
        receipt = json.loads(first)["workspace_patch"]
        self.assertEqual(receipt["range"], {"line_start": 2, "line_end": 3})
        self.assertNotIn("new one", first)

    def test_patch_rejects_changes_outside_window_and_changed_authority(self) -> None:
        target, envelope, authority, plan = self.patch_case()
        target.write_text("changed prefix\nold one\nold two\nsuffix\n", encoding="utf-8")
        with self.assertRaisesRegex(WorkspaceEditRejected, "preimage_changed"):
            apply_workspace_edit_plan(str(self.repository), envelope, plan, authority)

        target.write_text("prefix\nold one\nold two\nsuffix\n", encoding="utf-8")
        changed = dict(authority)
        changed["line_start"] = 1
        with self.assertRaisesRegex(WorkspaceEditRejected, "patch_authority_invalid"):
            apply_workspace_edit_plan(str(self.repository), envelope, plan, changed)
        changed = dict(authority)
        changed["version"] = True
        with self.assertRaisesRegex(WorkspaceEditRejected, "patch_authority_invalid"):
            apply_workspace_edit_plan(str(self.repository), envelope, plan, changed)

    def test_patch_rejects_worker_selected_range_and_unsafe_replacement(self) -> None:
        target, envelope, authority, plan = self.patch_case()
        value = json.loads(plan)
        value["edits"][0]["line_start"] = 1
        with self.assertRaisesRegex(WorkspaceEditRejected, "patch_entry_invalid"):
            apply_workspace_edit_plan(
                str(self.repository), envelope, json.dumps(value), authority
            )
        value = json.loads(plan)
        value["edits"][0]["replacement"] = "token=synthetic-secret-value\n"
        with self.assertRaisesRegex(WorkspaceEditRejected, "patch_content_unsafe"):
            apply_workspace_edit_plan(
                str(self.repository), envelope, json.dumps(value), authority
            )
        value = json.loads(plan)
        value["edits"][0]["replacement"] = "old one\nold two\n"
        with self.assertRaisesRegex(WorkspaceEditRejected, "patch_entry_invalid"):
            apply_workspace_edit_plan(
                str(self.repository), envelope, json.dumps(value), authority
            )
        duplicate = plan.replace('"version": 1,', '"version": 1, "version": 1,', 1)
        with self.assertRaisesRegex(WorkspaceEditRejected, "patch_result_invalid"):
            apply_workspace_edit_plan(
                str(self.repository), envelope, duplicate, authority
            )
        value = json.loads(plan)
        value["summary"] = "\ud800"
        with self.assertRaisesRegex(WorkspaceEditRejected, "patch_summary_invalid"):
            apply_workspace_edit_plan(
                str(self.repository), envelope, json.dumps(value), authority
            )
        with self.assertRaisesRegex(WorkspaceEditRejected, "patch_result_invalid"):
            apply_workspace_edit_plan(
                str(self.repository), envelope, " " * (600 * 1024), authority
            )
        self.assertEqual(
            target.read_text(encoding="utf-8"), "prefix\nold one\nold two\nsuffix\n"
        )

    def test_patch_preserves_crlf_and_missing_final_newline_outside_window(self) -> None:
        target = self.repository / "windows.txt"
        target.write_bytes(b"prefix\r\nold\r\nsuffix")
        capsule = capture_patch_scope_capsule(
            str(self.repository), ["windows.txt"], 2, 2
        )
        envelope = {
            "agent_lifecycle": "disposable",
            "allow_child_agents": True,
            "claim_scope_hash": capsule.base.claim_scope_hash,
            "objective": "Replace the admitted line.",
            "scope": ["windows.txt"],
            "scope_capsule": patch_capsule_document(capsule),
            "submission_fingerprint": "d" * 64,
            "task_mode": "workspace_patch",
            "version": 1,
        }
        plan = json.dumps(
            {
                "version": 1,
                "summary": "Replace the admitted line.",
                "edits": [
                    {
                        "path": "windows.txt",
                        "before_sha256": capsule.base.files[0].content_hash,
                        "line_start": 2,
                        "line_end": 2,
                        "before_text_sha256": capsule.window_hash,
                        "replacement": "new\r\n",
                    }
                ],
            }
        )

        apply_workspace_edit_plan(
            str(self.repository), envelope, plan, patch_private_authority(capsule)
        )

        self.assertEqual(target.read_bytes(), b"prefix\r\nnew\r\nsuffix")

    def test_patch_recovers_exactly_after_post_swap_fsync_failure(self) -> None:
        target, envelope, authority, plan = self.patch_case()
        original_fsync = workspace_edit_module.os.fsync
        calls = 0

        def fail_first_directory_fsync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected directory fsync failure")
            original_fsync(descriptor)

        with patch.object(workspace_edit_module.os, "fsync", fail_first_directory_fsync):
            with self.assertRaisesRegex(WorkspaceEditIndeterminate, "commit_unconfirmed"):
                apply_workspace_edit_plan(
                    str(self.repository), envelope, plan, authority
                )

        receipt = apply_workspace_edit_plan(
            str(self.repository), envelope, plan, authority
        )
        self.assertTrue(json.loads(receipt)["workspace_patch"]["applied"])
        self.assertEqual(
            target.read_text(encoding="utf-8"),
            "prefix\nnew one\nnew two\nnew three\nsuffix\n",
        )

    def test_applies_exact_files_and_returns_content_free_receipt(self) -> None:
        plan = self.plan(
            ("first.txt", "after one\n"),
        )

        receipt = json.loads(
            apply_workspace_edit_plan(str(self.repository), self.envelope, plan)
        )

        self.assertEqual(self.first.read_text(encoding="utf-8"), "after one\n")
        self.assertEqual(self.second.read_text(encoding="utf-8"), "before two\n")
        self.assertEqual(receipt["workspace_edit"]["edit_count"], 1)
        self.assertEqual(
            receipt["workspace_edit"]["plan_sha256"],
            hashlib.sha256(plan.encode("utf-8")).hexdigest(),
        )
        self.assertNotIn("after one", json.dumps(receipt))

    def test_retry_is_idempotent_after_every_postimage_landed(self) -> None:
        plan = self.plan(("first.txt", "after one\n"))
        first = apply_workspace_edit_plan(str(self.repository), self.envelope, plan)
        second = apply_workspace_edit_plan(str(self.repository), self.envelope, plan)
        self.assertEqual(first, second)
        self.assertEqual(self.first.read_text(encoding="utf-8"), "after one\n")

    def test_unknown_path_duplicate_and_changed_preimage_fail_closed(self) -> None:
        cases = (
            json.dumps(
                {
                    "version": True,
                    "summary": "boolean version",
                    "edits": [
                        {
                            "path": "first.txt",
                            "before_sha256": self.hashes["first.txt"],
                            "content": "bad\n",
                        }
                    ],
                }
            ),
            json.dumps(
                {
                    "version": 1,
                    "summary": "bad path",
                    "edits": [
                        {
                            "path": "outside.txt",
                            "before_sha256": "0" * 64,
                            "content": "bad\n",
                        }
                    ],
                }
            ),
            self.plan(("first.txt", "one\n"), ("first.txt", "two\n")),
        )
        for plan in cases:
            with self.subTest(plan=plan), self.assertRaises(WorkspaceEditRejected):
                apply_workspace_edit_plan(str(self.repository), self.envelope, plan)

        self.second.write_text("foreign change\n", encoding="utf-8")
        plan = self.plan(("nested/second.txt", "must not replace foreign change\n"))
        with self.assertRaisesRegex(WorkspaceEditRejected, "preimage_changed"):
            apply_workspace_edit_plan(str(self.repository), self.envelope, plan)
        self.assertEqual(self.first.read_text(encoding="utf-8"), "before one\n")
        self.assertEqual(self.second.read_text(encoding="utf-8"), "foreign change\n")

    def test_group_writable_target_is_rejected(self) -> None:
        self.first.chmod(0o664)
        plan = self.plan(("first.txt", "unsafe\n"))
        with self.assertRaisesRegex(WorkspaceEditRejected, "target_unsafe"):
            apply_workspace_edit_plan(str(self.repository), self.envelope, plan)
        self.assertEqual(self.first.read_text(encoding="utf-8"), "before one\n")

    def test_replacement_must_pass_the_same_public_text_policy(self) -> None:
        for content in ("token=synthetic-secret-value\n", "control\u0001text\n"):
            with self.subTest(content=content), self.assertRaisesRegex(
                WorkspaceEditRejected, "content_unsafe"
            ):
                apply_workspace_edit_plan(
                    str(self.repository),
                    self.envelope,
                    self.plan(("first.txt", content)),
                )
        self.assertEqual(self.first.read_text(encoding="utf-8"), "before one\n")

    def test_concurrent_target_change_is_swapped_back_not_overwritten(self) -> None:
        plan = self.plan(("first.txt", "worker content\n"))
        original_swap = workspace_edit_module._swap_names
        calls = 0

        def race_then_swap(parent: int, first: str, second: str) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                self.first.write_text("concurrent content\n", encoding="utf-8")
            original_swap(parent, first, second)

        with patch.object(workspace_edit_module, "_swap_names", race_then_swap):
            with self.assertRaisesRegex(WorkspaceEditRejected, "target_raced"):
                apply_workspace_edit_plan(str(self.repository), self.envelope, plan)

        self.assertEqual(self.first.read_text(encoding="utf-8"), "concurrent content\n")
        self.assertEqual(calls, 2)

    def test_repository_root_replacement_with_same_content_is_rejected(self) -> None:
        repository = self.repository / "captured-root"
        repository.mkdir()
        target = repository / "target.txt"
        target.write_text("same preimage\n", encoding="utf-8")
        capsule = capture_scope_capsule(str(repository), ["target.txt"])
        envelope = {
            "agent_lifecycle": "disposable",
            "allow_child_agents": True,
            "claim_scope_hash": capsule.claim_scope_hash,
            "objective": "Apply the bounded edit.",
            "scope": ["target.txt"],
            "scope_capsule": capsule_document(capsule),
            "submission_fingerprint": "b" * 64,
            "task_mode": "workspace_edit",
            "version": 1,
        }
        displaced = self.repository / "displaced-root"
        repository.rename(displaced)
        repository.mkdir()
        replacement = repository / "target.txt"
        replacement.write_text("same preimage\n", encoding="utf-8")
        plan = json.dumps(
            {
                "version": 1,
                "summary": "Edit the replaced root.",
                "edits": [
                    {
                        "path": "target.txt",
                        "before_sha256": capsule.files[0].content_hash,
                        "content": "must not land\n",
                    }
                ],
            }
        )

        with self.assertRaisesRegex(WorkspaceEditRejected, "repository_invalid"):
            apply_workspace_edit_plan(str(repository), envelope, plan)

        self.assertEqual(replacement.read_text(encoding="utf-8"), "same preimage\n")

    def test_post_swap_fsync_failure_is_recovered_on_exact_retry(self) -> None:
        plan = self.plan(("first.txt", "after uncertain commit\n"))
        original_fsync = workspace_edit_module.os.fsync
        calls = 0

        def fail_first_directory_fsync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected directory fsync failure")
            original_fsync(descriptor)

        with patch.object(workspace_edit_module.os, "fsync", fail_first_directory_fsync):
            with self.assertRaisesRegex(
                WorkspaceEditIndeterminate, "commit_unconfirmed"
            ):
                apply_workspace_edit_plan(str(self.repository), self.envelope, plan)

        self.assertEqual(
            self.first.read_text(encoding="utf-8"), "after uncertain commit\n"
        )
        receipt = apply_workspace_edit_plan(str(self.repository), self.envelope, plan)
        self.assertTrue(json.loads(receipt)["workspace_edit"]["applied"])
        self.assertEqual(list(self.repository.glob(".fugue-edit-*.tmp")), [])

    def test_crash_before_swap_recovers_plan_bound_stage(self) -> None:
        plan = self.plan(("first.txt", "after staged crash\n"))
        class SimulatedCrash(BaseException):
            pass

        with patch.object(
            workspace_edit_module,
            "_swap_names",
            side_effect=SimulatedCrash(),
        ):
            with self.assertRaises(SimulatedCrash):
                apply_workspace_edit_plan(str(self.repository), self.envelope, plan)

        self.assertEqual(self.first.read_text(encoding="utf-8"), "before one\n")
        self.assertEqual(len(list(self.repository.glob(".fugue-edit-*.tmp"))), 1)
        receipt = apply_workspace_edit_plan(str(self.repository), self.envelope, plan)
        self.assertTrue(json.loads(receipt)["workspace_edit"]["applied"])
        self.assertEqual(self.first.read_text(encoding="utf-8"), "after staged crash\n")
        self.assertEqual(list(self.repository.glob(".fugue-edit-*.tmp")), [])

    def test_conclusive_swap_failure_cleans_stage_and_rejects(self) -> None:
        plan = self.plan(("first.txt", "must not land\n"))
        with patch.object(
            workspace_edit_module,
            "_swap_names",
            side_effect=WorkspaceEditRejected("atomic swap unavailable"),
        ):
            with self.assertRaisesRegex(WorkspaceEditRejected, "atomic swap unavailable"):
                apply_workspace_edit_plan(str(self.repository), self.envelope, plan)
        self.assertEqual(self.first.read_text(encoding="utf-8"), "before one\n")
        self.assertEqual(list(self.repository.glob(".fugue-edit-*.tmp")), [])

    def test_deeply_nested_json_is_a_clean_plan_rejection(self) -> None:
        nested = "[" * 2000 + "]" * 2000
        with self.assertRaisesRegex(WorkspaceEditRejected, "result_invalid"):
            apply_workspace_edit_plan(str(self.repository), self.envelope, nested)
        self.assertEqual(self.first.read_text(encoding="utf-8"), "before one\n")

    def test_post_swap_read_failure_is_indeterminate_and_recoverable(self) -> None:
        plan = self.plan(("first.txt", "after validation interruption\n"))
        original_read = workspace_edit_module._read_current
        calls = 0

        def fail_landed_read(parent: int, name: str):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise WorkspaceEditRejected("injected landed read failure")
            return original_read(parent, name)

        with patch.object(workspace_edit_module, "_read_current", fail_landed_read):
            with self.assertRaisesRegex(
                WorkspaceEditIndeterminate, "post_swap_validation_unavailable"
            ):
                apply_workspace_edit_plan(str(self.repository), self.envelope, plan)

        self.assertEqual(
            self.first.read_text(encoding="utf-8"),
            "after validation interruption\n",
        )
        receipt = apply_workspace_edit_plan(str(self.repository), self.envelope, plan)
        self.assertTrue(json.loads(receipt)["workspace_edit"]["applied"])
        self.assertEqual(list(self.repository.glob(".fugue-edit-*.tmp")), [])

    def test_rollback_failure_is_indeterminate_and_never_clean_rejection(self) -> None:
        plan = self.plan(("first.txt", "worker content\n"))
        original_swap = workspace_edit_module._swap_names
        calls = 0

        def race_then_fail_rollback(parent: int, first: str, second: str) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                self.first.write_text("concurrent content\n", encoding="utf-8")
                original_swap(parent, first, second)
                return
            raise WorkspaceEditRejected("injected rollback failure")

        with patch.object(
            workspace_edit_module, "_swap_names", race_then_fail_rollback
        ):
            with self.assertRaises(WorkspaceEditIndeterminate):
                apply_workspace_edit_plan(str(self.repository), self.envelope, plan)

    def test_symlink_substitution_is_rejected_without_touching_target(self) -> None:
        outside = self.repository.parent / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        self.first.unlink()
        self.first.symlink_to(outside)
        plan = self.plan(("first.txt", "escaped\n"))

        with self.assertRaises(WorkspaceEditRejected):
            apply_workspace_edit_plan(str(self.repository), self.envelope, plan)

        self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")


if __name__ == "__main__":
    unittest.main()
