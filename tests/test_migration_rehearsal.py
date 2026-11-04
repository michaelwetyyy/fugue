from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
import zipfile
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from oc_rig.cockpit import normalize_snapshot
from oc_rig.daemon.identity import ServiceIdentityPolicy
from oc_rig.daemon.security import PrivateSocketPath
from oc_rig.migration import (
    ReleaseArtifact,
    SyntheticRehearsalError,
    build_release_artifact,
    import_validated_export,
    prepare_synthetic_root,
    restore_tree_snapshot,
    snapshot_tree,
    tree_digest,
    validate_synthetic_export,
    WheelCandidateDaemon,
    verify_release_artifact,
)
from oc_rig.migration import release as release_module
from oc_rig.migration import guarded as guarded_module
from oc_rig.protocol.client import RigClient
from oc_rig.store import PrivateRuntimeDirectory
from oc_rig.store.snapshot import _CockpitSnapshotProjection
from tools.migration_rehearsal import ABORT_PHASES, run_rehearsal


REPOSITORY = Path(__file__).resolve().parents[1]
FIXTURE = REPOSITORY / "tests" / "fixtures" / "migration_v1_minimal.json"
MIGRATIONS = tuple(
    f"{index:03d}_{suffix}.sql"
    for index, suffix in (
        (1, "initial"),
        (2, "queue_and_fences"),
        (3, "scheduler"),
        (4, "scheduler_authority"),
        (5, "transport"),
        (6, "completion_recovery"),
        (7, "disabled_callback_recovery"),
        (8, "opencode_delivery"),
        (9, "transport_adapter_selection"),
        (10, "local_codex_callbacks"),
        (11, "isolated_review_sessions"),
        (12, "isolated_session_cleanup"),
        (13, "provisional_review_sessions"),
        (14, "durable_completion_results"),
        (15, "agent_lifecycle"),
        (16, "cancelled_session_cleanup"),
        (17, "child_completion_barrier"),
        (18, "llm_behaviour"),
        (19, "control_pool_expansion"),
        (20, "codex_source_routes"),
        (21, "slot_session_rebind"),
        (22, "child_barrier_generation"),
        (23, "descendant_budget"),
        (24, "completed_transcript_archive"),
        (25, "callback_delivery_reconciliation"),
        (26, "source_inbox_read_indexes"),
        (27, "persistent_session_close"),
    )
)


def fresh_root(test: unittest.TestCase) -> Path:
    temporary = tempfile.TemporaryDirectory()
    test.addCleanup(temporary.cleanup)
    return prepare_synthetic_root(Path(temporary.name))


def explicit_export(root: Path, *, name: str = "export.json") -> Path:
    source = root / "synthetic-v1"
    source.mkdir(mode=0o700, exist_ok=True)
    path = source / name
    path.write_bytes(FIXTURE.read_bytes())
    path.chmod(0o600)
    return path


def rewrite_release(
    artifact: object,
    mutate: object,
    *,
    rebuild_record: bool,
) -> None:
    artifact.wheel.chmod(0o600)
    artifact.manifest.chmod(0o600)
    with zipfile.ZipFile(artifact.wheel) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    mutate(members)
    record_names = [name for name in members if name.endswith(".dist-info/RECORD")]
    if rebuild_record:
        record_name = record_names[0]
        del members[record_name]
        members[record_name] = release_module._record(members, record_name)
    with zipfile.ZipFile(artifact.wheel, "w") as archive:
        for name in sorted(members):
            archive.writestr(release_module._zip_info(name), members[name])
    wheel_bytes = artifact.wheel.read_bytes()
    manifest = json.loads(artifact.manifest.read_text(encoding="utf-8"))
    manifest["artifact"] = {
        "filename": artifact.wheel.name,
        "sha256": hashlib.sha256(wheel_bytes).hexdigest(),
        "size": len(wheel_bytes),
    }
    manifest["members"] = [
        {
            "path": name,
            "sha256": hashlib.sha256(members[name]).hexdigest(),
            "size": len(members[name]),
        }
        for name in sorted(members)
    ]
    manifest["required_migrations"] = [
        Path(name).name
        for name in sorted(members)
        if name.startswith("oc_rig/store/migrations/") and name.endswith(".sql")
    ]
    artifact.manifest.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


class ImmutableReleaseTests(unittest.TestCase):
    def _artifact(self) -> object:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name).resolve()
        output.chmod(0o700)
        return build_release_artifact(REPOSITORY, output)

    def test_migration_profiles_are_exact_current_or_known_historical(self) -> None:
        prefix = "oc_rig/store/migrations/"
        current = tuple(prefix + name for name in MIGRATIONS)
        historical = current[:10]
        self.assertEqual(release_module._required_migration_names(current), MIGRATIONS)
        self.assertEqual(
            release_module._required_migration_names(
                historical, allow_known_historical=True
            ),
            MIGRATIONS[:10],
        )
        for count in range(10, len(MIGRATIONS)):
            self.assertEqual(
                release_module._required_migration_names(
                    current[:count], allow_known_historical=True
                ),
                MIGRATIONS[:count],
            )
        rejected = (
            historical[:5] + historical[6:],
            historical + (prefix + "999_unknown.sql",),
            tuple(reversed(historical)),
        )
        with self.assertRaises(ValueError):
            release_module._required_migration_names(historical)
        for names in rejected:
            with self.subTest(names=names), self.assertRaises(ValueError):
                release_module._required_migration_names(
                    names, allow_known_historical=True
                )

        artifact = self._artifact()

        def remove_new_migrations(members: dict[str, bytes]) -> None:
            for name in MIGRATIONS[10:]:
                members.pop(prefix + name)

        rewrite_release(
            artifact,
            remove_new_migrations,
            rebuild_record=True,
        )
        with self.assertRaisesRegex(ValueError, "exactly migrations"):
            verify_release_artifact(artifact.wheel, artifact.manifest)
        verified = verify_release_artifact(
            artifact.wheel,
            artifact.manifest,
            allow_known_historical=True,
        )
        self.assertNotIn(prefix + MIGRATIONS[10], verified.members)

    def test_offline_wheel_is_reproducible_hashed_and_fixture_free(self) -> None:
        outputs = []
        for _index in range(2):
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            output = Path(temporary.name).resolve()
            output.chmod(0o700)
            artifact = build_release_artifact(REPOSITORY, output)
            verified = verify_release_artifact(artifact.wheel, artifact.manifest)
            outputs.append((artifact.wheel.read_bytes(), artifact.manifest.read_bytes()))
            self.assertEqual(artifact.wheel_sha256, verified.wheel_sha256)
            self.assertEqual(artifact.wheel.stat().st_mode & 0o777, 0o444)
            self.assertEqual(artifact.manifest.stat().st_mode & 0o777, 0o444)
            with zipfile.ZipFile(artifact.wheel) as archive:
                names = tuple(archive.namelist())
            packaged_migrations = tuple(
                Path(name).name
                for name in names
                if name.startswith("oc_rig/store/migrations/") and name.endswith(".sql")
            )
            self.assertEqual(packaged_migrations, MIGRATIONS)
            self.assertFalse(
                any(
                    part in {"tests", "fixtures", "__pycache__", ".pytest_cache"}
                    or name.endswith((".pyc", ".pyo"))
                    for name in names
                    for part in Path(name).parts
                )
            )
        self.assertEqual(outputs[0], outputs[1])

    def test_verifier_rejects_unrecorded_wheel_member(self) -> None:
        artifact = self._artifact()
        rewrite_release(
            artifact,
            lambda members: members.__setitem__("oc_rig/unrecorded.py", b"pass\n"),
            rebuild_record=False,
        )
        with self.assertRaisesRegex(ValueError, "RECORD does not cover"):
            verify_release_artifact(artifact.wheel, artifact.manifest)

    def test_verifier_rejects_recorded_member_hash_and_size_mismatch(self) -> None:
        artifact = self._artifact()
        rewrite_release(
            artifact,
            lambda members: members.__setitem__(
                "oc_rig/__init__.py",
                members["oc_rig/__init__.py"] + b"\n",
            ),
            rebuild_record=False,
        )
        with self.assertRaisesRegex(ValueError, "RECORD hash or size mismatch"):
            verify_release_artifact(artifact.wheel, artifact.manifest)

    def test_verifier_rejects_extra_and_missing_migrations_with_valid_record(self) -> None:
        for mutation in ("extra", "missing"):
            with self.subTest(mutation=mutation):
                artifact = self._artifact()

                def mutate(members: dict[str, bytes]) -> None:
                    if mutation == "extra":
                        members["oc_rig/store/migrations/010_extra.sql"] = b"SELECT 1;\n"
                    else:
                        del members[
                            "oc_rig/store/migrations/009_transport_adapter_selection.sql"
                        ]

                rewrite_release(artifact, mutate, rebuild_record=True)
                with self.assertRaisesRegex(ValueError, "exactly migrations"):
                    verify_release_artifact(artifact.wheel, artifact.manifest)

    def test_verifier_rejects_renamed_dist_info_with_self_consistent_record(self) -> None:
        artifact = self._artifact()

        def rename_dist_info(members: dict[str, bytes]) -> None:
            record_name = next(
                name for name in members if name.endswith(".dist-info/RECORD")
            )
            prefix = record_name.removesuffix("RECORD")
            renamed = {
                "evil.dist-info/" + name.removeprefix(prefix): data
                for name, data in members.items()
                if name.startswith(prefix)
            }
            for name in tuple(members):
                if name.startswith(prefix):
                    del members[name]
            members.update(renamed)

        rewrite_release(artifact, rename_dist_info, rebuild_record=True)
        with self.assertRaisesRegex(
            ValueError,
            "dist-info membership is not canonical",
        ):
            verify_release_artifact(artifact.wheel, artifact.manifest)


class SyntheticImportTests(unittest.TestCase):
    def test_validated_import_is_transactional_exact_and_idempotent(self) -> None:
        root = fresh_root(self)
        export_path = explicit_export(root)
        source_digest = tree_digest(export_path.parent, root)
        validated = validate_synthetic_export(export_path, root)
        runtime = PrivateRuntimeDirectory(root / "v2-state", root)
        result = import_validated_export(validated, runtime, root)
        self.assertTrue(result.applied)
        self.assertEqual(result.queued_work, ("synthetic-work-001",))
        self.assertEqual(tree_digest(export_path.parent, root), source_digest)

        with closing(sqlite3.connect(runtime.database, isolation_level=None)) as connection:
            self.assertEqual(
                tuple(
                    row[0]
                    for row in connection.execute(
                        "SELECT version FROM schema_migrations ORDER BY version"
                    )
                ),
                MIGRATIONS,
            )
            marker = json.loads(
                connection.execute(
                    "SELECT value_json FROM settings WHERE key = 'migration.synthetic_compat_v1'"
                ).fetchone()[0]
            )
            self.assertEqual(marker["controller_state"], "stopped")
            self.assertEqual(
                connection.execute(
                    "SELECT id, lane, state, queue_order FROM scheduler_work"
                ).fetchone(),
                ("synthetic-work-001", "tensorhost", "queued", 1),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT event_type, aggregate_id FROM events"
                ).fetchone(),
                ("migration.synthetic_imported", "synthetic-minimal-001"),
            )
            connection.execute("BEGIN")
            cockpit = dict(_CockpitSnapshotProjection().capture(connection))
            connection.rollback()
        normalized = normalize_snapshot(cockpit)
        self.assertEqual(normalized["availability"]["status"], "available")
        self.assertEqual([lane["id"] for lane in normalized["lanes"]], [
            "tensorhost", "homelab", "personal", "control", "hands-off"
        ])
        self.assertEqual(sum(len(lane["slots"]) for lane in normalized["lanes"]), 13)
        self.assertEqual(
            [item["work_id"] for item in normalized["queue"]["items"]],
            ["synthetic-work-001"],
        )
        self.assertEqual(
            normalized["snapshot_version"]["migration_version"],
            "027_persistent_session_close.sql",
        )
        repeated = import_validated_export(validated, runtime, root)
        self.assertFalse(repeated.applied)

    def test_changed_content_with_same_migration_id_is_rejected(self) -> None:
        root = fresh_root(self)
        first_path = explicit_export(root, name="first.json")
        first = validate_synthetic_export(first_path, root)
        runtime = PrivateRuntimeDirectory(root / "v2-state", root)
        import_validated_export(first, runtime, root)
        changed = json.loads(FIXTURE.read_text(encoding="utf-8"))
        changed["queue"][0]["enqueued_at"] = "2026-08-29T09:58:00Z"
        second_path = first_path.with_name("second.json")
        second_path.write_text(json.dumps(changed), encoding="utf-8")
        second_path.chmod(0o600)
        second = validate_synthetic_export(second_path, root)
        with self.assertRaisesRegex(SyntheticRehearsalError, "different content"):
            import_validated_export(second, runtime, root)

    def test_abort_before_import_commit_restores_absent_destination_exactly(self) -> None:
        root = fresh_root(self)
        validated = validate_synthetic_export(explicit_export(root), root)
        destination = root / "v2-state"
        snapshot = snapshot_tree(destination, root / "destination-backup", root)
        runtime = PrivateRuntimeDirectory(destination, root)

        def abort() -> None:
            raise RuntimeError("synthetic abort before import commit")

        with self.assertRaisesRegex(RuntimeError, "synthetic abort"):
            import_validated_export(validated, runtime, root, before_commit=abort)
        with closing(sqlite3.connect(runtime.database)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM settings").fetchone(), (0,))
            self.assertEqual(
                connection.execute("SELECT count(*) FROM scheduler_work").fetchone(),
                (0,),
            )
            self.assertEqual(connection.execute("SELECT count(*) FROM events").fetchone(), (0,))
        restore_tree_snapshot(snapshot)
        self.assertEqual(tree_digest(destination, root), snapshot.digest)
        self.assertFalse(destination.exists())

    def test_export_change_at_final_revalidation_rolls_back_every_import_row(self) -> None:
        root = fresh_root(self)
        export_path = explicit_export(root)
        validated = validate_synthetic_export(export_path, root)
        runtime = PrivateRuntimeDirectory(root / "v2-state", root)

        def change_export() -> None:
            value = json.loads(export_path.read_text(encoding="utf-8"))
            value["queue"][0]["enqueued_at"] = "2026-08-29T09:58:00Z"
            export_path.write_text(json.dumps(value), encoding="utf-8")
            export_path.chmod(0o600)

        with self.assertRaisesRegex(SyntheticRehearsalError, "changed before import"):
            import_validated_export(
                validated,
                runtime,
                root,
                before_commit=change_export,
            )
        with closing(sqlite3.connect(runtime.database)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM settings").fetchone(), (0,))
            self.assertEqual(
                connection.execute("SELECT count(*) FROM scheduler_work").fetchone(),
                (0,),
            )
            self.assertEqual(connection.execute("SELECT count(*) FROM events").fetchone(), (0,))
            self.assertEqual(
                connection.execute(
                    "SELECT current_value FROM scheduler_queue_clock"
                ).fetchone(),
                (0,),
            )

    def test_export_rejects_hardlinks_and_group_writable_files(self) -> None:
        root = fresh_root(self)
        export_path = explicit_export(root)
        hardlink = export_path.with_name("hardlink.json")
        os.link(export_path, hardlink)
        with self.assertRaisesRegex(SyntheticRehearsalError, "singly-linked"):
            validate_synthetic_export(hardlink, root)
        hardlink.unlink()
        export_path.chmod(0o620)
        with self.assertRaisesRegex(SyntheticRehearsalError, "controlled regular"):
            validate_synthetic_export(export_path, root)

    def test_export_rejects_fstat_identity_mismatch_before_read(self) -> None:
        root = fresh_root(self)
        export_path = explicit_export(root)
        facts = export_path.lstat()
        mismatched = SimpleNamespace(
            st_dev=facts.st_dev,
            st_ino=facts.st_ino + 1,
            st_mode=facts.st_mode,
            st_uid=facts.st_uid,
            st_gid=facts.st_gid,
            st_nlink=facts.st_nlink,
            st_size=facts.st_size,
            st_mtime_ns=facts.st_mtime_ns,
            st_ctime_ns=facts.st_ctime_ns,
        )
        with patch("oc_rig.migration.rehearsal.os.fstat", return_value=mismatched):
            with self.assertRaisesRegex(SyntheticRehearsalError, "while opening"):
                validate_synthetic_export(export_path, root)

    def test_validation_rejects_unknown_or_out_of_boundary_inputs_before_write(self) -> None:
        root = fresh_root(self)
        invalid = root / "invalid.json"
        invalid.write_text("{}", encoding="utf-8")
        invalid.chmod(0o600)
        destination = root / "v2-state"
        snapshot = snapshot_tree(destination, root / "validation-backup", root)
        with self.assertRaises(SyntheticRehearsalError):
            validate_synthetic_export(invalid, root)
        restore_tree_snapshot(snapshot)
        self.assertFalse(destination.exists())

        outside = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(lambda: Path(outside.name).unlink(missing_ok=True))
        outside.write(FIXTURE.read_bytes())
        outside.close()
        with self.assertRaisesRegex(SyntheticRehearsalError, "outside"):
            validate_synthetic_export(Path(outside.name), root)
        link = root / "linked-export.json"
        link.symlink_to(explicit_export(root, name="link-target.json"))
        with self.assertRaisesRegex(SyntheticRehearsalError, "symlinks"):
            validate_synthetic_export(link, root)


class AtomicRollbackTests(unittest.TestCase):
    def _snapshot_and_mutate(self) -> tuple[Path, object, Path]:
        root = fresh_root(self)
        target = root / "v2-state"
        target.mkdir(mode=0o700)
        (target / "state.bin").write_bytes(b"pre-cutover")
        snapshot = snapshot_tree(target, root / "backup", root)
        (target / "state.bin").write_bytes(b"candidate-state")
        return root, snapshot, target

    def test_corrupted_backup_leaves_current_target_byte_identical(self) -> None:
        root, snapshot, target = self._snapshot_and_mutate()
        before = tree_digest(target, root)
        (snapshot.backup / "payload" / "state.bin").write_bytes(b"corrupt")
        with self.assertRaisesRegex(SyntheticRehearsalError, "payload"):
            restore_tree_snapshot(snapshot)
        self.assertEqual(tree_digest(target, root), before)
        self.assertEqual((target / "state.bin").read_bytes(), b"candidate-state")

    def test_failed_atomic_swap_restores_retained_original(self) -> None:
        root, snapshot, target = self._snapshot_and_mutate()
        before = tree_digest(target, root)
        real_replace = os.replace
        calls = 0

        def fail_second(source: object, destination: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic atomic swap failure")
            real_replace(source, destination)

        with patch("oc_rig.migration.rehearsal.os.replace", side_effect=fail_second):
            with self.assertRaisesRegex(OSError, "synthetic atomic swap"):
                restore_tree_snapshot(snapshot)
        self.assertEqual(tree_digest(target, root), before)
        self.assertEqual((target / "state.bin").read_bytes(), b"candidate-state")

    def test_first_rename_failure_preserves_target_and_removes_staging(self) -> None:
        root, snapshot, target = self._snapshot_and_mutate()
        before = tree_digest(target, root)
        with patch(
            "oc_rig.migration.rehearsal.os.replace",
            side_effect=OSError("synthetic first rename failure"),
        ):
            with self.assertRaisesRegex(OSError, "synthetic first rename"):
                restore_tree_snapshot(snapshot)
        self.assertEqual(tree_digest(target, root), before)
        self.assertEqual((target / "state.bin").read_bytes(), b"candidate-state")
        self.assertEqual(tuple(root.glob(".v2-state.restore-*")), ())

    def test_replacement_at_rename_seam_is_retained_and_restore_fails_safe(self) -> None:
        root, snapshot, target = self._snapshot_and_mutate()
        real_replace = os.replace
        displaced = root / "displaced-candidate"
        calls = 0

        def replace_at_seam(source: object, destination: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                real_replace(target, displaced)
                target.mkdir(mode=0o700)
                (target / "state.bin").write_bytes(b"replacement")
            real_replace(source, destination)

        with patch(
            "oc_rig.migration.rehearsal.os.replace",
            side_effect=replace_at_seam,
        ):
            with self.assertRaisesRegex(
                SyntheticRehearsalError,
                "identity changed during atomic rename",
            ):
                restore_tree_snapshot(snapshot)
        self.assertEqual((target / "state.bin").read_bytes(), b"replacement")
        self.assertEqual(
            (displaced / "state.bin").read_bytes(),
            b"candidate-state",
        )
        self.assertEqual(tuple(root.glob(".v2-state.restore-*")), ())

    def test_late_retained_replacement_is_never_deleted(self) -> None:
        root, snapshot, target = self._snapshot_and_mutate()
        displaced = root / "late-displaced-original"
        replacement_path: Path | None = None

        def replace_before_retention(path: Path, _descriptor: int) -> None:
            nonlocal replacement_path
            replacement_path = path
            os.replace(path, displaced)
            path.mkdir(mode=0o700)
            (path / "state.bin").write_bytes(b"late-replacement")

        with patch(
            "oc_rig.migration.guarded._guarded_quarantine_seam",
            side_effect=replace_before_retention,
        ):
            with self.assertRaisesRegex(
                SyntheticRehearsalError,
                "pathname changed before evidence retention",
            ):
                restore_tree_snapshot(snapshot)
        self.assertIsNotNone(replacement_path)
        assert replacement_path is not None
        self.assertEqual((target / "state.bin").read_bytes(), b"pre-cutover")
        self.assertEqual(
            (replacement_path / "state.bin").read_bytes(),
            b"late-replacement",
        )
        self.assertEqual(
            (displaced / "state.bin").read_bytes(),
            b"candidate-state",
        )


class CandidateArtifactBindingTests(unittest.TestCase):
    def _daemon(
        self,
        root: Path,
        artifact: ReleaseArtifact,
        *,
        before_spawn: Callable[[], None] | None = None,
    ) -> tuple[WheelCandidateDaemon, Path]:
        validated = validate_synthetic_export(explicit_export(root), root)
        runtime = PrivateRuntimeDirectory(root / "v2-state", root)
        import_validated_export(validated, runtime, root)
        root.chmod(0o710)
        runtime.root.joinpath("rigd.lock").touch(mode=0o600)
        socket_path = root / "s" / "r"
        socket_path.parent.mkdir(mode=0o710)
        socket_path.parent.chmod(0o710)
        return (
            WheelCandidateDaemon(
                PrivateSocketPath(socket_path, root),
                runtime=runtime,
                identity_policy=ServiceIdentityPolicy(
                    os.geteuid(),
                    frozenset({os.geteuid() + 1}),
                    os.getegid(),
                ),
                artifact=artifact,
                before_spawn=before_spawn,
            ),
            socket_path,
        )

    def test_in_place_overwrite_before_popen_cannot_change_executed_wheel(self) -> None:
        if os.geteuid() <= 0 or os.getegid() <= 0:
            self.skipTest("candidate requires non-root synthetic identities")
        root = fresh_root(self)
        release_directory = root / "release"
        release_directory.mkdir(mode=0o700)
        artifact = build_release_artifact(REPOSITORY, release_directory)
        marker = root / "unverified-wheel-executed"
        with zipfile.ZipFile(artifact.wheel) as archive:
            members = {name: archive.read(name) for name in archive.namelist()}
        candidate_child = "oc_rig/migration/candidate_child.py"
        members[candidate_child] = (
            f"__import__('pathlib').Path({str(marker)!r}).write_text('executed')\n"
        ).encode("utf-8") + members[candidate_child]
        malicious = io.BytesIO()
        with zipfile.ZipFile(malicious, "w") as archive:
            for name in sorted(members):
                archive.writestr(release_module._zip_info(name), members[name])

        def overwrite_path_inode() -> None:
            artifact.wheel.chmod(0o600)
            artifact.wheel.write_bytes(malicious.getvalue())
            artifact.wheel.chmod(0o444)

        daemon, socket_path = self._daemon(
            root,
            artifact,
            before_spawn=overwrite_path_inode,
        )
        try:
            daemon.start()
            health = RigClient(
                socket_path,
                approved_root=root,
                service_uid=os.geteuid(),
                client_gid=os.getegid(),
            ).call(
                "health.v1",
                {},
                request_id="anonymous-copy-health-request",
                idempotency_id="anonymous-copy-health-idempotency",
            )
            provenance = health["release_provenance"]
            self.assertEqual(provenance["wheel_sha256"], artifact.wheel_sha256)
            self.assertEqual(
                provenance["artifact_binding"],
                "anonymous-descriptor-copy",
            )
            self.assertEqual(provenance["descriptor_link_count"], 0)
            self.assertNotEqual(
                provenance["descriptor_inode"],
                artifact.wheel.stat().st_ino,
            )
            self.assertIn(
                provenance["wheel_copy_kind"],
                {"sealed-memfd", "unlinked-regular-file"},
            )
            self.assertNotEqual(
                hashlib.sha256(artifact.wheel.read_bytes()).hexdigest(),
                artifact.wheel_sha256,
            )
            self.assertFalse(marker.exists())
        finally:
            daemon.shutdown()
        self.assertFalse((root / "candidate-home").exists())
        self.assertEqual(len(daemon.candidate_home_evidence), 1)
        self.assertTrue(daemon.candidate_home_evidence[0].path.is_dir())

    def test_popen_failure_cleans_home_and_same_daemon_retry_succeeds(self) -> None:
        if os.geteuid() <= 0 or os.getegid() <= 0:
            self.skipTest("candidate requires non-root synthetic identities")
        root = fresh_root(self)
        release_directory = root / "release"
        release_directory.mkdir(mode=0o700)
        artifact = build_release_artifact(REPOSITORY, release_directory)
        daemon, _socket_path = self._daemon(root, artifact)
        real_popen = subprocess.Popen
        calls = 0

        def fail_once(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("synthetic Popen failure")
            return real_popen(*args, **kwargs)

        with patch(
            "oc_rig.migration.candidate.subprocess.Popen",
            side_effect=fail_once,
        ):
            with self.assertRaisesRegex(OSError, "synthetic Popen failure"):
                daemon.start()
            self.assertFalse((root / "candidate-home").exists())
            self.assertIsNone(daemon.candidate_home_identity)
            self.assertEqual(len(daemon.candidate_home_evidence), 1)
            self.assertTrue(daemon.candidate_home_evidence[0].path.is_dir())
            daemon.start()
        try:
            self.assertIsNotNone(daemon.process)
        finally:
            daemon.shutdown()
        self.assertFalse((root / "candidate-home").exists())
        self.assertIsNone(daemon.candidate_home_identity)
        self.assertEqual(len(daemon.candidate_home_evidence), 2)
        self.assertTrue(
            all(item.path.is_dir() for item in daemon.candidate_home_evidence)
        )

    def test_home_substitution_is_retained_and_tracking_stays_armed(self) -> None:
        if os.geteuid() <= 0 or os.getegid() <= 0:
            self.skipTest("candidate requires non-root synthetic identities")
        root = fresh_root(self)
        release_directory = root / "release"
        release_directory.mkdir(mode=0o700)
        artifact = build_release_artifact(REPOSITORY, release_directory)
        daemon, _socket_path = self._daemon(root, artifact)
        displaced = root / "displaced-candidate-home"
        replacement_path: Path | None = None

        def replace_home(path: Path, _descriptor: int) -> None:
            nonlocal replacement_path
            replacement_path = path
            os.replace(path, displaced)
            path.mkdir(mode=0o700)
            (path / "replacement-marker").write_bytes(b"replacement")

        with patch(
            "oc_rig.migration.candidate.subprocess.Popen",
            side_effect=OSError("synthetic Popen failure"),
        ), patch(
            "oc_rig.migration.guarded._guarded_quarantine_seam",
            side_effect=replace_home,
        ):
            with self.assertRaisesRegex(
                guarded_module.GuardedQuarantineError,
                "pathname changed before evidence retention",
            ):
                daemon.start()
        self.assertIsNotNone(daemon.candidate_home_identity)
        self.assertEqual(len(daemon.candidate_home_evidence), 1)
        self.assertFalse(daemon.candidate_home_evidence[0].verified)
        self.assertIsNotNone(replacement_path)
        assert replacement_path is not None
        self.assertEqual(
            (replacement_path / "replacement-marker").read_bytes(),
            b"replacement",
        )
        self.assertTrue(displaced.is_dir())
        self.assertEqual(tuple(displaced.iterdir()), ())

    def test_preopen_home_substitution_wraps_raw_error_with_evidence(self) -> None:
        if os.geteuid() <= 0 or os.getegid() <= 0:
            self.skipTest("candidate requires non-root synthetic identities")
        root = fresh_root(self)
        release_directory = root / "release"
        release_directory.mkdir(mode=0o700)
        artifact = build_release_artifact(REPOSITORY, release_directory)
        daemon, _socket_path = self._daemon(root, artifact)
        displaced = root / "preopen-displaced-candidate-home"
        replacement_path: Path | None = None

        def replace_with_file(path: Path) -> None:
            nonlocal replacement_path
            replacement_path = path
            os.replace(path, displaced)
            path.write_bytes(b"preopen-replacement")

        with patch(
            "oc_rig.migration.candidate.subprocess.Popen",
            side_effect=OSError("synthetic Popen failure"),
        ), patch(
            "oc_rig.migration.guarded._guarded_quarantine_preopen_seam",
            side_effect=replace_with_file,
        ):
            with self.assertRaisesRegex(
                guarded_module.GuardedQuarantineError,
                "failed after atomic rename",
            ) as caught:
                daemon.start()
        self.assertIsInstance(caught.exception.__cause__, NotADirectoryError)
        self.assertIsNotNone(daemon.candidate_home_identity)
        self.assertEqual(len(daemon.candidate_home_evidence), 1)
        evidence = daemon.candidate_home_evidence[0]
        self.assertFalse(evidence.verified)
        self.assertIsNotNone(replacement_path)
        assert replacement_path is not None
        self.assertEqual(evidence.path, replacement_path)
        self.assertEqual(replacement_path.read_bytes(), b"preopen-replacement")
        self.assertTrue(displaced.is_dir())
        self.assertEqual(tuple(displaced.iterdir()), ())

    def test_home_content_changes_are_quarantined_intact_on_shutdown(self) -> None:
        if os.geteuid() <= 0 or os.getegid() <= 0:
            self.skipTest("candidate requires non-root synthetic identities")
        root = fresh_root(self)
        release_directory = root / "release"
        release_directory.mkdir(mode=0o700)
        artifact = build_release_artifact(REPOSITORY, release_directory)
        daemon, _socket_path = self._daemon(root, artifact)
        daemon.start()
        home = root / "candidate-home"
        (home / "regular.bin").write_bytes(b"regular-content")
        nested = home / "nested"
        nested.mkdir(mode=0o700)
        (nested / "nested.bin").write_bytes(b"nested-content")
        (home / "relative-link").symlink_to("nested/nested.bin")
        daemon.shutdown()

        self.assertFalse(home.exists())
        self.assertIsNone(daemon.candidate_home_identity)
        self.assertEqual(len(daemon.candidate_home_evidence), 1)
        evidence = daemon.candidate_home_evidence[0]
        self.assertTrue(evidence.verified)
        self.assertEqual(
            (evidence.path / "regular.bin").read_bytes(),
            b"regular-content",
        )
        self.assertEqual(
            (evidence.path / "nested" / "nested.bin").read_bytes(),
            b"nested-content",
        )
        self.assertTrue((evidence.path / "relative-link").is_symlink())
        self.assertEqual(
            os.readlink(evidence.path / "relative-link"),
            "nested/nested.bin",
        )


class EndToEndRehearsalTests(unittest.TestCase):
    def _unmarked_root(self, *, prefix: str | None = None) -> Path:
        temporary = tempfile.TemporaryDirectory(prefix=prefix)
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name).resolve()
        path.chmod(0o700)
        return path

    def test_candidate_starts_on_private_socket_then_rolls_back_byte_identically(self) -> None:
        root = self._unmarked_root(prefix="oc-rig-v2-m10-rehearsal.")
        report = run_rehearsal(root)
        self.assertEqual(report["status"], "verified_then_rolled_back")
        self.assertEqual(report["candidate_health"]["external_dependencies"], False)
        provenance = report["candidate_health"]["release_provenance"]
        self.assertTrue(provenance["isolated"])
        self.assertFalse(provenance["site_enabled"])
        self.assertFalse(provenance["bytecode_enabled"])
        self.assertEqual(
            provenance["artifact_binding"],
            "anonymous-descriptor-copy",
        )
        self.assertEqual(provenance["descriptor_link_count"], 0)
        self.assertTrue(provenance["module_origin"].startswith("/dev/fd/"))
        self.assertTrue(
            provenance["module_origin"].endswith(
                "/oc_rig/migration/candidate_child.py"
            )
        )
        self.assertEqual(provenance["artifact_filename"], report["release_artifact"])
        self.assertGreater(provenance["descriptor_device"], 0)
        self.assertGreater(provenance["descriptor_inode"], 0)
        self.assertGreater(provenance["descriptor_size"], 0)
        self.assertNotIn(str(REPOSITORY), provenance["module_origin"])
        self.assertEqual(report["candidate_cockpit"]["availability"]["status"], "available")
        self.assertEqual(
            report["candidate_cockpit"]["lane_ids"],
            ["tensorhost", "homelab", "personal", "control", "hands-off"],
        )
        self.assertEqual(len(report["candidate_cockpit"]["slot_ids"]), 13)
        self.assertTrue(report["old_synthetic_controller_stopped"])
        self.assertEqual(report["imported_work"], ["synthetic-work-001"])
        self.assertEqual(
            report["source_pre_cutover_sha256"],
            report["source_post_rollback_sha256"],
        )
        self.assertEqual(
            report["destination_pre_cutover_sha256"],
            report["destination_post_rollback_sha256"],
        )
        self.assertFalse(report["production_action_available"])
        self.assertFalse((root / "v2-state").exists())

    def test_abort_matrix_and_failed_validation_restore_pre_cutover_bytes(self) -> None:
        for phase in ABORT_PHASES:
            with self.subTest(phase=phase):
                report = run_rehearsal(self._unmarked_root(), abort_phase=phase)
                self.assertEqual(report["status"], "rolled_back")
                self.assertEqual(report["abort_phase"], phase)
                self.assertEqual(
                    report["source_pre_cutover_sha256"],
                    report["source_post_rollback_sha256"],
                )
                self.assertEqual(
                    report["destination_pre_cutover_sha256"],
                    report["destination_post_rollback_sha256"],
                )
        invalid = run_rehearsal(self._unmarked_root(), fixture_bytes=b"{}\n")
        self.assertEqual(invalid["status"], "rolled_back")
        self.assertIn("SyntheticRehearsalError", invalid["error"])
        self.assertEqual(
            invalid["destination_pre_cutover_sha256"],
            invalid["destination_post_rollback_sha256"],
        )

    def test_no_path_can_select_home_or_default_user_runtime(self) -> None:
        root = self._unmarked_root()
        forbidden_home = root / "must-remain-empty-home"
        forbidden_home.mkdir(mode=0o700)
        before = tuple(forbidden_home.iterdir())
        with patch.dict(os.environ, {"HOME": str(forbidden_home)}):
            report = run_rehearsal(root)
        self.assertEqual(tuple(forbidden_home.iterdir()), before)
        self.assertFalse(report["production_action_available"])
        runner_source = (REPOSITORY / "tools" / "migration_rehearsal.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("tests.fixtures", runner_source)
        self.assertNotIn("PYTHONPATH", runner_source)
        with self.assertRaisesRegex(SyntheticRehearsalError, "temporary root"):
            prepare_synthetic_root(REPOSITORY)


if __name__ == "__main__":
    unittest.main()
