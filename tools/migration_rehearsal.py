#!/usr/bin/env python3
"""Run the entirely synthetic, automatically rolled-back migration rehearsal."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

from oc_rig.cockpit import CockpitClient, normalize_snapshot
from oc_rig.daemon.identity import ServiceIdentityPolicy
from oc_rig.daemon.security import PrivateSocketPath
from oc_rig.migration import (
    ReleaseArtifact,
    SyntheticRehearsalError,
    WheelCandidateDaemon,
    build_release_artifact,
    import_validated_export,
    prepare_synthetic_root,
    restore_tree_snapshot,
    snapshot_tree,
    tree_digest,
    validate_synthetic_export,
    verify_release_artifact,
)
from oc_rig.protocol.client import RigClient
from oc_rig.store import PrivateRuntimeDirectory


ABORT_PHASES = (
    "after_validation",
    "after_destination_initialize",
    "before_import_commit",
    "after_import",
    "after_candidate_start",
)


class SyntheticAbort(RuntimeError):
    pass


def _abort(requested: str | None, phase: str) -> None:
    if requested == phase:
        raise SyntheticAbort(phase)


def _candidate(
    root: Path,
    runtime: PrivateRuntimeDirectory,
    abort_phase: str | None,
    release: ReleaseArtifact,
) -> tuple[dict[str, object], dict[str, object]]:
    service_uid = os.geteuid()
    client_gid = os.getegid()
    if service_uid <= 0 or client_gid <= 0:
        raise RuntimeError("synthetic candidate requires a non-root local test identity")
    root.chmod(0o710)
    runtime.root.joinpath("rigd.lock").touch(mode=0o600)
    runtime.root.joinpath("rigd.lock").chmod(0o600)
    # Keep enough headroom for macOS's short portable sockaddr_un path limit,
    # even when mktemp has produced a descriptive rehearsal-root name.
    socket_path = root / "s" / "r"
    socket_path.parent.mkdir(mode=0o710)
    socket_path.parent.chmod(0o710)
    policy = ServiceIdentityPolicy(
        service_uid,
        frozenset({service_uid + 1}),
        client_gid,
    )
    daemon = WheelCandidateDaemon(
        PrivateSocketPath(socket_path, root),
        runtime=runtime,
        identity_policy=policy,
        artifact=release,
    )
    try:
        daemon.start()
        client = RigClient(
            socket_path,
            approved_root=root,
            service_uid=service_uid,
            client_gid=client_gid,
        )
        health = dict(
            client.call(
                "health.v1",
                {},
                request_id="migration-health-request",
                idempotency_id="migration-health-idempotency",
            )
        )
        provenance = health.get("release_provenance")
        manifest_sha256 = hashlib.sha256(release.manifest.read_bytes()).hexdigest()
        if (
            health.get("status") != "ok"
            or health.get("controller") != "sqlite"
            or health.get("external_dependencies") is not False
            or not isinstance(provenance, dict)
            or provenance.get("wheel_sha256") != release.wheel_sha256
            or provenance.get("manifest_sha256") != manifest_sha256
            or provenance.get("artifact_binding") != "anonymous-descriptor-copy"
            or provenance.get("artifact_filename") != release.wheel.name
            or provenance.get("isolated") is not True
            or provenance.get("site_enabled") is not False
            or provenance.get("bytecode_enabled") is not False
            or provenance.get("descriptor_link_count") != 0
            or provenance.get("wheel_copy_kind")
            not in {"sealed-memfd", "unlinked-regular-file"}
            or not str(provenance.get("module_origin", "")).startswith("/dev/fd/")
        ):
            raise RuntimeError("candidate health did not prove disabled external dependencies")
        cockpit = dict(
            CockpitClient(
                socket_path,
                approved_root=root,
                service_uid=service_uid,
                client_gid=client_gid,
            ).refresh()
        )
        normalized = normalize_snapshot(cockpit)
        if (
            normalized["availability"]["status"] != "available"
            or len(normalized["lanes"]) != 5
            or sum(len(lane["slots"]) for lane in normalized["lanes"]) != 13
            or normalized["queue"]["lower_bound"] != 1
        ):
            raise RuntimeError("candidate cockpit state or topology is not exact")
        _abort(abort_phase, "after_candidate_start")
        cockpit_proof = {
            "availability": normalized["availability"],
            "lane_ids": [lane["id"] for lane in normalized["lanes"]],
            "slot_ids": [
                slot["slot_id"]
                for lane in normalized["lanes"]
                for slot in lane["slots"]
            ],
            "queue": normalized["queue"],
            "snapshot_version": normalized["snapshot_version"],
            "refresh": normalized["refresh"],
        }
        return health, cockpit_proof
    finally:
        daemon.shutdown()


def run_rehearsal(
    root: Path,
    *,
    abort_phase: str | None = None,
    fixture_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Run one synthetic attempt and always restore pre-cutover destination bytes."""
    if abort_phase is not None and abort_phase not in ABORT_PHASES:
        raise ValueError("unknown synthetic abort phase")
    root = prepare_synthetic_root(root)
    repository = Path(__file__).resolve().parents[1]
    canonical_fixture = repository / "tests" / "fixtures" / "migration_v1_minimal.json"

    release_directory = root / "release"
    release_directory.mkdir(mode=0o700)
    release = build_release_artifact(repository, release_directory)
    verify_release_artifact(release.wheel, release.manifest)

    source = root / "synthetic-v1"
    source.mkdir(mode=0o700)
    export_path = source / "minimal-export.json"
    if fixture_bytes is None:
        shutil.copyfile(canonical_fixture, export_path)
    else:
        export_path.write_bytes(fixture_bytes)
    export_path.chmod(0o600)
    destination = root / "v2-state"
    backups = root / "snapshots"
    backups.mkdir(mode=0o700)
    source_snapshot = snapshot_tree(source, backups / "source", root)
    destination_snapshot = snapshot_tree(destination, backups / "destination", root)
    runtime = PrivateRuntimeDirectory(destination, root)
    health: dict[str, object] | None = None
    cockpit: dict[str, object] | None = None
    status = "rolled_back"
    stopped = False
    error: str | None = None
    imported_work: tuple[str, ...] = ()
    export_digest: str | None = None
    try:
        export = validate_synthetic_export(export_path, root)
        export_digest = export.sha256
        stopped = export.controller_state == "stopped"
        _abort(abort_phase, "after_validation")
        result = import_validated_export(
            export,
            runtime,
            root,
            after_initialize=lambda: _abort(abort_phase, "after_destination_initialize"),
            before_commit=lambda: _abort(abort_phase, "before_import_commit"),
        )
        imported_work = result.queued_work
        _abort(abort_phase, "after_import")
        health, cockpit = _candidate(root, runtime, abort_phase, release)
        status = "verified_then_rolled_back"
    except (SyntheticAbort, SyntheticRehearsalError) as caught:
        error = f"{type(caught).__name__}:{caught}"
    finally:
        restore_tree_snapshot(destination_snapshot)
        if tree_digest(source, root) != source_snapshot.digest:
            raise RuntimeError("synthetic source changed during rehearsal")
        if tree_digest(destination, root) != destination_snapshot.digest:
            raise RuntimeError("synthetic destination rollback was not byte-identical")
    report: dict[str, Any] = {
        "format": "oc-rig-migration-rehearsal-report-v1",
        "status": status,
        "abort_phase": abort_phase,
        "error": error,
        "release_artifact": release.wheel.name,
        "release_sha256": release.wheel_sha256,
        "release_manifest": release.manifest.name,
        "source_pre_cutover_sha256": source_snapshot.digest,
        "source_post_rollback_sha256": tree_digest(source, root),
        "destination_pre_cutover_sha256": destination_snapshot.digest,
        "destination_post_rollback_sha256": tree_digest(destination, root),
        "export_sha256": export_digest,
        "old_synthetic_controller_stopped": stopped,
        "imported_work": list(imported_work),
        "candidate_health": health,
        "candidate_cockpit": cockpit,
        "production_action_available": False,
    }
    report_path = root / "rehearsal-report.json"
    report_path.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    report_path.chmod(0o600)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        required=True,
        help="fresh directory below the OS temporary root",
    )
    parser.add_argument("--abort-phase", choices=ABORT_PHASES)
    args = parser.parse_args()
    report = run_rehearsal(args.root, abort_phase=args.abort_phase)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
