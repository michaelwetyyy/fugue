"""Installed, release-pinned single-pane terminal cockpit for Fugue."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import sqlite3
import stat
import subprocess
import sys
import time
import uuid
from contextlib import closing
from pathlib import Path
from typing import Mapping

from oc_rig.adapters.opencode import LiveOpenCodeAdapterConfig
from oc_rig.cockpit import CockpitClient, normalize_snapshot, render_terminal
from oc_rig.deployment.user import (
    OpenCodeDeploymentConfig,
    UserDeployment,
    _read_state,
    _validate_opencode_configuration,
    _validate_runtime,
    _paths,
    _native_volume_uuid,
)
from oc_rig.protocol.client import RigClientError
from oc_rig.store.snapshot import _CockpitSnapshotProjection
from oc_rig.terminal_lifecycle import (
    ProcessIdentity,
    TerminalLifecycle,
    TerminalLifecycleError,
    _managed_backend_directory,
    _same_process,
    snapshot_is_quiescent,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="oc-rig-v2-terminal")
    parser.add_argument("--deployment-root", type=Path, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--plist", type=Path, required=True)
    parser.add_argument("--opencode", type=Path, required=True)
    parser.add_argument("--launchctl", type=Path, default=Path("/bin/launchctl"))
    parser.add_argument("--tmux", type=Path, required=True)
    parser.add_argument("--backend-directory", type=Path, required=True)
    parser.add_argument("--backend-work-directory", type=Path, required=True)
    parser.add_argument("--ownership", type=Path, required=True)
    parser.add_argument("--session", default="oc-rig-v2")
    parser.add_argument(
        "--mode", choices=("open", "app", "hub", "finalize", "stop"),
        default="open",
    )
    parser.add_argument("--cutover-existing", action="store_true")
    parser.add_argument("--legacy-backend-label")
    parser.add_argument("--legacy-backend-program", type=Path)
    parser.add_argument("--completed-cutover-evidence", type=Path)
    parser.add_argument("--completed-cutover-evidence-sha256")
    parser.add_argument("--completed-cutover-source", type=Path)
    parser.add_argument("--completed-cutover-source-release")
    parser.add_argument("--completed-cutover-source-config")
    parser.add_argument("--completed-cutover-controller-pid", type=int)
    parser.add_argument("--completed-cutover-legacy-pid", type=int)
    parser.add_argument("--finalize-timeout", type=float, default=21600.0)
    parser.add_argument("--finalize-interval", type=float, default=2.0)
    return parser


def _job(arguments: argparse.Namespace) -> UserDeployment:
    return UserDeployment(
        arguments.deployment_root,
        arguments.home,
        arguments.plist,
        arguments.launchctl,
        Path(sys.executable),
        dry_run=False,
    )


def _lifecycle(arguments: argparse.Namespace) -> TerminalLifecycle:
    root = arguments.deployment_root.resolve()
    return TerminalLifecycle(
        deployment=_job(arguments),
        opencode=arguments.opencode,
        ownership_path=arguments.ownership,
        backend_directory=arguments.backend_directory,
        backend_work_directory=arguments.backend_work_directory,
        adopt_running_controller=arguments.cutover_existing,
        require_backend_ownership=arguments.cutover_existing,
    )


def _selected_configuration(arguments: argparse.Namespace) -> OpenCodeDeploymentConfig:
    state = _read_state(arguments.deployment_root)
    if state.get("current") != arguments.release_id:
        raise TerminalLifecycleError("installed terminal release is no longer current")
    selected = _validate_opencode_configuration(arguments.deployment_root, state)
    if selected is None:
        raise TerminalLifecycleError("installed OpenCode configuration is absent")
    return selected


def _launcher_command(arguments: argparse.Namespace, mode: str) -> list[str]:
    root = arguments.deployment_root.resolve()
    command = [
        sys.executable, "-I", "-S", "-B", str(root / "launcher.py"), str(root),
        "--terminal", "--home", str(arguments.home), "--plist", str(arguments.plist),
        "--opencode", str(arguments.opencode), "--launchctl", str(arguments.launchctl),
        "--tmux", str(arguments.tmux), "--backend-directory",
        str(arguments.backend_directory), "--backend-work-directory",
        str(arguments.backend_work_directory), "--ownership", str(arguments.ownership),
        "--session", arguments.session,
        "--mode", mode, "--finalize-timeout", str(arguments.finalize_timeout),
        "--finalize-interval", str(arguments.finalize_interval),
    ]
    if arguments.cutover_existing:
        command.append("--cutover-existing")
    if arguments.legacy_backend_label:
        command.extend(["--legacy-backend-label", arguments.legacy_backend_label])
    if arguments.legacy_backend_program:
        command.extend(["--legacy-backend-program", str(arguments.legacy_backend_program)])
    evidence = getattr(arguments, "completed_cutover_evidence", None)
    if evidence is not None:
        command.extend(["--completed-cutover-evidence", str(evidence)])
    evidence_sha256 = getattr(arguments, "completed_cutover_evidence_sha256", None)
    if evidence_sha256 is not None:
        command.extend(["--completed-cutover-evidence-sha256", evidence_sha256])
    source = getattr(arguments, "completed_cutover_source", None)
    if source is not None:
        command.extend(["--completed-cutover-source", str(source)])
    for option, field in (
        ("--completed-cutover-source-release", "completed_cutover_source_release"),
        ("--completed-cutover-source-config", "completed_cutover_source_config"),
        ("--completed-cutover-controller-pid", "completed_cutover_controller_pid"),
        ("--completed-cutover-legacy-pid", "completed_cutover_legacy_pid"),
    ):
        value = getattr(arguments, field, None)
        if value is not None:
            command.extend([option, str(value)])
    return command


def _secure_bytes_at(path: Path, mode: int) -> tuple[bytes, os.stat_result] | None:
    if not path.is_absolute() or path.resolve() != path:
        raise TerminalLifecycleError("lifecycle ownership record path is unsafe")
    try:
        details = path.lstat()
        data = path.read_bytes()
        rechecked = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise TerminalLifecycleError("lifecycle ownership record is unreadable") from error
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_mode & 0o777 != mode
        or details.st_nlink != 1
        or (details.st_dev, details.st_ino, details.st_ctime_ns, details.st_size)
        != (
            rechecked.st_dev,
            rechecked.st_ino,
            rechecked.st_ctime_ns,
            rechecked.st_size,
        )
    ):
        raise TerminalLifecycleError("lifecycle ownership record is unsafe")
    return data, details


def _secure_json_at(
    path: Path, mode: int = 0o600
) -> tuple[dict[str, object], bytes] | None:
    loaded = _secure_bytes_at(path, mode)
    if loaded is None:
        return None
    data, _details = loaded
    try:
        value = json.loads(data)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise TerminalLifecycleError("lifecycle ownership record is malformed") from error
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if not isinstance(value, dict) or data != canonical:
        raise TerminalLifecycleError("lifecycle ownership record is malformed")
    return value, data


def _ownership_record_at(path: Path) -> dict[str, object] | None:
    loaded = _secure_json_at(path)
    if loaded is None:
        return None
    value, _data = loaded
    if value.get("format") != 1:
        raise TerminalLifecycleError("lifecycle ownership record is malformed")
    return value


def _ownership_record(arguments: argparse.Namespace) -> dict[str, object] | None:
    return _ownership_record_at(arguments.ownership)


def _canonical_stopped_record(record: Mapping[str, object]) -> bool:
    fields = {
        "backend",
        "backend_owned",
        "completed_cutover",
        "controller_owned",
        "controller_pid",
        "controller_starting",
        "cutover_intent",
        "format",
        "invocation_id",
        "phase",
        "reason",
        "tmux_nonce",
        "tmux_session_id",
    }
    if (
        set(record) != fields
        or record.get("format") != 1
        or record.get("phase") != "stopped"
        or record.get("backend") is not None
        or record.get("backend_owned") is not False
        or record.get("controller_owned") is not False
        or record.get("controller_pid") is not None
        or record.get("controller_starting") is not False
        or record.get("tmux_nonce") is not None
        or record.get("tmux_session_id") is not None
        or not isinstance(record.get("invocation_id"), str)
        or re.fullmatch(r"[0-9a-f]{32}", str(record.get("invocation_id"))) is None
        or not isinstance(record.get("reason"), str)
        or not record.get("reason")
        or (record.get("cutover_intent") is not None and not isinstance(record.get("cutover_intent"), dict))
    ):
        return False
    completed = record.get("completed_cutover")
    if completed is None:
        return True
    if (
        not isinstance(completed, dict)
        or set(completed) != {"format", "material", "receipt_id"}
        or completed.get("format") != 2
        or not isinstance(completed.get("material"), dict)
        or not isinstance(completed.get("receipt_id"), str)
        or re.fullmatch(r"[0-9a-f]{32}", str(completed.get("receipt_id"))) is None
        or completed["material"].get("intent") != record.get("cutover_intent")
    ):
        return False
    return True


def _authenticate_legacy_backend(
    arguments: argparse.Namespace,
    port: int,
    *,
    allow_absent: bool = False,
) -> dict[str, object] | None:
    """Return the exact loaded legacy identity; never mutate it."""
    label = arguments.legacy_backend_label
    program = arguments.legacy_backend_program
    if not label or program is None:
        raise TerminalLifecycleError(
            "direct cutover requires the exact legacy backend label and program"
        )
    target = f"gui/{os.geteuid()}/{label}"
    result = subprocess.run(
        [str(arguments.launchctl), "print", target], check=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={"HOME": str(arguments.home), "PATH": "/usr/bin:/bin"},
    )
    if result.returncode != 0:
        missing = result.returncode == 113 or (
            "could not find service" in result.stderr.lower()
        )
        if not missing:
            raise TerminalLifecycleError(
                "legacy backend launchd job could not be inspected"
            )
        if allow_absent:
            return None
        raise TerminalLifecycleError("legacy backend job is absent before direct cutover")
    program_match = re.search(r"(?m)^\s*program\s*=\s*(.+?)\s*$", result.stdout)
    pid_match = re.search(r"(?m)^\s*pid\s*=\s*([1-9][0-9]*)\s*$", result.stdout)
    arguments_match = re.search(
        r"(?ms)^\s*arguments\s*=\s*\{\s*$(.*?)^\s*\}\s*$", result.stdout
    )
    actual_arguments = () if arguments_match is None else tuple(
        line.strip() for line in arguments_match.group(1).splitlines() if line.strip()
    )
    expected = (str(program.resolve()), "serve", str(port), str(arguments.opencode))
    if (
        program_match is None
        or program_match.group(1) != str(program.resolve())
        or pid_match is None
        or actual_arguments != expected
    ):
        raise TerminalLifecycleError("legacy backend launchd job identity did not match")
    return {
        "arguments": list(actual_arguments),
        "label": label,
        "pid": int(pid_match.group(1)),
        "program": program_match.group(1),
        "target": target,
    }


def _completed_cutover_proof(
    arguments: argparse.Namespace,
    selected: OpenCodeDeploymentConfig,
    record: Mapping[str, object] | None,
) -> dict[str, object]:
    """Cross-check historical cutover evidence against retained immutable state."""

    evidence_path = getattr(arguments, "completed_cutover_evidence", None)
    expected_evidence_sha256 = getattr(
        arguments, "completed_cutover_evidence_sha256", None
    )
    source_root = getattr(arguments, "completed_cutover_source", None)
    expected_source_release = getattr(
        arguments, "completed_cutover_source_release", None
    )
    expected_source_config = getattr(arguments, "completed_cutover_source_config", None)
    expected_controller_pid = getattr(
        arguments, "completed_cutover_controller_pid", None
    )
    expected_legacy_pid = getattr(arguments, "completed_cutover_legacy_pid", None)
    if (
        evidence_path is None
        or source_root is None
        or not isinstance(expected_evidence_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_evidence_sha256) is None
        or not isinstance(expected_source_release, str)
        or not isinstance(expected_source_config, str)
        or not isinstance(expected_controller_pid, int)
        or isinstance(expected_controller_pid, bool)
        or expected_controller_pid <= 0
        or not isinstance(expected_legacy_pid, int)
        or isinstance(expected_legacy_pid, bool)
        or expected_legacy_pid <= 0
    ):
        raise TerminalLifecycleError(
            "completed cutover migration requires source, evidence, and pinned SHA-256"
        )
    evidence_loaded = _secure_json_at(evidence_path)
    if evidence_loaded is None:
        raise TerminalLifecycleError("completed cutover evidence is absent")
    evidence, evidence_bytes = evidence_loaded
    if hashlib.sha256(evidence_bytes).hexdigest() != expected_evidence_sha256:
        raise TerminalLifecycleError("completed cutover evidence hash does not match")
    expected_record_fields = {
        "backend",
        "backend_owned",
        "controller_owned",
        "controller_pid",
        "controller_starting",
        "cutover_intent",
        "format",
        "invocation_id",
        "phase",
        "reason",
        "tmux_nonce",
        "tmux_session_id",
    }
    intent = evidence.get("cutover_intent")
    backend = evidence.get("backend")
    if (
        set(evidence) != expected_record_fields
        or evidence.get("format") != 1
        or evidence.get("phase") not in {"running", "retained"}
        or evidence.get("controller_owned") is not True
        or evidence.get("backend_owned") is not True
        or evidence.get("controller_starting") is not False
        or not isinstance(evidence.get("invocation_id"), str)
        or not isinstance(evidence.get("tmux_nonce"), str)
        or not isinstance(evidence.get("tmux_session_id"), str)
        or not isinstance(backend, dict)
        or set(backend) != {"command", "pgid", "pid", "started"}
        or not isinstance(intent, dict)
        or set(intent) != {
            "config_id",
            "controller_pid",
            "endpoint",
            "event_sequence",
            "legacy",
            "release_id",
            "snapshot_digest",
        }
        or evidence.get("controller_pid") != intent.get("controller_pid")
        or intent.get("controller_pid") != expected_controller_pid
    ):
        raise TerminalLifecycleError("completed cutover evidence is not exact live proof")
    legacy = intent.get("legacy")
    label = arguments.legacy_backend_label
    program = arguments.legacy_backend_program
    if not label or program is None or not isinstance(legacy, dict) or set(legacy) != {
        "arguments",
        "label",
        "pid",
        "program",
        "target",
    }:
        raise TerminalLifecycleError("completed cutover legacy identity is malformed")
    expected_program = str(program.resolve())
    expected_arguments = [
        expected_program,
        "serve",
        str(int(selected.endpoint.rsplit(":", 1)[1])),
        str(arguments.opencode),
    ]
    if (
        legacy.get("arguments") != expected_arguments
        or legacy.get("label") != label
        or not isinstance(legacy.get("pid"), int)
        or isinstance(legacy.get("pid"), bool)
        or int(legacy["pid"]) <= 0
        or legacy.get("pid") != expected_legacy_pid
        or legacy.get("program") != expected_program
        or legacy.get("target") != f"gui/{os.geteuid()}/{label}"
        or intent.get("endpoint") != selected.endpoint
        or not isinstance(intent.get("controller_pid"), int)
        or isinstance(intent.get("controller_pid"), bool)
        or int(intent["controller_pid"]) <= 0
        or not isinstance(intent.get("event_sequence"), int)
        or isinstance(intent.get("event_sequence"), bool)
        or int(intent["event_sequence"]) < 0
    ):
        raise TerminalLifecycleError("completed cutover proof does not match invocation")
    for name, length in (("config_id", 64), ("snapshot_digest", 64)):
        value = intent.get(name)
        if (
            not isinstance(value, str)
            or len(value) != length
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise TerminalLifecycleError("completed cutover proof is malformed")
    release_id = intent.get("release_id")
    if not isinstance(release_id, str) or re.fullmatch(
        r"[0-9A-Za-z.]+-[0-9a-f]{16}", release_id
    ) is None:
        raise TerminalLifecycleError("completed cutover proof is malformed")
    if release_id != expected_source_release or intent.get("config_id") != expected_source_config:
        raise TerminalLifecycleError("completed cutover source binding does not match")
    source_root = source_root.resolve()
    source_details = source_root.lstat()
    if (
        source_root != getattr(arguments, "completed_cutover_source")
        or not stat.S_ISDIR(source_details.st_mode)
        or source_details.st_uid != os.geteuid()
        or stat.S_IMODE(source_details.st_mode) != 0o700
    ):
        raise TerminalLifecycleError("retained source root is unsafe")
    source_state_loaded = _secure_json_at(source_root / "deployment-state.json")
    if source_state_loaded is None:
        raise TerminalLifecycleError("retained source deployment state is absent")
    source_state, source_state_bytes = source_state_loaded
    if (
        source_state.get("format") != "oc-rig-local-user-deployment-v1"
        or release_id not in {source_state.get("current"), source_state.get("previous")}
        or not isinstance(source_state.get("opencode"), dict)
    ):
        raise TerminalLifecycleError("retained source state does not bind cutover")
    source_opencode = source_state["opencode"]
    config_id = intent["config_id"]
    if (
        source_opencode.get("format") != "oc-rig-local-user-opencode-v1"
        or source_opencode.get("config_id") != config_id
        or source_opencode.get("endpoint") != intent["endpoint"]
    ):
        raise TerminalLifecycleError("retained source config does not bind cutover")
    release_root = source_root / "releases" / str(release_id)
    release_details = release_root.lstat()
    if (
        not stat.S_ISDIR(release_details.st_mode)
        or release_details.st_uid != os.geteuid()
        or stat.S_IMODE(release_details.st_mode) != 0o500
    ):
        raise TerminalLifecycleError("retained source release is unsafe")
    pin_loaded = _secure_json_at(release_root / "release-pin.json", 0o400)
    if pin_loaded is None:
        raise TerminalLifecycleError("retained source release pin is absent")
    pin, pin_bytes = pin_loaded
    if pin.get("format") != "oc-rig-local-user-release-pin-v2" or pin.get(
        "release_id"
    ) != release_id:
        raise TerminalLifecycleError("retained source release pin does not match")
    artifact_hashes: dict[str, str] = {}
    for name in ("wheel", "manifest"):
        item = pin.get(name)
        if not isinstance(item, dict) or set(item) != {"filename", "sha256", "size"}:
            raise TerminalLifecycleError("retained source artifact pin is malformed")
        filename = item.get("filename")
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise TerminalLifecycleError("retained source artifact filename is unsafe")
        artifact_loaded = _secure_bytes_at(release_root / filename, 0o400)
        if artifact_loaded is None:
            raise TerminalLifecycleError("retained source artifact is absent")
        artifact, _facts = artifact_loaded
        digest = hashlib.sha256(artifact).hexdigest()
        if item.get("sha256") != digest or item.get("size") != len(artifact):
            raise TerminalLifecycleError("retained source artifact hash changed")
        artifact_hashes[name] = digest
    config_root = source_root / "config" / "opencode" / str(config_id)
    source_files = source_opencode.get("files")
    if not isinstance(source_files, dict):
        raise TerminalLifecycleError("retained source config pins are malformed")
    for name in ("auth.json", "topology.json", "trust.json"):
        loaded = _secure_bytes_at(config_root / name, 0o600)
        expected = source_files.get(name)
        if loaded is None or not isinstance(expected, dict):
            raise TerminalLifecycleError("retained source config file is absent")
        data, facts = loaded
        if (
            set(expected) != {"device", "inode", "sha256", "size"}
            or expected.get("inode") != facts.st_ino
            or expected.get("sha256") != hashlib.sha256(data).hexdigest()
            or expected.get("size") != len(data)
        ):
            raise TerminalLifecycleError("retained source config file changed")
    source_config = LiveOpenCodeAdapterConfig.from_historical_files(
        endpoint=str(intent["endpoint"]),
        auth_path=config_root / "auth.json",
        topology_path=config_root / "topology.json",
        trust_path=config_root / "trust.json",
    )
    database_path = source_root / "runtime" / "state" / "rig.sqlite3"
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = database_path.with_name(database_path.name + suffix)
        try:
            sidecar.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise TerminalLifecycleError(
                "retained source database sidecars cannot be inspected"
            ) from error
        raise TerminalLifecycleError(
            "retained source database is not proven checkpointed"
        )
    database_loaded = _secure_bytes_at(database_path, 0o600)
    if database_loaded is None:
        raise TerminalLifecycleError("retained source database is absent")
    database_bytes, _database_facts = database_loaded
    database_uri = f"file:{database_path}?mode=ro&immutable=1"
    with closing(
        sqlite3.connect(database_uri, uri=True, isolation_level=None)
    ) as connection:
        connection.execute("BEGIN")
        snapshot = dict(
            _CockpitSnapshotProjection(
                topology=source_config.topology,
                include_agent_lifecycle=False,
            ).capture(connection)
        )
        connection.rollback()
    version = snapshot["snapshot_version"]
    compatibility_snapshot = dict(snapshot)
    compatibility_graph = dict(snapshot["worker_graph"])
    compatibility_graph["workers"] = [
        {**worker, "agent_lifecycle": None}
        for worker in compatibility_graph["workers"]
    ]
    compatibility_snapshot["worker_graph"] = compatibility_graph
    quiescent, reason = snapshot_is_quiescent(compatibility_snapshot)
    if (
        not quiescent
        or version.get("event_sequence") != intent.get("event_sequence")
        or version.get("digest") != intent.get("snapshot_digest")
    ):
        raise TerminalLifecycleError(
            "retained source does not prove cutover quiescence: " + reason
        )
    destination_state_loaded = _secure_json_at(
        arguments.deployment_root / "deployment-state.json"
    )
    destination_pin_loaded = _secure_json_at(
        arguments.deployment_root
        / "releases"
        / arguments.release_id
        / "release-pin.json",
        0o400,
    )
    if destination_state_loaded is None or destination_pin_loaded is None:
        raise TerminalLifecycleError("destination binding is incomplete")
    destination_state, destination_state_bytes = destination_state_loaded
    destination_pin, destination_pin_bytes = destination_pin_loaded
    destination_opencode = destination_state.get("opencode")
    if (
        destination_state.get("current") != arguments.release_id
        or not isinstance(destination_opencode, dict)
        or destination_opencode.get("config_id") != selected.config_id
        or destination_pin.get("release_id") != arguments.release_id
    ):
        raise TerminalLifecycleError("destination release or config binding changed")
    material: dict[str, object] = {
        "destination": {
            "config_id": selected.config_id,
            "release_id": arguments.release_id,
            "release_pin_sha256": hashlib.sha256(destination_pin_bytes).hexdigest(),
            "root": str(arguments.deployment_root),
            "state_sha256": hashlib.sha256(destination_state_bytes).hexdigest(),
        },
        "evidence": {
            "path": str(evidence_path),
            "sha256": expected_evidence_sha256,
        },
        "intent": dict(intent),
        "source": {
            "config_id": config_id,
            "database_sha256": hashlib.sha256(database_bytes).hexdigest(),
            "manifest_sha256": artifact_hashes["manifest"],
            "release_id": release_id,
            "release_pin_sha256": hashlib.sha256(pin_bytes).hexdigest(),
            "root": str(source_root),
            "state_sha256": hashlib.sha256(source_state_bytes).hexdigest(),
            "volume_uuid": _native_volume_uuid(path=source_root),
            "wheel_sha256": artifact_hashes["wheel"],
        },
    }
    receipt_id = hashlib.sha256(
        b"oc-rig-completed-cutover-receipt-v2\0"
        + json.dumps(
            material, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()[:32]
    stored = record.get("completed_cutover") if record is not None else None
    if stored is None:
        return {"format": 2, "material": material, "receipt_id": receipt_id}
    if (
        not isinstance(stored, dict)
        or set(stored) != {"format", "material", "receipt_id"}
        or stored.get("format") != 2
        or not isinstance(stored.get("material"), dict)
        or not isinstance(stored.get("receipt_id"), str)
        or re.fullmatch(r"[0-9a-f]{32}", str(stored.get("receipt_id"))) is None
    ):
        raise TerminalLifecycleError("completed cutover receipt binding changed")
    stored_material = stored["material"]
    stored_destination = stored_material.get("destination")
    if not isinstance(stored_destination, dict):
        raise TerminalLifecycleError("completed cutover receipt binding changed")
    destination_key = (material["destination"]["release_id"], material["destination"]["config_id"])
    stored_key = (stored_destination.get("release_id"), stored_destination.get("config_id"))
    if stored_key == destination_key:
        if stored_material != material:
            raise TerminalLifecycleError("completed cutover receipt binding changed")
        if stored["receipt_id"] != receipt_id:
            receipt = arguments.ownership.with_name(
                "completed-cutover-receipt-"
                f"{destination_key[0]}-{destination_key[1]}.json"
            )
            loaded = _secure_bytes_at(receipt, 0o600)
            expected = (
                json.dumps(stored, sort_keys=True, separators=(",", ":")).encode()
                + b"\n"
            )
            if loaded is None or loaded[0] != expected:
                raise TerminalLifecycleError(
                    "completed cutover receipt binding changed"
                )
        return dict(stored)
    return {"format": 2, "material": material, "receipt_id": receipt_id}


def _cutover_backend(
    arguments: argparse.Namespace,
    port: int,
    expected_identity: Mapping[str, object],
) -> None:
    """Remove only the exact authenticated legacy launchd backend job."""
    if _authenticate_legacy_backend(arguments, port) != dict(expected_identity):
        raise TerminalLifecycleError("legacy backend changed after cutover authorization")
    label = arguments.legacy_backend_label
    assert label is not None
    subprocess.run(
        [str(arguments.launchctl), "remove", label], check=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"HOME": str(arguments.home), "PATH": "/usr/bin:/bin"},
    )


def _topology(arguments: argparse.Namespace) -> list[tuple[str, str, str]]:
    selected = _selected_configuration(arguments)
    value = json.loads(selected.topology.read_text(encoding="utf-8"))
    pools = value.get("pools") if isinstance(value, dict) else None
    if not isinstance(pools, dict):
        raise TerminalLifecycleError("installed topology has no pools")
    result = []
    for lane in ("control", "tensorhost", "homelab", "personal", "hands-off"):
        slots = pools.get(lane)
        if not isinstance(slots, list) or not slots or not isinstance(slots[0], dict):
            raise TerminalLifecycleError(f"installed topology has no primary {lane} slot")
        session, worker = slots[0].get("session_id"), slots[0].get("worker")
        if not isinstance(session, str) or not isinstance(worker, str):
            raise TerminalLifecycleError(f"installed primary {lane} slot is malformed")
        result.append((lane, session, worker))
    return result


def _tmux(arguments: argparse.Namespace, *values: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(arguments.tmux), *values], check=check, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=_terminal_env(arguments),
    )


def _terminal_env(arguments: argparse.Namespace) -> dict[str, str]:
    term = os.environ.get("TERM", "")
    if len(term) > 64 or (
        term and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.-]*", term) is None
    ):
        raise TerminalLifecycleError("terminal TERM is invalid")
    if term in {"", "dumb"} or subprocess.run(
        ["/usr/bin/infocmp"],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "TERM": term},
    ).returncode != 0:
        term = "xterm-256color"
        if subprocess.run(
            ["/usr/bin/infocmp"],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "TERM": term},
        ).returncode != 0:
            raise TerminalLifecycleError("safe terminal fallback is unavailable")
    return {
        "HOME": str(arguments.home),
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "TERM": term,
    }


def _tmux_session_id(arguments: argparse.Namespace) -> str | None:
    result = _tmux(
        arguments, "display-message", "-p", "-t", arguments.session,
        "#{session_id}", check=False,
    )
    value = result.stdout.strip()
    return value if result.returncode == 0 and value else None


def _tmux_nonce(arguments: argparse.Namespace) -> str | None:
    result = _tmux(
        arguments, "show-options", "-qv", "-t", arguments.session,
        "@oc_rig_nonce", check=False,
    )
    value = result.stdout.strip()
    return value if result.returncode == 0 and value else None


def _matching_existing_tmux(arguments: argparse.Namespace) -> bool:
    session_id = _tmux_session_id(arguments)
    if session_id is None:
        return False
    try:
        details = arguments.ownership.lstat()
        value = json.loads(arguments.ownership.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TerminalLifecycleError(
            "existing v2 tmux has no readable ownership record"
        ) from error
    if details.st_uid != os.geteuid() or details.st_mode & 0o777 != 0o600:
        raise TerminalLifecycleError("existing v2 tmux ownership record is unsafe")
    actual_nonce = _tmux_nonce(arguments)
    if not isinstance(value, dict) or value.get("tmux_nonce") != actual_nonce:
        raise TerminalLifecycleError("existing v2 tmux does not match lifecycle ownership")
    if value.get("tmux_session_id") is None:
        return False
    if (
        value.get("phase") not in {"starting", "running", "retained"}
        or value.get("tmux_session_id") != session_id
    ):
        raise TerminalLifecycleError("existing v2 tmux does not match lifecycle ownership")
    return True


def _recover_partial_tmux(arguments: argparse.Namespace, nonce: str) -> None:
    if _tmux_session_id(arguments) is None:
        return
    if _tmux_nonce(arguments) != nonce:
        raise TerminalLifecycleError("existing partial tmux nonce does not match")
    _tmux(arguments, "kill-session", "-t", arguments.session)


def _build_tmux(arguments: argparse.Namespace, nonce: str) -> str:
    if _tmux(arguments, "has-session", "-t", arguments.session, check=False).returncode == 0:
        raise TerminalLifecycleError("v2 tmux session already exists")
    root = arguments.backend_directory.resolve()
    hub = shlex.join(_launcher_command(arguments, "hub"))
    # Keep topology validation at the attended boundary, but leave every
    # OpenCode worker session headless. The terminal is now only the read-only
    # cockpit; work remains visible through the controller projection.
    _topology(arguments)
    width = max(200, int(os.environ.get("COLUMNS", "220")))
    height = max(48, int(os.environ.get("LINES", "54")))
    created = False
    try:
        _tmux(
            arguments, "new-session", "-d", "-s", arguments.session, "-n", "cockpit",
            "-c", str(root), "-x", str(width), "-y", str(height), hub,
            ";", "set-option", "-t", arguments.session, "@oc_rig_nonce", nonce,
        )
        created = True
        finalizer = shlex.join(_launcher_command(arguments, "finalize"))
        hook = f"run-shell {shlex.quote(finalizer + ' >/dev/null 2>&1 &')}"
        _tmux(arguments, "set-hook", "-t", arguments.session, "client-detached", hook)
        _tmux(arguments, "set-hook", "-t", arguments.session, "session-closed", hook)
        _tmux(arguments, "set", "-t", arguments.session, "mouse", "on")
        _tmux(arguments, "set", "-t", arguments.session, "history-limit", "50000")
        session_id = _tmux_session_id(arguments)
        if session_id is None:
            raise TerminalLifecycleError("created tmux session has no stable identity")
        if _tmux_nonce(arguments) != nonce:
            raise TerminalLifecycleError("created tmux session nonce did not match")
        return session_id
    except BaseException:
        if created:
            _tmux(arguments, "kill-session", "-t", arguments.session, check=False)
        raise


def _hub_frame(client: CockpitClient) -> str:
    """Render one privacy-safe frame without exiting on controller restarts."""

    try:
        return render_terminal(client.refresh(), width=100, ansi=True)
    except (OSError, RigClientError, ValueError):
        return (
            "Fugue · temporarily unavailable\n"
            "Controller connection is restarting; retrying automatically.\n"
        )


def _hub(arguments: argparse.Namespace) -> int:
    paths = _paths(arguments.deployment_root)
    client = CockpitClient(paths.socket, approved_root=paths.socket_root, identity_profile="local-user")
    while True:
        print("\033[2J\033[H", end="")
        print(_hub_frame(client), end="", flush=True)
        time.sleep(2.0)


def _finalizer_error_code(error: BaseException) -> str:
    if isinstance(error, TerminalLifecycleError):
        message = str(error)
        if message == "finalizer timeout":
            return "timeout"
        if message == "terminal signal deferral requires main thread":
            return "signal_context"
        if message == "cockpit snapshot validation failed":
            return "snapshot_validation"
        if message.startswith("terminal signal "):
            return "deferred_terminal_signal"
        if "backend" in message and "inspection" in message:
            return "backend_inspection"
        if "backend" in message and "identity" in message:
            return "backend_identity"
        if "controller" in message and "identity" in message:
            return "controller_identity"
        if "controller status" in message:
            return "controller_status"
        if "controller stop outcome" in message:
            return "controller_stop_outcome"
        if "process group" in message or "backend group" in message:
            return "backend_group"
        if "ownership" in message:
            return "ownership_validation"
        return "lifecycle_error"
    if isinstance(error, OSError):
        return "os_error"
    if isinstance(error, (KeyError, TypeError, ValueError)):
        return "invalid_runtime_state"
    if isinstance(error, RuntimeError):
        return "runtime_error"
    return "unexpected_error"


def _finalizer_error_category(error: BaseException) -> str:
    if isinstance(error, TerminalLifecycleError):
        return "lifecycle"
    if isinstance(error, subprocess.SubprocessError):
        return "subprocess"
    if isinstance(error, OSError):
        return "operating_system"
    return "unexpected"


def _record_finalizer_error(arguments: argparse.Namespace, error: BaseException) -> None:
    parent = arguments.ownership.parent.resolve()
    details = parent.lstat()
    if (
        parent != arguments.ownership.parent
        or not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o700
    ):
        raise TerminalLifecycleError("finalizer error directory is unsafe")
    value = {
        "error_category": _finalizer_error_category(error),
        "error_code": _finalizer_error_code(error),
        "format": "oc-rig-terminal-finalizer-error-v1",
        "recorded_at_ns": time.time_ns(),
    }
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    target = parent / "finalizer-error.json"
    temporary = parent / f".finalizer-error-{uuid.uuid4().hex}.pending"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(data):
            try:
                written = os.write(descriptor, data[offset:])
            except InterruptedError:
                continue
            if written <= 0:
                raise TerminalLifecycleError(
                    "finalizer error publication made no progress"
                )
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, target)
    directory = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _finalize_impl(arguments: argparse.Namespace) -> int:
    def attached() -> bool:
        result = _tmux(
            arguments, "display-message", "-p", "-t", arguments.session,
            "#{session_attached}", check=False,
        )
        return result.returncode == 0 and result.stdout.strip() not in {"", "0"}

    if attached():
        return 0
    lifecycle = _lifecycle(arguments)
    lifecycle.resume_cleanup()
    deadline = time.monotonic() + arguments.finalize_timeout
    while True:
        if attached():
            lifecycle.handoff()
            return 0
        stopped, reason = lifecycle.close(
            terminal_lost=False, should_abort=attached
        )
        if stopped:
            _tmux(arguments, "kill-session", "-t", arguments.session, check=False)
            return 0
        if reason == "terminal reattached":
            lifecycle.handoff()
            return 0
        if time.monotonic() >= deadline:
            lifecycle.close(terminal_lost=True)
            return 1
        time.sleep(arguments.finalize_interval)


def _finalize(arguments: argparse.Namespace) -> int:
    try:
        result = _finalize_impl(arguments)
        if result != 0:
            try:
                _record_finalizer_error(
                    arguments, TerminalLifecycleError("finalizer timeout")
                )
            except BaseException:
                pass
        return result
    except BaseException as error:
        try:
            _record_finalizer_error(arguments, error)
        except BaseException:
            pass
        raise


def _stop(arguments: argparse.Namespace) -> int:
    """Stop through durable ownership, never through controller/backend liveness probes."""

    record = _ownership_record(arguments)
    if record is not None and record.get("phase") == "stopped":
        if not _canonical_stopped_record(record):
            raise TerminalLifecycleError("stopped ownership record is inconsistent")
        return 0
    if _matching_existing_tmux(arguments):
        for hook in ("client-detached", "session-closed"):
            _tmux(arguments, "set-hook", "-u", "-t", arguments.session, hook)
        _tmux(arguments, "kill-session", "-t", arguments.session)
    if record is None:
        return 0
    return _finalize(arguments)


def _cutover_intent(
    arguments: argparse.Namespace,
    selected: OpenCodeDeploymentConfig,
    legacy_identity: Mapping[str, object],
) -> tuple[int, dict[str, object]]:
    status = _job(arguments).status().get("job")
    if (
        not isinstance(status, Mapping)
        or status.get("running") is not True
        or not isinstance(status.get("pid"), int)
    ):
        raise TerminalLifecycleError(
            "v2 controller must be running for direct cutover preflight"
        )
    paths = _paths(arguments.deployment_root)
    snapshot = CockpitClient(
        paths.socket,
        approved_root=paths.socket_root,
        identity_profile="local-user",
    ).refresh()
    quiescent, reason = snapshot_is_quiescent(snapshot)
    if not quiescent:
        raise TerminalLifecycleError(
            "direct cutover requires exact v2 quiescence: " + reason
        )
    view = normalize_snapshot(snapshot)
    version = view["snapshot_version"]
    return int(status["pid"]), {
        "config_id": selected.config_id,
        "controller_pid": int(status["pid"]),
        "endpoint": selected.endpoint,
        "event_sequence": version["event_sequence"],
        "legacy": dict(legacy_identity),
        "release_id": arguments.release_id,
        "snapshot_digest": version["digest"],
    }


def _open(arguments: argparse.Namespace, *, attach: bool = True) -> int:
    if _matching_existing_tmux(arguments):
        if not attach:
            return 0
        return subprocess.run(
            [str(arguments.tmux), "attach-session", "-t", arguments.session],
            env=_terminal_env(arguments),
        ).returncode
    selected = _selected_configuration(arguments)
    port = int(selected.endpoint.rsplit(":", 1)[1])
    lifecycle = _lifecycle(arguments)
    if arguments.cutover_existing:
        legacy_identity = _authenticate_legacy_backend(
            arguments, port, allow_absent=True
        )
        record = _ownership_record(arguments)
        if legacy_identity is not None:
            controller_pid, intent = _cutover_intent(
                arguments, selected, legacy_identity
            )
            lifecycle.prepare_cutover(controller_pid=controller_pid, intent=intent)
            _cutover_backend(arguments, port, legacy_identity)
        elif record is not None and record.get("completed_cutover") is not None:
            proof = _completed_cutover_proof(arguments, selected, record)
            if record.get("phase") == "starting":
                record = lifecycle.recover_conclusively_dead_starting_record(
                    proof=proof,
                    selected_config_id=selected.config_id,
                    expected_existing=record,
                    port=port,
                )
            if record.get("phase") == "running":
                record = lifecycle.recover_conclusively_dead_running_record(
                    proof=proof,
                    selected_config_id=selected.config_id,
                    expected_existing=record,
                    port=port,
                    tmux_absent=not _matching_existing_tmux(arguments),
                )
            if record.get("phase") == "stopped":
                if (
                    record.get("backend") is not None
                    and record.get("backend_owned") is False
                    and record.get("controller_owned") is False
                    and record.get("controller_starting") is False
                    and record.get("controller_pid") is None
                    and record.get("tmux_nonce") is None
                    and record.get("tmux_session_id") is None
                ):
                    record = lifecycle.recover_stale_stopped_backend(
                        proof=proof,
                        selected_config_id=selected.config_id,
                        expected_existing=record,
                    )
                if (
                    record.get("backend") is not None
                    or record.get("backend_binding") is not None
                    or record.get("backend_owned") is not False
                    or record.get("controller_owned") is not False
                    or record.get("controller_starting") is not False
                    or record.get("controller_pid") is not None
                    or record.get("tmux_nonce") is not None
                    or record.get("tmux_session_id") is not None
                ):
                    raise TerminalLifecycleError(
                        "completed cutover receipt has stale resource ownership"
                    )
                lifecycle.adopt_completed_cutover(
                    proof=proof,
                    expected_existing=record,
                )
        elif record is not None and record.get("phase") == "stopped":
            status = _job(arguments).status().get("job")
            recorded_backend = record.get("backend")
            backend_alive = False
            if recorded_backend is not None:
                backend_alive = _same_process(
                    ProcessIdentity.from_json(recorded_backend)
                )
            if (
                record.get("backend_owned") is not False
                or record.get("controller_owned") is not False
                or record.get("controller_starting") is not False
                or record.get("controller_pid") is not None
                or not isinstance(status, Mapping)
                or status.get("running") is not False
                or backend_alive
            ):
                raise TerminalLifecycleError(
                    "completed cutover migration requires stopped local resources"
                )
            proof = _completed_cutover_proof(arguments, selected, record)
            lifecycle.adopt_completed_cutover(
                proof=proof,
                expected_existing=record,
            )
        elif record is not None:
            durable = record.get("cutover_intent")
            if not isinstance(durable, dict) or not isinstance(durable.get("legacy"), dict):
                raise TerminalLifecycleError("absent legacy backend has no cutover intent")
            controller_pid, intent = _cutover_intent(
                arguments, selected, durable["legacy"]
            )
            lifecycle.prepare_cutover(controller_pid=controller_pid, intent=intent)
        else:
            raise TerminalLifecycleError(
                "legacy backend job is absent before direct cutover"
            )
        if legacy_identity is not None or (
            record is not None
            and record.get("phase") != "stopped"
            and record.get("completed_cutover") is None
        ):
            auth = json.loads(selected.auth.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 10.0
            while TerminalLifecycle._health(
                selected.endpoint.rstrip("/"), auth["username"], auth["password"]
            ):
                if time.monotonic() >= deadline:
                    raise TerminalLifecycleError(
                        "authenticated legacy backend remained healthy after removal"
                    )
                time.sleep(0.1)
    lifecycle.start()
    try:
        nonce = lifecycle.tmux_nonce or uuid.uuid4().hex
        lifecycle.prepare_tmux(nonce)
        _recover_partial_tmux(arguments, nonce)
        session_id = _build_tmux(arguments, nonce)
        lifecycle.bind_tmux(session_id, nonce)
        lifecycle.handoff()
    except BaseException:
        lifecycle.close(terminal_lost=True)
        raise
    if not attach:
        return 0
    result = subprocess.run(
        [str(arguments.tmux), "attach-session", "-t", arguments.session],
        env=_terminal_env(arguments),
    ).returncode
    if result != 0:
        _finalize(arguments)
    return result


def main(argv: list[str] | None = None) -> int:
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    if raw_arguments[4:5] == ["--codex-route"]:
        if (
            len(raw_arguments) < 7
            or raw_arguments[:1] != ["--deployment-root"]
            or raw_arguments[2:3] != ["--release-id"]
        ):
            print("oc-rig-v2-terminal: invalid Codex route prefix", file=sys.stderr)
            return 1
        deployment_root = Path(raw_arguments[1])
        release_id = raw_arguments[3]
        try:
            _validate_runtime(
                deployment_root,
                require_empty_socket=False,
                expected_release=release_id,
            )
            from oc_rig.route_cli import main as route_main

            return route_main(
                [str(deployment_root), raw_arguments[5], *raw_arguments[6:]]
            )
        except (OSError, ValueError, TerminalLifecycleError) as error:
            print(f"oc-rig-v2-terminal: {error}", file=sys.stderr)
            return 1
    arguments = build_parser().parse_args(raw_arguments)
    try:
        _managed_backend_directory(arguments.home, arguments.backend_directory)
    except TerminalLifecycleError as error:
        print(f"oc-rig-v2-terminal: {error}", file=sys.stderr)
        return 1
    expected_backend_work = (
        arguments.home / "Library" / "Application Support" / "oc-rig-v2-backend-work"
    )
    if (
        not arguments.backend_work_directory.is_absolute()
        or arguments.backend_work_directory != expected_backend_work
    ):
        print(
            "oc-rig-v2-terminal: backend work directory is not the managed path",
            file=sys.stderr,
        )
        return 1
    _validate_runtime(
        arguments.deployment_root,
        require_empty_socket=False,
        expected_release=arguments.release_id,
        allow_stale_codex_callback=arguments.mode in {"finalize", "stop"},
    )
    try:
        if arguments.mode == "hub":
            return _hub(arguments)
        if arguments.mode == "finalize":
            return _finalize(arguments)
        if arguments.mode == "stop":
            return _stop(arguments)
        return _open(arguments, attach=arguments.mode != "app")
    except (OSError, ValueError, subprocess.CalledProcessError, TerminalLifecycleError) as error:
        print(f"oc-rig-v2-terminal: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
