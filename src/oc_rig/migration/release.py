"""Deterministic, offline wheel construction for migration rehearsals."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


_DISTRIBUTION = "oc_rig"
_VERSION_PATTERN = re.compile(r'^__version__ = "([0-9A-Za-z.]+)"$', re.MULTILINE)
_FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_WHEEL_FILENAME = re.compile(
    r"^oc_rig-(?P<version>[0-9A-Za-z.]+)-py3-none-any[.]whl$"
)
_EXPECTED_MIGRATIONS = (
    "001_initial.sql",
    "002_queue_and_fences.sql",
    "003_scheduler.sql",
    "004_scheduler_authority.sql",
    "005_transport.sql",
    "006_completion_recovery.sql",
    "007_disabled_callback_recovery.sql",
    "008_opencode_delivery.sql",
    "009_transport_adapter_selection.sql",
    "010_local_codex_callbacks.sql",
    "011_isolated_review_sessions.sql",
    "012_isolated_session_cleanup.sql",
    "013_provisional_review_sessions.sql",
    "014_durable_completion_results.sql",
    "015_agent_lifecycle.sql",
    "016_cancelled_session_cleanup.sql",
    "017_child_completion_barrier.sql",
    "018_llm_behaviour.sql",
    "019_control_pool_expansion.sql",
    "020_codex_source_routes.sql",
    "021_slot_session_rebind.sql",
    "022_child_barrier_generation.sql",
    "023_descendant_budget.sql",
    "024_completed_transcript_archive.sql",
    "025_callback_delivery_reconciliation.sql",
    "026_source_inbox_read_indexes.sql",
    "027_persistent_session_close.sql",
)
_KNOWN_HISTORICAL_MIGRATIONS = tuple(
    _EXPECTED_MIGRATIONS[:count]
    for count in range(10, len(_EXPECTED_MIGRATIONS))
)
_FORBIDDEN_PARTS = frozenset({"tests", "fixtures", "__pycache__", ".pytest_cache"})
_DIST_INFO_FILES = frozenset(
    {"METADATA", "RECORD", "WHEEL", "entry_points.txt", "top_level.txt", "licenses/LICENSE"}
)
_HISTORICAL_DIST_INFO_FILES = _DIST_INFO_FILES - {"licenses/LICENSE"}
_MAX_WHEEL_BYTES = 64 * 1024 * 1024
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ReleaseArtifact:
    wheel: Path
    manifest: Path
    wheel_sha256: str
    members: tuple[str, ...]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _record_digest(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + encoded.decode("ascii")


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, _FIXED_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o444) << 16
    return info


def _version(package_root: Path) -> str:
    match = _VERSION_PATTERN.search(
        package_root.joinpath("__init__.py").read_text(encoding="utf-8")
    )
    if match is None:
        raise ValueError("package version is not a fixed literal")
    return match.group(1)


def _source_members(source_root: Path) -> dict[str, bytes]:
    package_root = source_root / "src" / "oc_rig"
    if not package_root.is_dir() or package_root.is_symlink():
        raise ValueError("source root does not contain a regular oc_rig package")
    members: dict[str, bytes] = {}
    for path in sorted(package_root.rglob("*")):
        relative = path.relative_to(source_root / "src")
        if any(part in _FORBIDDEN_PARTS for part in relative.parts):
            continue
        details = path.lstat()
        if stat.S_ISDIR(details.st_mode):
            continue
        if not stat.S_ISREG(details.st_mode) or path.is_symlink():
            raise ValueError(f"release source is not a regular file: {relative}")
        if path.suffix in {".pyc", ".pyo"}:
            continue
        members[PurePosixPath(*relative.parts).as_posix()] = path.read_bytes()
    return members


def _metadata(version: str, license_bytes: bytes) -> dict[str, bytes]:
    dist_info = f"{_DISTRIBUTION}-{version}.dist-info"
    return {
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.4\n"
            "Name: oc-rig\n"
            f"Version: {version}\n"
            "Summary: A clean-room controller for a local OpenCode orchestration rig\n"
            "License-Expression: MIT\n"
            "License-File: LICENSE\n"
            "Requires-Python: >=3.11\n"
            "\n"
        ).encode("utf-8"),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: oc-rig-offline-release-v1\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
            "\n"
        ).encode("utf-8"),
        f"{dist_info}/entry_points.txt": b"[console_scripts]\nrigctl = oc_rig.cli:main\n",
        f"{dist_info}/top_level.txt": b"oc_rig\n",
        f"{dist_info}/licenses/LICENSE": license_bytes,
    }


def _record(members: dict[str, bytes], record_name: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name in sorted(members):
        data = members[name]
        writer.writerow((name, _record_digest(data), len(data)))
    writer.writerow((record_name, "", ""))
    return output.getvalue().encode("utf-8")


def _required_migration_names(
    names: tuple[str, ...], *, allow_known_historical: bool = False
) -> tuple[str, ...]:
    prefix = "oc_rig/store/migrations/"
    migrations = tuple(
        name.removeprefix(prefix)
        for name in names
        if name.startswith(prefix) and name.endswith(".sql")
    )
    allowed = (_EXPECTED_MIGRATIONS,) + (
        _KNOWN_HISTORICAL_MIGRATIONS if allow_known_historical else ()
    )
    if migrations not in allowed:
        raise ValueError(f"release must contain exactly migrations 001 through {len(_EXPECTED_MIGRATIONS):03d}")
    return migrations


def _canonical_dist_info(
    artifact_filename: str,
    names: tuple[str, ...],
    *,
    allow_known_historical: bool = False,
) -> str:
    match = _WHEEL_FILENAME.fullmatch(artifact_filename)
    if match is None:
        raise ValueError("release wheel filename is not canonical")
    dist_info = f"oc_rig-{match.group('version')}.dist-info"
    members = {
        name.removeprefix(dist_info + "/")
        for name in names
        if name.startswith(dist_info + "/")
    }
    foreign = tuple(
        name
        for name in names
        if ".dist-info/" in name and not name.startswith(dist_info + "/")
    )
    allowed = members == _DIST_INFO_FILES or (
        allow_known_historical and members == _HISTORICAL_DIST_INFO_FILES
    )
    if not allowed or foreign:
        raise ValueError("release dist-info membership is not canonical")
    return dist_info


def _verify_wheel_record(
    archive: zipfile.ZipFile,
    names: tuple[str, ...],
    dist_info: str,
) -> None:
    record_name = f"{dist_info}/RECORD"
    try:
        text = archive.read(record_name).decode("utf-8")
        rows = tuple(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (UnicodeDecodeError, csv.Error) as error:
        raise ValueError("wheel RECORD is invalid") from error
    if any(len(row) != 3 for row in rows):
        raise ValueError("wheel RECORD rows must contain exactly three fields")
    recorded_names = tuple(row[0] for row in rows)
    if (
        len(recorded_names) != len(set(recorded_names))
        or set(recorded_names) != set(names)
    ):
        raise ValueError("wheel RECORD does not cover the exact archive membership")
    for name, digest, size_text in rows:
        if name == record_name:
            if digest or size_text:
                raise ValueError("wheel RECORD must leave its own hash and size empty")
            continue
        data = archive.read(name)
        if digest != _record_digest(data) or size_text != str(len(data)):
            raise ValueError(f"wheel RECORD hash or size mismatch: {name}")


def build_release_artifact(source_root: Path, output_directory: Path) -> ReleaseArtifact:
    """Build one byte-reproducible wheel without a build frontend or network."""
    source_root = source_root.resolve(strict=True)
    output_directory = output_directory.resolve(strict=True)
    version = _version(source_root / "src" / "oc_rig")
    wheel = output_directory / f"oc_rig-{version}-py3-none-any.whl"
    manifest = output_directory / "oc-rig-release-manifest.json"
    if wheel.exists() or manifest.exists():
        raise FileExistsError("release outputs are immutable and must not already exist")

    members = _source_members(source_root)
    license_path = source_root / "LICENSE"
    license_details = license_path.lstat()
    if (
        not stat.S_ISREG(license_details.st_mode)
        or license_path.is_symlink()
        or not 0 < license_details.st_size <= 64 * 1024
    ):
        raise ValueError("release LICENSE must be a bounded regular file")
    members.update(_metadata(version, license_path.read_bytes()))
    record_name = f"{_DISTRIBUTION}-{version}.dist-info/RECORD"
    members[record_name] = _record(members, record_name)
    ordered_names = tuple(sorted(members))
    migrations = _required_migration_names(ordered_names)

    with wheel.open("xb") as descriptor:
        with zipfile.ZipFile(descriptor, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name in ordered_names:
                archive.writestr(_zip_info(name), members[name], compresslevel=9)
        descriptor.flush()
        os.fsync(descriptor.fileno())
    wheel_bytes = wheel.read_bytes()
    wheel_hash = _sha256(wheel_bytes)
    manifest_value = {
        "format": "oc-rig-release-manifest-v1",
        "artifact": {
            "filename": wheel.name,
            "sha256": wheel_hash,
            "size": len(wheel_bytes),
        },
        "members": [
            {"path": name, "sha256": _sha256(members[name]), "size": len(members[name])}
            for name in ordered_names
        ],
        "required_migrations": list(migrations),
    }
    manifest.write_bytes(
        json.dumps(manifest_value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    wheel.chmod(0o444)
    manifest.chmod(0o444)
    return verify_release_artifact(wheel, manifest)


def _verify_release_bytes(
    wheel_bytes: bytes,
    manifest_bytes: bytes,
    *,
    artifact_filename: str,
    wheel_reference: Path,
    manifest_reference: Path,
    allow_known_historical: bool = False,
) -> ReleaseArtifact:
    value = json.loads(manifest_bytes)
    if not isinstance(value, dict) or value.get("format") != "oc-rig-release-manifest-v1":
        raise ValueError("release manifest format is invalid")
    artifact = value.get("artifact")
    if (
        not isinstance(artifact, dict)
        or artifact.get("filename") != artifact_filename
    ):
        raise ValueError("release manifest artifact name is invalid")
    wheel_hash = _sha256(wheel_bytes)
    if artifact.get("sha256") != wheel_hash or artifact.get("size") != len(wheel_bytes):
        raise ValueError("release artifact hash or size does not match")

    declared = value.get("members")
    if not isinstance(declared, list):
        raise ValueError("release member manifest is invalid")
    expected: dict[str, tuple[str, int]] = {}
    for item in declared:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise ValueError("release member manifest entry is invalid")
        name, digest, size = item["path"], item["sha256"], item["size"]
        if (
            not isinstance(name, str)
            or name in expected
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or type(size) is not int
            or size < 0
        ):
            raise ValueError("release member manifest facts are invalid")
        expected[name] = (digest, size)
    with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as archive:
        names = tuple(sorted(archive.namelist()))
        if len(names) != len(set(names)) or set(names) != set(expected):
            raise ValueError("release member set does not match its manifest")
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("release contains an unsafe member path")
            if any(part in _FORBIDDEN_PARTS for part in path.parts) or path.suffix in {
                ".pyc",
                ".pyo",
            }:
                raise ValueError("release contains a fixture or cache artifact")
            data = archive.read(name)
            if expected[name] != (_sha256(data), len(data)):
                raise ValueError(f"release member hash mismatch: {name}")
        dist_info = _canonical_dist_info(
            artifact_filename, names, allow_known_historical=allow_known_historical
        )
        _verify_wheel_record(archive, names, dist_info)
    migrations = _required_migration_names(
        names, allow_known_historical=allow_known_historical
    )
    if value.get("required_migrations") != list(migrations):
        raise ValueError("release migration manifest is invalid")
    return ReleaseArtifact(
        wheel_reference,
        manifest_reference,
        wheel_hash,
        names,
    )


def verify_release_artifact(
    wheel: Path, manifest: Path, *, allow_known_historical: bool = False
) -> ReleaseArtifact:
    """Verify path-bound release inputs and complete wheel metadata."""
    for path in (wheel, manifest):
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or path.is_symlink():
            raise ValueError("release inputs must be regular non-symlink files")
    return _verify_release_bytes(
        wheel.read_bytes(),
        manifest.read_bytes(),
        artifact_filename=wheel.name,
        wheel_reference=wheel,
        manifest_reference=manifest,
        allow_known_historical=allow_known_historical,
    )


def _descriptor_bytes(descriptor: int, limit: int) -> tuple[bytes, os.stat_result]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= limit:
        raise ValueError("release descriptor is not a bounded regular file")
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(descriptor, min(65536, before.st_size - offset), offset)
        if not chunk:
            raise ValueError("release descriptor ended before its pinned size")
        chunks.append(chunk)
        offset += len(chunk)
    after = os.fstat(descriptor)
    identity = lambda details: (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_uid,
        details.st_gid,
        details.st_nlink,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )
    if identity(before) != identity(after):
        raise ValueError("release descriptor identity changed while reading")
    return b"".join(chunks), before


def verify_release_descriptors(
    wheel_descriptor: int,
    manifest_descriptor: int,
    *,
    artifact_filename: str,
) -> ReleaseArtifact:
    """Verify immutable bytes through already-open descriptor identities."""
    wheel_bytes, _ = _descriptor_bytes(wheel_descriptor, _MAX_WHEEL_BYTES)
    manifest_bytes, _ = _descriptor_bytes(manifest_descriptor, _MAX_MANIFEST_BYTES)
    return _verify_release_bytes(
        wheel_bytes,
        manifest_bytes,
        artifact_filename=artifact_filename,
        wheel_reference=Path(f"/dev/fd/{wheel_descriptor}"),
        manifest_reference=Path(f"/dev/fd/{manifest_descriptor}"),
    )
