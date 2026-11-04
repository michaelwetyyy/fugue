"""Explicit, foreground entry point for the isolated Rig daemon."""

from __future__ import annotations

import argparse
import signal
import stat
from pathlib import Path

from oc_rig.daemon.identity import ServiceIdentityPolicy
from oc_rig.daemon.security import PrivateSocketPath
from oc_rig.daemon.server import (
    PinnedExecutable,
    RigdChildArtifact,
    RigDaemon,
)
from oc_rig.store import PrivateRuntimeDirectory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rigd")
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--approved-root", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--service-uid", type=int, required=True)
    parser.add_argument("--allow-client-uid", type=int, action="append", required=True)
    parser.add_argument("--client-gid", type=int, required=True)
    parser.add_argument("--child-artifact-root", type=Path, required=True)
    for name in ("bootstrap", "helper", "interpreter"):
        parser.add_argument(f"--child-{name}", type=Path, required=True)
        parser.add_argument(f"--child-{name}-digest", required=True)
        parser.add_argument(f"--child-{name}-device", type=int, required=True)
        parser.add_argument(f"--child-{name}-inode", type=int, required=True)
        parser.add_argument(f"--child-{name}-size", type=int, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    bootstrap_details = args.child_bootstrap.lstat()
    helper_details = args.child_helper.lstat()
    interpreter_details = args.child_interpreter.lstat()
    artifact = RigdChildArtifact(
        args.child_artifact_root,
        PinnedExecutable(
            args.child_bootstrap,
            args.child_bootstrap_digest,
            args.child_bootstrap_device,
            args.child_bootstrap_inode,
            bootstrap_details.st_uid,
            stat.S_IMODE(bootstrap_details.st_mode),
            args.child_bootstrap_size,
        ),
        PinnedExecutable(
            args.child_helper,
            args.child_helper_digest,
            args.child_helper_device,
            args.child_helper_inode,
            helper_details.st_uid,
            stat.S_IMODE(helper_details.st_mode),
            args.child_helper_size,
        ),
        PinnedExecutable(
            args.child_interpreter,
            args.child_interpreter_digest,
            args.child_interpreter_device,
            args.child_interpreter_inode,
            interpreter_details.st_uid,
            stat.S_IMODE(interpreter_details.st_mode),
            args.child_interpreter_size,
        ),
    )
    daemon = RigDaemon(
        PrivateSocketPath(args.socket, args.approved_root),
        runtime=PrivateRuntimeDirectory(args.state, args.approved_root),
        identity_policy=ServiceIdentityPolicy(
            args.service_uid,
            frozenset(args.allow_client_uid),
            args.client_gid,
        ),
        child_artifact=artifact,
    )

    def stop(_signum: int, _frame: object) -> None:
        daemon.shutdown()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    daemon.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
