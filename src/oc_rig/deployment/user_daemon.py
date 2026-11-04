"""Foreground rigd entry point for the explicit single-user launchd profile."""

from __future__ import annotations

import argparse
import os
import signal
from pathlib import Path

from oc_rig.adapters.opencode import LiveOpenCodeAdapterConfig
from oc_rig.completion.codex_callback import CodexQueueConfig
from oc_rig.daemon.identity import LocalUserIdentityPolicy
from oc_rig.daemon.security import PrivateSocketPath
from oc_rig.daemon.server import _DurableChildDaemon
from oc_rig.deployment.user import (
    validated_daemon_paths,
    validated_opencode_configuration,
)
from oc_rig.store.runtime import PrivateRuntimeDirectory


def main() -> int:
    parser = argparse.ArgumentParser(prog="rigd-local-user")
    parser.add_argument("--deployment-root", type=Path, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--opencode-config-id")
    parser.add_argument("--opencode-endpoint")
    parser.add_argument("--opencode-auth", type=Path)
    parser.add_argument("--opencode-topology", type=Path)
    parser.add_argument("--opencode-trust", type=Path)
    parser.add_argument("--codex-executable", type=Path)
    parser.add_argument("--codex-user-home", type=Path)
    parser.add_argument("--codex-home", type=Path)
    parser.add_argument("--codex-callback-timeout", type=float, default=15.0)
    args = parser.parse_args()
    paths = validated_daemon_paths(
        args.deployment_root,
        expected_release=args.release_id,
    )
    expected_environment = {
        "HOME": str(paths.home),
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1",
    }
    if dict(os.environ) != expected_environment:
        raise RuntimeError("local-user rigd environment is not isolated")
    live_values = (
        args.opencode_config_id,
        args.opencode_endpoint,
        args.opencode_auth,
        args.opencode_topology,
        args.opencode_trust,
    )
    if any(value is not None for value in live_values) and not all(
        value is not None for value in live_values
    ):
        raise RuntimeError("OpenCode launch arguments must be complete")
    adapter_config = None
    if all(value is not None for value in live_values):
        selected = validated_opencode_configuration(
            args.deployment_root,
            expected_release=args.release_id,
            expected_config_id=args.opencode_config_id,
        )
        if (
            selected.endpoint != args.opencode_endpoint
            or selected.auth != args.opencode_auth
            or selected.topology != args.opencode_topology
            or selected.trust != args.opencode_trust
        ):
            raise RuntimeError("OpenCode launch arguments do not match deployment state")
        adapter_config = LiveOpenCodeAdapterConfig.from_explicit_files(
            endpoint=selected.endpoint,
            auth_path=selected.auth,
            topology_path=selected.topology,
            trust_path=selected.trust,
        )
    callback_values = (
        args.codex_executable,
        args.codex_user_home,
        args.codex_home,
    )
    if any(value is not None for value in callback_values) and not all(
        value is not None for value in callback_values
    ):
        raise RuntimeError("Codex callback launch arguments must be complete")
    callback_config = None
    if all(value is not None for value in callback_values):
        if adapter_config is None:
            raise RuntimeError("Codex callbacks require configured OpenCode")
        callback_config = CodexQueueConfig(
            args.codex_executable,
            args.codex_user_home,
            args.codex_home,
            args.codex_callback_timeout,
        )
    daemon = _DurableChildDaemon(
        PrivateSocketPath(paths.socket, paths.socket_root),
        runtime=PrivateRuntimeDirectory(paths.state, paths.runtime_root),
        identity_policy=LocalUserIdentityPolicy(os.geteuid(), os.getegid()),
        adapter_config=adapter_config,
        callback_config=callback_config,
    )

    def stop(_signum: int, _frame: object) -> None:
        daemon.shutdown()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    daemon.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
