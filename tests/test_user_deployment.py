from __future__ import annotations

import base64
import copy
import errno
import fcntl
import hashlib
import json
import os
import plistlib
import pty
import signal
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from contextlib import closing
from unittest.mock import patch
import oc_rig.deployment.user as user_deployment_module

from oc_rig.daemon.identity import (
    LocalUserIdentityPolicy,
    OsIdentityProbe,
    ServiceIdentityError,
    validate_local_user_topology,
)
from oc_rig.completion.models import CompletionOutcome
from oc_rig.completion.service import _create_completion
from oc_rig.daemon.security import PrivateSocketPath, SocketSecurityError
from oc_rig.daemon.server import _DurableChildDaemon
from oc_rig.deployment.user import (
    CODEX_CALLBACK_CONFIG_FORMAT,
    OPENCODE_CONFIG_FORMAT,
    PIN_FORMAT,
    DeploymentError,
    UserDeployment,
    _codex_executable_pin,
    _controlled_runtime_identity,
    _native_volume_uuid,
    _runtime_pin_matches,
    _stable_codex_executable_pin,
)
from oc_rig.protocol.client import RigClient
from oc_rig.opencode_authority import (
    REVIEW_AGENT_NAME,
    generated_agent_markdown,
)
from oc_rig.terminal_lifecycle import ProcessIdentity, TerminalLifecycle
from oc_rig.store import RigStore
from oc_rig.store.database import _DaemonAuthority
from oc_rig.store.runtime import PrivateRuntimeDirectory
from tests.test_live_opencode_adapter import (
    BackendState,
    FakeServer,
    message_info,
    topology,
)


REPOSITORY = Path(__file__).resolve().parents[1]
_TEST_PYTHON_OVERRIDE = os.environ.get("FUGUE_TEST_PYTHON")
if _TEST_PYTHON_OVERRIDE and not Path(_TEST_PYTHON_OVERRIDE).is_absolute():
    raise ValueError("FUGUE_TEST_PYTHON must name an absolute interpreter path")
TEST_PYTHON = Path(_TEST_PYTHON_OVERRIDE or sys.executable).resolve()


class UserDeploymentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=Path.home(), prefix="r2-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.home = self.base / "home"
        self.home.mkdir(mode=0o700)
        self.root = self.base / "oc-rig-v2"
        self.plist = self.home / "Library" / "LaunchAgents" / "agent.plist"
        self.launch_state = self.base / "launch-state.json"
        self.launch_log = self.base / "launch-log.jsonl"
        self.launchctl = self.base / "launchctl"
        launchctl_source = """#!/usr/bin/env python3
import json, plistlib, sys
from pathlib import Path
state_path = Path(@STATE@)
log_path = Path(@LOG@)
with log_path.open("a") as output:
    output.write(json.dumps(sys.argv[1:]) + "\\n")
state = json.loads(state_path.read_text()) if state_path.exists() else {"loaded": False, "running": False}
command = sys.argv[1]
if command == "print":
    if state.get("print_error"):
        print("permission denied", file=sys.stderr)
        raise SystemExit(5)
    if not state["loaded"]:
        raise SystemExit(113)
    print("\tstate = " + state.get("detail", ("running" if state["running"] else "waiting")))
    for nested_state in state.get("nested_states", []):
        print("\t\tstate = " + nested_state)
    if state["running"] or state.get("pid") is not None:
        print("pid = " + str(state.get("pid", 4242)))
    print("path = " + state["path"])
    print("program = " + state["program"])
    print("arguments = {")
    for argument in state["arguments"]:
        print("    " + argument)
    print("}")
elif command == "bootstrap":
    if state["loaded"]:
        raise SystemExit(37)
    plist_path = Path(sys.argv[3])
    if state.get("replace_plist_on_bootstrap"):
        plist_path.unlink()
        plist_path.write_bytes(b"foreign plist replacement")
        plist_path.chmod(0o600)
        raise SystemExit(5)
    if state.get("bootstrap_error"):
        raise SystemExit(5)
    if state.get("foreign_job_on_bootstrap"):
        state = {"arguments": ["/private/tmp/foreign"], "loaded": True,
                 "path": "/private/tmp/foreign.plist",
                 "program": "/private/tmp/foreign", "running": False}
        state_path.write_text(json.dumps(state))
        raise SystemExit(37)
    plist = plistlib.loads(plist_path.read_bytes())
    state = {"arguments": plist["ProgramArguments"], "loaded": True,
             "path": str(plist_path), "program": plist["ProgramArguments"][0],
             "running": False}
elif command == "kickstart":
    if not state["loaded"]:
        raise SystemExit(3)
    state["running"] = True
elif command == "kill":
    state["running"] = False
    state["detail"] = "waiting"
    state.pop("pid", None)
elif command == "bootout":
    state = {"loaded": False, "running": False}
else:
    raise SystemExit(64)
state_path.write_text(json.dumps(state))
"""
        self.launchctl.write_text(
            launchctl_source.replace("@STATE@", repr(str(self.launch_state))).replace(
                "@LOG@", repr(str(self.launch_log))
            ),
            encoding="utf-8",
        )
        self.launchctl.chmod(0o755)

    def _set_job_running(self, running: bool) -> None:
        state = json.loads(self.launch_state.read_text(encoding="utf-8"))
        state["running"] = running
        self.launch_state.write_text(json.dumps(state), encoding="utf-8")

    def deployment(self, *, dry_run: bool = False) -> UserDeployment:
        return UserDeployment(
            self.root,
            self.home,
            self.plist,
            self.launchctl,
            TEST_PYTHON,
            dry_run=dry_run,
        )

    def _callback_refresh_fixture(self) -> tuple[Path, Path, Path]:
        self.deployment().install(REPOSITORY)
        password = self.base / "refresh.password"
        topology_path = self.base / "refresh.topology.json"
        trust_path = self.base / "refresh.trust.json"
        password.write_text("private-refresh-password-material", encoding="utf-8")
        topology_path.write_text(json.dumps(topology()), encoding="utf-8")
        trust_path.write_text(json.dumps({"mode": "secure", "secure_worker": "secure-worker"}), encoding="utf-8")
        for path in (password, topology_path, trust_path):
            path.chmod(0o600)
        with closing(socket.socket()) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        self.deployment().configure_opencode(endpoint=f"http://127.0.0.1:{port}", basic_username="opencode", basic_password_file=password, topology_file=topology_path, trust_file=trust_path)
        executable = self.base / "codex-reviewed"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)
        codex_home = self.base / "codex-home"
        codex_home.mkdir(mode=0o700)
        self.deployment().configure_codex_callback(executable=executable, home=self.home, codex_home=codex_home)
        ownership = self.base / "ownership.json"
        stopped = {"backend": None, "backend_owned": False, "completed_cutover": None, "controller_owned": False, "controller_pid": None, "controller_starting": False, "cutover_intent": None, "format": 1, "invocation_id": "a" * 32, "phase": "stopped", "reason": "operator closed", "tmux_nonce": None, "tmux_session_id": None}
        ownership.write_text(json.dumps(stopped, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        ownership.chmod(0o600)
        tmux = self.base / "tmux"
        tmux.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        tmux.chmod(0o700)
        return executable, ownership, tmux

    def _second_source(self) -> Path:
        source = self.base / "second-source"
        shutil.copytree(REPOSITORY / "src", source / "src")
        shutil.copy2(REPOSITORY / "LICENSE", source / "LICENSE")
        initializer = source / "src" / "oc_rig" / "__init__.py"
        initializer.write_text(
            initializer.read_text(encoding="utf-8").replace(
                '0.1.0.dev0', '0.1.0.dev1'
            ),
            encoding="utf-8",
        )
        return source

    def _old_policy_current_layout_fixture(self) -> tuple[str, str, Path]:
        self.deployment().install(REPOSITORY)
        password = self.base / "policy-refresh.password"
        topology_path = self.base / "policy-refresh.topology.json"
        trust_path = self.base / "policy-refresh.trust.json"
        password.write_text("private-policy-refresh-password", encoding="utf-8")
        topology_path.write_text(json.dumps(topology()), encoding="utf-8")
        trust_path.write_text(
            json.dumps({"mode": "secure", "secure_worker": "secure-worker"}),
            encoding="utf-8",
        )
        for path in (password, topology_path, trust_path):
            path.chmod(0o600)
        configured = self.deployment().configure_opencode(
            endpoint="http://127.0.0.1:4096",
            basic_username="opencode",
            basic_password_file=password,
            topology_file=topology_path,
            trust_file=trust_path,
        )
        current_id = configured["config_id"]
        current = self.root / "config/opencode" / current_id
        old_policy = copy.deepcopy(user_deployment_module._AUTOMATED_BACKEND_POLICY)
        for name in ("build", "explore", "general", "plan"):
            del old_policy["agent"][name]
        old_policy.pop("command")
        old_policy.pop("mode")
        files = {
            name: (current / name).read_bytes()
            for name in ("auth.json", "topology.json", "trust.json")
        }
        files.update(
            {
                "provider-auth-seed.json": b"{}\n",
                "automated-backend-policy.json": json.dumps(
                    old_policy, sort_keys=True, separators=(",", ":")
                ).encode() + b"\n",
            }
        )
        old_id = user_deployment_module._opencode_config_id(
            "http://127.0.0.1:4096", files
        )
        old = current.parent / old_id
        old.mkdir(mode=0o700)
        for name, data in files.items():
            path = old / name
            path.write_bytes(data)
            path.chmod(user_deployment_module._opencode_file_mode(name))
        state_path = self.root / "deployment-state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["opencode"] = {
            "config_id": old_id,
            "endpoint": "http://127.0.0.1:4096",
            "files": {
                name: user_deployment_module._config_file_pin(old / name, data)
                for name, data in files.items()
            },
            "format": user_deployment_module.OPENCODE_CONFIG_FORMAT,
        }
        state_path.write_text(
            json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        state_path.chmod(0o600)
        shutil.rmtree(current)
        return old_id, current_id, old

    def _previous_contaminated_opencode_fixture(
        self,
    ) -> tuple[Path, Path, Path, Path, str]:
        self.deployment().install(REPOSITORY)
        password = self.base / "previous.password"
        topology_path = self.base / "previous.topology.json"
        trust_path = self.base / "previous.trust.json"
        password.write_text("private-basic-password-material", encoding="utf-8")
        topology_path.write_text(json.dumps(topology()), encoding="utf-8")
        trust_path.write_text(
            json.dumps({"mode": "secure", "secure_worker": "secure-worker"}),
            encoding="utf-8",
        )
        for path in (password, topology_path, trust_path):
            path.chmod(0o600)
        configured = self.deployment().configure_opencode(
            endpoint="http://127.0.0.1:4096",
            basic_username="opencode",
            basic_password_file=password,
            topology_file=topology_path,
            trust_file=trust_path,
        )
        generation = self.root / "config/opencode" / configured["config_id"]
        (generation / "automated-backend-policy.json").unlink()
        for name, data in user_deployment_module._POLLUTED_SELECTED_BACKEND_FILES.items():
            path = generation / name
            if path.exists():
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o600)
        for directory in (generation / "xdg", generation / "xdg/opencode", generation / "xdg/opencode/agents"):
            directory.chmod(0o700)
        (generation / "provider-auth-seed.json").unlink()
        legacy_gitignore = generation / "xdg/opencode/.gitignore"
        legacy_gitignore.write_bytes(
            user_deployment_module._LEGACY_DISCARD_FILES[
                "xdg/opencode/.gitignore"
            ]
        )
        legacy_gitignore.chmod(0o644)
        runtime = generation / "xdg-data/opencode"
        runtime.mkdir(parents=True, mode=0o700)
        for directory in (generation / "xdg-data", runtime):
            directory.chmod(0o700)
        for name, data in (
            ("auth.json", b"{}\n"),
            ("opencode.db", b"runtime database"),
            ("opencode.db-shm", b"runtime shm"),
            ("opencode.db-wal", b"runtime wal"),
        ):
            (runtime / name).write_bytes(data)
            (runtime / name).chmod(0o600 if name == "auth.json" else 0o644)
        for directory in (runtime / "log", runtime / "repos"):
            directory.mkdir(mode=0o755)
        (runtime / "log/server.log").write_text("runtime log", encoding="utf-8")
        (runtime / "log/server.log").chmod(0o644)
        (runtime / "repos/repository.json").write_text("{}\n", encoding="utf-8")
        (runtime / "repos/repository.json").chmod(0o644)

        state_path = self.root / "deployment-state.json"
        state = json.loads(state_path.read_text())
        pinned_names = {
            "auth.json", "topology.json", "trust.json",
            "xdg/opencode/opencode.json",
            "xdg/opencode/agents/rig-read-only-review.md",
            "xdg/opencode/agents/secure-worker.md",
            "xdg-data/opencode/auth.json",
        }
        prior_backend = generation / "xdg/opencode/opencode.json"
        prior_backend.write_bytes(user_deployment_module._PRIOR_BACKEND_CONFIG)
        prior_backend.chmod(0o600)
        pinned_contents = {
            name: (generation / name).read_bytes() for name in pinned_names
        }
        previous_id = user_deployment_module._opencode_config_id(
            state["opencode"]["endpoint"], pinned_contents
        )
        previous_generation = generation.with_name(previous_id)
        generation.rename(previous_generation)
        state["opencode"]["config_id"] = previous_id
        state["opencode"]["files"] = {
            name: user_deployment_module._config_file_pin(
                previous_generation / name, data
            )
            for name, data in pinned_contents.items()
        }
        state_path.write_text(
            json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        state_path.chmod(0o600)
        reconciled_backend = previous_generation / "xdg/opencode/opencode.json"
        reconciled_backend.write_bytes(user_deployment_module._BACKEND_CONFIG)
        reconciled_backend.chmod(0o600)
        return password, topology_path, trust_path, previous_generation, previous_id

    def _prior_current_gitignore_contamination_fixture(
        self,
    ) -> tuple[Path, Path, Path, Path, str]:
        self.deployment().install(REPOSITORY)
        password = self.base / "prior-current.password"
        topology_path = self.base / "prior-current.topology.json"
        trust_path = self.base / "prior-current.trust.json"
        password.write_text("private-basic-password-material", encoding="utf-8")
        topology_path.write_text(json.dumps(topology()), encoding="utf-8")
        trust_path.write_text(
            json.dumps({"mode": "secure", "secure_worker": "secure-worker"}),
            encoding="utf-8",
        )
        for path in (password, topology_path, trust_path):
            path.chmod(0o600)
        configured = self.deployment().configure_opencode(
            endpoint="http://127.0.0.1:4096",
            basic_username="opencode",
            basic_password_file=password,
            topology_file=topology_path,
            trust_file=trust_path,
        )
        generation = self.root / "config/opencode" / configured["config_id"]
        (generation / "automated-backend-policy.json").unlink()
        for name, data in user_deployment_module._POLLUTED_SELECTED_BACKEND_FILES.items():
            path = generation / name
            if path.exists():
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o600)
        for directory in (generation / "xdg", generation / "xdg/opencode", generation / "xdg/opencode/agents"):
            directory.chmod(0o700)
        state_path = self.root / "deployment-state.json"
        state = json.loads(state_path.read_text())
        prior_backend = generation / "xdg/opencode/opencode.json"
        prior_backend.write_bytes(user_deployment_module._PRIOR_BACKEND_CONFIG)
        prior_backend.chmod(0o600)
        prior_names = {
            "auth.json", "topology.json", "trust.json",
            *user_deployment_module._PRIOR_CURRENT_BACKEND_FILES,
        }
        prior_contents = {
            name: (generation / name).read_bytes() for name in prior_names
        }
        prior_id = user_deployment_module._opencode_config_id(
            state["opencode"]["endpoint"], prior_contents
        )
        prior_generation = generation.with_name(prior_id)
        generation.rename(prior_generation)
        state["opencode"]["config_id"] = prior_id
        state["opencode"]["files"] = {
            name: user_deployment_module._config_file_pin(
                prior_generation / name, data
            )
            for name, data in prior_contents.items()
        }
        generated_gitignore = prior_generation / "xdg/opencode/.gitignore"
        generated_gitignore.chmod(0o644)
        (prior_generation / "xdg/opencode/opencode.json").write_bytes(
            user_deployment_module._BACKEND_CONFIG
        )
        (prior_generation / "xdg/opencode/opencode.json").chmod(0o600)
        state_path.write_text(
            json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        state_path.chmod(0o600)
        return password, topology_path, trust_path, prior_generation, prior_id

    def _polluted_selected_generation_fixture(self) -> tuple[Path, str]:
        self.deployment().install(REPOSITORY)
        password = self.base / "polluted.password"
        topology_path = self.base / "polluted.topology.json"
        trust_path = self.base / "polluted.trust.json"
        password.write_text("private-basic-password-material", encoding="utf-8")
        topology_path.write_text(json.dumps(topology()), encoding="utf-8")
        trust_path.write_text(
            json.dumps({"mode": "secure", "secure_worker": "secure-worker"}),
            encoding="utf-8",
        )
        for path in (password, topology_path, trust_path):
            path.chmod(0o600)
        configured = self.deployment().configure_opencode(
            endpoint="http://127.0.0.1:4096", basic_username="opencode",
            basic_password_file=password, topology_file=topology_path,
            trust_file=trust_path,
        )
        generation = self.root / "config/opencode" / configured["config_id"]
        (generation / "automated-backend-policy.json").unlink()
        for name, data in user_deployment_module._POLLUTED_SELECTED_BACKEND_FILES.items():
            path = generation / name
            if not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(0o600)
        for directory in (generation / "xdg", generation / "xdg/opencode", generation / "xdg/opencode/agents"):
            directory.chmod(0o700)
        state_path = self.root / "deployment-state.json"
        state = json.loads(state_path.read_text())
        names = {"auth.json", "topology.json", "trust.json", *user_deployment_module._POLLUTED_SELECTED_BACKEND_FILES}
        contents = {name: (generation / name).read_bytes() for name in names}
        old_id = user_deployment_module._opencode_config_id(
            state["opencode"]["endpoint"], contents
        )
        old_generation = generation.with_name(old_id)
        generation.rename(old_generation)
        state["opencode"]["config_id"] = old_id
        state["opencode"]["files"] = {
            name: user_deployment_module._config_file_pin(old_generation / name, data)
            for name, data in contents.items()
        }
        state_path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        state_path.chmod(0o600)
        bootstrap = old_generation / "xdg/opencode"
        (bootstrap / "package.json").write_text("{}\n", encoding="utf-8")
        (bootstrap / "package.json").chmod(0o644)
        modules = bootstrap / "node_modules"
        modules.mkdir(mode=0o755)
        (modules / "package.txt").write_text("runtime\n", encoding="utf-8")
        (modules / "package.txt").chmod(0o644)
        package_bin = modules / "package" / "bin"
        package_bin.mkdir(parents=True, mode=0o755)
        (modules / "package").chmod(0o755)
        (package_bin / "tool").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (package_bin / "tool").chmod(0o755)
        (modules / "package/native.node").write_bytes(b"native package payload")
        (modules / "package/native.node").chmod(0o755)
        links = modules / ".bin"
        links.mkdir(mode=0o755)
        (links / "package-tool").symlink_to("../package.txt")
        return old_generation, old_id

    def test_generated_agents_share_one_canonical_authority(self) -> None:
        self.assertEqual(
            user_deployment_module._REVIEW_AGENT,
            generated_agent_markdown(REVIEW_AGENT_NAME),
        )
        self.assertEqual(
            user_deployment_module._SECURE_AGENT,
            generated_agent_markdown("secure-worker"),
        )
        self.assertEqual(
            user_deployment_module._CHILD_AGENT,
            generated_agent_markdown("fugue-child"),
        )
        policy = user_deployment_module._AUTOMATED_BACKEND_POLICY["agent"]
        self.assertEqual(
            policy["secure-worker"]["prompt"],
            user_deployment_module.SECURE_AGENT_PROMPT,
        )
        self.assertEqual(
            policy["fugue-child"]["permission"],
            {"*": "deny", "task": "allow"},
        )

    def test_install_builds_pinned_release_and_does_not_start(self) -> None:
        result = self.deployment().install(REPOSITORY)
        release = self.root / "releases" / result["current"]
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(release.stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE((release / "release-pin.json").stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE((self.root / "runtime" / "state").stat().st_mode), 0o700)
        self.assertEqual(
            stat.S_IMODE((self.root / "runtime" / "state" / "rig.sqlite3").stat().st_mode),
            0o600,
        )
        state = json.loads(self.launch_state.read_text(encoding="utf-8"))
        self.assertTrue(state["loaded"])
        self.assertFalse(state["running"])
        plist = plistlib.loads(self.plist.read_bytes())
        self.assertFalse(plist["RunAtLoad"])
        self.assertFalse(plist["KeepAlive"])
        self.assertNotIn("EnvironmentVariables", plist)
        self.assertNotIn("sudo", " ".join(plist["ProgramArguments"]))
        self.assertEqual(plist["ProgramArguments"][1:4], ["-I", "-S", "-B"])
        self.assertNotIn(str(self.home), plist["ProgramArguments"])
        dedicated_home = self.root / "runtime" / "home"
        self.assertEqual(stat.S_IMODE(dedicated_home.stat().st_mode), 0o700)
        self.assertEqual(list(dedicated_home.iterdir()), [])
        pin = json.loads((release / "release-pin.json").read_text(encoding="utf-8"))
        self.assertEqual(pin["format"], PIN_FORMAT)
        self.assertTrue(pin["runtime"]["controlled"])
        self.assertTrue(
            all(
                "device" not in item and "volume_uuid" in item
                for item in pin["runtime"]["controlled"]
                if item["kind"] != "missing"
            )
        )
        directories = [
            item for item in pin["runtime"]["controlled"] if item["kind"] == "directory"
        ]
        files = [
            item for item in pin["runtime"]["controlled"] if item["kind"] == "file"
        ]
        self.assertTrue(directories)
        self.assertTrue(files)
        self.assertTrue(any("ctime_ns" not in item for item in directories))
        self.assertTrue(any("ctime_ns" in item for item in directories))
        self.assertTrue(all("links" not in item for item in directories))
        self.assertTrue(all("ctime_ns" in item and "links" in item for item in files))
        self.assertTrue(
            all("site-packages" not in entry for entry in pin["runtime"]["sys_path"])
        )

    def test_runtime_pin_accepts_device_renumbering_but_rejects_volume_change(self) -> None:
        controlled = self.base / "controlled-runtime"
        controlled.mkdir(mode=0o700)
        expected = _controlled_runtime_identity(controlled)
        real_lstat = Path.lstat

        class RemountedStat:
            def __init__(self, original: os.stat_result):
                self._original = original
                self.st_dev = original.st_dev + 3

            def __getattr__(self, name: str) -> object:
                return getattr(self._original, name)

        def remounted_lstat(path: Path) -> os.stat_result | RemountedStat:
            details = real_lstat(path)
            if path == controlled:
                return RemountedStat(details)
            return details

        with patch.object(Path, "lstat", remounted_lstat):
            remounted = _controlled_runtime_identity(controlled)
        self.assertEqual(remounted, expected)
        self.assertNotIn("device", remounted)

        changed_uuid = "00000000-0000-4000-8000-000000000001"
        with patch(
            "oc_rig.deployment.user._native_volume_uuid",
            return_value=changed_uuid,
        ):
            moved = _controlled_runtime_identity(controlled)
        self.assertNotEqual(moved, expected)
        self.assertEqual(moved["volume_uuid"], changed_uuid)

    def test_runtime_pin_allows_only_sealed_root_volume_rotation(self) -> None:
        python = TEST_PYTHON
        actual = user_deployment_module._interpreter_runtime(python)
        expected = json.loads(json.dumps(actual))
        root = next(item for item in expected["controlled"] if item["path"] == "/")
        root["volume_uuid"] = "00000000-0000-4000-8000-000000000001"
        self.assertTrue(_runtime_pin_matches(expected, actual))
        with patch.object(user_deployment_module.sys, "platform", "linux"):
            self.assertFalse(_runtime_pin_matches(expected, actual))

        changed_file = json.loads(json.dumps(expected))
        tracked = next(
            item for item in changed_file["controlled"] if item["kind"] == "file"
        )
        tracked["volume_uuid"] = "00000000-0000-4000-8000-000000000002"
        self.assertFalse(_runtime_pin_matches(changed_file, actual))

        changed_root_mode = json.loads(json.dumps(expected))
        next(
            item for item in changed_root_mode["controlled"] if item["path"] == "/"
        )["mode"] = 0o700
        self.assertFalse(_runtime_pin_matches(changed_root_mode, actual))

    def test_stopped_install_accepts_only_root_volume_rotation(self) -> None:
        installed = self.deployment().install(REPOSITORY)
        pin_path = (
            self.root / "releases" / installed["current"] / "release-pin.json"
        )
        pin = json.loads(pin_path.read_text(encoding="utf-8"))
        root = next(
            item for item in pin["runtime"]["controlled"] if item["path"] == "/"
        )
        root["volume_uuid"] = "00000000-0000-4000-8000-000000000001"
        pin_path.chmod(0o600)
        pin_path.write_text(
            json.dumps(pin, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        pin_path.chmod(0o400)

        repeated = self.deployment().install(REPOSITORY)

        self.assertEqual(repeated["current"], installed["current"])
        self.assertFalse(repeated["dry_run"])

    def test_runtime_directory_entry_churn_is_not_an_identity_change(self) -> None:
        controlled = self.base / "controlled-runtime"
        controlled.mkdir(mode=0o700)
        tracked_before = _controlled_runtime_identity(controlled)
        before = _controlled_runtime_identity(
            controlled,
            track_directory_entries=False,
        )
        transient = controlled / "ordinary-entry"
        transient.write_bytes(b"short lived")
        transient.unlink()
        self.assertNotEqual(controlled.stat().st_ctime_ns, 0)
        self.assertNotEqual(_controlled_runtime_identity(controlled), tracked_before)
        self.assertEqual(
            _controlled_runtime_identity(
                controlled,
                track_directory_entries=False,
            ),
            before,
        )

    def test_runtime_directory_security_identity_drift_still_fails_closed(self) -> None:
        controlled = self.base / "controlled-runtime"
        controlled.mkdir(mode=0o700)
        expected = _controlled_runtime_identity(
            controlled,
            track_directory_entries=False,
        )

        controlled.chmod(0o500)
        self.assertNotEqual(
            _controlled_runtime_identity(
                controlled,
                track_directory_entries=False,
            ),
            expected,
        )
        controlled.chmod(0o700)

        displaced = self.base / "controlled-runtime-old"
        controlled.rename(displaced)
        controlled.mkdir(mode=0o700)
        self.assertNotEqual(
            _controlled_runtime_identity(
                controlled,
                track_directory_entries=False,
            ),
            expected,
        )

        controlled.rmdir()
        controlled.symlink_to(displaced, target_is_directory=True)
        with self.assertRaisesRegex(DeploymentError, "symlink"):
            _controlled_runtime_identity(controlled)

        controlled.unlink()
        displaced.rename(controlled)
        with patch("oc_rig.deployment.user.os.geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(DeploymentError, "root/user-owned"):
                _controlled_runtime_identity(controlled)

    @unittest.skipUnless(sys.platform == "darwin", "macOS ACL pinning")
    def test_runtime_directory_write_acl_is_rejected(self) -> None:
        controlled = self.base / "controlled-runtime"
        controlled.mkdir(mode=0o700)
        listing = "drwx------  2 owner  staff  64 29 Aug 00:00 path\n 0: user:guest allow write\n"
        with (
            patch(
                "oc_rig.deployment.user._has_extended_acl",
                return_value=True,
            ),
            patch(
                "oc_rig.deployment.user.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=["/bin/ls"], returncode=0, stdout=listing, stderr=""
                ),
            ),
        ):
            with self.assertRaisesRegex(DeploymentError, "ACL grants write"):
                _controlled_runtime_identity(controlled)

    def test_first_install_failure_leaves_no_partial_layout_and_retry_succeeds(self) -> None:
        with patch(
            "oc_rig.deployment.user.build_release_artifact",
            side_effect=ValueError("malformed source"),
        ):
            with self.assertRaises(ValueError):
                self.deployment().install(REPOSITORY)
        self.assertFalse(self.root.exists())
        self.assertFalse(self.plist.exists())
        self.assertEqual(
            [entry for entry in self.root.parent.iterdir() if ".install-" in entry.name],
            [],
        )
        self.root.mkdir(mode=0o700)
        with patch(
            "oc_rig.deployment.user.build_release_artifact",
            side_effect=ValueError("malformed source"),
        ):
            with self.assertRaises(ValueError):
                self.deployment().install(REPOSITORY)
        self.assertTrue(self.root.is_dir())
        self.assertEqual(list(self.root.iterdir()), [])
        result = self.deployment().install(REPOSITORY)
        self.assertTrue((self.root / "releases" / result["current"]).is_dir())

    def test_initial_publish_failure_preserves_empty_root_inode(self) -> None:
        self.root.mkdir(mode=0o700)
        root_identity = (self.root.stat().st_dev, self.root.stat().st_ino)
        real_replace = os.replace

        def fail_internal_publish(source: os.PathLike[str], target: os.PathLike[str]) -> None:
            destination = Path(target)
            if destination.parent == self.root and destination.name == "runtime":
                raise OSError("injected internal publish failure")
            real_replace(source, target)

        with patch("oc_rig.deployment.user.os.replace", side_effect=fail_internal_publish):
            with self.assertRaisesRegex(OSError, "injected internal publish failure"):
                self.deployment().install(REPOSITORY)
        self.assertEqual(
            (self.root.stat().st_dev, self.root.stat().st_ino),
            root_identity,
        )
        self.assertEqual(list(self.root.iterdir()), [])

    def test_initial_install_preflights_foreign_label_and_prior_plist(self) -> None:
        foreign = {
            "arguments": ["/private/tmp/foreign"],
            "loaded": True,
            "path": "/private/tmp/foreign.plist",
            "program": "/private/tmp/foreign",
            "running": False,
        }
        self.launch_state.write_text(json.dumps(foreign), encoding="utf-8")
        with patch("oc_rig.deployment.user.build_release_artifact") as build:
            with self.assertRaisesRegex(DeploymentError, "label is occupied"):
                self.deployment().install(REPOSITORY)
        build.assert_not_called()
        self.assertFalse(self.root.exists())
        self.assertEqual(
            json.loads(self.launch_state.read_text(encoding="utf-8")),
            foreign,
        )

        self.launch_state.write_text(
            json.dumps({"loaded": False, "running": False}),
            encoding="utf-8",
        )
        self.plist.parent.mkdir(mode=0o700, parents=True)
        self.plist.write_bytes(b"prior unmanaged plist")
        self.plist.chmod(0o600)
        prior_identity = (self.plist.stat().st_dev, self.plist.stat().st_ino)
        with patch("oc_rig.deployment.user.build_release_artifact") as build:
            with self.assertRaisesRegex(DeploymentError, "plist exists"):
                self.deployment().install(REPOSITORY)
        build.assert_not_called()
        self.assertEqual(self.plist.read_bytes(), b"prior unmanaged plist")
        self.assertEqual(
            (self.plist.stat().st_dev, self.plist.stat().st_ino),
            prior_identity,
        )
        self.assertFalse(self.root.exists())

    def test_initial_install_rechecks_foreign_state_before_exclusive_plist(self) -> None:
        deployment = self.deployment()
        publish = deployment._publish_initial

        def publish_then_add_plist(source_root: Path):
            publication = publish(source_root)
            self.plist.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.plist.write_bytes(b"foreign plist after initial preflight")
            self.plist.chmod(0o600)
            return publication

        deployment._publish_initial = publish_then_add_plist
        with self.assertRaisesRegex(DeploymentError, "plist exists"):
            deployment.install(REPOSITORY)
        self.assertEqual(
            self.plist.read_bytes(),
            b"foreign plist after initial preflight",
        )
        self.assertFalse(self.root.exists())

    def test_initial_install_rechecks_foreign_job_before_plist_creation(self) -> None:
        deployment = self.deployment()
        publish = deployment._publish_initial
        foreign = {
            "arguments": ["/private/tmp/foreign"],
            "loaded": True,
            "path": "/private/tmp/foreign.plist",
            "program": "/private/tmp/foreign",
            "running": False,
        }

        def publish_then_load_job(source_root: Path):
            publication = publish(source_root)
            self.launch_state.write_text(json.dumps(foreign), encoding="utf-8")
            return publication

        deployment._publish_initial = publish_then_load_job
        with self.assertRaisesRegex(DeploymentError, "label is occupied"):
            deployment.install(REPOSITORY)
        self.assertEqual(
            json.loads(self.launch_state.read_text(encoding="utf-8")),
            foreign,
        )
        self.assertFalse(self.plist.exists())
        self.assertFalse(self.root.exists())

    def test_initial_plist_creation_is_exclusive_after_final_recheck(self) -> None:
        deployment = self.deployment()
        from oc_rig.deployment import user as deployment_module

        create_exclusive = deployment_module._create_file_exclusive_dirfd

        def race_create(path: Path, data: bytes, mode: int):
            if path == self.plist:
                path.write_bytes(b"foreign plist in exclusive-create race")
                path.chmod(0o600)
            return create_exclusive(path, data, mode)

        with patch(
            "oc_rig.deployment.user._create_file_exclusive_dirfd",
            side_effect=race_create,
        ):
            with self.assertRaises(FileExistsError):
                deployment.install(REPOSITORY)
        self.assertEqual(
            self.plist.read_bytes(),
            b"foreign plist in exclusive-create race",
        )
        self.assertFalse(self.root.exists())

    def test_sigkill_publish_recovers_exact_attempt_and_preserves_foreign_sibling(self) -> None:
        script = f"""
import os, signal
from pathlib import Path
from unittest.mock import patch
from oc_rig.deployment.user import UserDeployment

root = Path({str(self.root)!r})
real_replace = os.replace
def crash_after_first_publish(source, target):
    real_replace(source, target)
    destination = Path(target)
    if destination.parent == root and destination.name == "launcher.py":
        os.kill(os.getpid(), signal.SIGKILL)

deployment = UserDeployment(
    root,
    Path({str(self.home)!r}),
    Path({str(self.plist)!r}),
    Path({str(self.launchctl)!r}),
    Path({str(TEST_PYTHON)!r}),
    dry_run=False,
)
with patch("oc_rig.deployment.user.os.replace", side_effect=crash_after_first_publish):
    deployment.install(Path({str(REPOSITORY)!r}))
"""
        crashed = subprocess.run(
            [sys.executable, "-W", "error", "-c", script],
            cwd=REPOSITORY,
            env={
                "HOME": str(Path.home()),
                "PATH": "/usr/bin:/bin",
                "PYTHONPATH": str(REPOSITORY / "src"),
            },
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(crashed.returncode, -signal.SIGKILL)
        self.assertTrue((self.root / "launcher.py").exists())
        self.assertFalse((self.root / "deployment-state.json").exists())
        self.assertTrue(self.deployment().attempt_manifest.exists())
        attempt = json.loads(
            self.deployment().attempt_manifest.read_text(encoding="utf-8")
        )
        stage = Path(attempt["stage"]["path"])

        held_logs = self.root.parent / ".held-attempt-logs"
        os.replace(stage / "logs", held_logs)
        with self.assertRaisesRegex(DeploymentError, "artifact is missing: logs"):
            self.deployment().install(REPOSITORY)
        self.assertTrue(held_logs.is_dir())
        os.replace(held_logs, stage / "logs")

        os.link(self.root / "launcher.py", stage / "launcher.py")
        with self.assertRaisesRegex(DeploymentError, "duplicated"):
            self.deployment().install(REPOSITORY)
        self.assertTrue((stage / "launcher.py").exists())
        (stage / "launcher.py").unlink()

        held_stage = self.root.parent / ".held-attempt-stage"
        os.replace(stage, held_stage)
        with self.assertRaisesRegex(DeploymentError, "stage is missing"):
            self.deployment().install(REPOSITORY)
        self.assertTrue(held_stage.is_dir())
        os.replace(held_stage, stage)

        unknown = self.root / "foreign-artifact"
        unknown.write_bytes(b"preserve")
        with self.assertRaisesRegex(DeploymentError, "unknown artifacts"):
            self.deployment().install(REPOSITORY)
        self.assertEqual(unknown.read_bytes(), b"preserve")
        unknown.unlink()

        foreign = self.root.parent / f".{self.root.name}.install-foreign"
        foreign.mkdir(mode=0o700)
        sentinel = foreign / "do-not-delete"
        sentinel.write_bytes(b"foreign")
        result = self.deployment().install(REPOSITORY)
        self.assertTrue((self.root / "releases" / result["current"]).is_dir())
        self.assertEqual(sentinel.read_bytes(), b"foreign")
        self.assertFalse(self.deployment().attempt_manifest.exists())

    def test_short_manifest_write_cleans_exact_partial_and_allows_retry(self) -> None:
        real_write = os.write
        real_replace = os.replace
        target_descriptor: int | None = None
        target_calls = 0
        marker = b"oc-rig-local-user-initial-attempt-v1"
        published: list[Path] = []

        def record_publish(source: os.PathLike[str], target: os.PathLike[str]) -> None:
            destination = Path(target)
            if destination.parent == self.root:
                published.append(destination)
            real_replace(source, target)

        def short_then_stall(descriptor: int, data: bytes) -> int:
            nonlocal target_descriptor, target_calls
            payload = bytes(data)
            if target_descriptor is None and marker in payload:
                target_descriptor = descriptor
            if descriptor == target_descriptor:
                target_calls += 1
                if target_calls == 1:
                    return real_write(descriptor, payload[:17])
                if target_calls == 2:
                    return 0
            return real_write(descriptor, payload)

        with (
            patch("oc_rig.deployment.user.os.write", side_effect=short_then_stall),
            patch("oc_rig.deployment.user.os.replace", side_effect=record_publish),
        ):
            with self.assertRaisesRegex(DeploymentError, "made no progress"):
                self.deployment().install(REPOSITORY)
        self.assertIsNotNone(target_descriptor)
        self.assertEqual(published, [])
        self.assertFalse(self.deployment().attempt_manifest.exists())
        self.assertFalse(self.root.exists())
        self.assertFalse(self.plist.exists())

        retry_descriptor: int | None = None
        interrupted = False

        def interrupted_short_writes(descriptor: int, data: bytes) -> int:
            nonlocal retry_descriptor, interrupted
            payload = bytes(data)
            if retry_descriptor is None and marker in payload:
                retry_descriptor = descriptor
            if descriptor == retry_descriptor:
                if not interrupted:
                    interrupted = True
                    raise InterruptedError(errno.EINTR, "injected EINTR")
                return real_write(descriptor, payload[:23])
            return real_write(descriptor, payload)

        with patch(
            "oc_rig.deployment.user.os.write",
            side_effect=interrupted_short_writes,
        ):
            result = self.deployment().install(REPOSITORY)
        self.assertTrue(interrupted)
        self.assertTrue((self.root / "releases" / result["current"]).is_dir())

    def test_bootstrap_failure_cleans_only_attempt_owned_artifacts(self) -> None:
        self.launch_state.write_text(
            json.dumps(
                {
                    "bootstrap_error": True,
                    "loaded": False,
                    "running": False,
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaises(subprocess.CalledProcessError):
            self.deployment().install(REPOSITORY)
        self.assertFalse(self.root.exists())
        self.assertFalse(self.plist.exists())

        before = self.launch_log.read_text(encoding="utf-8").splitlines()
        self.launch_state.write_text(
            json.dumps(
                {
                    "foreign_job_on_bootstrap": True,
                    "loaded": False,
                    "running": False,
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaises(subprocess.CalledProcessError):
            self.deployment().install(REPOSITORY)
        self.assertFalse(self.root.exists())
        self.assertFalse(self.plist.exists())
        foreign = json.loads(self.launch_state.read_text(encoding="utf-8"))
        self.assertEqual(foreign["program"], "/private/tmp/foreign")
        cleanup_commands = [
            json.loads(line)
            for line in self.launch_log.read_text(encoding="utf-8").splitlines()[
                len(before):
            ]
        ]
        self.assertFalse(any(command[0] == "bootout" for command in cleanup_commands))

        self.launch_state.write_text(
            json.dumps(
                {
                    "loaded": False,
                    "replace_plist_on_bootstrap": True,
                    "running": False,
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaises(subprocess.CalledProcessError):
            self.deployment().install(REPOSITORY)
        self.assertFalse(self.root.exists())
        self.assertEqual(self.plist.read_bytes(), b"foreign plist replacement")
        self.assertEqual(stat.S_IMODE(self.plist.stat().st_mode), 0o600)

    def test_group_writable_interpreter_ancestry_is_rejected_before_execution(self) -> None:
        unsafe = self.base / "unsafe-runtime"
        unsafe.mkdir(mode=0o770)
        unsafe.chmod(0o770)
        marker = self.base / "interpreter-executed"
        interpreter = unsafe / "python3"
        interpreter.write_text(
            f"#!/bin/sh\ntouch {str(marker)!r}\n",
            encoding="utf-8",
        )
        interpreter.chmod(0o700)
        deployment = UserDeployment(
            self.root,
            self.home,
            self.plist,
            self.launchctl,
            interpreter,
            dry_run=False,
        )
        with self.assertRaisesRegex(DeploymentError, "group-writable"):
            deployment.install(REPOSITORY)
        self.assertFalse(marker.exists())
        self.assertFalse(self.root.exists())

    def test_managed_terminal_launcher_normalizes_dumb_term_under_pty(self) -> None:
        self.deployment().install(REPOSITORY)
        plist = plistlib.loads(self.plist.read_bytes())
        master, slave = pty.openpty()
        try:
            process = subprocess.Popen(
                [*plist["ProgramArguments"], "--terminal", "--help"],
                stdin=slave,
                stdout=slave,
                stderr=slave,
                env={
                    "HOME": str(self.home),
                    "PATH": "/usr/bin:/bin",
                    "TERM": "dumb",
                    "TERMINFO": "/hostile/terminfo",
                    "TERMINFO_DIRS": "/hostile/dirs",
                },
            )
            os.close(slave)
            slave = -1
            output = bytearray()
            while process.poll() is None:
                try:
                    output.extend(os.read(master, 4096))
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
            process.wait(timeout=10.0)
            self.assertEqual(process.returncode, 0)
            self.assertIn(b"oc-rig-v2-terminal", output)

            rejected = subprocess.run(
                [*plist["ProgramArguments"], "--terminal", "--help"],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "HOME": str(self.home),
                    "PATH": "/usr/bin:/bin",
                    "TERM": "-V",
                    "TERMINFO": "/hostile/terminfo",
                    "TERMINFO_DIRS": "/hostile/dirs",
                },
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(b"terminal TERM is invalid", rejected.stderr)
        finally:
            os.close(master)
            if slave >= 0:
                os.close(slave)

    def test_generated_launcher_uses_isolated_environment_and_serves_health(self) -> None:
        self.deployment().install(REPOSITORY)
        state = json.loads(
            (self.root / "deployment-state.json").read_text(encoding="utf-8")
        )
        release = self.root / "releases" / state["current"]
        pin = json.loads((release / "release-pin.json").read_text(encoding="utf-8"))
        writable_ancestor = next(
            Path(item["path"])
            for item in pin["runtime"]["controlled"]
            if item["kind"] == "directory"
            and "ctime_ns" not in item
            and item["uid"] == os.geteuid()
            and os.access(item["path"], os.W_OK)
        )
        before_ctime = writable_ancestor.stat().st_ctime_ns
        transient = writable_ancestor / f".oc-rig-ctime-test-{os.getpid()}"
        transient.write_bytes(b"ordinary directory churn")
        transient.unlink()
        self.assertNotEqual(writable_ancestor.stat().st_ctime_ns, before_ctime)
        self.deployment().status()
        plist = plistlib.loads(self.plist.read_bytes())
        socket_root = self.root / "runtime" / "socket-boundary"
        socket_path = socket_root / "socket" / "rig.sock"
        process = subprocess.Popen(
            plist["ProgramArguments"],
            cwd=self.root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "HOME": str(self.home),
                "OPENAI_API_KEY": "must-not-reach-rigd",
                "PATH": "/usr/bin:/bin",
                "PYTHONPATH": "/untrusted/site",
            },
        )
        try:
            deadline = time.monotonic() + 10.0
            last_error: Exception | None = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                try:
                    health = RigClient(
                        socket_path,
                        approved_root=socket_root,
                        identity_profile="local-user",
                        timeout=0.2,
                    ).call("health.v1")
                except Exception as error:
                    last_error = error
                    time.sleep(0.05)
                    continue
                self.assertEqual(health["status"], "ok")
                break
            else:
                self.fail(f"generated launcher did not become ready: {last_error}")
            if process.poll() is not None:
                _stdout, stderr = process.communicate(timeout=1.0)
                self.fail(f"generated launcher exited early: {stderr.decode()}")
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5.0)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        self.assertFalse(socket_path.exists())
        self.assertEqual(list((self.root / "runtime" / "home").iterdir()), [])

    def test_readiness_failure_terminates_authenticated_job(self) -> None:
        self.deployment().install(REPOSITORY)
        deployment = self.deployment()

        def fail_readiness() -> None:
            raise DeploymentError("injected readiness failure")

        deployment._wait_ready = fail_readiness
        with self.assertRaisesRegex(DeploymentError, "was terminated"):
            deployment.start()
        state = json.loads(self.launch_state.read_text(encoding="utf-8"))
        self.assertFalse(state["running"])
        commands = [json.loads(line) for line in self.launch_log.read_text().splitlines()]
        self.assertTrue(any(command[0] == "kickstart" for command in commands))
        self.assertTrue(any(command[0] == "kill" for command in commands))

    def test_foreign_launchd_job_and_inspection_error_are_left_untouched(self) -> None:
        self.deployment().install(REPOSITORY)
        state = json.loads(self.launch_state.read_text(encoding="utf-8"))
        state["program"] = "/private/tmp/foreign"
        state["arguments"] = ["/private/tmp/foreign"]
        self.launch_state.write_text(json.dumps(state), encoding="utf-8")
        before = self.launch_log.read_text(encoding="utf-8").splitlines()
        for operation in (
            lambda: self.deployment().start(),
            lambda: self.deployment().stop(),
            lambda: self.deployment().uninstall(purge=False, confirm_purge=False),
        ):
            with self.assertRaisesRegex(DeploymentError, "foreign"):
                operation()
        after = self.launch_log.read_text(encoding="utf-8").splitlines()[len(before):]
        dangerous = {"bootout", "kickstart", "kill"}
        self.assertFalse(
            any(json.loads(line)[0] in dangerous for line in after)
        )

        state["print_error"] = True
        self.launch_state.write_text(json.dumps(state), encoding="utf-8")
        with self.assertRaisesRegex(DeploymentError, "could not inspect"):
            self.deployment().status()

    def test_start_stop_rollback_and_non_destructive_uninstall(self) -> None:
        first = self.deployment().install(REPOSITORY)["current"]
        second = self.deployment().install(self._second_source())["current"]
        self.assertNotEqual(first, second)
        rolled_back = self.deployment().rollback(
            expected_current=second,
            target=first,
        )
        self.assertEqual(rolled_back["current"], first)
        repeated = self.deployment().rollback(
            expected_current=second,
            target=first,
        )
        self.assertEqual(repeated["current"], first)
        with self.assertRaisesRegex(DeploymentError, "does not match"):
            self.deployment().rollback(
                expected_current="0.1.0.dev9-0000000000000000",
                target=first,
            )
        deployment = self.deployment()
        deployment._wait_ready = lambda: None
        deployment.start()
        state = json.loads(self.launch_state.read_text(encoding="utf-8"))
        self.assertTrue(state["running"])
        with self.assertRaises(DeploymentError):
            self.deployment().rollback(
                expected_current=first,
                target=second,
            )
        self.deployment().stop()
        self.deployment().uninstall(purge=False, confirm_purge=False)
        self.assertTrue(self.root.exists())
        self.assertFalse(self.plist.exists())
        with self.assertRaises(DeploymentError):
            self.deployment().uninstall(purge=True, confirm_purge=False)
        self.deployment().install(REPOSITORY)
        self.deployment().uninstall(purge=True, confirm_purge=True)
        self.assertFalse(self.root.exists())

    def test_launchctl_not_running_normalizes_to_exact_not_detail(self) -> None:
        self.deployment().install(REPOSITORY)
        state = json.loads(self.launch_state.read_text(encoding="utf-8"))
        state["loaded"] = True
        state["running"] = False
        state["detail"] = "not running"
        state["nested_states"] = ["active", "idle", "not running"]
        self.launch_state.write_text(json.dumps(state), encoding="utf-8")
        status = self.deployment().job_status()
        self.assertTrue(status.loaded)
        self.assertFalse(status.running)
        self.assertIsNone(status.pid)
        self.assertEqual(status.detail, "not")

    def test_transitional_proxy_is_not_stopped_and_stop_terminates_it(self) -> None:
        self.deployment().install(REPOSITORY)
        self.assertEqual(
            plistlib.loads(self.plist.read_bytes())["ProcessType"],
            "Standard",
        )
        state = json.loads(self.launch_state.read_text(encoding="utf-8"))
        state.update(
            {
                "loaded": True,
                "running": False,
                "detail": "xpcproxy",
                "pid": 4242,
            }
        )
        self.launch_state.write_text(json.dumps(state), encoding="utf-8")

        with self.assertRaisesRegex(DeploymentError, "transitional state"):
            self.deployment()._require_stopped()

        result = self.deployment().stop()
        self.assertIn(
            ["kill", "SIGTERM", self.deployment().target],
            [json.loads(line) for line in self.launch_log.read_text().splitlines()],
        )
        stopped = json.loads(self.launch_state.read_text(encoding="utf-8"))
        self.assertFalse(stopped["running"])
        self.assertEqual(stopped["detail"], "waiting")
        self.assertNotIn("pid", stopped)
        self.assertFalse(result["dry_run"])

    def test_launchctl_state_parser_rejects_other_not_variants_and_duplicates(self) -> None:
        self.deployment().install(REPOSITORY)
        state = json.loads(self.launch_state.read_text(encoding="utf-8"))
        state["loaded"] = True
        state["running"] = False
        cases = {
            "not ready": "malformed state",
            "not compromised": "malformed state",
            "running garbage": "malformed state",
            "not": "malformed state",
            "": "malformed state",
            "not running\n\tstate = running": "duplicate state",
            "not running\nstate = active": "malformed state indentation",
            "not running\n  state = active": "malformed state indentation",
            "not running\n \tstate = active": "malformed state indentation",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                state["detail"] = raw
                self.launch_state.write_text(json.dumps(state), encoding="utf-8")
                with self.assertRaisesRegex(DeploymentError, expected):
                    self.deployment().job_status()

    def test_dry_run_does_not_create_destination_or_launch_state(self) -> None:
        result = self.deployment(dry_run=True).install(REPOSITORY)
        self.assertTrue(result["dry_run"])
        self.assertFalse(self.root.exists())
        self.assertFalse(self.plist.exists())
        self.assertFalse(self.launch_state.exists())

    def test_unmanaged_nonempty_state_symlink_mode_and_hash_fail_closed(self) -> None:
        self.root.mkdir(mode=0o700)
        (self.root / "unknown").write_text("do not adopt", encoding="utf-8")
        with self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        shutil.rmtree(self.root)
        result = self.deployment().install(REPOSITORY)
        stdout_log = self.root / "logs" / "rigd.stdout.log"
        stdout_log.chmod(0o644)
        with self.assertRaises(DeploymentError):
            self.deployment().status()
        stdout_log.chmod(0o600)
        release = self.root / "releases" / result["current"]
        pin = json.loads((release / "release-pin.json").read_text(encoding="utf-8"))
        wheel = release / pin["wheel"]["filename"]
        wheel.chmod(0o600)
        wheel.write_bytes(wheel.read_bytes() + b"tamper")
        wheel.chmod(0o400)
        with self.assertRaises(DeploymentError):
            self.deployment().status()
        release.chmod(0o700)
        wheel.unlink()
        wheel.symlink_to(self.plist)
        release.chmod(0o500)
        with self.assertRaises(DeploymentError):
            self.deployment().status()

    def test_installed_local_user_daemon_serves_only_on_0600_socket(self) -> None:
        self.deployment().install(REPOSITORY)
        runtime_root = self.root / "runtime"
        socket_root = runtime_root / "socket-boundary"
        socket_path = socket_root / "socket" / "rig.sock"
        daemon = _DurableChildDaemon(
            PrivateSocketPath(socket_path, socket_root),
            runtime=PrivateRuntimeDirectory(runtime_root / "state", runtime_root),
            identity_policy=LocalUserIdentityPolicy(os.geteuid(), os.getegid()),
        )
        thread = daemon.start_background()
        try:
            self.assertEqual(stat.S_IMODE(socket_path.lstat().st_mode), 0o600)
            self._set_job_running(True)
            self.deployment()._wait_ready()
            result = RigClient(
                socket_path,
                approved_root=socket_root,
                identity_profile="local-user",
            ).call("health.v1")
            self.assertEqual(result["status"], "ok")
            with self.assertRaises(ValueError):
                RigClient(
                    socket_path,
                    approved_root=socket_root,
                    service_uid=os.geteuid(),
                    client_gid=os.getegid(),
                    identity_profile="local-user",
                )
        finally:
            daemon.shutdown()
            thread.join(timeout=2.0)
        self.assertFalse(socket_path.exists())

    def test_generated_launcher_live_opencode_end_to_end_is_exactly_once(self) -> None:
        backend = BackendState()
        password = "offline-basic-password-with-entropy"
        backend.auth_header = "Basic " + base64.b64encode(
            f"opencode:{password}".encode()
        ).decode()
        backend.event_wait = threading.Event()
        backend.auto_complete_prompt = True
        server = FakeServer(backend)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(lambda: server_thread.join(timeout=2.0))

        self.deployment().install(REPOSITORY)
        password_file = self.base / "opencode.password"
        topology_file = self.base / "opencode.topology.json"
        trust_file = self.base / "opencode.trust.json"
        password_file.write_text(password, encoding="utf-8")
        topology_file.write_text(json.dumps(topology()), encoding="utf-8")
        trust_file.write_text(
            json.dumps({"mode": "secure", "secure_worker": "secure-worker"}),
            encoding="utf-8",
        )
        for path in (password_file, topology_file, trust_file):
            path.chmod(0o600)
        configured = self.deployment().configure_opencode(
            endpoint=f"http://127.0.0.1:{server.server_port}",
            basic_username="opencode",
            basic_password_file=password_file,
            topology_file=topology_file,
            trust_file=trust_file,
        )
        self.assertTrue(configured["configured"])
        self.assertNotIn(password, json.dumps(configured))
        callback_log = self.base / "callback-invocations.log"
        callback_executable = self.base / "codex-callback"
        callback_executable.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + str(callback_log) + "\nexit 0\n",
            encoding="utf-8",
        )
        callback_executable.chmod(0o700)
        codex_home = self.base / "codex-home"
        codex_home.mkdir(mode=0o700)
        self.deployment().configure_codex_callback(
            executable=callback_executable,
            home=self.home,
            codex_home=codex_home,
        )

        plist = plistlib.loads(self.plist.read_bytes())
        socket_root = self.root / "runtime" / "socket-boundary"
        socket_path = socket_root / "socket" / "rig.sock"

        def launch() -> subprocess.Popen[bytes]:
            return subprocess.Popen(
                plist["ProgramArguments"],
                cwd=self.root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"HOME": str(self.home), "PATH": "/usr/bin:/bin"},
            )

        def ready(process: subprocess.Popen[bytes]) -> RigClient:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    _stdout, stderr = process.communicate()
                    self.fail(f"live generated launcher exited: {stderr.decode()}")
                try:
                    client = RigClient(
                        socket_path,
                        approved_root=socket_root,
                        identity_profile="local-user",
                        timeout=0.3,
                    )
                    if client.call("health.v1")["status"] == "ok":
                        return client
                except Exception:
                    pass
                time.sleep(0.05)
            self.fail("live generated launcher did not become ready")

        process = launch()
        try:
            client = ready(process)
            repository = self.base / "repository"
            repository.mkdir(mode=0o700)
            (repository / "work.txt").write_text("bounded", encoding="utf-8")

            def call(operation: str, params: dict[str, object], key: str) -> dict[str, object]:
                return dict(
                    client.call(
                        operation,
                        params,
                        request_id=f"request-{key}",
                        idempotency_id=key,
                    )
                )

            call(
                "operation.create.v1",
                {"operation_id": "owner-live-e2e", "kind": "dispatch"},
                "operation-live-e2e",
            )
            claim = call(
                "scope.claim.v1",
                {
                    "owner_operation_id": "owner-live-e2e",
                    "repository": str(repository),
                    "scope": ["work.txt"],
                },
                "claim-live-e2e",
            )
            call(
                "scheduler.enqueue.v1",
                {"work_id": "work-live-e2e", "lane": "tensorhost"},
                "enqueue-live-e2e",
            )
            decision = call(
                "scheduler.admit.v1",
                {
                    "work_id": "work-live-e2e",
                    "claim_id": claim["claim_id"],
                    "repository": str(repository),
                    "scope": ["work.txt"],
                    "content": "offline bounded prompt",
                    "dispatch_kind": "automated",
                    "trust": "secure",
                    "classification": "PUBLIC",
                    "risk_categories": [],
                },
                "admit-live-e2e",
            )
            self.assertTrue(decision["allowed"])
            reservation = call(
                "scheduler.reserve.v1", {}, "reserve-live-e2e"
            )["reservation"]
            self.assertIsNotNone(reservation)

            state = json.loads(
                (self.root / "deployment-state.json").read_text(encoding="utf-8")
            )
            release = self.root / "releases" / state["current"]
            pin = json.loads((release / "release-pin.json").read_text(encoding="utf-8"))
            wheel = release / pin["wheel"]["filename"]
            rigctl_bootstrap = (
                "import runpy,sys;"
                "wheel=sys.argv.pop(1);sys.path.insert(0,wheel);"
                "runpy.run_module('oc_rig.cli',run_name='__main__')"
            )
            base_command = [
                str(TEST_PYTHON),
                "-I",
                "-S",
                "-B",
                "-c",
                rigctl_bootstrap,
                str(wheel),
                "--socket",
                str(socket_path),
                "--approved-root",
                str(socket_root),
                "--identity-profile",
                "local-user",
            ]
            dispatch_params = {
                "work_id": "work-live-e2e",
                "pool": "tensorhost",
                "payload": {
                    "prompt": "offline bounded prompt",
                    "classification": "PUBLIC",
                    "trust": "secure",
                },
                "return_route": {
                    "kind": "local_codex",
                    "thread_id": "00000000-0000-7000-8000-abcdef000002",
                },
            }
            first = call(
                "transport.dispatch.v1", dispatch_params, "dispatch-live-e2e"
            )
            self.assertEqual(first["state"], "accepted")
            self.assertEqual(
                call("transport.dispatch.v1", dispatch_params, "dispatch-live-e2e"),
                first,
            )
            prompt_requests = [
                request
                for request in backend.requests
                if str(request["path"]).endswith("/prompt_async")
            ]
            self.assertEqual(len(prompt_requests), 1)

            database = self.root / "runtime" / "state" / "rig.sqlite3"
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with closing(sqlite3.connect(database)) as connection:
                    completion_count = connection.execute(
                        "SELECT count(*) FROM completion_events"
                    ).fetchone()[0]
                    lease = connection.execute(
                        "SELECT lease_state FROM opencode_deliveries"
                    ).fetchone()
                    assignment = connection.execute(
                        "SELECT state FROM scheduler_assignments"
                    ).fetchone()
                    scope = connection.execute(
                        "SELECT state FROM scope_claims"
                    ).fetchone()
                    callback = connection.execute(
                        "SELECT state, attempts FROM callbacks"
                    ).fetchone()
                if (
                    completion_count == 1
                    and lease == ("released",)
                    and assignment == ("released",)
                    and scope == ("released",)
                    and callback == ("delivered", 1)
                ):
                    break
                time.sleep(0.05)
            else:
                self.fail("SSE completion was not durably accepted and released")
            self.assertEqual(len(callback_log.read_text(encoding="utf-8").splitlines()), 1)
            cockpit = client.call("cockpit.snapshot.v1")["snapshot"]
            self.assertIn("opencode-http-sse-v1", json.dumps(cockpit))
            clear_workers = [
                worker
                for worker in cockpit["worker_graph"]["workers"]
                if worker["slot_state"] == "clear"
            ]
            self.assertTrue(clear_workers)
            for worker in clear_workers:
                slot_number = next(
                    index
                    for index, configured in enumerate(
                        member
                        for pool in topology()["pools"].values()
                        for member in pool
                    )
                    if configured["slot_id"] == worker["slot_id"]
                ) + 1
                self.assertEqual(
                    worker["session"],
                    {"status": "available", "ref": f"session-{slot_number}"},
                )
                self.assertEqual(worker["transport"]["state"], "idle")
                self.assertEqual(
                    worker["completion"]["registration_state"], "not-applicable"
                )
                self.assertEqual(
                    worker["completion"]["callback_adapter"],
                    {"status": "available", "reason": None},
                )
                self.assertEqual(worker["recovery"]["phase"], "not-applicable")

            cancelled = subprocess.run(
                [
                    *base_command,
                    "--idempotency-id",
                    "cancel-live-e2e",
                    "cancel-transport",
                    "tensorhost",
                    "work-live-e2e",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(
                json.loads(cancelled.stdout)["abort"]["error_code"],
                "abort_authority_stale",
            )
            self.assertFalse(
                any(str(item["path"]).endswith("/abort") for item in backend.requests)
            )

            backend.auto_complete_prompt = False
            (repository / "crash.txt").write_text("bounded", encoding="utf-8")
            call(
                "operation.create.v1",
                {"operation_id": "owner-live-crash", "kind": "dispatch"},
                "operation-live-crash",
            )
            crash_claim = call(
                "scope.claim.v1",
                {
                    "owner_operation_id": "owner-live-crash",
                    "repository": str(repository),
                    "scope": ["crash.txt"],
                },
                "claim-live-crash",
            )
            call(
                "scheduler.enqueue.v1",
                {"work_id": "work-live-crash", "lane": "tensorhost"},
                "enqueue-live-crash",
            )
            crash_decision = call(
                "scheduler.admit.v1",
                {
                    "work_id": "work-live-crash",
                    "claim_id": crash_claim["claim_id"],
                    "repository": str(repository),
                    "scope": ["crash.txt"],
                    "content": "offline crash seam prompt",
                    "dispatch_kind": "automated",
                    "trust": "secure",
                    "classification": "PUBLIC",
                    "risk_categories": [],
                },
                "admit-live-crash",
            )
            self.assertTrue(crash_decision["allowed"])
            self.assertIsNotNone(
                call("scheduler.reserve.v1", {}, "reserve-live-crash")["reservation"]
            )
            crash_dispatch = [
                *base_command,
                "--idempotency-id",
                "dispatch-live-crash",
                "dispatch",
                "tensorhost",
                "work-live-crash",
                "--payload-json",
                json.dumps(
                    {
                        "prompt": "offline crash seam prompt",
                        "classification": "PUBLIC",
                        "trust": "secure",
                    }
                ),
            ]
            subprocess.run(
                crash_dispatch,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(
                len(
                    [
                        request
                        for request in backend.requests
                        if str(request["path"]).endswith("/prompt_async")
                    ]
                ),
                2,
            )
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        self.assertFalse(socket_path.exists())

        store = RigStore(
            PrivateRuntimeDirectory(
                self.root / "runtime" / "state",
                self.root / "runtime",
            )
        )
        lock_path = self.root / "runtime" / "state" / "rigd.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        details = os.fstat(descriptor)
        authority = object.__new__(_DaemonAuthority)
        authority._store = store
        authority._closed = False
        authority._descriptor = descriptor
        authority._path = lock_path
        authority._identity = (details.st_dev, details.st_ino)
        authority._activate_usage_guard()
        store._open_daemon_connection(authority)
        capability = object()
        completion = _create_completion(store, authority, capability)
        try:
            with store._daemon_transaction(authority) as connection:
                connection.row_factory = sqlite3.Row
                crash_row = connection.execute(
                    """SELECT delivery.transport_id,
                              coalesce(delivery.isolated_session_id, delivery.session_id)
                                  AS session_id,
                              delivery.session_id AS base_session_id,
                              delivery.assignment_generation,
                              delivery.prompt_message_id,
                              registration.id AS registration_id,
                              registration.assignment_attempt, registration.work_id
                       FROM opencode_deliveries AS delivery
                       JOIN transport_completion_registrations AS registration
                         ON registration.id = delivery.completion_registration_id
                       WHERE registration.work_id = 'work-live-crash'"""
                ).fetchone()
                self.assertIsNotNone(crash_row)
                assert crash_row is not None
                completion_digest = hashlib.sha256(
                    (
                        f"{crash_row['registration_id']}:"
                        f"{crash_row['session_id']}:"
                        f"{crash_row['assignment_generation']}:"
                        f"{crash_row['prompt_message_id']}"
                    ).encode()
                ).hexdigest()
                completion.accept(
                    capability,
                    connection,
                    completion_key=f"opencode-completion-{completion_digest}",
                    registration_id=str(crash_row["registration_id"]),
                    work_id=str(crash_row["work_id"]),
                    generation=int(crash_row["assignment_attempt"]),
                    outcome=CompletionOutcome.SUCCEEDED,
                )
        finally:
            authority.close()
        backend.messages[str(crash_row["session_id"])] = [
            {
                "info": message_info(
                    str(crash_row["prompt_message_id"]),
                    session_id=str(crash_row["session_id"]),
                ),
                "parts": [],
            }
        ]
        backend.statuses.pop(str(crash_row["session_id"]), None)

        backend.event_wait = threading.Event()
        process = launch()
        try:
            client = ready(process)
            self.assertEqual(
                call("transport.dispatch.v1", dispatch_params, "dispatch-live-e2e"),
                first,
            )
            self.assertEqual(
                len(
                    [
                        request
                        for request in backend.requests
                        if str(request["path"]).endswith("/prompt_async")
                    ]
                ),
                2,
            )
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with closing(sqlite3.connect(database)) as connection:
                    lease = connection.execute(
                        """SELECT lease_state FROM opencode_deliveries
                           WHERE transport_id = ?""",
                        (crash_row["transport_id"],),
                    ).fetchone()
                if lease == ("released",):
                    break
                time.sleep(0.05)
            else:
                self.fail("restart did not release the crash-seam reservation")
            self.assertEqual(len(callback_log.read_text(encoding="utf-8").splitlines()), 1)

            for session_id in ("session-1", "session-2", "session-3"):
                backend.statuses[session_id] = {"type": "busy"}
            backend.statuses[str(crash_row["base_session_id"])] = {"type": "idle"}
            (repository / "capacity.txt").write_text("bounded", encoding="utf-8")

            def restarted_call(
                operation: str,
                params: dict[str, object],
                key: str,
            ) -> dict[str, object]:
                return dict(
                    client.call(
                        operation,
                        params,
                        request_id=f"request-{key}",
                        idempotency_id=key,
                    )
                )

            restarted_call(
                "operation.create.v1",
                {"operation_id": "owner-live-capacity", "kind": "dispatch"},
                "operation-live-capacity",
            )
            capacity_claim = restarted_call(
                "scope.claim.v1",
                {
                    "owner_operation_id": "owner-live-capacity",
                    "repository": str(repository),
                    "scope": ["capacity.txt"],
                },
                "claim-live-capacity",
            )
            restarted_call(
                "scheduler.enqueue.v1",
                {"work_id": "work-live-capacity", "lane": "tensorhost"},
                "enqueue-live-capacity",
            )
            restarted_call(
                "scheduler.admit.v1",
                {
                    "work_id": "work-live-capacity",
                    "claim_id": capacity_claim["claim_id"],
                    "repository": str(repository),
                    "scope": ["capacity.txt"],
                    "content": "offline capacity prompt",
                    "dispatch_kind": "automated",
                    "trust": "secure",
                    "classification": "PUBLIC",
                    "risk_categories": [],
                },
                "admit-live-capacity",
            )
            self.assertIsNotNone(
                restarted_call(
                    "scheduler.reserve.v1", {}, "reserve-live-capacity"
                )["reservation"]
            )
            capacity_dispatch = [
                *base_command,
                "--idempotency-id",
                "dispatch-live-capacity",
                "dispatch",
                "tensorhost",
                "work-live-capacity",
                "--payload-json",
                json.dumps(
                    {
                        "prompt": "offline capacity prompt",
                        "classification": "PUBLIC",
                        "trust": "secure",
                    }
                ),
            ]
            subprocess.run(
                capacity_dispatch,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(
                len(
                    [
                        request
                        for request in backend.requests
                        if str(request["path"]).endswith("/prompt_async")
                    ]
                ),
                3,
            )
            with closing(sqlite3.connect(database)) as connection:
                reused = connection.execute(
                    """SELECT prior.slot_id, current.slot_id
                       FROM opencode_deliveries AS prior
                       JOIN opencode_deliveries AS current
                         ON current.work_id = 'work-live-capacity'
                       WHERE prior.work_id = 'work-live-crash'"""
                ).fetchone()
            self.assertIsNotNone(reused)
            assert reused is not None
            self.assertEqual(reused[0], reused[1])
        finally:
            if backend.event_wait is not None:
                backend.event_wait.set()
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=15)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        self.assertFalse(socket_path.exists())

    def test_opencode_config_is_private_pinned_replaceable_and_secret_free(self) -> None:
        self.deployment().install(REPOSITORY)
        password = self.base / "basic.password"
        topology_path = self.base / "topology.json"
        trust_path = self.base / "trust.json"
        password.write_text("private-basic-password-material", encoding="utf-8")
        topology_path.write_text(json.dumps(topology()), encoding="utf-8")
        trust_path.write_text(
            json.dumps({"mode": "secure", "secure_worker": "secure-worker"}),
            encoding="utf-8",
        )
        for path in (password, topology_path, trust_path):
            path.chmod(0o600)
        staged_legacy = topology()
        staged_legacy["pools"]["control"] = staged_legacy["pools"]["control"][:1]
        topology_path.write_text(json.dumps(staged_legacy), encoding="utf-8")
        topology_path.chmod(0o600)
        with self.assertRaisesRegex(DeploymentError, "topology_invalid"):
            self.deployment().configure_opencode(
                endpoint="http://127.0.0.1:4096",
                basic_username="opencode",
                basic_password_file=password,
                topology_file=topology_path,
                trust_file=trust_path,
            )
        topology_path.write_text(json.dumps(topology()), encoding="utf-8")
        topology_path.chmod(0o600)
        first = self.deployment().configure_opencode(
            endpoint="http://127.0.0.1:4096",
            basic_username="opencode",
            basic_password_file=password,
            topology_file=topology_path,
            trust_file=trust_path,
        )
        status = self.deployment().status()
        self.assertTrue(status["opencode"]["configured"])
        self.assertNotIn(password.read_text(), json.dumps(status))
        generation = self.root / "config" / "opencode" / first["config_id"]
        self.assertEqual(
            {entry.name for entry in generation.iterdir()},
            {
                "auth.json", "automated-backend-policy.json",
                "provider-auth-seed.json", "topology.json", "trust.json",
            },
        )
        self.assertTrue(
            all(
                stat.S_IMODE((generation / name).stat().st_mode) == 0o600
                for name in ("auth.json", "topology.json", "trust.json")
            )
        )
        self.assertEqual(
            json.loads((generation / "automated-backend-policy.json").read_text()),
            user_deployment_module._AUTOMATED_BACKEND_POLICY,
        )
        self.assertEqual(
            stat.S_IMODE((generation / "automated-backend-policy.json").stat().st_mode),
            0o400,
        )
        self.assertFalse((generation / "xdg").exists())
        self.assertEqual((generation / "provider-auth-seed.json").read_bytes(), b"{}\n")
        self.assertFalse((generation / "xdg-data").exists())
        historical = user_deployment_module.validated_historical_opencode_configuration(
            self.root,
            config_id=first["config_id"],
            endpoint="http://127.0.0.1:4096",
        )
        self.assertEqual(historical.config_id, first["config_id"])

        updated = topology()
        updated["pools"]["tensorhost"][0]["session_id"] = "session-updated"
        topology_path.write_text(json.dumps(updated), encoding="utf-8")
        topology_path.chmod(0o600)
        second = self.deployment().configure_opencode(
            endpoint="http://127.0.0.1:4096",
            basic_username="opencode",
            basic_password_file=password,
            topology_file=topology_path,
            trust_file=trust_path,
        )
        self.assertNotEqual(first["config_id"], second["config_id"])
        self.assertFalse(generation.exists())
        selected = self.root / "config" / "opencode" / second["config_id"]
        with self.assertRaisesRegex(DeploymentError, "absolute"):
            self.deployment().configure_opencode(
                endpoint="http://127.0.0.1:4096",
                basic_username="opencode",
                basic_password_file=Path("relative.password"),
                topology_file=topology_path,
                trust_file=trust_path,
            )
        extra = selected / "extra-empty"
        extra.mkdir(mode=0o700)
        with self.assertRaisesRegex(DeploymentError, "topology"):
            self.deployment().status()
        extra.rmdir()
        policy = selected / "automated-backend-policy.json"
        policy_bytes = policy.read_bytes()
        policy.unlink()
        policy.symlink_to(selected / "trust.json")
        with self.assertRaises(DeploymentError):
            self.deployment().status()
        policy.unlink()
        policy.write_bytes(policy_bytes)
        policy.chmod(0o600)
        (selected / "trust.json").unlink()
        with self.assertRaisesRegex(DeploymentError, "partial"):
            self.deployment().status()

    def test_install_refreshes_stopped_current_layout_policy_and_then_noops(self) -> None:
        old_id, expected_id, old = self._old_policy_current_layout_fixture()
        old_auth = (old / "auth.json").read_bytes()
        old_topology = (old / "topology.json").read_bytes()
        old_trust = (old / "trust.json").read_bytes()
        self.deployment().install(REPOSITORY)
        refreshed = self.deployment().status()["opencode"]
        self.assertNotEqual(refreshed["config_id"], old_id)
        self.assertEqual(refreshed["config_id"], expected_id)
        target = self.root / "config/opencode" / expected_id
        self.assertEqual((target / "auth.json").read_bytes(), old_auth)
        self.assertEqual((target / "topology.json").read_bytes(), old_topology)
        self.assertEqual((target / "trust.json").read_bytes(), old_trust)
        self.assertEqual(
            (target / "automated-backend-policy.json").read_bytes(),
            user_deployment_module._BACKEND_POLICY_BYTES,
        )
        self.assertEqual(
            (target / "provider-auth-seed.json").read_bytes(), b"{}\n"
        )
        state_before = (self.root / "deployment-state.json").read_bytes()
        policy_identity = (target / "automated-backend-policy.json").stat().st_ino
        self.deployment().install(REPOSITORY)
        self.assertEqual(
            (self.root / "deployment-state.json").read_bytes(), state_before
        )
        self.assertEqual(
            (target / "automated-backend-policy.json").stat().st_ino,
            policy_identity,
        )

    def test_install_policy_refresh_rejects_base_tamper_and_race(self) -> None:
        old_id, _expected_id, old = self._old_policy_current_layout_fixture()
        state_path = self.root / "deployment-state.json"
        prior_state = state_path.read_bytes()
        topology_path = old / "topology.json"
        topology_path.write_bytes(b'{}\n')
        topology_path.chmod(0o600)
        with self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        self.assertEqual(state_path.read_bytes(), prior_state)
        self.assertEqual(
            json.loads(state_path.read_text())["opencode"]["config_id"], old_id
        )

    def test_install_policy_refresh_rejects_base_replacement_race(self) -> None:
        old_id, expected_id, old = self._old_policy_current_layout_fixture()
        state_path = self.root / "deployment-state.json"
        prior_state = state_path.read_bytes()
        real_validate = user_deployment_module._validate_opencode_configuration
        raced = False

        def replace_after_validation(*args: object, **kwargs: object):
            nonlocal raced
            result = real_validate(*args, **kwargs)
            if not raced:
                raced = True
                trust = old / "trust.json"
                trust.write_bytes(b'{}\n')
                trust.chmod(0o600)
            return result

        with patch.object(
            user_deployment_module,
            "_validate_opencode_configuration",
            side_effect=replace_after_validation,
        ), self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        self.assertEqual(state_path.read_bytes(), prior_state)
        self.assertEqual(
            json.loads(state_path.read_text())["opencode"]["config_id"], old_id
        )
        self.assertFalse((self.root / "config/opencode" / expected_id).exists())

    def test_install_policy_refresh_rolls_back_after_state_switch_failure(self) -> None:
        old_id, expected_id, _old = self._old_policy_current_layout_fixture()
        state_path = self.root / "deployment-state.json"
        prior_state = state_path.read_bytes()
        real_read_state = user_deployment_module._read_state

        def reject_new_state(root: Path, **kwargs: object) -> dict[str, object]:
            value = real_read_state(root, **kwargs)
            if value.get("opencode", {}).get("config_id") == expected_id:
                raise DeploymentError("synthetic post-switch validation failure")
            return value

        with patch.object(
            user_deployment_module, "_read_state", side_effect=reject_new_state
        ), self.assertRaisesRegex(DeploymentError, "post-switch"):
            self.deployment().install(REPOSITORY)
        self.assertEqual(state_path.read_bytes(), prior_state)
        self.assertEqual(
            json.loads(state_path.read_text())["opencode"]["config_id"], old_id
        )
        self.assertFalse((self.root / "config/opencode" / expected_id).exists())

    def test_install_policy_refresh_preserves_target_when_state_rollback_fails(self) -> None:
        _old_id, expected_id, _old = self._old_policy_current_layout_fixture()
        state_path = self.root / "deployment-state.json"
        prior_state = state_path.read_bytes()
        real_read_state = user_deployment_module._read_state
        real_replace_file = user_deployment_module._replace_file

        def reject_new_state(root: Path, **kwargs: object) -> dict[str, object]:
            value = real_read_state(root, **kwargs)
            if value.get("opencode", {}).get("config_id") == expected_id:
                raise DeploymentError("synthetic post-switch validation failure")
            return value

        def reject_prior_restore(
            path: Path, data: bytes, mode: int = 0o600
        ) -> None:
            if path == state_path and data == prior_state:
                raise DeploymentError("synthetic rollback write failure")
            real_replace_file(path, data, mode)

        with patch.object(
            user_deployment_module, "_read_state", side_effect=reject_new_state
        ), patch.object(
            user_deployment_module, "_replace_file", side_effect=reject_prior_restore
        ), self.assertRaisesRegex(DeploymentError, "cleanup was incomplete"):
            self.deployment().install(REPOSITORY)
        selected = json.loads(state_path.read_text())["opencode"]["config_id"]
        self.assertEqual(selected, expected_id)
        target = self.root / "config/opencode" / expected_id
        self.assertTrue((target / "automated-backend-policy.json").is_file())
        self.assertEqual(self.deployment().status()["opencode"]["config_id"], expected_id)

    def test_owned_generation_fsyncs_nested_directories_bottom_up(self) -> None:
        tree = self.base / "fsync-tree"
        nested = tree / "one/two"
        nested.mkdir(parents=True)
        (nested / "file").write_bytes(b"bounded")
        snapshot = user_deployment_module._snapshot_owned_tree(tree)
        identities = {
            path: (tree if path == "." else tree / path).stat().st_ino
            for path, (_device, _inode, kind) in snapshot.items()
            if kind == "directory"
        }
        observed: list[int] = []

        def record_fsync(descriptor: int) -> None:
            observed.append(os.fstat(descriptor).st_ino)

        with patch.object(os, "fsync", side_effect=record_fsync):
            user_deployment_module._fsync_owned_tree(tree, snapshot)
        self.assertLess(observed.index(identities["one/two"]), observed.index(identities["one"]))
        self.assertLess(observed.index(identities["one"]), observed.index(identities["."]))

    def test_install_policy_refresh_fsync_failure_removes_only_owned_stage(self) -> None:
        old_id, expected_id, _old = self._old_policy_current_layout_fixture()
        state_path = self.root / "deployment-state.json"
        prior_state = state_path.read_bytes()
        with patch.object(
            user_deployment_module,
            "_fsync_owned_tree",
            side_effect=DeploymentError("synthetic stage fsync failure"),
        ), self.assertRaisesRegex(DeploymentError, "stage fsync"):
            self.deployment().install(REPOSITORY)
        self.assertEqual(state_path.read_bytes(), prior_state)
        self.assertEqual(
            json.loads(state_path.read_text())["opencode"]["config_id"], old_id
        )
        self.assertFalse((self.root / "config/opencode" / expected_id).exists())
        self.assertEqual(list(self.root.parent.glob(".oc-rig-opencode-*.tmp")), [])

    def test_install_policy_refresh_fsyncs_stage_before_rename_and_parent_after(self) -> None:
        _old_id, expected_id, _old = self._old_policy_current_layout_fixture()
        target = self.root / "config/opencode" / expected_id
        opencode_root = target.parent
        events: list[str] = []
        real_tree_fsync = user_deployment_module._fsync_owned_tree
        real_replace = os.replace
        real_directory_fsync = user_deployment_module._fsync_directory

        def tree_fsync(path: Path, expected: object) -> None:
            events.append("stage-fsync")
            real_tree_fsync(path, expected)

        def replace(source: object, destination: object) -> None:
            if Path(destination) == target:
                events.append("rename")
            real_replace(source, destination)

        def directory_fsync(path: Path) -> None:
            if path == opencode_root:
                events.append("parent-fsync")
            real_directory_fsync(path)

        with patch.object(
            user_deployment_module, "_fsync_owned_tree", side_effect=tree_fsync
        ), patch.object(
            os, "replace", side_effect=replace
        ), patch.object(
            user_deployment_module, "_fsync_directory", side_effect=directory_fsync
        ):
            self.deployment().install(REPOSITORY)
        self.assertLess(events.index("stage-fsync"), events.index("rename"))
        self.assertLess(events.index("rename"), events.index("parent-fsync"))

    def test_exact_owned_removal_preserves_replacement_symlink(self) -> None:
        owned = self.base / "owned-tree"
        owned.mkdir()
        (owned / "file").write_bytes(b"owned")
        snapshot = user_deployment_module._snapshot_owned_tree(owned)
        moved = self.base / "moved-owned-tree"
        owned.rename(moved)
        foreign = self.base / "foreign-tree"
        foreign.mkdir()
        owned.symlink_to(foreign)
        self.assertFalse(
            user_deployment_module._remove_exact_owned_tree(owned, snapshot)
        )
        self.assertTrue(owned.is_symlink())
        self.assertTrue(foreign.is_dir())
        self.assertTrue((moved / "file").is_file())

    def test_install_policy_refresh_preserves_foreign_target_replacement(self) -> None:
        old_id, expected_id, _old = self._old_policy_current_layout_fixture()
        target = self.root / "config/opencode" / expected_id
        diverted = self.base / "diverted-owned-generation"
        real_replace = os.replace

        def replace_with_foreign(source: object, destination: object) -> None:
            if Path(destination) == target:
                real_replace(source, diverted)
                target.mkdir(mode=0o700)
                (target / "foreign").write_bytes(b"foreign")
                return
            real_replace(source, destination)

        with patch.object(
            os, "replace", side_effect=replace_with_foreign
        ), self.assertRaisesRegex(DeploymentError, "cleanup was incomplete"):
            self.deployment().install(REPOSITORY)
        self.assertTrue((target / "foreign").is_file())
        self.assertTrue((diverted / "auth.json").is_file())
        self.assertEqual(
            self.deployment().status()["opencode"]["config_id"], old_id
        )

    def test_install_atomically_migrates_stopped_three_file_opencode_generation(self) -> None:
        self.deployment().install(REPOSITORY)
        password = self.base / "legacy.password"
        topology_path = self.base / "legacy.topology.json"
        trust_path = self.base / "legacy.trust.json"
        password.write_text("private-basic-password-material", encoding="utf-8")
        topology_path.write_text(json.dumps(topology()), encoding="utf-8")
        trust_path.write_text(
            json.dumps({"mode": "secure", "secure_worker": "secure-worker"}),
            encoding="utf-8",
        )
        for path in (password, topology_path, trust_path):
            path.chmod(0o600)
        configured = self.deployment().configure_opencode(
            endpoint="http://127.0.0.1:4096",
            basic_username="opencode",
            basic_password_file=password,
            topology_file=topology_path,
            trust_file=trust_path,
        )
        generation = self.root / "config/opencode" / configured["config_id"]
        (generation / "provider-auth-seed.json").unlink()
        (generation / "automated-backend-policy.json").unlink()
        state_path = self.root / "deployment-state.json"
        state = json.loads(state_path.read_text())
        legacy_files = {
            name: (generation / name).read_bytes()
            for name in ("auth.json", "topology.json", "trust.json")
        }
        legacy_id = user_deployment_module._opencode_config_id(
            state["opencode"]["endpoint"], legacy_files
        )
        legacy_generation = generation.with_name(legacy_id)
        generation.rename(legacy_generation)
        state["opencode"]["config_id"] = legacy_id
        state["opencode"]["files"] = {
            name: user_deployment_module._config_file_pin(
                legacy_generation / name, (legacy_generation / name).read_bytes()
            )
            for name in legacy_files
        }
        state_path.write_text(
            json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        state_path.chmod(0o600)

        self.deployment().install(REPOSITORY)
        migrated = self.deployment().status()["opencode"]
        self.assertNotEqual(migrated["config_id"], legacy_id)
        target = self.root / "config/opencode" / migrated["config_id"]
        self.assertEqual((target / "provider-auth-seed.json").read_bytes(), b"{}\n")
        self.assertEqual(
            (target / "automated-backend-policy.json").read_bytes(),
            user_deployment_module._BACKEND_POLICY_BYTES,
        )
        self.assertFalse((target / "xdg-data").exists())
        self.assertTrue(legacy_generation.is_dir())

    def test_install_recovers_previous_generation_contaminated_by_runtime_data(self) -> None:
        _password, _topology, _trust, previous_generation, previous_id = (
            self._previous_contaminated_opencode_fixture()
        )
        with self.assertRaises(DeploymentError):
            self.deployment().status()

        self.deployment().install(REPOSITORY)
        migrated = self.deployment().status()["opencode"]
        target = self.root / "config/opencode" / migrated["config_id"]
        self.assertNotEqual(migrated["config_id"], previous_id)
        self.assertEqual((target / "provider-auth-seed.json").read_bytes(), b"{}\n")
        self.assertFalse((target / "xdg-data").exists())
        self.assertEqual((target / "automated-backend-policy.json").read_bytes(), user_deployment_module._BACKEND_POLICY_BYTES)
        self.assertTrue((previous_generation / "xdg-data/opencode/opencode.db").is_file())

    def test_configure_recovers_previous_contaminated_generation(self) -> None:
        password, topology_path, trust_path, previous_generation, previous_id = (
            self._previous_contaminated_opencode_fixture()
        )
        with self.assertRaises(DeploymentError):
            self.deployment().status()
        configured = self.deployment().configure_opencode(
            endpoint="http://127.0.0.1:4096",
            basic_username="opencode",
            basic_password_file=password,
            topology_file=topology_path,
            trust_file=trust_path,
        )
        self.assertNotEqual(configured["config_id"], previous_id)
        self.assertTrue(previous_generation.is_dir())
        self.assertFalse(
            (self.root / "config/opencode" / configured["config_id"] / "xdg-data").exists()
        )
        self.assertEqual(
            (
                self.root / "config/opencode" / configured["config_id"]
                / "automated-backend-policy.json"
            ).read_bytes(),
            user_deployment_module._BACKEND_POLICY_BYTES,
        )
        self.assertEqual(
            self.deployment().status()["opencode"]["config_id"], configured["config_id"]
        )

    def test_install_migrates_prior_current_generated_gitignore(self) -> None:
        _password, _topology, _trust, prior_generation, prior_id = (
            self._prior_current_gitignore_contamination_fixture()
        )
        with self.assertRaises(DeploymentError):
            self.deployment().status()
        self.deployment().install(REPOSITORY)
        selected = self.deployment().status()["opencode"]["config_id"]
        self.assertNotEqual(selected, prior_id)
        target = self.root / "config/opencode" / selected
        self.assertEqual((target / "automated-backend-policy.json").read_bytes(), user_deployment_module._BACKEND_POLICY_BYTES)
        self.assertTrue(prior_generation.is_dir())

    def test_configure_migrates_prior_current_generated_gitignore(self) -> None:
        password, topology_path, trust_path, _prior_generation, prior_id = (
            self._prior_current_gitignore_contamination_fixture()
        )
        configured = self.deployment().configure_opencode(
            endpoint="http://127.0.0.1:4096",
            basic_username="opencode",
            basic_password_file=password,
            topology_file=topology_path,
            trust_file=trust_path,
        )
        self.assertNotEqual(configured["config_id"], prior_id)
        target = self.root / "config/opencode" / configured["config_id"]
        self.assertEqual(
            (target / "automated-backend-policy.json").read_bytes(),
            user_deployment_module._BACKEND_POLICY_BYTES,
        )

    def test_prior_current_gitignore_migration_rejects_deviation_and_race(self) -> None:
        _password, _topology, _trust, generation, prior_id = (
            self._prior_current_gitignore_contamination_fixture()
        )
        state_path = self.root / "deployment-state.json"
        prior_state = state_path.read_bytes()
        gitignore = generation / "xdg/opencode/.gitignore"
        expected = user_deployment_module._BACKEND_GITIGNORE
        backend = generation / "xdg/opencode/opencode.json"
        canonical_backend = user_deployment_module._BACKEND_CONFIG

        gitignore.unlink()
        with self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        gitignore.write_bytes(expected)
        gitignore.chmod(0o644)

        for invalid_backend in (
            user_deployment_module._PRIOR_BACKEND_CONFIG,
            b'{"$schema":"https://opencode.ai/config.json","mcp":{},"plugin":[]}',
            b'{\n  "$schema": "https://opencode.ai/config.json","mcp":{"unsafe":{}},"plugin":[]}\n',
        ):
            with self.subTest(backend=invalid_backend):
                backend.write_bytes(invalid_backend)
                with self.assertRaises(DeploymentError):
                    self.deployment().install(REPOSITORY)
        backend.write_bytes(canonical_backend)
        backend.chmod(0o600)

        gitignore.write_bytes(b"x" * len(expected))
        with self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        gitignore.write_bytes(expected)
        gitignore.chmod(0o600)
        with self.assertRaisesRegex(DeploymentError, "identity is unsafe"):
            self.deployment().install(REPOSITORY)
        gitignore.chmod(0o644)

        extra = gitignore.with_name("unexpected.json")
        extra.write_text("{}\n", encoding="utf-8")
        extra.chmod(0o600)
        with self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        extra.unlink()

        original = user_deployment_module._read_legacy_pinned_file
        replaced = False

        def replace_after_read(descriptor: int, size: int) -> bytes:
            nonlocal replaced
            content = original(descriptor, size)
            if content == expected and not replaced:
                replaced = True
                replacement = gitignore.with_name("replacement.gitignore")
                replacement.write_bytes(b"arbitrary")
                replacement.chmod(0o644)
                replacement.replace(gitignore)
            return content

        with patch(
            "oc_rig.deployment.user._read_legacy_pinned_file",
            side_effect=replace_after_read,
        ), self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        self.assertTrue(replaced)
        self.assertEqual(state_path.read_bytes(), prior_state)
        self.assertEqual(json.loads(prior_state)["opencode"]["config_id"], prior_id)

    def test_prior_current_backend_reconciliation_detects_replacement_race(self) -> None:
        _password, _topology, _trust, generation, _prior_id = (
            self._prior_current_gitignore_contamination_fixture()
        )
        backend = generation / "xdg/opencode/opencode.json"
        original = user_deployment_module._validate_semantic_legacy_backend_config
        replaced = False

        def replace_after_validation(content: bytes) -> None:
            nonlocal replaced
            original(content)
            if content == user_deployment_module._BACKEND_CONFIG and not replaced:
                replaced = True
                replacement = backend.with_name("replacement-opencode.json")
                replacement.write_bytes(
                    b'{"$schema":"https://opencode.ai/config.json","mcp":{"unsafe":{}},"plugin":[]}'
                )
                replacement.chmod(0o600)
                replacement.replace(backend)

        with patch(
            "oc_rig.deployment.user._validate_semantic_legacy_backend_config",
            side_effect=replace_after_validation,
        ), self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        self.assertTrue(replaced)

    def test_failed_start_historical_generation_is_exact_and_race_bound(self) -> None:
        _password, _topology, _trust, generation, config_id = (
            self._prior_current_gitignore_contamination_fixture()
        )
        endpoint = "http://127.0.0.1:4096"
        validated = (
            user_deployment_module.validated_failed_start_historical_opencode_configuration(
                self.root, config_id=config_id, endpoint=endpoint
            )
        )
        self.assertEqual(validated.config_id, config_id)
        gitignore = generation / "xdg/opencode/.gitignore"
        backend = generation / "xdg/opencode/opencode.json"

        gitignore.chmod(0o600)
        with self.assertRaises(DeploymentError):
            user_deployment_module.validated_failed_start_historical_opencode_configuration(
                self.root, config_id=config_id, endpoint=endpoint
            )
        gitignore.chmod(0o644)
        gitignore.write_bytes(b"x" * len(user_deployment_module._BACKEND_GITIGNORE))
        with self.assertRaises(DeploymentError):
            user_deployment_module.validated_failed_start_historical_opencode_configuration(
                self.root, config_id=config_id, endpoint=endpoint
            )
        gitignore.write_bytes(user_deployment_module._BACKEND_GITIGNORE)
        gitignore.chmod(0o644)

        backend.write_bytes(
            b'{"$schema":"https://opencode.ai/config.json","mcp":{},"plugin":[]}'
        )
        with self.assertRaises(DeploymentError):
            user_deployment_module.validated_failed_start_historical_opencode_configuration(
                self.root, config_id=config_id, endpoint=endpoint
            )
        backend.write_bytes(user_deployment_module._BACKEND_CONFIG)
        backend.chmod(0o600)

        extra = generation / "xdg/opencode/unexpected.json"
        extra.write_text("{}\n", encoding="utf-8")
        extra.chmod(0o600)
        with self.assertRaises(DeploymentError):
            user_deployment_module.validated_failed_start_historical_opencode_configuration(
                self.root, config_id=config_id, endpoint=endpoint
            )
        extra.unlink()

        original = user_deployment_module._bounded_descriptor_names
        swapped = False

        def replace_after_scan(descriptor: int, limit: int) -> tuple[str, ...]:
            nonlocal swapped
            names = original(descriptor, limit)
            if not swapped and ".gitignore" in names:
                swapped = True
                replacement = gitignore.with_name("replacement.gitignore")
                replacement.write_bytes(b"arbitrary")
                replacement.chmod(0o644)
                replacement.replace(gitignore)
            return names

        with patch(
            "oc_rig.deployment.user._bounded_descriptor_names",
            side_effect=replace_after_scan,
        ), self.assertRaises(DeploymentError):
            user_deployment_module.validated_failed_start_historical_opencode_configuration(
                self.root, config_id=config_id, endpoint=endpoint
            )
        self.assertTrue(swapped)

    def test_failed_start_historical_special_leaf_rejects_without_blocking(self) -> None:
        _password, _topology, _trust, generation, config_id = (
            self._prior_current_gitignore_contamination_fixture()
        )
        endpoint = "http://127.0.0.1:4096"
        leaf = generation / "provider-auth-seed.json"
        leaf.unlink()

        def alarm(_signal: int, _frame: object) -> None:
            raise TimeoutError("special leaf validation blocked")

        previous = signal.signal(signal.SIGALRM, alarm)
        try:
            os.mkfifo(leaf, 0o600)
            signal.setitimer(signal.ITIMER_REAL, 0.5)
            started = time.monotonic()
            with self.assertRaises(DeploymentError):
                user_deployment_module.validated_failed_start_historical_opencode_configuration(
                    self.root, config_id=config_id, endpoint=endpoint
                )
            self.assertLess(time.monotonic() - started, 0.5)
            signal.setitimer(signal.ITIMER_REAL, 0)
            leaf.unlink()

            special = socket.socket(socket.AF_UNIX)
            self.addCleanup(special.close)
            short_socket = Path("/tmp") / (
                f"oc-rig-special-{os.getpid()}-{time.time_ns()}"
            )
            self.addCleanup(lambda: short_socket.unlink(missing_ok=True))
            special.bind(str(short_socket))
            short_socket.replace(leaf)
            signal.setitimer(signal.ITIMER_REAL, 0.5)
            started = time.monotonic()
            with self.assertRaises(DeploymentError):
                user_deployment_module.validated_failed_start_historical_opencode_configuration(
                    self.root, config_id=config_id, endpoint=endpoint
                )
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)

    def test_install_discards_bounded_selected_xdg_pollution(self) -> None:
        polluted, old_id = self._polluted_selected_generation_fixture()
        with self.assertRaises(DeploymentError):
            self.deployment().status()
        self.deployment().install(REPOSITORY)
        selected = self.deployment().status()["opencode"]["config_id"]
        self.assertNotEqual(selected, old_id)
        target = self.root / "config/opencode" / selected
        self.assertEqual(
            (target / "automated-backend-policy.json").read_bytes(),
            user_deployment_module._BACKEND_POLICY_BYTES,
        )
        self.assertFalse((target / "xdg").exists())
        self.assertTrue((polluted / "xdg/opencode/node_modules/package.txt").is_file())
        self.assertTrue(
            (polluted / "xdg/opencode/node_modules/.bin/package-tool").is_symlink()
        )

    def test_selected_xdg_pollution_rejects_unsafe_debris(self) -> None:
        polluted, _old_id = self._polluted_selected_generation_fixture()
        package = polluted / "xdg/opencode/package.json"
        package.chmod(0o666)
        with self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        package.chmod(0o644)
        link = polluted / "xdg/opencode/node_modules/link"
        link.symlink_to(polluted / "trust.json")
        with self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)

    def test_selected_xdg_pollution_symlinks_are_exactly_bounded(self) -> None:
        polluted, _old_id = self._polluted_selected_generation_fixture()
        link = polluted / "xdg/opencode/node_modules/.bin/package-tool"
        link.unlink()
        link.symlink_to("/private/escape")
        with self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        link.unlink()
        link.symlink_to("../../../../trust.json")
        with self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        link.unlink()
        link.symlink_to("../package.txt")
        outside = polluted / "xdg/opencode/unexpected-link"
        outside.symlink_to("node_modules/package.txt")
        with self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        outside.unlink()
        with patch(
            "oc_rig.deployment.user._legacy_symlink_has_extended_acl",
            return_value=True,
        ), self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)

        original_readlink = os.readlink
        calls = 0

        def racing_readlink(path: object, *, dir_fd: int | None = None) -> str:
            nonlocal calls
            value = original_readlink(path, dir_fd=dir_fd)
            if value == "../package.txt":
                calls += 1
                return value if calls == 1 else "../other.txt"
            return value

        with patch(
            "oc_rig.deployment.user.os.readlink", side_effect=racing_readlink
        ), self.assertRaisesRegex(DeploymentError, "changed during validation"):
            self.deployment().install(REPOSITORY)

    def test_selected_xdg_package_executables_are_narrow_and_race_bound(self) -> None:
        polluted, _old_id = self._polluted_selected_generation_fixture()
        executable = polluted / "xdg/opencode/node_modules/package/bin/tool"
        native = polluted / "xdg/opencode/node_modules/package/native.node"
        self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(native.stat().st_mode), 0o755)

        for unsafe_mode in (0o4755, 0o775, 0o757, 0o744):
            with self.subTest(mode=oct(unsafe_mode)):
                executable.chmod(unsafe_mode)
                with self.assertRaises(DeploymentError):
                    self.deployment().install(REPOSITORY)
        executable.chmod(0o755)

        outside = polluted / "xdg/opencode/package.json"
        outside.chmod(0o755)
        with self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        outside.chmod(0o644)

        target_inode = executable.stat().st_ino
        original_facts = user_deployment_module._legacy_descriptor_facts
        calls = 0

        def racing_facts(descriptor: int) -> tuple[int, ...]:
            nonlocal calls
            facts = original_facts(descriptor)
            if os.fstat(descriptor).st_ino == target_inode:
                calls += 1
                if calls == 2:
                    return (*facts[:-1], facts[-1] + 1)
            return facts

        with patch(
            "oc_rig.deployment.user._legacy_descriptor_facts",
            side_effect=racing_facts,
        ), self.assertRaisesRegex(DeploymentError, "changed during validation"):
            self.deployment().install(REPOSITORY)

    def test_polluted_historical_generation_revalidates_full_debris(self) -> None:
        polluted, config_id = self._polluted_selected_generation_fixture()
        endpoint = "http://127.0.0.1:4096"
        validated = (
            user_deployment_module.validated_polluted_historical_opencode_configuration(
                self.root, config_id=config_id, endpoint=endpoint
            )
        )
        self.assertEqual(validated.config_id, config_id)
        package = polluted / "xdg/opencode/node_modules/package.txt"
        package.chmod(0o666)
        with self.assertRaises(DeploymentError):
            user_deployment_module.validated_polluted_historical_opencode_configuration(
                self.root, config_id=config_id, endpoint=endpoint
            )
        package.chmod(0o644)
        extra = polluted / "outside-debris"
        extra.write_text("unsafe\n", encoding="utf-8")
        extra.chmod(0o600)
        with self.assertRaises(DeploymentError):
            user_deployment_module.validated_polluted_historical_opencode_configuration(
                self.root, config_id=config_id, endpoint=endpoint
            )
        extra.unlink()

        original_names = user_deployment_module._bounded_descriptor_names
        changed = False

        def mutate_after_scan(descriptor: int, limit: int) -> tuple[str, ...]:
            nonlocal changed
            names = original_names(descriptor, limit)
            if not changed and "package.txt" in names:
                changed = True
                package.write_text("changed\n", encoding="utf-8")
                package.chmod(0o644)
            return names

        with patch(
            "oc_rig.deployment.user._bounded_descriptor_names",
            side_effect=mutate_after_scan,
        ), self.assertRaises(DeploymentError):
            user_deployment_module.validated_polluted_historical_opencode_configuration(
                self.root, config_id=config_id, endpoint=endpoint
            )
        self.assertTrue(changed)

    def test_malformed_contaminated_generation_fails_without_migration(self) -> None:
        _password, _topology, _trust, previous_generation, previous_id = (
            self._previous_contaminated_opencode_fixture()
        )
        runtime = previous_generation / "xdg-data/opencode"
        (runtime / "foreign-link").symlink_to(previous_generation / "trust.json")
        prior_state = (self.root / "deployment-state.json").read_bytes()
        with self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        self.assertEqual((self.root / "deployment-state.json").read_bytes(), prior_state)
        self.assertEqual(
            json.loads(prior_state)["opencode"]["config_id"], previous_id
        )

    def test_contaminated_generation_entry_bound_is_enforced_before_accumulation(self) -> None:
        _password, _topology, _trust, generation, _previous_id = (
            self._previous_contaminated_opencode_fixture()
        )
        runtime = generation / "xdg-data/opencode/repos"
        for index in range(user_deployment_module._LEGACY_ENTRY_LIMIT):
            path = runtime / f"entry-{index:04d}"
            path.touch(mode=0o600)
        with self.assertRaisesRegex(DeploymentError, "entry bounds"):
            self.deployment().install(REPOSITORY)

    def test_contaminated_generation_depth_and_path_bounds_are_enforced(self) -> None:
        _password, _topology, _trust, generation, _previous_id = (
            self._previous_contaminated_opencode_fixture()
        )
        runtime = generation / "xdg-data/opencode/repos"
        cursor = runtime
        for index in range(user_deployment_module._LEGACY_DEPTH_LIMIT):
            cursor /= f"d{index}"
            cursor.mkdir(mode=0o700)
        with self.assertRaisesRegex(DeploymentError, "depth bounds"):
            self.deployment().install(REPOSITORY)

        shutil.rmtree(runtime)
        runtime.mkdir(mode=0o700)
        cursor = runtime
        for index in range(4):
            cursor /= f"p{index}-" + ("x" * 196)
            cursor.mkdir(mode=0o700)
        with self.assertRaisesRegex(DeploymentError, "path bounds"):
            self.deployment().install(REPOSITORY)

    def test_contaminated_generation_rejects_hardlink_unsafe_modes_and_acl(self) -> None:
        _password, _topology, _trust, generation, _previous_id = (
            self._previous_contaminated_opencode_fixture()
        )
        runtime = generation / "xdg-data/opencode"
        os.link(runtime / "opencode.db", runtime / "hardlink.db")
        with self.assertRaisesRegex(DeploymentError, "identity is unsafe"):
            self.deployment().install(REPOSITORY)
        (runtime / "hardlink.db").unlink()
        for path, unsafe_mode, restored_mode in (
            (runtime / "log", 0o775, 0o755),
            (runtime / "repos", 0o757, 0o755),
            (runtime / "opencode.db", 0o664, 0o644),
            (runtime / "opencode.db", 0o646, 0o644),
            (runtime / "opencode.db", 0o744, 0o644),
        ):
            with self.subTest(path=path.name, mode=oct(unsafe_mode)):
                path.chmod(unsafe_mode)
                with self.assertRaisesRegex(DeploymentError, "identity is unsafe"):
                    self.deployment().install(REPOSITORY)
                path.chmod(restored_mode)
        target_inode = (runtime / "opencode.db").stat().st_ino
        original_fstat = os.fstat

        def foreign_owner(descriptor: int) -> os.stat_result:
            details = original_fstat(descriptor)
            if details.st_ino != target_inode:
                return details
            values = list(details)
            values[4] = os.geteuid() + 1
            return os.stat_result(values)

        with patch(
            "oc_rig.deployment.user.os.fstat", side_effect=foreign_owner
        ), self.assertRaisesRegex(DeploymentError, "identity is unsafe"):
            self.deployment().install(REPOSITORY)
        original_acl = user_deployment_module._has_extended_acl

        def descriptor_acl(path: Path) -> bool:
            if path.parent in {Path("/dev/fd"), Path("/proc/self/fd")}:
                try:
                    if os.fstat(int(path.name)).st_ino == target_inode:
                        return True
                except (OSError, ValueError):
                    pass
            return original_acl(path)

        with patch(
            "oc_rig.deployment.user._has_extended_acl", side_effect=descriptor_acl
        ), self.assertRaisesRegex(DeploymentError, "identity is unsafe"):
            self.deployment().install(REPOSITORY)

    def test_legacy_gitignore_discard_requires_exact_safe_file(self) -> None:
        _password, _topology, _trust, generation, _previous_id = (
            self._previous_contaminated_opencode_fixture()
        )
        gitignore = generation / "xdg/opencode/.gitignore"
        expected = user_deployment_module._LEGACY_DISCARD_FILES[
            "xdg/opencode/.gitignore"
        ]

        gitignore.write_bytes(b"x" * len(expected))
        with self.assertRaisesRegex(DeploymentError, "content is unexpected"):
            self.deployment().install(REPOSITORY)
        gitignore.write_bytes(expected)
        for unsafe_mode in (0o664, 0o744):
            with self.subTest(mode=oct(unsafe_mode)):
                gitignore.chmod(unsafe_mode)
                with self.assertRaisesRegex(DeploymentError, "identity is unsafe"):
                    self.deployment().install(REPOSITORY)
        gitignore.chmod(0o644)

        hardlink = gitignore.with_name("gitignore-hardlink")
        os.link(gitignore, hardlink)
        with self.assertRaisesRegex(DeploymentError, "identity is unsafe"):
            self.deployment().install(REPOSITORY)
        hardlink.unlink()

        gitignore.unlink()
        gitignore.symlink_to(generation / "trust.json")
        with self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        gitignore.unlink()
        gitignore.write_bytes(expected)
        gitignore.chmod(0o644)

        unexpected = gitignore.with_name(".gitignore.backup")
        unexpected.write_bytes(expected)
        unexpected.chmod(0o644)
        with self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        unexpected.unlink()

        target_inode = gitignore.stat().st_ino
        original_acl = user_deployment_module._has_extended_acl

        def discard_acl(path: Path) -> bool:
            if path.parent in {Path("/dev/fd"), Path("/proc/self/fd")}:
                try:
                    if os.fstat(int(path.name)).st_ino == target_inode:
                        return True
                except (OSError, ValueError):
                    pass
            return original_acl(path)

        with patch(
            "oc_rig.deployment.user._has_extended_acl", side_effect=discard_acl
        ), self.assertRaisesRegex(DeploymentError, "identity is unsafe"):
            self.deployment().install(REPOSITORY)

    def test_legacy_gitignore_discard_detects_replacement_race(self) -> None:
        _password, _topology, _trust, generation, _previous_id = (
            self._previous_contaminated_opencode_fixture()
        )
        gitignore = generation / "xdg/opencode/.gitignore"
        expected = user_deployment_module._LEGACY_DISCARD_FILES[
            "xdg/opencode/.gitignore"
        ]
        original = user_deployment_module._read_legacy_pinned_file
        replaced = False

        def replace_after_read(descriptor: int, size: int) -> bytes:
            nonlocal replaced
            content = original(descriptor, size)
            if content == expected and not replaced:
                replaced = True
                replacement = gitignore.with_name("replacement.gitignore")
                replacement.write_bytes(b"arbitrary")
                replacement.chmod(0o644)
                replacement.replace(gitignore)
            return content

        with patch(
            "oc_rig.deployment.user._read_legacy_pinned_file",
            side_effect=replace_after_read,
        ), self.assertRaisesRegex(
            DeploymentError, "(identity changed|changed during validation)"
        ):
            self.deployment().install(REPOSITORY)
        self.assertTrue(replaced)

    def test_legacy_backend_reconciliation_rejects_semantic_changes(self) -> None:
        _password, _topology, _trust, generation, _previous_id = (
            self._previous_contaminated_opencode_fixture()
        )
        backend = generation / "xdg/opencode/opencode.json"
        valid = backend.read_bytes()
        invalid_documents = (
            b'{"$schema":"https://example.invalid/config.json","mcp":{},"plugin":[]}',
            b'{"$schema":"https://opencode.ai/config.json","mcp":{},"plugin":[],"extra":true}',
            b'{"$schema":"https://opencode.ai/config.json","mcp":{"unsafe":{}},"plugin":[]}',
            b'{"$schema":"https://opencode.ai/config.json","mcp":{},"plugin":["unsafe"]}',
            b'{"$schema":"https://opencode.ai/config.json","$schema":"https://opencode.ai/config.json","mcp":{},"plugin":[]}',
            b'{"$schema":"https://opencode.ai/config.json","mcp":{},',
        )
        for document in invalid_documents:
            with self.subTest(document=document):
                backend.write_bytes(document)
                with self.assertRaises(DeploymentError):
                    self.deployment().install(REPOSITORY)
        backend.write_bytes(valid)
        backend.chmod(0o600)

    def test_legacy_backend_reconciliation_requires_strict_identity(self) -> None:
        _password, _topology, _trust, generation, _previous_id = (
            self._previous_contaminated_opencode_fixture()
        )
        backend = generation / "xdg/opencode/opencode.json"
        valid = backend.read_bytes()
        for unsafe_mode in (0o644, 0o700):
            with self.subTest(mode=oct(unsafe_mode)):
                backend.chmod(unsafe_mode)
                with self.assertRaisesRegex(DeploymentError, "identity is unsafe"):
                    self.deployment().install(REPOSITORY)
        backend.chmod(0o600)

        hardlink = backend.with_name("opencode-hardlink.json")
        os.link(backend, hardlink)
        with self.assertRaisesRegex(DeploymentError, "identity is unsafe"):
            self.deployment().install(REPOSITORY)
        hardlink.unlink()

        backend.unlink()
        backend.symlink_to(generation / "trust.json")
        with self.assertRaises(DeploymentError):
            self.deployment().install(REPOSITORY)
        backend.unlink()
        backend.write_bytes(valid)
        backend.chmod(0o600)

        target_inode = backend.stat().st_ino
        original_acl = user_deployment_module._has_extended_acl

        def backend_acl(path: Path) -> bool:
            if path.parent in {Path("/dev/fd"), Path("/proc/self/fd")}:
                try:
                    if os.fstat(int(path.name)).st_ino == target_inode:
                        return True
                except (OSError, ValueError):
                    pass
            return original_acl(path)

        with patch(
            "oc_rig.deployment.user._has_extended_acl", side_effect=backend_acl
        ), self.assertRaisesRegex(DeploymentError, "identity is unsafe"):
            self.deployment().install(REPOSITORY)

    def test_legacy_backend_reconciliation_detects_replacement_race(self) -> None:
        _password, _topology, _trust, generation, _previous_id = (
            self._previous_contaminated_opencode_fixture()
        )
        backend = generation / "xdg/opencode/opencode.json"
        original = user_deployment_module._validate_semantic_legacy_backend_config
        replaced = False

        def replace_after_validation(content: bytes) -> None:
            nonlocal replaced
            original(content)
            if not replaced:
                replaced = True
                replacement = backend.with_name("replacement-opencode.json")
                replacement.write_bytes(b'{"mcp":{"unsafe":{}},"plugin":[]}')
                replacement.chmod(0o600)
                replacement.replace(backend)

        with patch(
            "oc_rig.deployment.user._validate_semantic_legacy_backend_config",
            side_effect=replace_after_validation,
        ), self.assertRaisesRegex(
            DeploymentError, "(identity changed|changed during validation)"
        ):
            self.deployment().install(REPOSITORY)
        self.assertTrue(replaced)

    def test_contaminated_generation_detects_directory_replacement_race(self) -> None:
        _password, _topology, _trust, generation, _previous_id = (
            self._previous_contaminated_opencode_fixture()
        )
        repos = generation / "xdg-data/opencode/repos"
        original = user_deployment_module._bounded_descriptor_names
        swapped = False

        def replace_after_scan(descriptor: int, limit: int) -> tuple[str, ...]:
            nonlocal swapped
            names = original(descriptor, limit)
            if not swapped and names == ("repository.json",):
                swapped = True
                repos.rename(repos.with_name("repos-old"))
                repos.mkdir(mode=0o700)
            return names

        with patch(
            "oc_rig.deployment.user._bounded_descriptor_names",
            side_effect=replace_after_scan,
        ), self.assertRaisesRegex(DeploymentError, "changed during validation"):
            self.deployment().install(REPOSITORY)
        self.assertTrue(swapped)

    def test_contaminated_generation_revalidates_descendants_before_publication(self) -> None:
        _password, _topology, _trust, generation, previous_id = (
            self._previous_contaminated_opencode_fixture()
        )
        state_path = self.root / "deployment-state.json"
        prior_state = state_path.read_bytes()
        database = generation / "xdg-data/opencode/opencode.db"
        original = (
            user_deployment_module._validate_legacy_contaminated_opencode_configuration
        )
        calls = 0

        def replace_after_snapshot(root: Path, state: dict[str, object]):
            nonlocal calls
            evidence = original(root, state)
            calls += 1
            if calls == 1:
                replacement = database.with_name("replacement.db")
                replacement.write_bytes(b"changed runtime database")
                replacement.chmod(0o600)
                replacement.replace(database)
            return evidence

        with patch(
            "oc_rig.deployment.user._validate_legacy_contaminated_opencode_configuration",
            side_effect=replace_after_snapshot,
        ), self.assertRaisesRegex(DeploymentError, "changed before publication"):
            self.deployment().install(REPOSITORY)
        self.assertGreaterEqual(calls, 2)
        self.assertEqual(state_path.read_bytes(), prior_state)
        self.assertEqual(json.loads(prior_state)["opencode"]["config_id"], previous_id)

    def test_contaminated_generation_migration_rolls_back_failed_publication(self) -> None:
        _password, _topology, _trust, previous_generation, previous_id = (
            self._previous_contaminated_opencode_fixture()
        )
        state_path = self.root / "deployment-state.json"
        prior_state = state_path.read_bytes()
        opencode_root = previous_generation.parent
        prior_generations = {entry.name for entry in opencode_root.iterdir()}
        original = user_deployment_module._validate_opencode_configuration

        def reject_current(root: Path, state: dict[str, object], **kwargs: object):
            selected = state.get("opencode")
            files = selected.get("files", {}) if isinstance(selected, dict) else {}
            if (
                not kwargs.get("_allow_previous_contaminated", False)
                and "provider-auth-seed.json" in files
            ):
                raise DeploymentError("injected current-generation validation failure")
            return original(root, state, **kwargs)

        with patch(
            "oc_rig.deployment.user._validate_opencode_configuration",
            side_effect=reject_current,
        ), self.assertRaisesRegex(DeploymentError, "injected"):
            self.deployment().install(REPOSITORY)
        self.assertEqual(state_path.read_bytes(), prior_state)
        self.assertEqual({entry.name for entry in opencode_root.iterdir()}, prior_generations)
        self.assertEqual(json.loads(prior_state)["opencode"]["config_id"], previous_id)

    def test_codex_callback_is_explicit_private_and_launcher_configured(self) -> None:
        self.deployment().install(REPOSITORY)
        password = self.base / "callback.password"
        topology_path = self.base / "callback.topology.json"
        trust_path = self.base / "callback.trust.json"
        password.write_text("private-basic-password-material", encoding="utf-8")
        topology_path.write_text(json.dumps(topology()), encoding="utf-8")
        trust_path.write_text(
            json.dumps({"mode": "secure", "secure_worker": "secure-worker"}),
            encoding="utf-8",
        )
        for path in (password, topology_path, trust_path):
            path.chmod(0o600)
        self.deployment().configure_opencode(
            endpoint="http://127.0.0.1:4096",
            basic_username="opencode",
            basic_password_file=password,
            topology_file=topology_path,
            trust_file=trust_path,
        )
        executable = self.base / "codex-reviewed"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)
        codex_home = self.base / "codex-home"
        codex_home.mkdir(mode=0o700)
        configured = self.deployment().configure_codex_callback(
            executable=executable,
            home=self.home,
            codex_home=codex_home,
            timeout_seconds=12.0,
        )
        self.assertTrue(configured["configured"])
        status = self.deployment().status()
        self.assertEqual(status["codex_callback"], {"configured": True})
        self.assertNotIn(str(executable), json.dumps(status))
        state = json.loads(
            (self.root / "deployment-state.json").read_text(encoding="utf-8")
        )
        self.assertEqual(state["codex_callback"]["timeout_seconds"], 12.0)
        self.assertEqual(
            state["codex_callback"]["format"], CODEX_CALLBACK_CONFIG_FORMAT
        )
        self.assertEqual(state["opencode"]["format"], OPENCODE_CONFIG_FORMAT)
        callback_pin = state["codex_callback"]["executable_pin"]
        self.assertNotIn("device", callback_pin)
        self.assertIn("volume_uuid", callback_pin)
        for config_pin in state["opencode"]["files"].values():
            self.assertNotIn("device", config_pin)
            self.assertIn("volume_uuid", config_pin)
        launcher = (self.root / "launcher.py").read_text(encoding="utf-8")
        self.assertIn("--codex-executable", launcher)
        self.assertIn("--codex-callback-timeout", launcher)

        config_files = {
            self.root / "config" / "opencode" / state["opencode"]["config_id"] / name
            for name in ("auth.json", "topology.json", "trust.json")
        }
        real_lstat = Path.lstat
        real_fstat = os.fstat

        class RemountedStat:
            def __init__(self, original: os.stat_result):
                self._original = original
                self.st_dev = original.st_dev + 3

            def __getattr__(self, name: str) -> object:
                return getattr(self._original, name)

        def remounted_lstat(path: Path) -> os.stat_result | RemountedStat:
            details = real_lstat(path)
            if path in config_files:
                return RemountedStat(details)
            return details

        def remounted_fstat(descriptor: int) -> os.stat_result | RemountedStat:
            details = real_fstat(descriptor)
            try:
                opened_path = Path(os.readlink(f"/dev/fd/{descriptor}"))
            except OSError:
                return details
            if opened_path == executable:
                return RemountedStat(details)
            return details

        with (
            patch.object(Path, "lstat", remounted_lstat),
            patch("oc_rig.deployment.user.os.fstat", side_effect=remounted_fstat),
        ):
            self.assertEqual(
                self.deployment().status()["codex_callback"], {"configured": True}
            )

        real_volume_uuid = _native_volume_uuid
        moved_config = next(iter(config_files))

        def moved_volume_uuid(
            *, path: Path | None = None, descriptor: int | None = None
        ) -> str:
            if path == moved_config:
                return "00000000-0000-4000-8000-000000000002"
            return real_volume_uuid(path=path, descriptor=descriptor)

        with patch(
            "oc_rig.deployment.user._native_volume_uuid",
            side_effect=moved_volume_uuid,
        ), self.assertRaisesRegex(DeploymentError, "identity or hash changed"):
            self.deployment().status()

        executable.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        executable.chmod(0o700)
        with self.assertRaisesRegex(DeploymentError, "identity changed"):
            self.deployment().status()

    def test_explicit_stopped_callback_refresh_accepts_legitimate_upgrade_only(self) -> None:
        executable, ownership, tmux = self._callback_refresh_fixture()
        before = json.loads((self.root / "deployment-state.json").read_text())
        executable.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
        executable.chmod(0o700)
        with self.assertRaisesRegex(DeploymentError, "identity changed"):
            self.deployment().status()
        with self.assertRaisesRegex(DeploymentError, "identity changed"):
            self.deployment().start()
        self.assertFalse(json.loads(self.launch_state.read_text())["running"])
        result = self.deployment().refresh_codex_callback(executable=executable, terminal_ownership=ownership, tmux=tmux)
        self.assertTrue(result["configured"])
        after = json.loads((self.root / "deployment-state.json").read_text())
        self.assertEqual(after["current"], before["current"])
        self.assertEqual(after["previous"], before["previous"])
        self.assertEqual(after["opencode"], before["opencode"])
        for name in ("codex_home", "format", "home", "timeout_seconds"):
            self.assertEqual(after["codex_callback"][name], before["codex_callback"][name])
        self.assertNotEqual(after["codex_callback"]["executable_pin"], before["codex_callback"]["executable_pin"])
        self.assertEqual(self.deployment().status()["codex_callback"], {"configured": True})

    def test_stale_callback_pin_can_stop_before_explicit_refresh(self) -> None:
        executable, ownership, tmux = self._callback_refresh_fixture()
        self._set_job_running(True)
        executable.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
        executable.chmod(0o700)

        result = self.deployment().stop()
        self.assertFalse(result["dry_run"])
        self.assertFalse(json.loads(self.launch_state.read_text())["running"])
        with self.assertRaisesRegex(DeploymentError, "identity changed"):
            self.deployment().status()
        self.assertFalse(self.deployment().stop_status()["job"]["running"])

        refreshed = self.deployment().refresh_codex_callback(
            executable=executable,
            terminal_ownership=ownership,
            tmux=tmux,
        )
        self.assertTrue(refreshed["configured"])
        self.assertEqual(
            self.deployment().status()["codex_callback"], {"configured": True}
        )

    def test_callback_refresh_dry_run_validates_but_does_not_write(self) -> None:
        executable, ownership, tmux = self._callback_refresh_fixture()
        executable.write_text("#!/bin/sh\nexit 8\n", encoding="utf-8")
        executable.chmod(0o700)
        state = (self.root / "deployment-state.json").read_bytes()
        result = self.deployment(dry_run=True).refresh_codex_callback(executable=executable, terminal_ownership=ownership, tmux=tmux)
        self.assertTrue(result["dry_run"])
        self.assertEqual((self.root / "deployment-state.json").read_bytes(), state)

    def test_callback_refresh_refuses_running_controller(self) -> None:
        executable, ownership, tmux = self._callback_refresh_fixture()
        executable.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
        executable.chmod(0o700)
        self._set_job_running(True)
        state = (self.root / "deployment-state.json").read_bytes()
        with self.assertRaisesRegex(DeploymentError, "stop it first"):
            self.deployment(dry_run=True).refresh_codex_callback(executable=executable, terminal_ownership=ownership, tmux=tmux)
        with self.assertRaisesRegex(DeploymentError, "stop it first"):
            self.deployment().refresh_codex_callback(executable=executable, terminal_ownership=ownership, tmux=tmux)
        self.assertEqual((self.root / "deployment-state.json").read_bytes(), state)
        self._set_job_running(False)
        tmux.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        tmux.chmod(0o700)
        with self.assertRaisesRegex(DeploymentError, "tmux session is still running"):
            self.deployment().refresh_codex_callback(executable=executable, terminal_ownership=ownership, tmux=tmux)
        self.assertEqual((self.root / "deployment-state.json").read_bytes(), state)
        tmux.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        tmux.chmod(0o700)
        endpoint = json.loads(state)["opencode"]["endpoint"]
        port = int(endpoint.rsplit(":", 1)[1])
        with closing(socket.socket()) as backend:
            backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            backend.bind(("127.0.0.1", port))
            backend.listen()
            with self.assertRaisesRegex(DeploymentError, "backend is still running"):
                self.deployment().refresh_codex_callback(executable=executable, terminal_ownership=ownership, tmux=tmux)
        self.assertEqual((self.root / "deployment-state.json").read_bytes(), state)

    def test_callback_refresh_refuses_unrelated_config_tamper(self) -> None:
        executable, ownership, tmux = self._callback_refresh_fixture()
        state_path = self.root / "deployment-state.json"
        state = json.loads(state_path.read_text())
        trust = self.root / "config" / "opencode" / state["opencode"]["config_id"] / "trust.json"
        trust.write_text('{"mode":"insecure"}\n', encoding="utf-8")
        trust.chmod(0o600)
        original_state = state_path.read_bytes()
        with self.assertRaisesRegex(DeploymentError, "identity or hash changed"):
            self.deployment().refresh_codex_callback(executable=executable, terminal_ownership=ownership, tmux=tmux)
        self.assertEqual(state_path.read_bytes(), original_state)

    def test_callback_refresh_refuses_unrelated_state_tamper(self) -> None:
        executable, ownership, tmux = self._callback_refresh_fixture()
        state_path = self.root / "deployment-state.json"
        state = json.loads(state_path.read_text())
        state["foreign"] = "unexpected"
        state_path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        state_path.chmod(0o600)
        tampered = state_path.read_bytes()
        with self.assertRaisesRegex(DeploymentError, "unexpected fields"):
            self.deployment().refresh_codex_callback(executable=executable, terminal_ownership=ownership, tmux=tmux)
        self.assertEqual(state_path.read_bytes(), tampered)

    def test_callback_refresh_rejects_symlink_and_executable_hash_race(self) -> None:
        executable, ownership, tmux = self._callback_refresh_fixture()
        symlink = self.base / "codex-symlink"
        symlink.symlink_to(executable)
        with self.assertRaisesRegex(DeploymentError, "symlink"):
            self.deployment().refresh_codex_callback(executable=symlink, terminal_ownership=ownership, tmux=tmux)
        state = (self.root / "deployment-state.json").read_bytes()
        calls = 0
        displaced = self.base / "codex-displaced"
        def path_racing_pin(path: Path) -> dict[str, object]:
            nonlocal calls
            if path == executable:
                calls += 1
                if calls == 2:
                    executable.rename(displaced)
                    executable.write_text("#!/bin/sh\nexit 41\n", encoding="utf-8")
                    executable.chmod(0o700)
            return _codex_executable_pin(path)
        with patch("oc_rig.deployment.user._codex_executable_pin", side_effect=path_racing_pin), self.assertRaisesRegex(DeploymentError, "changed during pin refresh"):
            self.deployment().refresh_codex_callback(executable=executable, terminal_ownership=ownership, tmux=tmux)
        self.assertEqual((self.root / "deployment-state.json").read_bytes(), state)
        calls = 0
        def racing_pin(path: Path) -> dict[str, object]:
            nonlocal calls
            if path == executable:
                calls += 1
                if calls == 2:
                    executable.write_text("#!/bin/sh\nexit 42\n", encoding="utf-8")
                    executable.chmod(0o700)
            return _codex_executable_pin(path)
        with patch("oc_rig.deployment.user._codex_executable_pin", side_effect=racing_pin), self.assertRaisesRegex(DeploymentError, "changed during pin refresh"):
            self.deployment().refresh_codex_callback(executable=executable, terminal_ownership=ownership, tmux=tmux)
        self.assertEqual((self.root / "deployment-state.json").read_bytes(), state)

    def test_callback_refreshes_serialize_without_stale_overwrite(self) -> None:
        _executable, ownership, tmux = self._callback_refresh_fixture()
        first = self.base / "codex-first"
        second = self.base / "codex-second"
        for path, code in ((first, 11), (second, 12)):
            path.write_text(f"#!/bin/sh\nexit {code}\n", encoding="utf-8")
            path.chmod(0o700)
        entered = threading.Event()
        release = threading.Event()
        second_done = threading.Event()
        failures: list[BaseException] = []
        def paused_pin(path: Path) -> dict[str, object]:
            if path == first and not entered.is_set():
                entered.set()
                self.assertTrue(release.wait(timeout=5))
            return _stable_codex_executable_pin(path)
        def refresh(path: Path, done: threading.Event | None = None) -> None:
            try:
                self.deployment().refresh_codex_callback(executable=path, terminal_ownership=ownership, tmux=tmux)
            except BaseException as error:
                failures.append(error)
            finally:
                if done is not None:
                    done.set()
        with patch("oc_rig.deployment.user._stable_codex_executable_pin", side_effect=paused_pin):
            one = threading.Thread(target=refresh, args=(first,))
            two = threading.Thread(target=refresh, args=(second, second_done))
            one.start()
            self.assertTrue(entered.wait(timeout=5))
            two.start()
            self.assertFalse(second_done.wait(timeout=0.2))
            release.set()
            one.join(timeout=10)
            two.join(timeout=10)
        self.assertFalse(one.is_alive() or two.is_alive())
        self.assertEqual(failures, [])
        state = json.loads((self.root / "deployment-state.json").read_text())
        self.assertEqual(state["codex_callback"]["executable"], str(second))

    def test_callback_refresh_serializes_against_start(self) -> None:
        executable, ownership, tmux = self._callback_refresh_fixture()
        executable.write_text("#!/bin/sh\nexit 13\n", encoding="utf-8")
        executable.chmod(0o700)
        entered = threading.Event()
        release = threading.Event()
        start_done = threading.Event()
        failures: list[BaseException] = []
        def paused_pin(path: Path) -> dict[str, object]:
            if path == executable and not entered.is_set():
                entered.set()
                self.assertTrue(release.wait(timeout=5))
            return _stable_codex_executable_pin(path)
        def refresh() -> None:
            try:
                self.deployment().refresh_codex_callback(executable=executable, terminal_ownership=ownership, tmux=tmux)
            except BaseException as error:
                failures.append(error)
        def start() -> None:
            try:
                self.deployment(dry_run=True).start()
            except BaseException as error:
                failures.append(error)
            finally:
                start_done.set()
        with patch("oc_rig.deployment.user._stable_codex_executable_pin", side_effect=paused_pin):
            refresh_thread = threading.Thread(target=refresh)
            start_thread = threading.Thread(target=start)
            refresh_thread.start()
            self.assertTrue(entered.wait(timeout=5))
            start_thread.start()
            self.assertFalse(start_done.wait(timeout=0.2))
            release.set()
            refresh_thread.join(timeout=10)
            start_thread.join(timeout=10)
        self.assertFalse(refresh_thread.is_alive() or start_thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(self.deployment().status()["codex_callback"], {"configured": True})

    def test_terminal_stop_exception_recovery_blocks_start_until_stopped_publication(self) -> None:
        self.deployment().install(REPOSITORY)
        self._set_job_running(True)
        deployment = self.deployment()
        ownership = self.base / "terminal-ownership.json"
        lifecycle = TerminalLifecycle(
            deployment=deployment,
            opencode=Path("/bin/echo"),
            ownership_path=ownership,
            backend_directory=(
                deployment.home / ".config/opencode/.rig-v2-automated-backend"
            ),
        )
        lifecycle.controller_owned = True
        lifecycle.controller_pid = 4242
        lifecycle.backend_owned = True
        lifecycle.backend_identity = ProcessIdentity(4343, 4343, "started", ("backend",))
        lifecycle.tmux_nonce = "nonce"
        lifecycle.tmux_session_id = "$0"
        lifecycle._acquire_lock()
        lifecycle.refresh = unittest.mock.Mock(return_value={})
        start_done = threading.Event()
        failures: list[BaseException] = []
        def start() -> None:
            try:
                self.deployment(dry_run=True).start()
            except BaseException as error:
                failures.append(error)
            finally:
                start_done.set()
        start_thread = threading.Thread(target=start)
        real_status = deployment.stop_status
        status_calls = 0
        def status() -> dict[str, object]:
            nonlocal status_calls
            status_calls += 1
            if status_calls == 2:
                start_thread.start()
                self.assertFalse(start_done.wait(timeout=0.2))
                return {
                    "job": {
                        "detail": "unknown",
                        "loaded": True,
                        "pid": None,
                        "running": False,
                    }
                }
            return real_status()
        def stop_then_raise() -> None:
            self._set_job_running(False)
            raise RuntimeError("post-stop injected failure")
        with patch.object(deployment, "status", side_effect=status), patch.object(deployment, "_stop_unlocked", side_effect=stop_then_raise), patch("oc_rig.terminal_lifecycle.snapshot_is_quiescent", return_value=(True, "quiescent")), patch.object(lifecycle, "_stop_backend", side_effect=lambda: setattr(lifecycle, "backend_owned", False)):
            self.assertEqual(
                lifecycle.close(terminal_lost=False),
                (True, "stopped invocation-owned resources"),
            )
        start_thread.join(timeout=10)
        self.assertFalse(start_thread.is_alive())
        self.assertTrue(start_done.is_set())
        self.assertEqual(failures, [])
        stopped = json.loads(ownership.read_text())
        self.assertEqual(stopped["phase"], "stopped")
        self.assertFalse(stopped["controller_owned"])

    def test_terminal_resume_holds_operation_lock_against_start_until_publication(self) -> None:
        self.deployment().install(REPOSITORY)
        launch = json.loads(self.launch_state.read_text())
        launch["loaded"] = True
        launch["running"] = False
        launch["detail"] = "not running"
        self.launch_state.write_text(json.dumps(launch), encoding="utf-8")
        deployment = self.deployment()
        ownership = self.base / "resume-ownership.json"
        record = {"backend": None, "backend_owned": False, "completed_cutover": None, "controller_owned": True, "controller_pid": 4242, "controller_starting": False, "cutover_intent": None, "format": 1, "invocation_id": "a" * 32, "phase": "running", "reason": "terminal attached", "tmux_nonce": "nonce", "tmux_session_id": "$0"}
        ownership.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        ownership.chmod(0o600)
        lifecycle = TerminalLifecycle(
            deployment=deployment,
            opencode=Path("/bin/echo"),
            ownership_path=ownership,
            backend_directory=(
                deployment.home / ".config/opencode/.rig-v2-automated-backend"
            ),
        )
        start_done = threading.Event()
        failures: list[BaseException] = []
        def start() -> None:
            try:
                self.deployment(dry_run=True).start()
            except BaseException as error:
                failures.append(error)
            finally:
                start_done.set()
        start_thread = threading.Thread(target=start)
        real_status = deployment.status
        def status() -> dict[str, object]:
            start_thread.start()
            self.assertFalse(start_done.wait(timeout=0.2))
            return real_status()
        with patch.object(deployment, "stop_status", side_effect=status):
            lifecycle.resume_cleanup()
        self.assertFalse(start_done.is_set())
        self.assertTrue(lifecycle.close(terminal_lost=False)[0])
        start_thread.join(timeout=10)
        self.assertFalse(start_thread.is_alive())
        self.assertEqual(failures, [])
        stopped = json.loads(ownership.read_text())
        self.assertEqual(stopped["phase"], "stopped")
        self.assertFalse(stopped["controller_owned"])

    def test_callback_refresh_never_rolls_back_over_changed_state(self) -> None:
        executable, ownership, tmux = self._callback_refresh_fixture()
        executable.write_text("#!/bin/sh\nexit 14\n", encoding="utf-8")
        executable.chmod(0o700)
        state_path = self.root / "deployment-state.json"
        replacement_by_other = b'{"foreign":"concurrent-state"}\n'
        from oc_rig.deployment.user import _validate_runtime as real_validate_runtime
        def fail_postvalidate(root: Path, **kwargs: object):
            if kwargs.get("allow_stale_codex_callback") is True:
                return real_validate_runtime(root, **kwargs)
            state_path.write_bytes(replacement_by_other)
            state_path.chmod(0o600)
            raise DeploymentError("injected postvalidation failure")
        with patch("oc_rig.deployment.user._validate_runtime", side_effect=fail_postvalidate), self.assertRaisesRegex(DeploymentError, "rollback was incomplete"):
            self.deployment().refresh_codex_callback(executable=executable, terminal_ownership=ownership, tmux=tmux)
        self.assertEqual(state_path.read_bytes(), replacement_by_other)

    def test_pre_callback_deployment_state_upgrades_without_live_action(self) -> None:
        self.deployment().install(REPOSITORY)
        state_path = self.root / "deployment-state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        del state["codex_callback"]
        state_path.write_text(
            json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        state_path.chmod(0o600)
        self.assertEqual(
            self.deployment().status()["codex_callback"], {"configured": False}
        )

    def test_existing_opencode_config_survives_eintr_and_short_writes(self) -> None:
        self.deployment().install(REPOSITORY)
        password = self.base / "short-basic.password"
        topology_path = self.base / "short-topology.json"
        trust_path = self.base / "short-trust.json"
        password.write_text("private-short-write-material", encoding="utf-8")
        topology_path.write_text(json.dumps(topology()), encoding="utf-8")
        trust_path.write_text(
            json.dumps({"mode": "secure", "secure_worker": "secure-worker"}),
            encoding="utf-8",
        )
        for path in (password, topology_path, trust_path):
            path.chmod(0o600)
        first = self.deployment().configure_opencode(
            endpoint="http://127.0.0.1:4096",
            basic_username="opencode",
            basic_password_file=password,
            topology_file=topology_path,
            trust_file=trust_path,
        )
        real_write = os.write
        calls = 0

        def interrupted_short_write(descriptor: int, data: bytes) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError(errno.EINTR, "interrupted")
            amount = max(1, len(data) // 2)
            return real_write(descriptor, data[:amount])

        with patch(
            "oc_rig.deployment.user.os.write",
            side_effect=interrupted_short_write,
        ):
            repeated = self.deployment().configure_opencode(
                endpoint="http://127.0.0.1:4096",
                basic_username="opencode",
                basic_password_file=password,
                topology_file=topology_path,
                trust_file=trust_path,
            )
        self.assertGreater(calls, 4)
        self.assertEqual(repeated["config_id"], first["config_id"])
        self.assertEqual(
            self.deployment().status()["opencode"]["config_id"],
            first["config_id"],
        )
        with patch(
            "oc_rig.deployment.user.os.write", return_value=0
        ), self.assertRaisesRegex(DeploymentError, "no progress"):
            self.deployment().configure_opencode(
                endpoint="http://127.0.0.1:4096",
                basic_username="opencode",
                basic_password_file=password,
                topology_file=topology_path,
                trust_file=trust_path,
            )
        self.assertEqual(
            self.deployment().status()["opencode"]["config_id"],
            first["config_id"],
        )

    def test_failed_opencode_rotation_restores_prior_state_and_retries(self) -> None:
        self.deployment().install(REPOSITORY)
        password = self.base / "rotate-basic.password"
        topology_path = self.base / "rotate-topology.json"
        trust_path = self.base / "rotate-trust.json"
        password.write_text("private-rotation-material", encoding="utf-8")
        topology_path.write_text(json.dumps(topology()), encoding="utf-8")
        trust_path.write_text(
            json.dumps({"mode": "secure", "secure_worker": "secure-worker"}),
            encoding="utf-8",
        )
        for path in (password, topology_path, trust_path):
            path.chmod(0o600)
        first = self.deployment().configure_opencode(
            endpoint="http://127.0.0.1:4096",
            basic_username="opencode",
            basic_password_file=password,
            topology_file=topology_path,
            trust_file=trust_path,
        )
        updated = topology()
        updated["pools"]["tensorhost"][0]["session_id"] = "session-rotated"
        topology_path.write_text(json.dumps(updated), encoding="utf-8")
        topology_path.chmod(0o600)
        from oc_rig.deployment import user as user_deployment

        real_validate = user_deployment._validate_runtime
        validations = 0

        def fail_after_publish(*args: object, **kwargs: object) -> None:
            nonlocal validations
            validations += 1
            if validations == 2:
                raise DeploymentError("injected post-publication validation failure")
            real_validate(*args, **kwargs)

        with patch(
            "oc_rig.deployment.user._validate_runtime",
            side_effect=fail_after_publish,
        ), self.assertRaisesRegex(DeploymentError, "post-publication"):
            self.deployment().configure_opencode(
                endpoint="http://127.0.0.1:4096",
                basic_username="opencode",
                basic_password_file=password,
                topology_file=topology_path,
                trust_file=trust_path,
            )
        generations = self.root / "config" / "opencode"
        self.assertEqual(
            {item.name for item in generations.iterdir()},
            {first["config_id"]},
        )
        self.assertEqual(
            self.deployment().status()["opencode"]["config_id"],
            first["config_id"],
        )
        retried = self.deployment().configure_opencode(
            endpoint="http://127.0.0.1:4096",
            basic_username="opencode",
            basic_password_file=password,
            topology_file=topology_path,
            trust_file=trust_path,
        )
        self.assertNotEqual(retried["config_id"], first["config_id"])

    def test_start_refuses_an_unexpected_daemon_lock_owner(self) -> None:
        self.deployment().install(REPOSITORY)
        lock = self.root / "runtime" / "state" / "rigd.lock"
        with lock.open("r+b") as descriptor:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(DeploymentError):
                self.deployment().start()


class LocalUserIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=Path.home(), prefix="r2-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.runtime_root = self.root / "runtime"
        self.state = self.runtime_root / "state"
        self.socket_root = self.root / "socket-boundary"
        self.socket_directory = self.socket_root / "socket"
        for directory in (
            self.runtime_root,
            self.state,
            self.socket_root,
            self.socket_directory,
        ):
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
        for name in ("rig.sqlite3", "rigd.lock"):
            path = self.state / name
            path.touch(mode=0o600)
            path.chmod(0o600)
        self.socket_path = self.socket_directory / "rig.sock"
        self.address = PrivateSocketPath(self.socket_path, self.socket_root)

    def test_local_user_topology_accepts_owner_only_and_rejects_service_modes(self) -> None:
        policy = LocalUserIdentityPolicy(os.geteuid(), os.getegid())
        validate_local_user_topology(
            PrivateRuntimeDirectory(self.state, self.runtime_root),
            self.address,
            policy,
            OsIdentityProbe(),
        )
        self.socket_root.chmod(0o710)
        with self.assertRaises(ServiceIdentityError):
            validate_local_user_topology(
                PrivateRuntimeDirectory(self.state, self.runtime_root),
                self.address,
                policy,
                OsIdentityProbe(),
            )

    def test_client_profiles_cannot_silently_accept_the_other_socket_mode(self) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(str(self.socket_path))
        self.socket_path.chmod(0o600)
        self.assertEqual(
            self.address.validate_for_connect(identity_profile="local-user"),
            self.socket_path,
        )
        with self.assertRaises(SocketSecurityError):
            self.address.validate_for_connect()
        with self.assertRaises(SocketSecurityError):
            self.address.validate_for_connect(os.geteuid(), os.getegid())

        listener.close()
        self.socket_path.unlink()
        self.socket_root.chmod(0o710)
        self.socket_directory.chmod(0o710)
        service_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(service_listener.close)
        service_listener.bind(str(self.socket_path))
        self.socket_path.chmod(0o620)
        service_gid = self.socket_directory.stat().st_gid
        self.assertEqual(
            self.address.validate_for_connect(os.geteuid(), service_gid),
            self.socket_path,
        )
        with self.assertRaises(SocketSecurityError):
            self.address.validate_for_connect(identity_profile="local-user")

    def test_local_user_client_must_be_explicit_and_cannot_mix_service_fields(self) -> None:
        with self.assertRaises(ValueError):
            RigClient(self.socket_path, approved_root=self.socket_root)
        with self.assertRaises(ValueError):
            RigClient(
                self.socket_path,
                approved_root=self.socket_root,
                service_uid=os.geteuid(),
                client_gid=os.getegid(),
                identity_profile="local-user",
            )


if __name__ == "__main__":
    unittest.main()
