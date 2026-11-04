from __future__ import annotations

import concurrent.futures
import json
import errno
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from oc_rig.adapters import (
    AdapterDisposition,
    AdapterRequest,
    DisabledAdapter,
    NoCancellation,
    OpenCodeAdapter,
    TmuxAdapter,
)
from tests.fixtures.synthetic_process import (
    SyntheticProcessAdapter,
    SyntheticProcessAdapterConfig,
)
from tests.fixtures import synthetic_process as synthetic_fixture


class SyntheticProcessAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.runtime = self.root / "runtime"

    def request(self, label: str = "one") -> AdapterRequest:
        return AdapterRequest(
            f"transport-{label}",
            f"work-{label}",
            "tensorhost",
            json.dumps({"task": "bounded"}),
            f"completion-{label}",
            f"callback-{label}",
        )

    def executable(self, body: str, name: str = "fake-adapter.py") -> Path:
        path = self.root / name
        path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
        path.chmod(0o700)
        return path

    def adapter(self, executable: Path, **changes: object) -> SyntheticProcessAdapter:
        values: dict[str, object] = {
            "executable": executable,
            "fixture_root": self.root,
            "runtime_root": self.runtime,
        }
        values.update(changes)
        return SyntheticProcessAdapter(SyntheticProcessAdapterConfig(**values))  # type: ignore[arg-type]

    def assert_process_gone(self, pid: int) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except OSError as error:
                if error.errno == errno.ESRCH:
                    return
                raise
            time.sleep(0.01)
        self.fail(f"process {pid} survived its supervised adapter run")

    def assert_copy_removed(self, result: object) -> None:
        provenance = result.provenance
        self.assertIsNotNone(provenance)
        self.assertFalse(provenance.path.exists())
        self.assertFalse(provenance.path.parent.exists())

    @staticmethod
    def response_script(response: dict[str, str], *, prefix: str = "") -> str:
        return f"""
import json, struct, sys
size = struct.unpack('!I', sys.stdin.buffer.read(4))[0]
request = json.loads(sys.stdin.buffer.read(size))
payload = json.dumps({response!r}, separators=(',', ':')).encode()
sys.stdout.buffer.write({prefix!r}.encode() + struct.pack('!I', len(payload)) + payload)
"""

    def test_positive_ack_has_exact_provenance_and_isolated_environment(self) -> None:
        body = """
import json, os, struct, sys
size = struct.unpack('!I', sys.stdin.buffer.read(4))[0]
request = json.loads(sys.stdin.buffer.read(size))
assert request['pool'] == 'tensorhost'
assert 'PATH' not in os.environ and 'PYTHONPATH' not in os.environ
assert os.getcwd().startswith(os.environ['HOME'].rsplit('/home', 1)[0])
payload = json.dumps({'status':'accepted','acknowledgement_id':'ack-one'}, separators=(',', ':')).encode()
sys.stdout.buffer.write(struct.pack('!I', len(payload)) + payload)
"""
        executable = self.executable(body)
        prepared = self.adapter(executable).prepare(self.request())
        provenance = prepared.provenance
        with patch("os.fork", side_effect=AssertionError("adapter parent called os.fork")):
            result = prepared.send(NoCancellation())
        self.assertEqual(result.disposition, AdapterDisposition.ACCEPTED)
        self.assertEqual(result.acknowledgement_id, "ack-one")
        self.assertEqual((result.provenance.device, result.provenance.inode),
                         (provenance.device, provenance.inode))
        self.assertNotIn(str(Path.home()), result.output or "")
        self.assert_copy_removed(result)

    def test_definite_and_ambiguous_results_are_distinct(self) -> None:
        definite = self.executable(
            self.response_script(
                {"status": "definite_failed", "error_code": "not_delivered"}
            ),
            "definite.py",
        )
        unknown = self.executable(
            self.response_script(
                {"status": "delivery_unknown", "error_code": "disconnected"}
            ),
            "unknown.py",
        )
        definite_result = self.adapter(definite).prepare(self.request("definite")).send(
            NoCancellation()
        )
        unknown_result = self.adapter(unknown).prepare(self.request("unknown")).send(
            NoCancellation()
        )
        self.assertEqual(definite_result.disposition, AdapterDisposition.DEFINITE_FAILED)
        self.assertEqual(unknown_result.disposition, AdapterDisposition.DELIVERY_UNKNOWN)

    def test_output_injection_is_ambiguous_and_never_parsed_as_ack(self) -> None:
        executable = self.executable(
            self.response_script(
                {"status": "accepted", "acknowledgement_id": "injected"},
                prefix="junk",
            )
        )
        result = self.adapter(executable).prepare(self.request()).send(NoCancellation())
        self.assertEqual(result.disposition, AdapterDisposition.DELIVERY_UNKNOWN)
        self.assertEqual(result.error_code, "invalid_adapter_response")

    def test_output_limit_is_enforced_without_persisting_child_text(self) -> None:
        executable = self.executable(
            """
import os, pathlib, sys, time
child = os.fork()
if child == 0:
    time.sleep(30)
    os._exit(0)
pathlib.Path(os.environ['HOME'], 'grandchild.pid').write_text(str(child))
sys.stdout.buffer.write(b'x' * (8 * 1024 * 1024))
"""
        )
        result = self.adapter(executable, max_output_bytes=256).prepare(
            self.request()
        ).send(NoCancellation())
        self.assertEqual(result.disposition, AdapterDisposition.DELIVERY_UNKNOWN)
        self.assertEqual(result.error_code, "adapter_output_too_large")
        metadata = json.loads(result.output or "{}")
        self.assertEqual(metadata["stdout_bytes"], 256)
        self.assertTrue(metadata["truncated"])
        self.assertNotIn("xxx", result.output or "")
        grandchild = int(
            (self.runtime / "transport-one" / "home" / "grandchild.pid").read_text()
        )
        for pid in (result.process_identity.target_pid, grandchild):
            with self.subTest(pid=pid):
                self.assert_process_gone(pid)
        self.assert_copy_removed(result)

    def test_accepted_ack_reaps_background_descendant_before_reporting(self) -> None:
        executable = self.executable(
            """
import json, os, pathlib, struct, sys, time
child = os.fork()
if child == 0:
    time.sleep(30)
    os._exit(0)
pathlib.Path(os.environ['HOME'], 'background.pid').write_text(str(child))
size = struct.unpack('!I', sys.stdin.buffer.read(4))[0]
json.loads(sys.stdin.buffer.read(size))
reply = json.dumps({'status':'accepted','acknowledgement_id':'ack-clean'}, separators=(',', ':')).encode()
sys.stdout.buffer.write(struct.pack('!I', len(reply)) + reply)
"""
        )
        result = self.adapter(executable).prepare(self.request("background")).send(
            NoCancellation()
        )
        self.assertEqual(result.disposition, AdapterDisposition.ACCEPTED)
        descendant = int(
            (self.runtime / "transport-background" / "home" / "background.pid").read_text()
        )
        self.assert_process_gone(descendant)
        self.assert_copy_removed(result)

    def test_parent_death_before_identity_persist_kills_the_entire_target_group(self) -> None:
        executable = self.executable(
            """
import os, pathlib, sys, time
child = os.fork()
if child == 0:
    time.sleep(30)
    os._exit(0)
pathlib.Path(os.environ['HOME'], 'started.json').write_text(
    __import__('json').dumps({
        'target_pid': os.getpid(),
        'grandchild_pid': child,
        'pgid': os.getpgrp(),
    })
)
sys.stdin.buffer.read()
"""
        )
        repository = Path(__file__).resolve().parents[1]
        driver = repository / "tests" / "fixtures" / "crash_adapter_parent.py"
        adapter_parent = subprocess.Popen(
            [
                sys.executable,
                str(driver),
                "spawn",
                str(executable),
                str(self.root),
                str(self.runtime),
                "-",
            ],
            executable=sys.executable,
            cwd=repository,
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONPATH": f"{repository / 'src'}:{repository}",
            },
            close_fds=True,
            stdout=subprocess.PIPE,
        )
        assert adapter_parent.stdout is not None
        encoded = adapter_parent.stdout.read()
        adapter_parent.stdout.close()
        self.assertEqual(adapter_parent.wait(timeout=3), 23)
        identity = json.loads(encoded)
        self.assertEqual(identity["target_pid"], identity["marker"]["pgid"])
        self.assertEqual(len(identity["token"]), 32)
        self.assert_process_gone(identity["target_pid"])
        self.assert_process_gone(identity["marker"]["target_pid"])
        self.assert_process_gone(identity["marker"]["grandchild_pid"])
        cleanup = self.adapter(executable).prepare(self.request("cleanup"))
        cleanup.close()
        self.assertFalse(
            (self.runtime / "transport-parent-death" / "bin" / "adapter").exists()
        )

    def test_identity_persisted_before_result_survives_adapter_parent_crash(self) -> None:
        executable = self.executable(
            """
import json, os, pathlib, struct, sys
pathlib.Path(os.environ['HOME'], 'started.json').write_text(
    json.dumps({'target_pid': os.getpid(), 'grandchild_pid': os.getpid(), 'pgid': os.getpgrp()})
)
size = struct.unpack('!I', sys.stdin.buffer.read(4))[0]
json.loads(sys.stdin.buffer.read(size))
reply = json.dumps({'status':'accepted','acknowledgement_id':'not-journalled'}, separators=(',', ':')).encode()
sys.stdout.buffer.write(struct.pack('!I', len(reply)) + reply)
"""
        )
        repository = Path(__file__).resolve().parents[1]
        driver = repository / "tests" / "fixtures" / "crash_adapter_parent.py"
        identity_path = self.root / "persisted-identity.json"
        adapter_parent = subprocess.Popen(
            [
                sys.executable,
                str(driver),
                "persist",
                str(executable),
                str(self.root),
                str(self.runtime),
                str(identity_path),
            ],
            executable=sys.executable,
            cwd=repository,
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONPATH": f"{repository / 'src'}:{repository}",
            },
            close_fds=True,
        )
        self.assertEqual(adapter_parent.wait(timeout=3), 24)
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        self.assertEqual(identity["target_pid"], identity["marker"]["pgid"])
        self.assert_process_gone(identity["target_pid"])
        self.assertFalse(
            (self.runtime / "transport-parent-death" / "bin" / "adapter").exists()
        )

    def test_timeout_kills_the_process_group_and_is_delivery_unknown(self) -> None:
        executable = self.executable("import time\ntime.sleep(30)\n")
        started = time.monotonic()
        result = self.adapter(executable, timeout_seconds=0.1).prepare(
            self.request()
        ).send(NoCancellation())
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(result.disposition, AdapterDisposition.DELIVERY_UNKNOWN)
        self.assertEqual(result.error_code, "adapter_timeout")
        self.assert_copy_removed(result)

    def test_cancellation_kills_the_process_group(self) -> None:
        executable = self.executable("import time\ntime.sleep(30)\n")
        cancellation = threading.Event()
        prepared = self.adapter(executable, timeout_seconds=5).prepare(self.request())
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(prepared.send, cancellation)
            time.sleep(0.08)
            cancellation.set()
            result = future.result(timeout=2)
        self.assertEqual(result.disposition, AdapterDisposition.CANCELLED)
        self.assert_copy_removed(result)

    def test_source_swap_and_restore_cannot_change_immutable_run_copy(self) -> None:
        executable = self.executable(
            self.response_script({"status": "accepted", "acknowledgement_id": "old"})
        )
        original = self.root / "original-adapter.py"
        executable.rename(original)
        original.rename(executable)
        prepared = self.adapter(executable).prepare(self.request())
        source_inode = prepared.provenance.source_inode
        executable.rename(original)
        self.executable(
            self.response_script({"status": "accepted", "acknowledgement_id": "new"})
        )
        executable.unlink()
        original.rename(executable)
        self.assertEqual(executable.stat().st_ino, source_inode)
        result = prepared.send(NoCancellation())
        self.assertEqual(result.disposition, AdapterDisposition.ACCEPTED)
        self.assertEqual(result.acknowledgement_id, "old")
        self.assertEqual(result.provenance.source_inode, source_inode)
        self.assertNotEqual(result.provenance.inode, source_inode)
        self.assert_copy_removed(result)

    def test_close_and_bounded_orphan_sweep_remove_only_verified_fixture_files(self) -> None:
        executable = self.executable("import time\ntime.sleep(30)\n")
        adapter = self.adapter(executable, max_sweep_entries=1)
        abandoned = adapter.prepare(self.request("abandoned"))
        abandoned_copy = abandoned.provenance.path
        retained = self.runtime / "transport-abandoned" / "home" / "retain.txt"
        retained.write_text("unverified", encoding="utf-8")
        active = adapter.prepare(self.request("active"))
        self.assertFalse(abandoned_copy.exists())
        self.assertFalse(abandoned_copy.parent.exists())
        self.assertEqual(retained.read_text(encoding="utf-8"), "unverified")
        active_copy = active.provenance.path
        active.close()
        self.assertFalse(active_copy.exists())
        self.assertFalse(active_copy.parent.exists())

    def test_max_one_sweep_rotates_past_retained_unverified_invocation(self) -> None:
        executable = self.executable("import time\ntime.sleep(30)\n")
        adapter = self.adapter(executable, max_sweep_entries=1)
        retained = adapter.prepare(self.request("retained"))
        retained_file = self.runtime / "transport-retained" / "home" / "retain.txt"
        retained_file.write_text("do not remove", encoding="utf-8")
        later = adapter.prepare(self.request("later"))
        later_copy = later.provenance.path
        trigger = adapter.prepare(self.request("trigger"))
        self.assertEqual(retained_file.read_text(encoding="utf-8"), "do not remove")
        self.assertFalse(later_copy.exists())
        self.assertFalse(later_copy.parent.exists())
        retained.close()
        later.close()
        trigger.close()

    def test_large_orphan_directory_consumes_only_configured_scandir_work(self) -> None:
        executable = self.executable("import time\ntime.sleep(30)\n")
        adapter = self.adapter(executable, max_sweep_entries=1)
        self.runtime.mkdir(mode=0o700)
        for index in range(128):
            (self.runtime / f"unverified-{index:03d}").mkdir(mode=0o700)
        native_scandir = os.scandir
        consumed = 0

        class CountingScandir:
            def __init__(self, path: object):
                self._iterator = native_scandir(path)

            def __enter__(self):
                self._iterator.__enter__()
                return self

            def __exit__(self, *args: object):
                return self._iterator.__exit__(*args)

            def __iter__(self):
                return self

            def __next__(self):
                nonlocal consumed
                consumed += 1
                return next(self._iterator)

        with patch.object(synthetic_fixture.os, "scandir", CountingScandir):
            synthetic_fixture._sweep_orphans(adapter.config)
        self.assertLessEqual(consumed, 1)

    def test_prepare_and_pre_spawn_error_paths_remove_exact_copy_and_bin(self) -> None:
        executable = self.executable("import time\ntime.sleep(30)\n")
        with patch.object(
            synthetic_fixture,
            "_write_manifest",
            side_effect=OSError("manifest seam"),
        ):
            with self.assertRaises(OSError):
                self.adapter(executable).prepare(self.request("prepare-error"))
        prepare_bin = self.runtime / "transport-prepare-error" / "bin"
        self.assertFalse((prepare_bin / "adapter").exists())
        self.assertFalse(prepare_bin.exists())

        prepared = self.adapter(executable).prepare(self.request("spawn-error"))
        copy = prepared.provenance.path
        with patch.object(
            synthetic_fixture,
            "_launch_supervisor",
            side_effect=OSError("spawn seam"),
        ):
            result = prepared.send(NoCancellation())
        self.assertEqual(result.disposition, AdapterDisposition.DEFINITE_FAILED)
        self.assertFalse(copy.exists())
        self.assertFalse(copy.parent.exists())

    def test_production_adapters_are_unconfigured_and_do_no_discovery(self) -> None:
        request = self.request()
        for adapter in (DisabledAdapter(), OpenCodeAdapter(), TmuxAdapter()):
            with self.subTest(adapter=type(adapter).__name__):
                result = adapter.prepare(request).send(NoCancellation())
                self.assertEqual(result.disposition, AdapterDisposition.DEFINITE_FAILED)
                self.assertIsNone(adapter.provenance)


if __name__ == "__main__":
    unittest.main()
