"""Exit after supervisor identity but before a fixture can retain its result."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from oc_rig.adapters import AdapterRequest, NoCancellation
from tests.fixtures.synthetic_process import (
    SyntheticProcessAdapter,
    SyntheticProcessAdapterConfig,
)


def main() -> int:
    if len(sys.argv) != 6 or sys.argv[1] not in {"spawn", "persist"}:
        return 125
    mode = sys.argv[1]
    executable, fixture_root, runtime_root, identity_path = map(Path, sys.argv[2:])
    prepared = SyntheticProcessAdapter(
        SyntheticProcessAdapterConfig(
            executable=executable,
            fixture_root=fixture_root,
            runtime_root=runtime_root,
            timeout_seconds=5,
        )
    ).prepare(
        AdapterRequest(
            "transport-parent-death",
            "work-parent-death",
            "tensorhost",
            "{}",
            "completion-parent-death",
            "callback-parent-death",
        )
    )

    def record_identity(identity: object) -> None:
        marker = runtime_root / "transport-parent-death" / "home" / "started.json"
        deadline = time.monotonic() + 2
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        encoded = json.dumps(
            {
                "supervisor_pid": identity.supervisor_pid,
                "target_pid": identity.target_pid,
                "token": identity.token,
                "marker": json.loads(marker.read_text()),
            }
        )
        if mode == "spawn":
            os.write(1, encoded.encode())
            os._exit(23)
        identity_path.write_text(encoded, encoding="utf-8")

    prepared.send(NoCancellation(), record_identity)
    os._exit(24)


if __name__ == "__main__":
    raise SystemExit(main())
