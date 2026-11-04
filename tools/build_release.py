#!/usr/bin/env python3
"""Build and verify one immutable offline Fugue wheel."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from oc_rig.migration.release import build_release_artifact


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    artifact = build_release_artifact(args.source_root, args.output_directory)
    print(
        json.dumps(
            {
                "manifest": str(artifact.manifest),
                "members": len(artifact.members),
                "sha256": artifact.wheel_sha256,
                "wheel": str(artifact.wheel),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
