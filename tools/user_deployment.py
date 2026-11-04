#!/usr/bin/env python3
"""Run the source-tree local-user deployment manager without installation."""

from oc_rig.deployment.user import main


if __name__ == "__main__":
    raise SystemExit(main())
