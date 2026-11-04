"""Remain in an exact process group until its supervisor reaps the group."""

from __future__ import annotations

import signal


while True:
    signal.pause()
