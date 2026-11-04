"""Pure runtime path calculation.

This module calculates paths only. It never creates directories or reads state.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class RuntimeDirectories:
    """Mutable locations used by the Fugue controller."""

    state: Path
    cache: Path
    logs: Path

    @classmethod
    def for_home(cls, home: Path) -> "RuntimeDirectories":
        """Return the macOS runtime layout for ``home`` without I/O."""
        return cls(
            state=home / "Library" / "Application Support" / "oc-rig",
            cache=home / "Library" / "Caches" / "oc-rig",
            logs=home / "Library" / "Logs" / "oc-rig",
        )
