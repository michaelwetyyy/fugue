"""Fixed-operation client for one explicit cockpit refresh."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from oc_rig.protocol.client import RigClient as _RigClient


class CockpitClient:
    """Expose only the authenticated, read-only cockpit snapshot operation."""

    __slots__ = ("__client",)

    def __init__(
        self,
        socket_path: Path,
        *,
        approved_root: Path | None = None,
        service_uid: int | None = None,
        client_gid: int | None = None,
        identity_profile: str | None = None,
        timeout: float = 5.0,
    ):
        self.__client = _RigClient(
            socket_path,
            approved_root=approved_root,
            service_uid=service_uid,
            client_gid=client_gid,
            identity_profile=identity_profile,
            timeout=timeout,
        )

    def refresh(self) -> Mapping[str, Any]:
        """Perform exactly one socket request; no watch or polling API exists."""
        result = self.__client.call("cockpit.snapshot.v1", {})
        snapshot = result.get("snapshot")
        if not isinstance(snapshot, Mapping):
            return {
                "projection_version": 1,
                "availability": {
                    "status": "unavailable",
                    "errors": ["daemon response omitted the cockpit snapshot"],
                },
            }
        return snapshot
