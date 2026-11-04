"""Pure read-only cockpit client, normalization, and rendering surfaces."""

from oc_rig.cockpit.client import CockpitClient
from oc_rig.cockpit.render import render_details, render_json, render_terminal
from oc_rig.cockpit.view import normalize_snapshot

__all__ = (
    "CockpitClient",
    "normalize_snapshot",
    "render_details",
    "render_json",
    "render_terminal",
)
