"""Typed adapter ports and inert production integrations."""

from oc_rig.adapters.disabled import DisabledAdapter, OpenCodeAdapter, TmuxAdapter
from oc_rig.adapters.models import (
    AdapterDisposition,
    AdapterPort,
    AdapterRequest,
    AdapterResult,
    ExecutableProvenance,
    IdentityRecorder,
    NoCancellation,
    PreparedAdapterPort,
    ProcessIdentity,
)
__all__ = [
    "AdapterDisposition",
    "AdapterPort",
    "AdapterRequest",
    "AdapterResult",
    "DisabledAdapter",
    "ExecutableProvenance",
    "IdentityRecorder",
    "NoCancellation",
    "OpenCodeAdapter",
    "PreparedAdapterPort",
    "ProcessIdentity",
    "TmuxAdapter",
]
