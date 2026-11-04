"""Permanently inert production adapter placeholders."""

from __future__ import annotations

from oc_rig.adapters.models import AdapterRequest, AdapterResult, Cancellation


class DisabledAdapter:
    """An adapter with no executable, discovery, attachment, or ambient config."""

    __slots__ = ("_reason",)

    def __init__(self, reason: str = "adapter_unconfigured"):
        self._reason = reason

    @property
    def kind(self) -> str:
        return "disabled"

    @property
    def provenance(self) -> None:
        return None

    def prepare(self, request: AdapterRequest) -> "DisabledAdapter":
        del request
        return self

    def send(self, cancellation: Cancellation, identity_recorder: object = None) -> AdapterResult:
        del cancellation, identity_recorder
        return AdapterResult.definite_failure(self._reason)

    def close(self) -> None:
        return None


class OpenCodeAdapter(DisabledAdapter):
    """Rig v2 production OpenCode integration remains deliberately disarmed."""

    def __init__(self) -> None:
        super().__init__("opencode_adapter_unconfigured")


class TmuxAdapter(DisabledAdapter):
    """Rig v2 production tmux integration remains deliberately disarmed."""

    def __init__(self) -> None:
        super().__init__("tmux_adapter_unconfigured")
