"""Typed, backend-neutral transport adapter contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from oc_rig.policy.models import AgentLifecycle


class AdapterDisposition(StrEnum):
    """Only the delivery facts an adapter is allowed to assert."""

    ACCEPTED = "accepted"
    DEFINITE_FAILED = "definite_failed"
    DELIVERY_UNKNOWN = "delivery_unknown"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class ExecutableProvenance:
    """The exact executable inode used for one process attempt."""

    path: Path
    device: int
    inode: int
    mode: int
    size: int
    digest: str
    source_path: Path
    source_device: int
    source_inode: int
    source_digest: str


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """Supervisor-owned child identity for evidence, never PID-only recovery."""

    supervisor_pid: int
    target_pid: int
    token: str

    def __post_init__(self) -> None:
        if (
            type(self.supervisor_pid) is not int
            or self.supervisor_pid <= 0
            or type(self.target_pid) is not int
            or self.target_pid <= 0
        ):
            raise ValueError("process identity requires positive exact PIDs")
        if (
            not isinstance(self.token, str)
            or len(self.token) != 32
            or any(character not in "0123456789abcdef" for character in self.token)
        ):
            raise ValueError("process identity token must be 128-bit lowercase hex")


@dataclass(frozen=True, slots=True)
class AdapterRequest:
    """A logical pool/work target; it deliberately contains no slot or PID."""

    transport_id: str
    work_id: str
    pool: str
    payload_json: str
    completion_registration_id: str
    callback_registration_id: str
    admitted_content_hash: str | None = None
    claim_scope_hash: str | None = None
    capsule_scope_hash: str | None = None
    agent_lifecycle: AgentLifecycle = AgentLifecycle.PERSISTENT
    allow_child_agents: bool = False

    def __post_init__(self) -> None:
        if type(self.agent_lifecycle) is not AgentLifecycle:
            raise TypeError("adapter request lifecycle must be exact")
        if type(self.allow_child_agents) is not bool:
            raise TypeError("adapter request child-agent policy must be exact")


@dataclass(frozen=True, slots=True)
class AdapterResult:
    disposition: AdapterDisposition
    acknowledgement_id: str | None = None
    error_code: str | None = None
    exit_code: int | None = None
    output: str | None = None
    provenance: ExecutableProvenance | None = None
    process_identity: ProcessIdentity | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, AdapterDisposition):
            raise TypeError("adapter disposition must be typed")
        if self.disposition is AdapterDisposition.ACCEPTED:
            if not self.acknowledgement_id or self.error_code is not None:
                raise ValueError("accepted adapter result requires only an acknowledgement")
        elif self.acknowledgement_id is not None or not self.error_code:
            raise ValueError("non-accepted adapter result requires only an error code")

    @classmethod
    def accepted(
        cls,
        acknowledgement_id: str,
        *,
        exit_code: int | None = None,
        output: str | None = None,
        provenance: ExecutableProvenance | None = None,
        process_identity: ProcessIdentity | None = None,
    ) -> "AdapterResult":
        return cls(
            AdapterDisposition.ACCEPTED,
            acknowledgement_id=acknowledgement_id,
            exit_code=exit_code,
            output=output,
            provenance=provenance,
            process_identity=process_identity,
        )

    @classmethod
    def definite_failure(
        cls,
        error_code: str,
        *,
        exit_code: int | None = None,
        output: str | None = None,
        provenance: ExecutableProvenance | None = None,
        process_identity: ProcessIdentity | None = None,
    ) -> "AdapterResult":
        return cls(
            AdapterDisposition.DEFINITE_FAILED,
            error_code=error_code,
            exit_code=exit_code,
            output=output,
            provenance=provenance,
            process_identity=process_identity,
        )

    @classmethod
    def unknown(
        cls,
        error_code: str,
        *,
        exit_code: int | None = None,
        output: str | None = None,
        provenance: ExecutableProvenance | None = None,
        process_identity: ProcessIdentity | None = None,
    ) -> "AdapterResult":
        return cls(
            AdapterDisposition.DELIVERY_UNKNOWN,
            error_code=error_code,
            exit_code=exit_code,
            output=output,
            provenance=provenance,
            process_identity=process_identity,
        )

    @classmethod
    def cancelled(
        cls,
        error_code: str = "cancelled",
        *,
        exit_code: int | None = None,
        output: str | None = None,
        provenance: ExecutableProvenance | None = None,
        process_identity: ProcessIdentity | None = None,
    ) -> "AdapterResult":
        return cls(
            AdapterDisposition.CANCELLED,
            error_code=error_code,
            exit_code=exit_code,
            output=output,
            provenance=provenance,
            process_identity=process_identity,
        )


class Cancellation(Protocol):
    def is_set(self) -> bool: ...


class AdapterPort(Protocol):
    """Prepare exact provenance before durable send intent is committed."""

    @property
    def kind(self) -> str: ...

    def prepare(self, request: AdapterRequest) -> "PreparedAdapterPort": ...


class PreparedAdapterPort(Protocol):
    @property
    def provenance(self) -> ExecutableProvenance | None: ...

    def send(
        self,
        cancellation: Cancellation,
        identity_recorder: "IdentityRecorder | None" = None,
    ) -> AdapterResult: ...

    def close(self) -> None: ...


class IdentityRecorder(Protocol):
    def __call__(self, identity: ProcessIdentity) -> None: ...


class NoCancellation:
    __slots__ = ()

    def is_set(self) -> bool:
        return False
