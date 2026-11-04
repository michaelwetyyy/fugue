"""Unwired OpenCode adapter with a daemon-owned durable reservation boundary."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from threading import Lock
from types import MappingProxyType
from typing import Any, Mapping, Protocol

from oc_rig.adapters.models import AdapterRequest, AdapterResult, Cancellation
from oc_rig.adapters.opencode_client import (
    MAX_REQUEST_BYTES,
    MAX_PROMPT_BYTES,
    OpenCodeAuth,
    OpenCodeClient,
    OpenCodeClientConfig,
    OpenCodeClientError,
    OpenCodeConfigError,
    REVIEW_AGENT_NAME,
    validate_identifier,
)
from oc_rig.policy.capsule import (
    MAX_SCOPE_ENVELOPE_BYTES,
    REVIEW_SYSTEM_PROMPT,
    ScopeCapsuleError,
    parse_capsule_prompt,
    parse_task_prompt,
)
from oc_rig.policy.models import AgentLifecycle
from oc_rig.policy.scanner import scan_content
from oc_rig.llm_behaviour import prompt_fields as llm_prompt_fields
from oc_rig.opencode_authority import DEFAULT_AGENT_EFFORT, _MODEL


POOL_SIZES = MappingProxyType(
    {"tensorhost": 3, "homelab": 3, "personal": 3, "control": 3, "hands-off": 1}
)
LEGACY_POOL_SIZES = MappingProxyType(
    {"tensorhost": 3, "homelab": 3, "personal": 3, "control": 1, "hands-off": 1}
)
ALLOWED_CLASSIFICATIONS = frozenset({"PUBLIC", "SANITIZED"})


def _utf8_size(value: str) -> int | None:
    try:
        return len(value.encode("utf-8"))
    except UnicodeError:
        return None


@dataclass(frozen=True, slots=True)
class OpenCodeSlot:
    slot_id: str
    session_id: str
    worker: str

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("OpenCodeSlot is sealed")

    def __post_init__(self) -> None:
        for value, label in (
            (self.slot_id, "slot_id"),
            (self.session_id, "session_id"),
            (self.worker, "worker"),
        ):
            try:
                validate_identifier(value, label)
            except OpenCodeClientError:
                raise OpenCodeConfigError("topology_invalid") from None


@dataclass(frozen=True, slots=True)
class OpenCodeTopology:
    pools: Mapping[str, tuple[OpenCodeSlot, ...]]

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("OpenCodeTopology is sealed")

    def __post_init__(self) -> None:
        if not isinstance(self.pools, Mapping) or set(self.pools) != set(POOL_SIZES):
            raise OpenCodeConfigError("topology_invalid")
        copied: dict[str, tuple[OpenCodeSlot, ...]] = {}
        slots: set[str] = set()
        sessions: set[str] = set()
        sizes = (
            LEGACY_POOL_SIZES
            if len(self.pools.get("control", ())) == 1
            else POOL_SIZES
        )
        for pool, size in sizes.items():
            members = self.pools[pool]
            if not isinstance(members, tuple) or len(members) != size:
                raise OpenCodeConfigError("topology_invalid")
            if any(not isinstance(member, OpenCodeSlot) for member in members):
                raise OpenCodeConfigError("topology_invalid")
            for position, member in enumerate(members, start=1):
                if (
                    member.slot_id != f"{pool}-{position}"
                    or member.slot_id in slots
                    or member.session_id in sessions
                ):
                    raise OpenCodeConfigError("topology_invalid")
                slots.add(member.slot_id)
                sessions.add(member.session_id)
            copied[pool] = tuple(members)
        object.__setattr__(self, "pools", MappingProxyType(copied))


@dataclass(frozen=True, slots=True)
class OpenCodeTrust:
    mode: str
    secure_worker: str

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("OpenCodeTrust is sealed")

    def __post_init__(self) -> None:
        if self.mode != "secure":
            raise OpenCodeConfigError("secure_mode_required")
        try:
            validate_identifier(self.secure_worker, "secure_worker")
        except OpenCodeClientError:
            raise OpenCodeConfigError("trust_invalid") from None


@dataclass(frozen=True, slots=True)
class DispatchRegistration:
    transport_id: str
    work_id: str
    completion_registration_id: str
    callback_registration_id: str
    session_id: str
    generation: int
    prompt_message_id: str
    idempotency_key: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.transport_id, "transport_id"),
            (self.work_id, "work_id"),
            (self.completion_registration_id, "completion_registration_id"),
            (self.callback_registration_id, "callback_registration_id"),
            (self.session_id, "session_id"),
            (self.prompt_message_id, "prompt_message_id"),
            (self.idempotency_key, "idempotency_key"),
        ):
            validate_identifier(value, label)
        if (
            type(self.generation) is not int
            or self.generation <= 0
            or self.idempotency_key != self.transport_id
        ):
            raise ValueError("dispatch_registration_invalid")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("DispatchRegistration is sealed")


class AcquisitionState(StrEnum):
    CREATED = "created"
    IN_FLIGHT = "in_flight"
    TERMINAL = "terminal"


@dataclass(frozen=True, slots=True)
class ReservationCandidate:
    slot_id: str
    session_id: str
    worker: str
    last_used: int


@dataclass(frozen=True, slots=True)
class ReservationRequest:
    transport_id: str
    work_id: str
    pool: str
    request_fingerprint: str
    completion_registration_id: str
    callback_registration_id: str
    candidates: tuple[ReservationCandidate, ...]
    isolated_session_id: str | None = None
    provisional_claim_token: str | None = None
    agent_lifecycle: AgentLifecycle = AgentLifecycle.PERSISTENT
    persistent_scope_hash: str | None = None


@dataclass(frozen=True, slots=True)
class DurableReservation:
    """Exact target persisted atomically by :class:`DurableReservationPort`."""

    transport_id: str
    work_id: str
    pool: str
    request_fingerprint: str
    completion_registration_id: str
    callback_registration_id: str
    slot_id: str
    session_id: str
    worker: str
    assignment_generation: int
    prompt_message_id: str
    capability: str = field(repr=False)
    isolated_session_id: str | None = None
    abort_capability: str | None = field(default=None, repr=False)
    outcome: AdapterResult | None = None
    abort_outcome: AdapterResult | None = None

    def __post_init__(self) -> None:
        for value, label in (
            (self.transport_id, "transport_id"),
            (self.work_id, "work_id"),
            (self.pool, "pool"),
            (self.completion_registration_id, "completion_registration_id"),
            (self.callback_registration_id, "callback_registration_id"),
            (self.slot_id, "slot_id"),
            (self.session_id, "session_id"),
            (self.worker, "worker"),
            (self.prompt_message_id, "prompt_message_id"),
        ):
            validate_identifier(value, label)
        if self.isolated_session_id is not None:
            validate_identifier(self.isolated_session_id, "isolated_session_id")
        if (
            len(self.request_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in self.request_fingerprint)
            or type(self.assignment_generation) is not int
            or self.assignment_generation <= 0
            or len(self.capability) != 64
            or any(character not in "0123456789abcdef" for character in self.capability)
            or (
                self.isolated_session_id is not None
                and type(self.isolated_session_id) is not str
            )
            or (
                self.abort_capability is not None
                and (
                    len(self.abort_capability) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in self.abort_capability
                    )
                )
            )
            or (self.outcome is not None and type(self.outcome) is not AdapterResult)
            or (
                self.abort_outcome is not None
                and type(self.abort_outcome) is not AdapterResult
            )
        ):
            raise ValueError("durable_reservation_invalid")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("DurableReservation is sealed")

    def registration(self) -> DispatchRegistration:
        return DispatchRegistration(
            self.transport_id,
            self.work_id,
            self.completion_registration_id,
            self.callback_registration_id,
            self.target_session_id,
            self.assignment_generation,
            self.prompt_message_id,
            self.transport_id,
        )

    @property
    def target_session_id(self) -> str:
        return self.isolated_session_id or self.session_id


@dataclass(frozen=True, slots=True)
class DeliveryAcquisition:
    state: AcquisitionState
    reservation: DurableReservation

    def __post_init__(self) -> None:
        if (
            type(self.state) is not AcquisitionState
            or type(self.reservation) is not DurableReservation
        ):
            raise TypeError("delivery acquisition must be exact")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("DeliveryAcquisition is sealed")


@dataclass(frozen=True, slots=True)
class AbortAcquisition:
    state: AcquisitionState
    reservation: DurableReservation

    def __post_init__(self) -> None:
        if (
            type(self.state) is not AcquisitionState
            or type(self.reservation) is not DurableReservation
        ):
            raise TypeError("abort acquisition must be exact")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("AbortAcquisition is sealed")


@dataclass(frozen=True, slots=True)
class SessionCleanup:
    transport_id: str
    session_id: str
    idempotency_key: str
    attempt: int


@dataclass(frozen=True, slots=True)
class ProvisionalSession:
    transport_id: str
    title: str
    state: str
    session_id: str | None = None
    claim_token: str | None = None


@dataclass(frozen=True, slots=True)
class PersistentSession:
    scope_hash: str
    pool: str
    worker: str
    title: str
    state: str
    session_id: str | None = None
    claim_token: str | None = None


class DurableReservationPort(Protocol):
    """Daemon-owned atomic persistence and slot-exclusion capability.

    ``acquire_delivery`` must, in one durable transaction, select one candidate not held
    by another active assignment, increment that slot's generation, persist the
    exact target and completion registration by ``transport_id``, and return
    ``CREATED`` only to the transaction which created the send intent.
    """

    def acquire_delivery(
        self, request: ReservationRequest
    ) -> DeliveryAcquisition | None: ...

    def provisional_intent(self, request: ReservationRequest) -> ProvisionalSession: ...

    def claim_provisional(
        self, request: ReservationRequest, title: str
    ) -> ProvisionalSession | None: ...

    def bind_provisional(
        self, request: ReservationRequest, title: str, session_id: str,
        claim_token: str,
    ) -> ProvisionalSession: ...

    def mark_provisional(
        self, request: ReservationRequest, title: str, state: str, error: str | None,
        claim_token: str,
    ) -> None: ...

    def outstanding_provisionals(self, limit: int) -> tuple[ProvisionalSession, ...]: ...

    def bind_outstanding_provisional(
        self, transport_id: str, title: str, session_id: str, claim_token: str
    ) -> ProvisionalSession: ...

    def mark_outstanding_provisional(
        self, transport_id: str, title: str, state: str, error: str | None,
        claim_token: str,
    ) -> None: ...

    def release_provisional_claim(
        self, transport_id: str, title: str, claim_token: str
    ) -> None: ...

    def persistent_intent(
        self, request: ReservationRequest, scope_hash: str, worker: str
    ) -> PersistentSession: ...

    def claim_persistent(
        self, scope_hash: str, title: str
    ) -> PersistentSession | None: ...

    def bind_persistent(
        self, scope_hash: str, title: str, session_id: str, claim_token: str
    ) -> PersistentSession: ...

    def claim_persistent_close(
        self, scope_hash: str
    ) -> PersistentSession | None: ...

    def finish_persistent_close(
        self, scope_hash: str, title: str, session_id: str, claim_token: str,
        state: str, error: str | None,
    ) -> PersistentSession: ...

    def record_outcome(
        self, reservation: DurableReservation, result: AdapterResult
    ) -> AdapterResult: ...

    def acquire_abort(self, transport_id: str) -> AbortAcquisition | None: ...

    def revalidate_abort(self, reservation: DurableReservation) -> bool: ...

    def record_abort(
        self, reservation: DurableReservation, result: AdapterResult
    ) -> AdapterResult: ...

    def release_completed_in_transaction(
        self,
        connection: sqlite3.Connection,
        registration: DispatchRegistration,
    ) -> bool: ...

    def acquire_session_cleanup(self) -> SessionCleanup | None: ...

    def record_session_cleanup(
        self, cleanup: SessionCleanup, state: str, error: str | None
    ) -> None: ...

    def session_cleanup_attention(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class LiveOpenCodeAdapterConfig:
    client: OpenCodeClientConfig
    topology: OpenCodeTopology
    trust: OpenCodeTrust

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("LiveOpenCodeAdapterConfig is sealed")

    def __post_init__(self) -> None:
        if (
            type(self.client) is not OpenCodeClientConfig
            or type(self.topology) is not OpenCodeTopology
            or type(self.trust) is not OpenCodeTrust
        ):
            raise OpenCodeConfigError("adapter_config_invalid")
        for members in self.topology.pools.values():
            if any(member.worker != self.trust.secure_worker for member in members):
                raise OpenCodeConfigError("secure_worker_required")

    @classmethod
    def from_explicit_files(
        cls,
        *,
        endpoint: str,
        auth_path: Path,
        topology_path: Path,
        trust_path: Path,
    ) -> "LiveOpenCodeAdapterConfig":
        auth = _parse_auth(_load_private_json(auth_path, "auth"))
        trust = _parse_trust(_load_private_json(trust_path, "trust"))
        topology = _parse_topology(_load_private_json(topology_path, "topology"))
        return cls(OpenCodeClientConfig.explicit(endpoint, auth), topology, trust)

    @classmethod
    def from_historical_files(
        cls,
        *,
        endpoint: str,
        auth_path: Path,
        topology_path: Path,
        trust_path: Path,
    ) -> "LiveOpenCodeAdapterConfig":
        """Validate the immutable eleven-slot cutover source only."""

        auth = _parse_auth(_load_private_json(auth_path, "auth"))
        trust = _parse_trust(_load_private_json(trust_path, "trust"))
        topology_value = _load_private_json(topology_path, "topology")
        try:
            topology = _parse_topology(topology_value)
        except OpenCodeConfigError as error:
            if str(error) != "topology_invalid":
                raise
            topology = _parse_topology_with_sizes(
                topology_value, LEGACY_POOL_SIZES
            )
        return cls(OpenCodeClientConfig.explicit(endpoint, auth), topology, trust)


def _load_private_json(path: Path, label: str) -> Mapping[str, Any]:
    if not isinstance(path, Path) or not path.is_absolute():
        raise OpenCodeConfigError(f"{label}_path_not_explicit")
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode) or facts.st_nlink != 1:
            raise OpenCodeConfigError(f"{label}_file_invalid")
        if facts.st_uid != os.geteuid() or facts.st_mode & 0o077:
            raise OpenCodeConfigError(f"{label}_file_permissions")
        raw = os.read(descriptor, MAX_REQUEST_BYTES + 1)
    except OpenCodeConfigError:
        raise
    except OSError:
        raise OpenCodeConfigError(f"{label}_file_unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not raw or len(raw) > MAX_REQUEST_BYTES:
        raise OpenCodeConfigError(f"{label}_file_invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeError):
        raise OpenCodeConfigError(f"{label}_file_invalid") from None
    if type(value) is not dict:
        raise OpenCodeConfigError(f"{label}_file_invalid")
    return value


def _parse_auth(value: Mapping[str, Any]) -> OpenCodeAuth:
    if value.get("type") == "bearer" and set(value) == {"type", "token"}:
        return OpenCodeAuth.bearer(value.get("token"))
    if value.get("type") == "basic" and set(value) == {
        "type", "username", "password"
    }:
        return OpenCodeAuth.basic(value.get("username"), value.get("password"))
    raise OpenCodeConfigError("auth_invalid")


def _parse_trust(value: Mapping[str, Any]) -> OpenCodeTrust:
    if set(value) != {"mode", "secure_worker"}:
        raise OpenCodeConfigError("trust_invalid")
    return OpenCodeTrust(value.get("mode"), value.get("secure_worker"))


def _parse_topology_with_sizes(
    value: Mapping[str, Any], sizes: Mapping[str, int]
) -> OpenCodeTopology:
    if set(value) != {"version", "pools"} or value.get("version") != 1:
        raise OpenCodeConfigError("topology_invalid")
    raw_pools = value.get("pools")
    if type(raw_pools) is not dict or set(raw_pools) != set(sizes):
        raise OpenCodeConfigError("topology_invalid")
    pools: dict[str, tuple[OpenCodeSlot, ...]] = {}
    for pool, size in sizes.items():
        raw_members = raw_pools.get(pool)
        if type(raw_members) is not list or len(raw_members) != size:
            raise OpenCodeConfigError("topology_invalid")
        members: list[OpenCodeSlot] = []
        for raw in raw_members:
            if type(raw) is not dict or set(raw) != {"slot_id", "session_id", "worker"}:
                raise OpenCodeConfigError("topology_invalid")
            members.append(OpenCodeSlot(raw["slot_id"], raw["session_id"], raw["worker"]))
        pools[pool] = tuple(members)
    return OpenCodeTopology(pools)


def _parse_topology(value: Mapping[str, Any]) -> OpenCodeTopology:
    return _parse_topology_with_sizes(value, POOL_SIZES)


def _admit_payload(
    payload_json: str,
    *,
    admitted_content_hash: str | None = None,
    claim_scope_hash: str | None = None,
    capsule_scope_hash: str | None = None,
    agent_lifecycle: AgentLifecycle = AgentLifecycle.PERSISTENT,
    allow_child_agents: bool = False,
) -> tuple[str, bool]:
    if (
        type(agent_lifecycle) is not AgentLifecycle
        or type(allow_child_agents) is not bool
    ):
        raise OpenCodeClientError("payload_binding_invalid")
    size = _utf8_size(payload_json) if type(payload_json) is str else None
    if size is None or size > MAX_REQUEST_BYTES:
        raise OpenCodeClientError("payload_invalid")
    try:
        value = json.loads(payload_json)
    except (json.JSONDecodeError, UnicodeError):
        raise OpenCodeClientError("payload_invalid") from None
    if type(value) is not dict or set(value) != {"prompt", "classification", "trust"}:
        raise OpenCodeClientError("payload_invalid")
    prompt = value.get("prompt")
    prompt_size = _utf8_size(prompt) if type(prompt) is str else None
    if not prompt or prompt_size is None or prompt_size > MAX_PROMPT_BYTES:
        raise OpenCodeClientError("payload_invalid")
    if value.get("classification") not in ALLOWED_CLASSIFICATIONS:
        raise OpenCodeClientError("classification_rejected")
    if value.get("trust") != "secure":
        raise OpenCodeClientError("secure_mode_required")
    prompt_scan = scan_content(prompt)
    if admitted_content_hash is not None and (
        type(admitted_content_hash) is not str
        or len(admitted_content_hash) != 64
        or any(character not in "0123456789abcdef" for character in admitted_content_hash)
        or admitted_content_hash != prompt_scan.content_hash
    ):
        raise OpenCodeClientError("payload_binding_invalid")
    try:
        decoded_prompt = parse_capsule_prompt(prompt)
    except ScopeCapsuleError:
        raise OpenCodeClientError("payload_rejected") from None
    try:
        task_prompt = parse_task_prompt(prompt) if decoded_prompt is None else None
    except ScopeCapsuleError:
        raise OpenCodeClientError("payload_rejected") from None
    if decoded_prompt is not None:
        capsule_binding = (
            decoded_prompt["claim_scope_hash"],
            decoded_prompt["scope_capsule"]["manifest"]["scope_hash"],
        )
        if (
            value.get("classification") != "PUBLIC"
            or prompt_size > MAX_SCOPE_ENVELOPE_BYTES
            or type(admitted_content_hash) is not str
            or type(claim_scope_hash) is not str
            or type(capsule_scope_hash) is not str
            or capsule_binding != (claim_scope_hash, capsule_scope_hash)
            or agent_lifecycle is not AgentLifecycle.DISPOSABLE
            or allow_child_agents
        ):
            raise OpenCodeClientError("payload_binding_invalid")
    elif task_prompt is not None:
        task_binding = (
            task_prompt["claim_scope_hash"],
            task_prompt["scope_capsule"]["manifest"]["scope_hash"],
        )
        if (
            value.get("classification") != "PUBLIC"
            or prompt_size > MAX_SCOPE_ENVELOPE_BYTES
            or type(admitted_content_hash) is not str
            or type(claim_scope_hash) is not str
            or type(capsule_scope_hash) is not str
            or task_binding != (claim_scope_hash, capsule_scope_hash)
            or task_prompt["agent_lifecycle"] != agent_lifecycle.value
            or task_prompt["allow_child_agents"] is not allow_child_agents
        ):
            raise OpenCodeClientError("payload_binding_invalid")
    elif capsule_scope_hash is not None or not prompt_scan.safe:
        raise OpenCodeClientError("payload_rejected")
    return prompt, decoded_prompt is not None


def _snapshot_adapter_request(request: AdapterRequest) -> AdapterRequest:
    if type(request) is not AdapterRequest:
        raise TypeError("exact AdapterRequest required")
    snapshot = AdapterRequest(
        request.transport_id,
        request.work_id,
        request.pool,
        request.payload_json,
        request.completion_registration_id,
        request.callback_registration_id,
        request.admitted_content_hash,
        request.claim_scope_hash,
        request.capsule_scope_hash,
        request.agent_lifecycle,
        request.allow_child_agents,
    )
    for value, label in (
        (snapshot.transport_id, "transport_id"),
        (snapshot.work_id, "work_id"),
        (snapshot.completion_registration_id, "completion_registration_id"),
        (snapshot.callback_registration_id, "callback_registration_id"),
    ):
        validate_identifier(value, label)
    if snapshot.pool not in POOL_SIZES:
        raise OpenCodeClientError("pool_invalid")
    return snapshot


def _fingerprint(request: AdapterRequest) -> str:
    if type(request) is not AdapterRequest:
        raise TypeError("exact AdapterRequest required")
    document = {
        "transport_id": request.transport_id,
        "work_id": request.work_id,
        "pool": request.pool,
        "payload_json": request.payload_json,
        "completion_registration_id": request.completion_registration_id,
        "callback_registration_id": request.callback_registration_id,
        "admitted_content_hash": request.admitted_content_hash,
        "claim_scope_hash": request.claim_scope_hash,
        "capsule_scope_hash": request.capsule_scope_hash,
        "agent_lifecycle": request.agent_lifecycle.value,
        "allow_child_agents": request.allow_child_agents,
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _session_updated(session: Mapping[str, Any]) -> int | None:
    time_value = session.get("time")
    value = time_value.get("updated") if type(time_value) is dict else None
    return value if type(value) is int and value >= 0 else None


def _status_type(value: object) -> str | None:
    return value.get("type") if type(value) is dict and type(value.get("type")) is str else None


def _validated_status_types(statuses: Mapping[str, Any]) -> dict[str, str]:
    """Decode OpenCode's sparse status map without broadening malformed data.

    OpenCode removes idle sessions from ``/session/status``.  A session that is
    present in the authoritative ``/session`` list but absent from this map is
    therefore idle.  Present entries must still carry one of the exact status
    discriminators; malformed or future shapes fail closed instead of being
    mistaken for an omitted idle entry.
    """

    if type(statuses) is not dict:
        raise OpenCodeClientError("status_invalid")
    decoded: dict[str, str] = {}
    for session_id, properties in statuses.items():
        status_type = _status_type(properties)
        if type(session_id) is not str or status_type not in {"idle", "busy", "retry"}:
            raise OpenCodeClientError("status_invalid")
        decoded[session_id] = status_type
    return decoded


def _todos_clear(todos: list[Mapping[str, Any]]) -> bool:
    return all(item.get("status") in {"completed", "cancelled"} for item in todos)


def _expected_message_id(transport_id: str, session_id: str, generation: int) -> str:
    digest = hashlib.sha256(
        f"{transport_id}:{session_id}:{generation}".encode()
    ).hexdigest()[:40]
    return f"msg-{digest}"


_DAEMON_CONSTRUCTION_TOKEN = object()


class LiveOpenCodeAdapter:
    """Submit only after the daemon-owned port durably excludes one slot."""

    __slots__ = (
        "_client", "_reservations", "_secure_worker", "_topology", "_sealed",
        "_tool_roster_hash", "_tool_roster_lock",
        "_review_agent_hash",
    )

    def __new__(cls, *_args: object, **_kwargs: object) -> "LiveOpenCodeAdapter":
        raise TypeError("LiveOpenCodeAdapter requires a daemon-owned factory")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("LiveOpenCodeAdapter is sealed")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("LiveOpenCodeAdapter is immutable")

    @classmethod
    def _construct(
        cls,
        construction_token: object,
        config: LiveOpenCodeAdapterConfig,
        *,
        reservations: DurableReservationPort,
    ) -> "LiveOpenCodeAdapter":
        if construction_token is not _DAEMON_CONSTRUCTION_TOKEN:
            raise PermissionError("adapter construction authority is absent")
        if type(config) is not LiveOpenCodeAdapterConfig:
            raise TypeError("validated LiveOpenCodeAdapterConfig required")
        for method in (
            "acquire_delivery",
            "provisional_intent",
            "claim_provisional",
            "bind_provisional",
            "mark_provisional",
            "outstanding_provisionals",
            "bind_outstanding_provisional",
            "mark_outstanding_provisional",
            "release_provisional_claim",
            "persistent_intent",
            "claim_persistent",
            "bind_persistent",
            "claim_persistent_close",
            "finish_persistent_close",
            "record_outcome",
            "acquire_abort",
            "revalidate_abort",
            "record_abort",
            "acquire_session_cleanup",
            "record_session_cleanup",
            "session_cleanup_attention",
        ):
            if not callable(getattr(reservations, method, None)):
                raise TypeError("durable reservation port required")
        from oc_rig.adapters.opencode_store import _RigStoreOpenCodeReservations

        if type(reservations) is not _RigStoreOpenCodeReservations:
            raise TypeError("production adapter requires the RigStore port")
        adapter = object.__new__(cls)
        object.__setattr__(adapter, "_client", OpenCodeClient(config.client))
        object.__setattr__(adapter, "_reservations", reservations)
        object.__setattr__(adapter, "_secure_worker", config.trust.secure_worker)
        object.__setattr__(adapter, "_topology", config.topology.pools)
        object.__setattr__(adapter, "_tool_roster_hash", None)
        object.__setattr__(adapter, "_review_agent_hash", None)
        object.__setattr__(adapter, "_tool_roster_lock", Lock())
        object.__setattr__(adapter, "_sealed", True)
        return adapter

    @property
    def kind(self) -> str:
        return "opencode-http-sse-v1"

    def _delete_isolated_session(
        self, session_id: str, transport_id: str
    ) -> AdapterResult | None:
        try:
            root_key = (
                f"{transport_id}:cleanup:"
                + hashlib.sha256(session_id.encode()).hexdigest()[:16]
            )
            outcome = self._delete_session_tree(session_id, root_key)
        except OpenCodeClientError as error:
            return AdapterResult.unknown(error.code)
        if outcome == "refused":
            return AdapterResult.unknown("session_cleanup_refused")
        return None

    def _delete_session_tree(self, root_id: str, root_idempotency_key: str) -> str:
        """Delete only descendants rooted at an exact disposable session, deepest first."""

        sessions = self._client.list_sessions()
        if len(sessions) > 1024:
            raise OpenCodeClientError("session_tree_too_large")
        parents: dict[str, str | None] = {}
        for item in sessions:
            session_id = item.get("id")
            parent_id = item.get("parentID")
            if (
                type(session_id) is not str
                or session_id in parents
                or parent_id not in (None, "")
                and type(parent_id) is not str
            ):
                raise OpenCodeClientError("session_tree_invalid")
            parents[session_id] = None if parent_id in (None, "") else parent_id
        descendants: list[tuple[int, str]] = []
        for session_id in parents:
            if session_id == root_id:
                continue
            seen = {session_id}
            current = parents[session_id]
            depth = 1
            while current is not None and current != root_id:
                if current in seen or current not in parents:
                    current = None
                    break
                seen.add(current)
                current = parents[current]
                depth += 1
            if current == root_id:
                descendants.append((depth, session_id))
        targets = [session_id for _depth, session_id in sorted(descendants, reverse=True)]
        targets.append(root_id)
        final = "absent"
        for session_id in targets:
            idempotency_key = (
                root_idempotency_key
                if session_id == root_id
                else (
                    f"{root_idempotency_key}:child:"
                    + hashlib.sha256(session_id.encode()).hexdigest()[:16]
                )
            )
            outcome = self._client.delete(
                session_id,
                idempotency_key=idempotency_key,
            )
            if outcome == "refused":
                return outcome
            final = outcome
        return final

    @staticmethod
    def _persistent_close_targets(
        sessions: list[Mapping[str, Any]], *, root_id: str, title: str
    ) -> tuple[str, ...]:
        """Return one exact retained tree deepest-first, or empty when fully absent."""

        if type(sessions) is not list or len(sessions) > 1024:
            raise OpenCodeClientError("persistent_session_tree_invalid")
        parents: dict[str, str | None] = {}
        titles: dict[str, object] = {}
        for item in sessions:
            if type(item) is not dict:
                raise OpenCodeClientError("persistent_session_tree_invalid")
            try:
                session_id = validate_identifier(item.get("id"), "session_id")
            except OpenCodeClientError:
                raise OpenCodeClientError("persistent_session_tree_invalid") from None
            parent_value = item.get("parentID")
            if parent_value in (None, ""):
                parent_id = None
            else:
                try:
                    parent_id = validate_identifier(parent_value, "parent_session_id")
                except OpenCodeClientError:
                    raise OpenCodeClientError("persistent_session_tree_invalid") from None
            if session_id in parents:
                raise OpenCodeClientError("persistent_session_tree_invalid")
            parents[session_id] = parent_id
            titles[session_id] = item.get("title")

        title_matches = sorted(
            session_id for session_id, candidate in titles.items() if candidate == title
        )
        if root_id in parents:
            if parents[root_id] is not None or titles[root_id] != title or title_matches != [root_id]:
                raise OpenCodeClientError("persistent_session_binding_changed")
        elif title_matches:
            raise OpenCodeClientError("persistent_session_binding_changed")

        descendants: list[tuple[int, str]] = []
        for session_id, parent_id in parents.items():
            if session_id == root_id:
                continue
            seen = {session_id}
            current = parent_id
            depth = 1
            while current is not None and current != root_id:
                if current in seen:
                    break
                seen.add(current)
                if current not in parents:
                    break
                current = parents[current]
                depth += 1
            if current == root_id:
                descendants.append((depth, session_id))
        descendants.sort(reverse=True)
        targets = [session_id for _depth, session_id in descendants]
        if root_id in parents:
            targets.append(root_id)
        return tuple(targets)

    def _finish_persistent_close(
        self,
        persistent: PersistentSession,
        *,
        state: str,
        error: str | None,
    ) -> PersistentSession:
        if persistent.session_id is None or persistent.claim_token is None:
            raise OpenCodeClientError("persistent_close_authority_invalid")
        try:
            return self._reservations.finish_persistent_close(
                persistent.scope_hash,
                persistent.title,
                persistent.session_id,
                persistent.claim_token,
                state,
                error,
            )
        except Exception as exc:
            raise OpenCodeClientError(
                "persistent_close_persistence_failed",
                delivery_unknown=state != "active",
            ) from exc

    def close_persistent_session(self, scope_hash: str) -> str:
        """Close one retained session only under durable exact-scope authority."""

        if (
            type(scope_hash) is not str
            or len(scope_hash) != 64
            or any(character not in "0123456789abcdef" for character in scope_hash)
        ):
            raise OpenCodeClientError("persistent_scope_invalid")
        try:
            persistent = self._reservations.claim_persistent_close(scope_hash)
        except Exception as exc:
            raise OpenCodeClientError("persistent_close_authority_invalid") from exc
        if persistent is None:
            return "busy"
        if persistent.state == "closed":
            return "closed"
        if persistent.state == "attention":
            return "attention"
        if (
            persistent.state != "active"
            or persistent.session_id is None
            or persistent.claim_token is None
        ):
            return "busy"

        try:
            sessions = self._client.list_sessions()
            targets = self._persistent_close_targets(
                sessions,
                root_id=persistent.session_id,
                title=persistent.title,
            )
        except OpenCodeClientError as error:
            self._finish_persistent_close(
                persistent, state="active", error=error.code
            )
            raise
        if not targets:
            self._finish_persistent_close(persistent, state="closed", error=None)
            return "closed"

        try:
            statuses = _validated_status_types(self._client.session_status())
            for session_id in targets:
                if statuses.get(session_id, "idle") != "idle" or not _todos_clear(
                    self._client.todos(session_id)
                ):
                    self._finish_persistent_close(
                        persistent, state="active", error="persistent_session_busy"
                    )
                    return "busy"
        except OpenCodeClientError as error:
            self._finish_persistent_close(
                persistent, state="active", error=error.code
            )
            raise

        deleted_any = False
        completed_all = False
        root_key = f"persistent-close:{scope_hash}"
        for session_id in targets:
            idempotency_key = (
                root_key
                if session_id == persistent.session_id
                else (
                    f"{root_key}:child:"
                    + hashlib.sha256(session_id.encode()).hexdigest()[:16]
                )
            )
            try:
                outcome = self._client.delete(
                    session_id,
                    idempotency_key=idempotency_key,
                )
            except OpenCodeClientError as error:
                if not error.delivery_unknown and not deleted_any:
                    self._finish_persistent_close(
                        persistent, state="active", error=error.code
                    )
                    raise
                break
            if outcome == "refused":
                if not deleted_any:
                    self._finish_persistent_close(
                        persistent, state="active", error="persistent_delete_refused"
                    )
                    return "busy"
                break
            deleted_any |= outcome == "deleted"
        else:
            completed_all = True

        try:
            remaining = self._persistent_close_targets(
                self._client.list_sessions(),
                root_id=persistent.session_id,
                title=persistent.title,
            )
        except OpenCodeClientError:
            remaining = (persistent.session_id,)
        if not remaining:
            self._finish_persistent_close(persistent, state="closed", error=None)
            return "closed"
        self._finish_persistent_close(
            persistent,
            state="attention",
            error=(
                "persistent_delete_incomplete"
                if deleted_any or completed_all
                else "persistent_delete_uncertain"
            ),
        )
        return "attention"

    def _attested_tools(self, *, allow_child_agents: bool) -> dict[str, bool]:
        first = self._client.tool_ids()
        second = self._client.tool_ids()
        if first != second:
            raise OpenCodeClientError("tool_roster_changed")
        digest = hashlib.sha256(",".join(first).encode()).hexdigest()
        with self._tool_roster_lock:
            if self._tool_roster_hash is None:
                object.__setattr__(self, "_tool_roster_hash", digest)
            elif self._tool_roster_hash != digest:
                raise OpenCodeClientError("tool_roster_identity_changed")
        tools = {tool_id: False for tool_id in first}
        if allow_child_agents:
            if "task" not in tools:
                raise OpenCodeClientError("child_agent_tool_unavailable")
            tools["task"] = True
        return tools

    def _attest_review_agent(self) -> None:
        first = self._client.review_agent_identity()
        second = self._client.review_agent_identity()
        if first != second:
            raise OpenCodeClientError("review_agent_changed")
        with self._tool_roster_lock:
            if self._review_agent_hash is None:
                object.__setattr__(self, "_review_agent_hash", first)
            elif self._review_agent_hash != first:
                raise OpenCodeClientError("review_agent_identity_changed")

    def _future_dispatch_llm_fields(self) -> dict[str, object]:
        """Read the durable choice immediately before a new root dispatch."""

        store = getattr(self._reservations, "_store", None)
        authority = getattr(self._reservations, "_authority", None)
        if store is None or authority is None:
            # Fake-only adapters have no durable store; retain the production default.
            return {"model": dict(_MODEL), "variant": DEFAULT_AGENT_EFFORT}
        try:
            with store._daemon_read_transaction(authority) as connection:
                return llm_prompt_fields(connection)
        except (sqlite3.Error, ValueError, RuntimeError) as error:
            raise OpenCodeClientError("llm_behaviour_unavailable") from error

    def prepare(self, request: AdapterRequest) -> "PreparedLiveOpenCodeAdapter":
        request_snapshot = _snapshot_adapter_request(request)
        _admit_payload(
            request_snapshot.payload_json,
            admitted_content_hash=request_snapshot.admitted_content_hash,
            claim_scope_hash=request_snapshot.claim_scope_hash,
            capsule_scope_hash=request_snapshot.capsule_scope_hash,
            agent_lifecycle=request_snapshot.agent_lifecycle,
            allow_child_agents=request_snapshot.allow_child_agents,
        )
        _fingerprint(request_snapshot)
        prepared = object.__new__(PreparedLiveOpenCodeAdapter)
        object.__setattr__(
            prepared, "_PreparedLiveOpenCodeAdapter__adapter", self
        )
        object.__setattr__(
            prepared, "_PreparedLiveOpenCodeAdapter__request", request_snapshot
        )
        object.__setattr__(prepared, "_PreparedLiveOpenCodeAdapter__closed", False)
        object.__setattr__(
            prepared, "_PreparedLiveOpenCodeAdapter__close_lock", Lock()
        )
        return prepared

    def completion_registration(
        self, transport_id: str
    ) -> DispatchRegistration | None:
        return self._reservations.registration_for_transport(transport_id)

    def completion_registrations(self) -> tuple[DispatchRegistration, ...]:
        return self._reservations.monitor_registrations()

    def dispatch_completion_consolidation(
        self,
        registration: DispatchRegistration,
        *,
        message_id: str,
        prompt: str,
        idempotency_key: str,
    ) -> None:
        """Send the one barrier-authorized, no-tool consolidation turn.

        The caller must durably prepare the exact message and idempotency IDs
        before entering this network boundary.  This method deliberately does
        not retry an uncertain send.
        """

        if type(registration) is not DispatchRegistration:
            raise TypeError("exact completion registration required")
        exact = self.completion_registration(registration.transport_id)
        if exact != registration:
            raise OpenCodeClientError("completion_registration_changed")
        validate_identifier(message_id, "message_id")
        validate_identifier(idempotency_key, "idempotency_key")
        if type(prompt) is not str or not prompt or len(prompt.encode("utf-8")) > 4096:
            raise OpenCodeClientError("consolidation_prompt_invalid")
        tools = self._attested_tools(allow_child_agents=False)
        self._client.prompt_async(
            registration.session_id,
            {
                "agent": self._secure_worker,
                "messageID": message_id,
                "parts": [{"type": "text", "text": prompt}],
                "tools": tools,
            },
            idempotency_key=idempotency_key,
        )

    def pump_provisional_sessions(self, limit: int = 8) -> int:
        outstanding = self._reservations.outstanding_provisionals(limit)
        if not outstanding:
            return 0
        sessions = self._client.list_sessions()
        topology_ids = {
            slot.session_id
            for members in self._topology.values()
            for slot in members
        }
        completed = 0
        for provisional in outstanding:
            matches = [
                item for item in sessions if item.get("title") == provisional.title
            ]
            if (
                len(matches) > 1
                or any(
                    type(item.get("id")) is not str
                    or item.get("parentID") not in (None, "")
                    for item in matches
                )
            ):
                self._reservations.mark_outstanding_provisional(
                    provisional.transport_id, provisional.title, "attention",
                    "provisional_session_ambiguous",
                    provisional.claim_token or "",
                )
                continue
            discovered = matches[0].get("id") if matches else None
            if discovered in topology_ids:
                self._reservations.mark_outstanding_provisional(
                    provisional.transport_id, provisional.title, "attention",
                    "session_create_not_isolated",
                    provisional.claim_token or "",
                )
                continue
            if provisional.state == "intended":
                if discovered is None:
                    self._reservations.release_provisional_claim(
                        provisional.transport_id, provisional.title,
                        provisional.claim_token or "",
                    )
                    continue
                provisional = self._reservations.bind_outstanding_provisional(
                    provisional.transport_id, provisional.title, str(discovered),
                    provisional.claim_token or "",
                )
            elif discovered is not None and discovered != provisional.session_id:
                self._reservations.mark_outstanding_provisional(
                    provisional.transport_id, provisional.title, "attention",
                    "provisional_session_binding_changed",
                    provisional.claim_token or "",
                )
                continue
            assert provisional.session_id is not None
            try:
                root_key = (
                    f"{provisional.transport_id}:cleanup:"
                    + hashlib.sha256(provisional.session_id.encode()).hexdigest()[:16]
                )
                outcome = self._delete_session_tree(
                    provisional.session_id,
                    root_key,
                )
            except OpenCodeClientError as error:
                self._reservations.release_provisional_claim(
                    provisional.transport_id, provisional.title,
                    provisional.claim_token or "",
                )
                raise OpenCodeClientError(
                    error.code, delivery_unknown=True
                ) from error
            if outcome == "refused":
                self._reservations.release_provisional_claim(
                    provisional.transport_id, provisional.title,
                    provisional.claim_token or "",
                )
                raise OpenCodeClientError(
                    "session_cleanup_refused", delivery_unknown=True
                )
            self._reservations.mark_outstanding_provisional(
                provisional.transport_id, provisional.title, "cleaned", None,
                provisional.claim_token or "",
            )
            completed += 1
        return completed

    def pump_session_cleanup(self, limit: int = 8) -> int:
        completed = self.pump_provisional_sessions(limit)
        for _ in range(limit):
            cleanup = self._reservations.acquire_session_cleanup()
            if cleanup is None:
                break
            try:
                outcome = self._delete_session_tree(
                    cleanup.session_id,
                    cleanup.idempotency_key,
                )
                if outcome == "refused":
                    state, error = "ambiguous", "cleanup_refused"
                else:
                    state, error = "succeeded", None
            except OpenCodeClientError as exc:
                state = "ambiguous" if exc.delivery_unknown else "failed"
                error = exc.code
            self._reservations.record_session_cleanup(cleanup, state, error)
            completed += state == "succeeded"
            if state == "ambiguous":
                raise OpenCodeClientError(
                    "session_cleanup_ambiguous", delivery_unknown=True
                )
            if state == "failed":
                raise OpenCodeClientError("session_cleanup_failed")
        if self._reservations.session_cleanup_attention():
            raise OpenCodeClientError("session_cleanup_attention_required")
        return completed

    def release_completed(self, registration: DispatchRegistration) -> bool:
        return self._reservations.release_completed(registration)

    def release_completed_in_transaction(
        self,
        connection: sqlite3.Connection,
        registration: DispatchRegistration,
    ) -> bool:
        return self._reservations.release_completed_in_transaction(
            connection,
            registration,
        )

    def safe_abort(self, transport_id: str) -> AdapterResult:
        try:
            transport_id = validate_identifier(transport_id, "transport_id")
            acquisition = self._reservations.acquire_abort(transport_id)
        except Exception:
            return AdapterResult.definite_failure("abort_authority_invalid")
        if acquisition is None:
            return AdapterResult.definite_failure("abort_authority_stale")
        if type(acquisition) is not AbortAcquisition:
            return AdapterResult.definite_failure("abort_authority_invalid")
        reservation = acquisition.reservation
        if acquisition.state is AcquisitionState.IN_FLIGHT:
            return AdapterResult.unknown("abort_already_in_flight")
        if acquisition.state is AcquisitionState.TERMINAL:
            return reservation.abort_outcome or AdapterResult.definite_failure(
                "abort_authority_stale"
            )
        if (
            acquisition.state is not AcquisitionState.CREATED
            or not self._reservation_current(reservation, abort=True)
        ):
            return AdapterResult.definite_failure("abort_authority_stale")
        try:
            statuses = self._client.session_status()
        except OpenCodeClientError as error:
            return self._finish_abort(
                reservation, AdapterResult.definite_failure(error.code)
            )
        backend_state = _status_type(statuses.get(reservation.target_session_id))
        if backend_state in {None, "idle"}:
            return self._finish_abort(
                reservation, AdapterResult.cancelled("abort_backend_already_idle")
            )
        if backend_state != "busy":
            return self._finish_abort(
                reservation, AdapterResult.definite_failure("abort_backend_not_active")
            )
        try:
            still_active = self._reservations.revalidate_abort(reservation)
        except Exception:
            still_active = False
        if not still_active:
            return AdapterResult.definite_failure("abort_authority_stale")
        try:
            aborted = self._client.abort(
                reservation.target_session_id,
                idempotency_key=(
                    "abort-" + hashlib.sha256(transport_id.encode()).hexdigest()
                ),
            )
            result = (
                AdapterResult.cancelled("abort_acknowledged")
                if aborted
                else AdapterResult.unknown("abort_not_acknowledged")
            )
        except OpenCodeClientError as error:
            result = (
                AdapterResult.unknown(error.code)
                if error.delivery_unknown
                else AdapterResult.definite_failure(error.code)
            )
        try:
            canonical = self._reservations.record_abort(reservation, result)
        except Exception:
            return AdapterResult.unknown("abort_outcome_persistence_unknown")
        return canonical if isinstance(canonical, AdapterResult) else AdapterResult.unknown(
            "abort_outcome_persistence_unknown"
        )

    def _finish_abort(
        self, reservation: DurableReservation, result: AdapterResult
    ) -> AdapterResult:
        try:
            canonical = self._reservations.record_abort(reservation, result)
        except Exception:
            return AdapterResult.unknown("abort_outcome_persistence_unknown")
        return canonical if isinstance(canonical, AdapterResult) else AdapterResult.unknown(
            "abort_outcome_persistence_unknown"
        )

    def _reservation_current(
        self, reservation: DurableReservation, *, abort: bool = False
    ) -> bool:
        if type(reservation) is not DurableReservation:
            return False
        members = self._topology.get(reservation.pool, ())
        topology_sessions = {
            member.session_id
            for pool_members in self._topology.values()
            for member in pool_members
        }
        structurally_current = (
            reservation.assignment_generation > 0
            and reservation.worker == self._secure_worker
            and reservation.prompt_message_id == _expected_message_id(
                reservation.transport_id,
                reservation.target_session_id,
                reservation.assignment_generation,
            )
            and any(
                member.slot_id == reservation.slot_id
                and member.session_id == reservation.session_id
                and member.worker == reservation.worker
                for member in members
            )
            and (
                reservation.isolated_session_id is None
                or (
                    reservation.isolated_session_id != reservation.session_id
                    and reservation.isolated_session_id not in topology_sessions
                    and reservation.target_session_id
                    == reservation.isolated_session_id
                )
            )
        )
        if not structurally_current:
            return False
        try:
            return (
                self._reservations.revalidate_abort(reservation)
                if abort
                else True
            )
        except Exception:
            return False


class PreparedLiveOpenCodeAdapter:
    __slots__ = (
        "__adapter",
        "__close_lock",
        "__closed",
        "__request",
    )

    def __new__(cls, *_args: object, **_kwargs: object) -> "PreparedLiveOpenCodeAdapter":
        raise TypeError("prepared adapters are created only by an admitted adapter")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("PreparedLiveOpenCodeAdapter is sealed")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("prepared adapter authority is immutable")

    def _is_closed(self) -> bool:
        with self.__close_lock:
            return self.__closed

    @property
    def provenance(self) -> None:
        return None

    def _candidates(
        self, request: AdapterRequest, *, is_capsule: bool
    ) -> tuple[ReservationCandidate, ...]:
        if is_capsule or request.capsule_scope_hash is not None:
            return tuple(
                sorted(
                    (
                        ReservationCandidate(
                            slot.slot_id, slot.session_id, slot.worker, 0
                        )
                        for slot in self.__adapter._topology[request.pool]
                    ),
                    key=lambda item: item.slot_id,
                )
            )
        sessions = self.__adapter._client.list_sessions()
        statuses = self.__adapter._client.session_status()
        status_types = _validated_status_types(statuses)
        by_id: dict[str, Mapping[str, Any]] = {}
        duplicates: set[str] = set()
        for session in sessions:
            session_id = session.get("id")
            if type(session_id) is not str:
                raise OpenCodeClientError("sessions_invalid")
            if session_id in by_id:
                duplicates.add(session_id)
            by_id[session_id] = session
        candidates: list[ReservationCandidate] = []
        for slot in self.__adapter._topology[request.pool]:
            session = by_id.get(slot.session_id)
            updated = _session_updated(session) if session is not None else None
            if (
                session is None
                or slot.session_id in duplicates
                or updated is None
                or status_types.get(slot.session_id, "idle") != "idle"
                or not _todos_clear(self.__adapter._client.todos(slot.session_id))
            ):
                continue
            candidates.append(
                ReservationCandidate(slot.slot_id, slot.session_id, slot.worker, updated)
            )
        return tuple(sorted(candidates, key=lambda item: (item.last_used, item.slot_id)))

    def _valid_reservation(
        self,
        reservation: DurableReservation,
        candidates: tuple[ReservationCandidate, ...],
        request: AdapterRequest,
        request_fingerprint: str,
        *,
        is_capsule: bool,
    ) -> bool:
        topology_sessions = {
            slot.session_id
            for members in self.__adapter._topology.values()
            for slot in members
        }
        return (
            type(reservation) is DurableReservation
            and reservation.transport_id == request.transport_id
            and reservation.work_id == request.work_id
            and reservation.pool == request.pool
            and reservation.request_fingerprint == request_fingerprint
            and reservation.completion_registration_id
            == request.completion_registration_id
            and reservation.callback_registration_id
            == request.callback_registration_id
            and reservation.assignment_generation > 0
            and len(reservation.capability) == 64
            and all(
                character in "0123456789abcdef"
                for character in reservation.capability
            )
            and reservation.prompt_message_id == _expected_message_id(
                reservation.transport_id,
                reservation.target_session_id,
                reservation.assignment_generation,
            )
            and (
                not candidates
                or any(
                    item.slot_id == reservation.slot_id
                    and item.session_id == reservation.session_id
                    and item.worker == reservation.worker
                    for item in candidates
                )
            )
            and reservation.worker == self.__adapter._secure_worker
            and (
                (
                    request.agent_lifecycle is AgentLifecycle.DISPOSABLE
                    and reservation.isolated_session_id is not None
                    and reservation.isolated_session_id
                    != reservation.session_id
                    and reservation.isolated_session_id not in topology_sessions
                    and reservation.target_session_id
                    == reservation.isolated_session_id
                )
                or (
                    request.agent_lifecycle is AgentLifecycle.PERSISTENT
                    and (
                        (
                            reservation.isolated_session_id is None
                            and reservation.target_session_id
                            == reservation.session_id
                        )
                        or (
                            reservation.isolated_session_id is not None
                            and reservation.isolated_session_id
                            != reservation.session_id
                            and reservation.isolated_session_id
                            not in topology_sessions
                            and reservation.target_session_id
                            == reservation.isolated_session_id
                        )
                    )
                )
            )
            and self.__adapter._reservation_current(reservation)
        )

    def _request_for(
        self,
        request: AdapterRequest,
        request_fingerprint: str,
        candidates: tuple[ReservationCandidate, ...],
        isolated_session_id: str | None = None,
        provisional_claim_token: str | None = None,
    ) -> ReservationRequest:
        return ReservationRequest(
            request.transport_id,
            request.work_id,
            request.pool,
            request_fingerprint,
            request.completion_registration_id,
            request.callback_registration_id,
            candidates,
            isolated_session_id,
            provisional_claim_token,
            request.agent_lifecycle,
            (
                request.claim_scope_hash
                if request.agent_lifecycle is AgentLifecycle.PERSISTENT
                else None
            ),
        )

    def _existing_result(
        self,
        acquisition: DeliveryAcquisition,
        request: AdapterRequest,
        request_fingerprint: str,
        *,
        is_capsule: bool,
    ) -> AdapterResult:
        reservation = acquisition.reservation
        if not self._valid_reservation(
            reservation, (), request, request_fingerprint,
            is_capsule=is_capsule,
        ):
            return AdapterResult.definite_failure("reservation_invalid")
        if acquisition.state is AcquisitionState.IN_FLIGHT:
            return (
                AdapterResult.unknown("delivery_already_in_flight")
                if reservation.outcome is None
                else AdapterResult.definite_failure("reservation_invalid")
            )
        if acquisition.state is AcquisitionState.TERMINAL:
            return reservation.outcome or AdapterResult.definite_failure(
                "reservation_invalid"
            )
        return AdapterResult.definite_failure("reservation_invalid")

    def _finish(
        self, reservation: DurableReservation, result: AdapterResult
    ) -> AdapterResult:
        try:
            canonical = self.__adapter._reservations.record_outcome(reservation, result)
        except Exception:
            return AdapterResult.unknown("reservation_outcome_persistence_unknown")
        return canonical if isinstance(canonical, AdapterResult) else AdapterResult.unknown(
            "reservation_outcome_persistence_unknown"
        )

    def send(self, cancellation: Cancellation, identity_recorder: object = None) -> AdapterResult:
        del identity_recorder
        if self._is_closed():
            return AdapterResult.definite_failure("adapter_closed")
        if cancellation.is_set():
            return AdapterResult.cancelled()
        try:
            request = _snapshot_adapter_request(self.__request)
            prompt, is_capsule = _admit_payload(
                request.payload_json,
                admitted_content_hash=request.admitted_content_hash,
                claim_scope_hash=request.claim_scope_hash,
                capsule_scope_hash=request.capsule_scope_hash,
                agent_lifecycle=request.agent_lifecycle,
                allow_child_agents=request.allow_child_agents,
            )
            request_fingerprint = _fingerprint(request)
        except OpenCodeClientError as error:
            return AdapterResult.definite_failure(error.code)
        except (AttributeError, TypeError, ValueError):
            return AdapterResult.definite_failure("request_invalid")
        try:
            existing = self.__adapter._reservations.acquire_delivery(
                self._request_for(request, request_fingerprint, ())
            )
        except Exception:
            return AdapterResult.definite_failure("reservation_failed")
        if existing is not None:
            if type(existing) is not DeliveryAcquisition:
                return AdapterResult.definite_failure("reservation_invalid")
            return self._existing_result(
                existing, request, request_fingerprint, is_capsule=is_capsule
            )
        try:
            candidates = self._candidates(request, is_capsule=is_capsule)
        except OpenCodeClientError as error:
            return AdapterResult.definite_failure(error.code)
        if not candidates:
            return AdapterResult.definite_failure("no_capacity")
        isolated_session_id: str | None = None
        provisional: ProvisionalSession | None = None
        if (
            request.agent_lifecycle is AgentLifecycle.PERSISTENT
            and type(request.claim_scope_hash) is str
        ):
            try:
                intent_request = self._request_for(
                    request, request_fingerprint, candidates
                )
                persistent = self.__adapter._reservations.persistent_intent(
                    intent_request,
                    request.claim_scope_hash,
                    self.__adapter._secure_worker,
                )
                sessions = self.__adapter._client.list_sessions()
                matches = [
                    item for item in sessions if item.get("title") == persistent.title
                ]
                topology_ids = {
                    slot.session_id
                    for members in self.__adapter._topology.values()
                    for slot in members
                }
                if (
                    len(matches) > 1
                    or any(
                        type(item.get("id")) is not str
                        or item.get("parentID") not in (None, "")
                        or item.get("id") in topology_ids
                        for item in matches
                    )
                ):
                    return AdapterResult.definite_failure("no_capacity")
                discovered = str(matches[0]["id"]) if matches else None
                if persistent.state == "active":
                    if discovered != persistent.session_id:
                        return AdapterResult.definite_failure("no_capacity")
                    isolated_session_id = persistent.session_id
                else:
                    claimed = self.__adapter._reservations.claim_persistent(
                        persistent.scope_hash, persistent.title
                    )
                    if claimed is None:
                        return AdapterResult.definite_failure("no_capacity")
                    assert claimed.claim_token is not None
                    isolated_session_id = discovered
                    if isolated_session_id is None:
                        isolated_session_id = self.__adapter._client.create_session(
                            title=persistent.title,
                            idempotency_key=(
                                f"persistent-session:{persistent.scope_hash}"
                            ),
                        )
                    persistent = self.__adapter._reservations.bind_persistent(
                        persistent.scope_hash,
                        persistent.title,
                        isolated_session_id,
                        claimed.claim_token,
                    )
                if isolated_session_id is None:
                    return AdapterResult.definite_failure("no_capacity")
                statuses = _validated_status_types(
                    self.__adapter._client.session_status()
                )
                if statuses.get(isolated_session_id, "idle") != "idle":
                    return AdapterResult.definite_failure("no_capacity")
                if not _todos_clear(
                    self.__adapter._client.todos(isolated_session_id)
                ):
                    return AdapterResult.definite_failure("no_capacity")
            except OpenCodeClientError:
                return AdapterResult.definite_failure("no_capacity")
            except Exception:
                return AdapterResult.definite_failure("no_capacity")
        tool_policy: dict[str, bool]
        try:
            self.__adapter._attest_review_agent()
            tool_policy = self.__adapter._attested_tools(
                allow_child_agents=request.allow_child_agents
            )
        except OpenCodeClientError as error:
            return AdapterResult.definite_failure(error.code)
        if request.agent_lifecycle is AgentLifecycle.DISPOSABLE:
            try:
                intent_request = self._request_for(
                    request, request_fingerprint, candidates
                )
                provisional = self.__adapter._reservations.provisional_intent(
                    intent_request
                )
                claimed = self.__adapter._reservations.claim_provisional(
                    intent_request, provisional.title
                )
                if claimed is None:
                    return AdapterResult.unknown("provisional_reconcile_in_flight")
                provisional = claimed
                assert provisional.claim_token is not None
                sessions = self.__adapter._client.list_sessions()
                matches = [
                    item for item in sessions
                    if item.get("title") == provisional.title
                ]
                topology_ids = {
                    slot.session_id
                    for members in self.__adapter._topology.values()
                    for slot in members
                }
                if (
                    len(matches) > 1
                    or any(
                        type(item.get("id")) is not str
                        or item.get("parentID") not in (None, "")
                        for item in matches
                    )
                ):
                    self.__adapter._reservations.mark_provisional(
                        intent_request, provisional.title, "attention",
                        "provisional_session_ambiguous",
                        provisional.claim_token,
                    )
                    return AdapterResult.unknown("provisional_session_ambiguous")
                discovered = matches[0].get("id") if matches else None
                if discovered in topology_ids:
                    self.__adapter._reservations.mark_provisional(
                        intent_request, provisional.title, "attention",
                        "session_create_not_isolated",
                        provisional.claim_token,
                    )
                    return AdapterResult.unknown("session_create_not_isolated")
                if provisional.state == "cleanup":
                    isolated_session_id = provisional.session_id
                elif provisional.state == "bound":
                    if discovered is not None and discovered != provisional.session_id:
                        self.__adapter._reservations.mark_provisional(
                            intent_request, provisional.title, "attention",
                            "provisional_session_binding_changed",
                            provisional.claim_token,
                        )
                        return AdapterResult.unknown(
                            "provisional_session_binding_changed"
                        )
                    isolated_session_id = provisional.session_id
                elif discovered is not None:
                    isolated_session_id = str(discovered)
                    provisional = self.__adapter._reservations.bind_provisional(
                        intent_request, provisional.title, isolated_session_id,
                        provisional.claim_token,
                    )
                else:
                    isolated_session_id = self.__adapter._client.create_session(
                        title=provisional.title,
                        idempotency_key=f"{request.transport_id}:session",
                    )
                    if isolated_session_id in topology_ids:
                        self.__adapter._reservations.mark_provisional(
                            intent_request, provisional.title, "attention",
                            "session_create_not_isolated",
                            provisional.claim_token,
                        )
                        return AdapterResult.unknown("session_create_not_isolated")
                    provisional = self.__adapter._reservations.bind_provisional(
                        intent_request, provisional.title, isolated_session_id,
                        provisional.claim_token,
                    )
            except OpenCodeClientError as error:
                return (
                    AdapterResult.unknown(error.code)
                    if error.delivery_unknown
                    else AdapterResult.definite_failure(error.code)
                )
            except Exception:
                return AdapterResult.unknown("provisional_persistence_unknown")
        if provisional is not None and provisional.state == "cleanup":
            assert isolated_session_id is not None and provisional.claim_token is not None
            cleanup = self.__adapter._delete_isolated_session(
                isolated_session_id, request.transport_id
            )
            if cleanup is not None:
                try:
                    self.__adapter._reservations.release_provisional_claim(
                        provisional.transport_id, provisional.title,
                        provisional.claim_token,
                    )
                except Exception:
                    return AdapterResult.unknown(
                        "provisional_cleanup_persistence_unknown"
                    )
                return cleanup
            try:
                self.__adapter._reservations.mark_provisional(
                    intent_request, provisional.title, "cleaned", None,
                    provisional.claim_token,
                )
            except Exception:
                return AdapterResult.unknown(
                    "provisional_cleanup_persistence_unknown"
                )
            return AdapterResult.definite_failure("no_capacity")
        reservation_request = self._request_for(
            request,
            request_fingerprint,
            candidates,
            isolated_session_id,
            provisional.claim_token if provisional is not None else None,
        )
        try:
            acquisition = self.__adapter._reservations.acquire_delivery(
                reservation_request
            )
        except Exception:
            if (
                isolated_session_id is not None
                and request.agent_lifecycle is AgentLifecycle.DISPOSABLE
            ):
                assert provisional is not None and provisional.claim_token is not None
                try:
                    self.__adapter._reservations.mark_provisional(
                        reservation_request, provisional.title, "cleanup", None,
                        provisional.claim_token,
                    )
                except Exception:
                    return AdapterResult.unknown(
                        "provisional_cleanup_persistence_unknown"
                    )
                cleanup = self.__adapter._delete_isolated_session(
                    isolated_session_id, request.transport_id
                )
                if cleanup is not None:
                    try:
                        self.__adapter._reservations.release_provisional_claim(
                            provisional.transport_id, provisional.title,
                            provisional.claim_token,
                        )
                    except Exception:
                        return AdapterResult.unknown(
                            "provisional_cleanup_persistence_unknown"
                        )
                    return cleanup
                try:
                    self.__adapter._reservations.mark_provisional(
                        reservation_request, provisional.title, "cleaned", None,
                        provisional.claim_token,
                    )
                except Exception:
                    return AdapterResult.unknown(
                        "provisional_cleanup_persistence_unknown"
                    )
            return AdapterResult.definite_failure("reservation_failed")
        if acquisition is None:
            if (
                isolated_session_id is not None
                and request.agent_lifecycle is AgentLifecycle.DISPOSABLE
            ):
                assert provisional is not None and provisional.claim_token is not None
                try:
                    self.__adapter._reservations.mark_provisional(
                        reservation_request, provisional.title, "cleanup", None,
                        provisional.claim_token,
                    )
                    provisional = ProvisionalSession(
                        provisional.transport_id, provisional.title, "cleanup",
                        isolated_session_id, provisional.claim_token,
                    )
                except Exception:
                    return AdapterResult.unknown(
                        "provisional_cleanup_persistence_unknown"
                    )
                cleanup = self.__adapter._delete_isolated_session(
                    isolated_session_id, request.transport_id
                )
                if cleanup is not None:
                    try:
                        self.__adapter._reservations.release_provisional_claim(
                            provisional.transport_id, provisional.title,
                            provisional.claim_token,
                        )
                    except Exception:
                        return AdapterResult.unknown(
                            "provisional_cleanup_persistence_unknown"
                        )
                    return cleanup
                if provisional is not None:
                    try:
                        self.__adapter._reservations.mark_provisional(
                            reservation_request, provisional.title, "cleaned", None,
                            provisional.claim_token or "",
                        )
                    except Exception:
                        return AdapterResult.unknown(
                            "provisional_cleanup_persistence_unknown"
                        )
            return AdapterResult.definite_failure("no_capacity")
        if type(acquisition) is not DeliveryAcquisition:
            if (
                isolated_session_id is not None
                and request.agent_lifecycle is AgentLifecycle.DISPOSABLE
            ):
                cleanup = self.__adapter._delete_isolated_session(
                    isolated_session_id, request.transport_id
                )
                if cleanup is not None:
                    return cleanup
            return AdapterResult.definite_failure("reservation_invalid")
        reservation = acquisition.reservation
        if (
            isolated_session_id is not None
            and reservation.isolated_session_id != isolated_session_id
            and request.agent_lifecycle is AgentLifecycle.DISPOSABLE
        ):
            cleanup = self.__adapter._delete_isolated_session(
                isolated_session_id, request.transport_id
            )
            if cleanup is not None:
                return cleanup
        if acquisition.state in {
            AcquisitionState.IN_FLIGHT,
            AcquisitionState.TERMINAL,
        }:
            return self._existing_result(
                acquisition, request, request_fingerprint,
                is_capsule=is_capsule,
            )
        if acquisition.state is not AcquisitionState.CREATED:
            return AdapterResult.definite_failure("reservation_invalid")
        if (
            reservation.outcome is not None
            or not self._valid_reservation(
                reservation, candidates, request, request_fingerprint,
                is_capsule=is_capsule,
            )
        ):
            return AdapterResult.definite_failure("reservation_invalid")
        if cancellation.is_set():
            return self._finish(reservation, AdapterResult.cancelled())
        body = {
            "agent": REVIEW_AGENT_NAME if is_capsule else reservation.worker,
            "messageID": reservation.prompt_message_id,
            "parts": [{"type": "text", "text": prompt}],
        }
        if is_capsule:
            body["system"] = REVIEW_SYSTEM_PROMPT
        body["tools"] = tool_policy
        body.update(self.__adapter._future_dispatch_llm_fields())
        try:
            self.__adapter._client.prompt_async(
                reservation.target_session_id,
                body,
                idempotency_key=request.transport_id,
            )
            acknowledgement = hashlib.sha256(
                (
                    f"{reservation.transport_id}:{reservation.target_session_id}:"
                    f"{reservation.assignment_generation}:accepted"
                ).encode()
            ).hexdigest()
            result = AdapterResult.accepted(f"opencode-{acknowledgement}")
        except OpenCodeClientError as error:
            result = (
                AdapterResult.unknown(error.code)
                if error.delivery_unknown
                else AdapterResult.definite_failure(error.code)
            )
        return self._finish(reservation, result)

    def close(self) -> None:
        with self.__close_lock:
            if not self.__closed:
                object.__setattr__(
                    self, "_PreparedLiveOpenCodeAdapter__closed", True
                )
