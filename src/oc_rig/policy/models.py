"""Typed, immutable values used by standalone-worker admission policy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class TrustMode(StrEnum):
    """Controller trust modes.

    Untrusted input is converted to this type by :func:`classify_trust`; callers
    must not interpret unknown values themselves.
    """

    SECURE = "secure"
    INSECURE = "insecure"


class DispatchKind(StrEnum):
    """How a standalone-worker request entered the controller."""

    AUTOMATED = "automated"
    INTERACTIVE = "interactive"
    UNKNOWN = "unknown"


class AgentLifecycle(StrEnum):
    """Closed lifecycle choices accepted at the admission boundary."""

    DISPOSABLE = "disposable"
    PERSISTENT = "persistent"


class DataClassification(StrEnum):
    """Explicit classifications accepted at the policy boundary."""

    PUBLIC = "PUBLIC"
    SANITIZED = "SANITIZED"
    SENSITIVE = "SENSITIVE"


class RiskCategory(StrEnum):
    """Task categories that may not be routed to a standalone worker."""

    SENSITIVE = "sensitive"
    CREDENTIAL = "credential"
    PRODUCTION = "production"
    OPERATOR_GATED = "operator_gated"
    DESTRUCTIVE = "destructive"
    PURCHASE = "purchase"
    SIGNATURE = "signature"
    FILING = "filing"
    EXTERNAL_COMMITMENT = "external_commitment"


class FindingCode(StrEnum):
    """Non-secret scanner finding categories."""

    SENSITIVE_FIELD = "sensitive_field"
    SECRET_MATERIAL = "secret_material"
    RISK_LANGUAGE = "risk_language"
    CONFUSABLE_TEXT = "confusable_text"
    INVALID_STRUCTURE = "invalid_structure"
    LIMIT_EXCEEDED = "limit_exceeded"


class ReasonCode(StrEnum):
    """Stable reason codes persisted with an admission decision."""

    ALLOWED = "allowed"
    TRUST_MISSING_DEFAULTED_SECURE = "trust_missing_defaulted_secure"
    TRUST_MALFORMED_DEFAULTED_SECURE = "trust_malformed_defaulted_secure"
    UNKNOWN_DISPATCH_KIND = "unknown_dispatch_kind"
    AGENT_LIFECYCLE_MALFORMED = "agent_lifecycle_malformed"
    ALLOW_CHILD_AGENTS_MALFORMED = "allow_child_agents_malformed"
    SCOPE_CAPSULE_DISALLOWS_CHILD_AGENTS = (
        "scope_capsule_disallows_child_agents"
    )
    CLASSIFICATION_REQUIRED = "classification_required"
    CLASSIFICATION_MALFORMED = "classification_malformed"
    CLASSIFICATION_SENSITIVE = "classification_sensitive"
    INVALID_CONTENT = "invalid_content"
    SCANNER_LIMIT_EXCEEDED = "scanner_limit_exceeded"
    SENSITIVE_CONTENT = "sensitive_content"
    CONFUSABLE_CONTENT = "confusable_content"
    SENSITIVE_TASK = "sensitive_task"
    CREDENTIAL_TASK = "credential_task"
    PRODUCTION_TASK = "production_task"
    OPERATOR_GATED_TASK = "operator_gated_task"
    DESTRUCTIVE_TASK = "destructive_task"
    PURCHASE_TASK = "purchase_task"
    SIGNATURE_TASK = "signature_task"
    FILING_TASK = "filing_task"
    EXTERNAL_COMMITMENT_TASK = "external_commitment_task"
    UNKNOWN_RISK_CATEGORY = "unknown_risk_category"
    SCOPE_REQUIRED = "scope_required"
    SCOPE_INVALID_ENTRY = "scope_invalid_entry"
    SCOPE_ABSOLUTE = "scope_absolute"
    SCOPE_TRAVERSAL = "scope_traversal"
    SCOPE_GIT_ADMIN = "scope_git_admin"
    SCOPE_OUTSIDE_REPOSITORY = "scope_outside_repository"
    SCOPE_SYMLINK = "scope_symlink"
    SCOPE_HARDLINK = "scope_hardlink"
    SCOPE_NON_REGULAR = "scope_non_regular"
    SCOPE_COLLISION = "scope_collision"
    SCOPE_PREFIX_AMBIGUITY = "scope_prefix_ambiguity"
    SCOPE_INSPECTION_FAILED = "scope_inspection_failed"
    REPOSITORY_INVALID = "repository_invalid"
    SCOPE_CAPSULE_REQUIRES_PUBLIC = "scope_capsule_requires_public"


@dataclass(frozen=True, slots=True)
class ScanFinding:
    """A scanner result that never retains the matched content."""

    code: FindingCode
    path: str
    risk_category: RiskCategory | None = None


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Deterministic content classification result."""

    safe: bool
    content_hash: str
    findings: tuple[ScanFinding, ...]


@dataclass(frozen=True, slots=True)
class ScopedPath:
    """One normalized, inspected filesystem scope entry."""

    relative: str
    absolute: Path
    is_directory: bool


@dataclass(frozen=True, slots=True)
class ScopeInspection:
    """Fail-closed result of exact-scope normalization and inspection."""

    accepted: bool
    repository: Path | None
    paths: tuple[ScopedPath, ...]
    reason_codes: tuple[ReasonCode, ...]


@dataclass(frozen=True, slots=True)
class ScopeCapsuleFile:
    """One exact reviewed file, retaining no repository-local absolute path."""

    relative: str
    content: str
    size_bytes: int
    line_count: int
    content_hash: str
    device: int
    inode: int
    mode: int
    ctime_ns: int


@dataclass(frozen=True, slots=True)
class ScopeCapsule:
    """Canonical, content-bound material safe to embed in a worker prompt."""

    claim_scope_hash: str
    scope_hash: str
    root_device: int
    root_inode: int
    root_mode: int
    root_ctime_ns: int
    files: tuple[ScopeCapsuleFile, ...]


@dataclass(frozen=True, slots=True)
class AdmissionRequest:
    """Inputs for a standalone-worker admission decision.

    Boundary fields intentionally accept ``object``: the engine converts every
    untrusted value into a closed type and fails closed instead of relying on
    optimistic caller-side parsing.
    """

    repository: Path | str | object
    scope: object
    content: object
    dispatch_kind: DispatchKind | object = DispatchKind.AUTOMATED
    trust: TrustMode | object = None
    classification: DataClassification | object = None
    risk_categories: object = ()
    agent_lifecycle: AgentLifecycle | object = AgentLifecycle.PERSISTENT
    allow_child_agents: object = False


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Immutable admission decision suitable for durable journaling."""

    allowed: bool
    terminal: bool
    trust_mode: TrustMode
    dispatch_kind: DispatchKind
    classification: DataClassification | None
    agent_lifecycle: AgentLifecycle
    allow_child_agents: bool
    repository: str | None
    normalized_scope: tuple[str, ...]
    reason_codes: tuple[ReasonCode, ...]
    findings: tuple[ScanFinding, ...]
    content_hash: str
    policy_version: str
    policy_hash: str
    decision_hash: str

    def journal_record(self) -> dict[str, Any]:
        """Return a fresh JSON-compatible record without task content."""

        return {
            "allowed": self.allowed,
            "terminal": self.terminal,
            "trust_mode": self.trust_mode.value,
            "dispatch_kind": self.dispatch_kind.value,
            "classification": (
                self.classification.value if self.classification is not None else None
            ),
            "agent_lifecycle": self.agent_lifecycle.value,
            "allow_child_agents": self.allow_child_agents,
            "repository": self.repository,
            "normalized_scope": list(self.normalized_scope),
            "reason_codes": [reason.value for reason in self.reason_codes],
            "findings": [
                {
                    "code": finding.code.value,
                    "path": finding.path,
                    "risk_category": (
                        finding.risk_category.value
                        if finding.risk_category is not None
                        else None
                    ),
                }
                for finding in self.findings
            ],
            "content_hash": self.content_hash,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "decision_hash": self.decision_hash,
        }
