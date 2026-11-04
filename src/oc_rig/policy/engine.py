"""Secure-by-default standalone-worker admission decisions."""

from __future__ import annotations

import hashlib
import json

from oc_rig.policy.models import (
    AgentLifecycle,
    AdmissionRequest,
    DataClassification,
    DispatchKind,
    FindingCode,
    PolicyDecision,
    ReasonCode,
    RiskCategory,
    ScanFinding,
    ScanResult,
    TrustMode,
)
from oc_rig.policy.capsule import (
    MAX_SCOPE_ENVELOPE_BYTES,
    ScopeCapsuleError,
    parse_capsule_prompt,
    parse_task_prompt,
)
from oc_rig.policy.scanner import scan_content, scanner_policy_material
from oc_rig.policy.scope import inspect_scope


POLICY_VERSION = "rig-v2-trust-scope/7"

_RISK_REASONS = {
    RiskCategory.SENSITIVE: ReasonCode.SENSITIVE_TASK,
    RiskCategory.CREDENTIAL: ReasonCode.CREDENTIAL_TASK,
    RiskCategory.PRODUCTION: ReasonCode.PRODUCTION_TASK,
    RiskCategory.OPERATOR_GATED: ReasonCode.OPERATOR_GATED_TASK,
    RiskCategory.DESTRUCTIVE: ReasonCode.DESTRUCTIVE_TASK,
    RiskCategory.PURCHASE: ReasonCode.PURCHASE_TASK,
    RiskCategory.SIGNATURE: ReasonCode.SIGNATURE_TASK,
    RiskCategory.FILING: ReasonCode.FILING_TASK,
    RiskCategory.EXTERNAL_COMMITMENT: ReasonCode.EXTERNAL_COMMITMENT_TASK,
}


def _policy_document() -> dict[str, object]:
    return {
        "version": POLICY_VERSION,
        "trust": {
            "accepted": [mode.value for mode in TrustMode],
            "missing_or_malformed": TrustMode.SECURE.value,
        },
        "dispatch_kinds": [
            DispatchKind.AUTOMATED.value,
            DispatchKind.INTERACTIVE.value,
        ],
        "agent_lifecycles": [lifecycle.value for lifecycle in AgentLifecycle],
        "allow_child_agents": "exact-boolean",
        "classification_parsing": "exact-enum-value",
        "secure_automated_classifications": [
            DataClassification.PUBLIC.value,
            DataClassification.SANITIZED.value,
        ],
        "standalone_worker_rejected_risks": {
            risk.value: _RISK_REASONS[risk].value for risk in RiskCategory
        },
        "reason_codes": [reason.value for reason in ReasonCode],
        "scope": {
            "relative_posix_only": True,
            "reject_dot_traversal_git_symlink_hardlink_nonregular": True,
            "reject_unicode_collisions_and_prefix_ambiguity": True,
        },
        "scanner": scanner_policy_material(),
        "scope_capsule": {
            "mode": "read_only_review",
            "classification": DataClassification.PUBLIC.value,
            "max_envelope_bytes": MAX_SCOPE_ENVELOPE_BYTES,
            "scanner_is_defense_in_depth_only": True,
            "closed_review_profiles": True,
            "fresh_no_tool_session_required": True,
            "transport_revalidates_manifest_and_claim_hash": True,
            "agent_lifecycle": AgentLifecycle.DISPOSABLE.value,
            "allow_child_agents": False,
        },
        "task_capsule": {
            "modes": ["agent_task", "workspace_edit", "workspace_patch"],
            "classification": DataClassification.PUBLIC.value,
            "max_envelope_bytes": MAX_SCOPE_ENVELOPE_BYTES,
            "workspace_tools": "none",
            "child_tools": "none",
            "transport_revalidates_manifest_and_claim_hash": True,
            "workspace_patch": {
                "lifecycle": AgentLifecycle.DISPOSABLE.value,
                "one_file": True,
                "one_caller_selected_line_window": True,
                "full_preimage_worker_visible": False,
            },
        },
    }


POLICY_HASH = hashlib.sha256(
    json.dumps(_policy_document(), sort_keys=True, separators=(",", ":")).encode()
).hexdigest()


def classify_trust(value: object) -> tuple[TrustMode, ReasonCode | None]:
    """Classify untrusted mode input, defaulting missing/malformed to secure."""

    if isinstance(value, TrustMode):
        return value, None
    if value is None:
        return TrustMode.SECURE, ReasonCode.TRUST_MISSING_DEFAULTED_SECURE
    if type(value) is str and value in {mode.value for mode in TrustMode}:
        return TrustMode(value), None
    return TrustMode.SECURE, ReasonCode.TRUST_MALFORMED_DEFAULTED_SECURE


def _dispatch_kind(value: object) -> DispatchKind:
    if isinstance(value, DispatchKind):
        return value
    if type(value) is str and value in {
        DispatchKind.AUTOMATED.value,
        DispatchKind.INTERACTIVE.value,
    }:
        return DispatchKind(value)
    return DispatchKind.UNKNOWN


def _classification(value: object) -> tuple[DataClassification | None, bool]:
    if isinstance(value, DataClassification):
        return value, True
    if type(value) is str and value in {item.value for item in DataClassification}:
        return DataClassification(value), True
    return None, value is None


def _agent_lifecycle(value: object) -> AgentLifecycle | None:
    if isinstance(value, AgentLifecycle):
        return value
    if type(value) is str and value in {
        lifecycle.value for lifecycle in AgentLifecycle
    }:
        return AgentLifecycle(value)
    return None


def _allow_child_agents(value: object) -> bool | None:
    return value if type(value) is bool else None


def _risk_categories(value: object) -> tuple[tuple[RiskCategory, ...], bool]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return (), False
    parsed: set[RiskCategory] = set()
    for item in value:
        if isinstance(item, RiskCategory):
            parsed.add(item)
        elif type(item) is str and item in {risk.value for risk in RiskCategory}:
            parsed.add(RiskCategory(item))
        else:
            return (), False
    return tuple(sorted(parsed, key=lambda risk: risk.value)), True


def _decision_hash(document: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _scan_admission_content(value: object) -> tuple[ScanResult, bool]:
    """Hash the exact envelope while scanning v2 review material by its role."""

    complete = scan_content(value)
    if type(value) is not str:
        return complete, False
    try:
        decoded = parse_capsule_prompt(value)
    except ScopeCapsuleError as error:
        code = (
            FindingCode.SECRET_MATERIAL
            if error.code in {"scope_file_sensitive", "scope_file_high_entropy"}
            else FindingCode.INVALID_STRUCTURE
        )
        category = RiskCategory.SENSITIVE if code is FindingCode.SECRET_MATERIAL else None
        return (
            ScanResult(False, complete.content_hash, (ScanFinding(code, "$/scope_capsule", category),)),
            True,
        )
    except (json.JSONDecodeError, UnicodeError):
        return complete, False
    if decoded is None:
        try:
            task = parse_task_prompt(value)
        except ScopeCapsuleError as error:
            code = (
                FindingCode.SECRET_MATERIAL
                if error.code
                in {
                    "scope_file_sensitive",
                    "scope_file_high_entropy",
                    "scope_task_objective_unsafe",
                }
                else FindingCode.INVALID_STRUCTURE
            )
            category = (
                RiskCategory.SENSITIVE
                if code is FindingCode.SECRET_MATERIAL
                else None
            )
            return (
                ScanResult(
                    False,
                    complete.content_hash,
                    (ScanFinding(code, "$/scope_task", category),),
                ),
                False,
            )
        if task is None:
            return complete, False
        return ScanResult(True, complete.content_hash, ()), False
    try:
        if len(value.encode("utf-8")) > MAX_SCOPE_ENVELOPE_BYTES:
            return (
                ScanResult(
                    False,
                    complete.content_hash,
                    (
                        ScanFinding(
                            FindingCode.LIMIT_EXCEEDED,
                            "$/scope_capsule",
                        ),
                    ),
                ),
                True,
            )
    except UnicodeError:
        raise AssertionError("scan_content accepted invalid UTF-8") from None
    return ScanResult(True, complete.content_hash, ()), True


def decide_standalone_worker(request: AdmissionRequest) -> PolicyDecision:
    """Return an immutable, terminal admission decision for one request."""

    trust, trust_reason = classify_trust(request.trust)
    dispatch = _dispatch_kind(request.dispatch_kind)
    classification, classification_missing = _classification(request.classification)
    requested_lifecycle = _agent_lifecycle(request.agent_lifecycle)
    requested_allow_child_agents = _allow_child_agents(request.allow_child_agents)
    risks, risks_valid = _risk_categories(request.risk_categories)
    scan, is_scope_capsule = _scan_admission_content(request.content)
    scope = inspect_scope(request.repository, request.scope)

    reasons: set[ReasonCode] = set()
    if trust_reason is not None:
        reasons.add(trust_reason)
    if dispatch is DispatchKind.UNKNOWN:
        reasons.add(ReasonCode.UNKNOWN_DISPATCH_KIND)
    if requested_lifecycle is None:
        reasons.add(ReasonCode.AGENT_LIFECYCLE_MALFORMED)
    if requested_allow_child_agents is None:
        reasons.add(ReasonCode.ALLOW_CHILD_AGENTS_MALFORMED)
    if not classification_missing and classification is None:
        reasons.add(ReasonCode.CLASSIFICATION_MALFORMED)
    if classification is DataClassification.SENSITIVE:
        reasons.add(ReasonCode.CLASSIFICATION_SENSITIVE)
    if is_scope_capsule and classification is not DataClassification.PUBLIC:
        reasons.add(ReasonCode.SCOPE_CAPSULE_REQUIRES_PUBLIC)
    if is_scope_capsule and requested_allow_child_agents is True:
        reasons.add(ReasonCode.SCOPE_CAPSULE_DISALLOWS_CHILD_AGENTS)
    if (
        trust is TrustMode.SECURE
        and dispatch is DispatchKind.AUTOMATED
        and classification not in {
            DataClassification.PUBLIC,
            DataClassification.SANITIZED,
        }
    ):
        reasons.add(ReasonCode.CLASSIFICATION_REQUIRED)
    if not risks_valid:
        reasons.add(ReasonCode.UNKNOWN_RISK_CATEGORY)
    for risk in risks:
        reasons.add(_RISK_REASONS[risk])
    for finding in scan.findings:
        if finding.code is FindingCode.INVALID_STRUCTURE:
            reasons.add(ReasonCode.INVALID_CONTENT)
        elif finding.code is FindingCode.LIMIT_EXCEEDED:
            reasons.add(ReasonCode.SCANNER_LIMIT_EXCEEDED)
        elif finding.code is FindingCode.CONFUSABLE_TEXT:
            reasons.add(ReasonCode.CONFUSABLE_CONTENT)
        elif finding.code in {FindingCode.SENSITIVE_FIELD, FindingCode.SECRET_MATERIAL}:
            reasons.add(ReasonCode.SENSITIVE_CONTENT)
        if finding.risk_category is not None:
            reasons.add(_RISK_REASONS[finding.risk_category])
    reasons.update(scope.reason_codes)

    non_terminal = {
        ReasonCode.TRUST_MISSING_DEFAULTED_SECURE,
        ReasonCode.TRUST_MALFORMED_DEFAULTED_SECURE,
    }
    allowed = not (reasons - non_terminal)
    if allowed:
        reasons.add(ReasonCode.ALLOWED)
    ordered_reasons = tuple(sorted(reasons, key=lambda reason: reason.value))
    repository = str(scope.repository) if scope.repository is not None else None
    normalized_scope = tuple(path.relative for path in scope.paths)
    agent_lifecycle = (
        AgentLifecycle.DISPOSABLE
        if is_scope_capsule
        else requested_lifecycle or AgentLifecycle.PERSISTENT
    )
    allow_child_agents = (
        False if is_scope_capsule else requested_allow_child_agents is True
    )
    base_document: dict[str, object] = {
        "allowed": allowed,
        "terminal": not allowed,
        "trust_mode": trust.value,
        "dispatch_kind": dispatch.value,
        "classification": classification.value if classification is not None else None,
        "agent_lifecycle": agent_lifecycle.value,
        "allow_child_agents": allow_child_agents,
        "repository": repository,
        "normalized_scope": normalized_scope,
        "reason_codes": [reason.value for reason in ordered_reasons],
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
            for finding in scan.findings
        ],
        "content_hash": scan.content_hash,
        "policy_version": POLICY_VERSION,
        "policy_hash": POLICY_HASH,
    }
    return PolicyDecision(
        allowed=allowed,
        terminal=not allowed,
        trust_mode=trust,
        dispatch_kind=dispatch,
        classification=classification,
        agent_lifecycle=agent_lifecycle,
        allow_child_agents=allow_child_agents,
        repository=repository,
        normalized_scope=normalized_scope,
        reason_codes=ordered_reasons,
        findings=scan.findings,
        content_hash=scan.content_hash,
        policy_version=POLICY_VERSION,
        policy_hash=POLICY_HASH,
        decision_hash=_decision_hash(base_document),
    )
