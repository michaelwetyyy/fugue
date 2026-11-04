from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from oc_rig.policy import (
    MAX_SCOPE_ENVELOPE_BYTES,
    POLICY_HASH,
    AdmissionRequest,
    DataClassification,
    DispatchKind,
    ReasonCode,
    RiskCategory,
    TrustMode,
    classify_trust,
    decide_standalone_worker,
    capsule_document,
    capture_patch_scope_capsule,
    capture_scope_capsule,
    patch_capsule_document,
    render_capsule_prompt,
)
from oc_rig.policy.models import AgentLifecycle


class AdmissionPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name).resolve() / "repository"
        self.repository.mkdir()
        (self.repository / "work.txt").write_text("synthetic\n", encoding="utf-8")

    def request(self, **changes: object) -> AdmissionRequest:
        values: dict[str, object] = {
            "repository": self.repository,
            "scope": ["work.txt"],
            "content": {"instructions": "Summarize the synthetic fixture."},
            "dispatch_kind": DispatchKind.AUTOMATED,
            "trust": TrustMode.SECURE,
            "classification": DataClassification.PUBLIC,
        }
        values.update(changes)
        return AdmissionRequest(**values)

    def test_missing_and_malformed_trust_default_to_secure(self) -> None:
        cases = (
            (None, ReasonCode.TRUST_MISSING_DEFAULTED_SECURE),
            ("SECURE", ReasonCode.TRUST_MALFORMED_DEFAULTED_SECURE),
            ("secure\u200b", ReasonCode.TRUST_MALFORMED_DEFAULTED_SECURE),
            (False, ReasonCode.TRUST_MALFORMED_DEFAULTED_SECURE),
            ({"mode": "insecure"}, ReasonCode.TRUST_MALFORMED_DEFAULTED_SECURE),
        )
        for value, reason in cases:
            with self.subTest(value=value):
                mode, actual_reason = classify_trust(value)
                self.assertIs(mode, TrustMode.SECURE)
                self.assertIs(actual_reason, reason)

    def test_agent_lifecycle_and_child_policy_are_closed_exact_values(self) -> None:
        compatible = decide_standalone_worker(self.request())
        self.assertTrue(compatible.allowed)
        self.assertIs(compatible.agent_lifecycle, AgentLifecycle.PERSISTENT)
        self.assertIs(compatible.allow_child_agents, False)

        for lifecycle in AgentLifecycle:
            for allow_children in (False, True):
                with self.subTest(
                    lifecycle=lifecycle, allow_children=allow_children
                ):
                    decision = decide_standalone_worker(
                        self.request(
                            agent_lifecycle=lifecycle.value,
                            allow_child_agents=allow_children,
                        )
                    )
                    self.assertTrue(decision.allowed)
                    self.assertIs(decision.agent_lifecycle, lifecycle)
                    self.assertIs(decision.allow_child_agents, allow_children)
                    self.assertEqual(
                        decision.journal_record()["agent_lifecycle"],
                        lifecycle.value,
                    )

        malformed = (
            {"agent_lifecycle": "temporary"},
            {"agent_lifecycle": "PERSISTENT"},
            {"agent_lifecycle": None},
            {"allow_child_agents": 1},
            {"allow_child_agents": "true"},
            {"allow_child_agents": None},
        )
        for changes in malformed:
            with self.subTest(changes=changes):
                decision = decide_standalone_worker(self.request(**changes))
                self.assertFalse(decision.allowed)
                expected = (
                    ReasonCode.AGENT_LIFECYCLE_MALFORMED
                    if "agent_lifecycle" in changes
                    else ReasonCode.ALLOW_CHILD_AGENTS_MALFORMED
                )
                self.assertIn(expected, decision.reason_codes)

    def test_task_capsule_preserves_lifecycle_and_child_policy(self) -> None:
        capsule = capture_scope_capsule(str(self.repository), ["work.txt"])
        envelope = json.dumps(
            {
                "agent_lifecycle": "persistent",
                "allow_child_agents": True,
                "claim_scope_hash": capsule.claim_scope_hash,
                "objective": "Return a bounded implementation proposal.",
                "scope": ["work.txt"],
                "scope_capsule": capsule_document(capsule),
                "submission_fingerprint": "a" * 64,
                "task_mode": "agent_task",
                "version": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

        decision = decide_standalone_worker(
            self.request(
                content=envelope,
                agent_lifecycle="persistent",
                allow_child_agents=True,
            )
        )

        self.assertTrue(decision.allowed)
        self.assertIs(decision.agent_lifecycle, AgentLifecycle.PERSISTENT)
        self.assertIs(decision.allow_child_agents, True)

    def test_patch_task_admits_only_valid_slice_capsule(self) -> None:
        (self.repository / "work.txt").write_text(
            "outside one\neditable\noutside two\n", encoding="utf-8"
        )
        capsule = capture_patch_scope_capsule(
            str(self.repository), ["work.txt"], 2, 2
        )
        task = {
            "agent_lifecycle": "disposable",
            "allow_child_agents": True,
            "claim_scope_hash": capsule.base.claim_scope_hash,
            "objective": "Edit the admitted line.",
            "scope": ["work.txt"],
            "scope_capsule": patch_capsule_document(capsule),
            "submission_fingerprint": "f" * 64,
            "task_mode": "workspace_patch",
            "version": 1,
        }
        envelope = json.dumps(task, sort_keys=True, separators=(",", ":"))

        accepted = decide_standalone_worker(
            self.request(
                content=envelope,
                agent_lifecycle="disposable",
                allow_child_agents=True,
            )
        )
        self.assertTrue(accepted.allowed)

        task["scope_capsule"]["files"][0]["content"] = "tampered\n"
        rejected = decide_standalone_worker(
            self.request(
                content=json.dumps(task, sort_keys=True, separators=(",", ":")),
                agent_lifecycle="disposable",
                allow_child_agents=True,
            )
        )
        self.assertFalse(rejected.allowed)
        self.assertIn(ReasonCode.INVALID_CONTENT, rejected.reason_codes)

    def test_secure_automated_dispatch_needs_exact_explicit_label(self) -> None:
        cases = (
            (None, ReasonCode.CLASSIFICATION_REQUIRED),
            ("public", ReasonCode.CLASSIFICATION_MALFORMED),
            ("PUBLIC\u200b", ReasonCode.CLASSIFICATION_MALFORMED),
            ({"label": "PUBLIC"}, ReasonCode.CLASSIFICATION_MALFORMED),
            (DataClassification.SENSITIVE, ReasonCode.CLASSIFICATION_SENSITIVE),
        )
        for classification, reason in cases:
            with self.subTest(classification=classification):
                decision = decide_standalone_worker(
                    self.request(classification=classification)
                )
                self.assertFalse(decision.allowed)
                self.assertTrue(decision.terminal)
                self.assertIn(reason, decision.reason_codes)

        for classification in (
            DataClassification.PUBLIC,
            DataClassification.SANITIZED,
            "PUBLIC",
            "SANITIZED",
        ):
            with self.subTest(classification=classification):
                self.assertTrue(
                    decide_standalone_worker(
                        self.request(classification=classification)
                    ).allowed
                )

    def test_interactive_secure_prompt_can_be_scanner_classified_without_label(self) -> None:
        accepted = decide_standalone_worker(
            self.request(
                dispatch_kind=DispatchKind.INTERACTIVE,
                classification=None,
            )
        )
        rejected = decide_standalone_worker(
            self.request(
                dispatch_kind=DispatchKind.INTERACTIVE,
                classification=None,
                content={"instructions": "Use token=synthetic-secret"},
            )
        )

        self.assertTrue(accepted.allowed)
        self.assertFalse(rejected.allowed)
        self.assertIn(ReasonCode.SENSITIVE_CONTENT, rejected.reason_codes)

    def test_secure_public_label_cannot_bypass_confusable_or_encoded_scanning(self) -> None:
        cases = (
            (
                {"instructions": "Deploy to pr\u043eduction now"},
                {ReasonCode.CONFUSABLE_CONTENT, ReasonCode.PRODUCTION_TASK},
            ),
            (
                {"p\u0430ssword": "fixture"},
                {
                    ReasonCode.CONFUSABLE_CONTENT,
                    ReasonCode.SENSITIVE_CONTENT,
                    ReasonCode.CREDENTIAL_TASK,
                },
            ),
            (
                {
                    "instructions": (
                        "Review payload cHJvZHVjdGlvbg== before execution"
                    )
                },
                {ReasonCode.PRODUCTION_TASK},
            ),
        )
        for content, expected_reasons in cases:
            with self.subTest(content=content):
                decision = decide_standalone_worker(self.request(content=content))
                self.assertFalse(decision.allowed)
                self.assertTrue(decision.terminal)
                self.assertTrue(expected_reasons.issubset(decision.reason_codes))

    def test_scope_capsule_is_rescanned_by_role_and_requires_sanitized(self) -> None:
        (self.repository / "work.txt").write_text(
            "Describe production behavior without changing it.\n",
            encoding="utf-8",
        )
        capsule = capture_scope_capsule(str(self.repository), ["work.txt"])
        envelope_document = {
                "claim_scope_hash": capsule.claim_scope_hash,
                "review_profiles": ["security"],
                "scope": ["work.txt"],
                "scope_capsule": capsule_document(capsule),
                "task_mode": "read_only_review",
                "version": 2,
            }
        envelope = render_capsule_prompt(envelope_document)

        accepted = decide_standalone_worker(
            self.request(content=envelope, classification=DataClassification.PUBLIC)
        )
        sanitized = decide_standalone_worker(
            self.request(content=envelope, classification=DataClassification.SANITIZED)
        )
        invalid = decide_standalone_worker(
            self.request(
                content=envelope + "tampered",
                classification=DataClassification.PUBLIC,
            )
        )

        self.assertTrue(accepted.allowed)
        self.assertIs(accepted.agent_lifecycle, AgentLifecycle.DISPOSABLE)
        self.assertIs(accepted.allow_child_agents, False)
        child_enabled = decide_standalone_worker(
            self.request(
                content=envelope,
                classification=DataClassification.PUBLIC,
                allow_child_agents=True,
            )
        )
        self.assertFalse(child_enabled.allowed)
        self.assertIn(
            ReasonCode.SCOPE_CAPSULE_DISALLOWS_CHILD_AGENTS,
            child_enabled.reason_codes,
        )
        self.assertFalse(sanitized.allowed)
        self.assertIn(
            ReasonCode.SCOPE_CAPSULE_REQUIRES_PUBLIC,
            sanitized.reason_codes,
        )
        self.assertFalse(invalid.allowed)
        self.assertIn(ReasonCode.INVALID_CONTENT, invalid.reason_codes)

        (self.repository / "large.txt").write_text(
            "safe line\n" * 4800, encoding="utf-8"
        )
        large_capsule = capture_scope_capsule(str(self.repository), ["large.txt"])
        oversized = render_capsule_prompt(
            {
                "claim_scope_hash": large_capsule.claim_scope_hash,
                "review_profiles": ["correctness"],
                "scope": ["large.txt"],
                "scope_capsule": capsule_document(large_capsule),
                "task_mode": "read_only_review",
                "version": 2,
            }
        )
        oversized_decision = decide_standalone_worker(
            self.request(
                content=oversized,
                scope=["large.txt"],
                classification=DataClassification.PUBLIC,
            )
        )
        self.assertFalse(oversized_decision.allowed)
        self.assertIn(
            ReasonCode.SCANNER_LIMIT_EXCEEDED,
            oversized_decision.reason_codes,
        )

    def test_prohibited_standalone_worker_categories_are_terminal(self) -> None:
        expected = {
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
        for category, reason in expected.items():
            with self.subTest(category=category):
                decision = decide_standalone_worker(
                    self.request(
                        trust=TrustMode.INSECURE,
                        classification=None,
                        risk_categories=(category,),
                    )
                )
                self.assertFalse(decision.allowed)
                self.assertTrue(decision.terminal)
                self.assertIn(reason, decision.reason_codes)

    def test_unknown_inputs_fail_closed(self) -> None:
        cases = (
            ("dispatch_kind", "scheduled", ReasonCode.UNKNOWN_DISPATCH_KIND),
            ("risk_categories", ("novel_risk",), ReasonCode.UNKNOWN_RISK_CATEGORY),
            ("content", object(), ReasonCode.INVALID_CONTENT),
            ("scope", object(), ReasonCode.SCOPE_REQUIRED),
        )
        for field, value, reason in cases:
            with self.subTest(field=field):
                decision = decide_standalone_worker(self.request(**{field: value}))
                self.assertFalse(decision.allowed)
                self.assertIn(reason, decision.reason_codes)

    def test_decision_and_hashes_are_deterministic_and_immutable(self) -> None:
        first = decide_standalone_worker(
            self.request(content={"z": [1, True], "a": {"fixture": "safe"}})
        )
        second = decide_standalone_worker(
            self.request(content={"a": {"fixture": "safe"}, "z": [1, True]})
        )

        self.assertEqual(first, second)
        self.assertEqual(first.policy_hash, POLICY_HASH)
        self.assertEqual(len(first.policy_hash), 64)
        self.assertEqual(len(first.decision_hash), 64)
        self.assertFalse(first.terminal)
        with self.assertRaises(FrozenInstanceError):
            first.allowed = False  # type: ignore[misc]
        journal = first.journal_record()
        journal["allowed"] = False
        self.assertTrue(first.allowed)


if __name__ == "__main__":
    unittest.main()
