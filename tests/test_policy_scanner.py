from __future__ import annotations

import base64
import unittest

from oc_rig.policy import FindingCode, RiskCategory, scan_content


class DeterministicScannerTests(unittest.TestCase):
    def test_nested_structured_sensitive_fields_are_found_without_values(self) -> None:
        result = scan_content(
            {
                "outer": [
                    {"safe": "fixture"},
                    {"cre\u200bdential": {"value": "do-not-journal"}},
                ]
            }
        )

        self.assertFalse(result.safe)
        self.assertTrue(
            any(finding.code is FindingCode.SENSITIVE_FIELD for finding in result.findings)
        )
        self.assertNotIn("do-not-journal", repr(result))

    def test_attacker_controlled_secret_key_is_not_copied_into_findings(self) -> None:
        secret_key = "token=do-not-journal-this"
        result = scan_content({secret_key: "fixture"})

        self.assertFalse(result.safe)
        self.assertNotIn(secret_key, repr(result))

    def test_unicode_and_encoded_downgrade_tricks_are_scanned(self) -> None:
        encoded_secret = base64.b64encode(b"token=synthetic-secret").decode("ascii")
        cases = (
            {"instructions": "Use to\u200bken=synthetic-secret"},
            {"instructions": "%74%6f%6b%65%6e%3dsynthetic-secret"},
            {"instructions": encoded_secret},
            {"instructions": "Operate on \uff30\uff32\uff2f\uff24\uff35\uff23\uff34\uff29\uff2f\uff2e"},
        )
        for content in cases:
            with self.subTest(content=content):
                self.assertFalse(scan_content(content).safe)

    def test_mixed_script_confusables_cover_risk_words_and_sensitive_keys(self) -> None:
        cases = (
            ({"instructions": "Deploy to pr\u043eduction"}, RiskCategory.PRODUCTION),
            ({"instructions": "Deploy to pr\u03bfduction"}, RiskCategory.PRODUCTION),
            ({"instructions": "Deploy to pro\u0338duction"}, RiskCategory.PRODUCTION),
            ({"p\u0430ssword": "fixture"}, RiskCategory.CREDENTIAL),
            ({"t\u03bfken": "fixture"}, RiskCategory.CREDENTIAL),
        )
        for content, category in cases:
            with self.subTest(content=content):
                result = scan_content(content)
                self.assertFalse(result.safe)
                self.assertTrue(
                    any(
                        finding.code is FindingCode.CONFUSABLE_TEXT
                        for finding in result.findings
                    )
                )
                self.assertTrue(
                    any(
                        finding.risk_category is category
                        for finding in result.findings
                    )
                )

    def test_separate_scripts_and_safe_encoded_text_do_not_false_positive(self) -> None:
        cases = (
            {"instructions": "Review \u043f\u0440\u0438\u043c\u0435\u0440 fixture"},
            {
                "instructions": (
                    "Review c3ludGhldGljLWZpeHR1cmU= before execution"
                )
            },
            {"instructions": "A short cHJvZA== fixture token"},
        )
        for content in cases:
            with self.subTest(content=content):
                self.assertTrue(scan_content(content).safe)

    def test_embedded_base64_hex_and_recursive_encoding_are_scanned(self) -> None:
        encoded_once = base64.b64encode(b"production").decode("ascii")
        encoded_twice = base64.b64encode(encoded_once.encode("ascii")).decode("ascii")
        cases = (
            f"Review payload {encoded_once} before execution",
            f"Review payload {encoded_once.rstrip('=')} before execution",
            f"Review payload {encoded_once[:4]}\u200b{encoded_once[4:]} before execution",
            "Review payload 70726f64756374696f6e before execution",
            f"Review payload {encoded_twice} before execution",
        )
        for instructions in cases:
            with self.subTest(instructions=instructions):
                result = scan_content({"instructions": instructions})
                self.assertFalse(result.safe)
                self.assertTrue(
                    any(
                        finding.risk_category is RiskCategory.PRODUCTION
                        for finding in result.findings
                    )
                )

    def test_encoding_beyond_recursion_budget_fails_closed(self) -> None:
        encoded = "production"
        for _ in range(4):
            encoded = base64.b64encode(encoded.encode("ascii")).decode("ascii")
        result = scan_content({"instructions": f"Review {encoded}"})

        self.assertFalse(result.safe)
        self.assertTrue(
            any(
                finding.code is FindingCode.LIMIT_EXCEEDED
                for finding in result.findings
            )
        )

    def test_encoded_substring_work_is_bounded_and_fails_closed_on_overflow(self) -> None:
        too_long = "A" * 2049
        too_many = " ".join(f"{index:012x}" for index in range(40))
        for content in (
            {"instructions": f"Review {too_long}"},
            {"instructions": f"Review {too_many}"},
        ):
            with self.subTest(size=len(content["instructions"])):
                result = scan_content(content)
                self.assertFalse(result.safe)
                self.assertTrue(
                    any(
                        finding.code is FindingCode.LIMIT_EXCEEDED
                        for finding in result.findings
                    )
                )

    def test_risk_language_has_structured_categories(self) -> None:
        result = scan_content(
            {"instructions": "Place the order and send the agreement externally."}
        )
        categories = {
            finding.risk_category
            for finding in result.findings
            if finding.risk_category is not None
        }
        self.assertIn(RiskCategory.PURCHASE, categories)
        self.assertIn(RiskCategory.EXTERNAL_COMMITMENT, categories)

    def test_non_json_and_opaque_encoded_values_fail_closed(self) -> None:
        for value in (b"opaque", {"nested": ("tuple",)}, {1: "non-string key"}):
            with self.subTest(value=value):
                result = scan_content(value)
                self.assertFalse(result.safe)
                self.assertEqual(result.findings[0].code, FindingCode.INVALID_STRUCTURE)

    def test_depth_and_size_limits_fail_closed(self) -> None:
        nested: object = "leaf"
        for _ in range(40):
            nested = [nested]
        for value in (nested, "x" * (64 * 1024 + 1)):
            with self.subTest(kind=type(value).__name__):
                result = scan_content(value)
                self.assertFalse(result.safe)
                self.assertEqual(result.findings[0].code, FindingCode.LIMIT_EXCEEDED)

    def test_content_hash_does_not_depend_on_mapping_order(self) -> None:
        first = scan_content({"b": [2, 3], "a": 1})
        second = scan_content({"a": 1, "b": [2, 3]})
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
