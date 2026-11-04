"""Deterministic, bounded scanning for standalone-worker task content."""

from __future__ import annotations

import base64
import binascii
import hashlib
import html
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

from oc_rig.policy.models import FindingCode, RiskCategory, ScanFinding, ScanResult


_SENSITIVE_KEY_MARKERS = (
    "apikey",
    "authorization",
    "browserprofile",
    "cookie",
    "credential",
    "password",
    "privatekey",
    "secret",
    "token",
    "transcript",
)
_SECRET_PATTERNS = (
    r"-----begin[a-z ]*private key-----",
    r"\bakia[0-9a-z]{16}\b",
    r"\b(?:api\s*key|password|secret|token)\s*[:=]\s*\S+",
    r"\beyj[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}\b",
)
_RISK_PATTERNS: tuple[tuple[RiskCategory, tuple[str, ...]], ...] = (
    (RiskCategory.CREDENTIAL, (r"\bcredentials?\b", r"\bpasswords?\b", r"\bapi\s*keys?\b")),
    (RiskCategory.PRODUCTION, (r"\bproduction\b", r"\bcustomer\s+traffic\b", r"\blive\s+state\b")),
    (RiskCategory.OPERATOR_GATED, (r"\boperator[\s_-]*gated\b", r"\brequires?\s+operator\s+approval\b")),
    (RiskCategory.DESTRUCTIVE, (r"\bdestroy\b", r"\bdestructive\b", r"\bdelete\s+(?:the\s+)?(?:data|database|account|volume)\b")),
    (RiskCategory.PURCHASE, (r"\bpurchase\b", r"\bbuy\b", r"\bplace\s+(?:the\s+)?order\b")),
    (RiskCategory.SIGNATURE, (r"\bsign\s+(?:the\s+)?(?:agreement|contract|document)\b", r"\bsignature\b")),
    (RiskCategory.FILING, (r"\bfile\s+(?:the\s+)?(?:return|form|claim|application)\b", r"\bregulatory\s+filing\b")),
    (RiskCategory.EXTERNAL_COMMITMENT, (r"\bexternal[\s_-]*commitment\b", r"\bcommit\s+(?:us|the\s+company)\b", r"\bsend\s+(?:the\s+)?(?:offer|acceptance|agreement)\b")),
    (RiskCategory.SENSITIVE, (r"\bsensitive\s+(?:data|material|information)\b", r"\bconfidential\b")),
)
_MAX_DEPTH = 32
_MAX_NODES = 10_000
_MAX_STRING_BYTES = 64 * 1024
_MAX_CONTENT_BYTES = 256 * 1024
_MAX_DECODE_ROUNDS = 3
_MIN_ENCODED_TOKEN_CHARS = 12
_MAX_ENCODED_TOKEN_CHARS = 2048
_MAX_ENCODED_TOKENS_PER_VARIANT = 64
_MAX_DECODED_VARIANTS = 128
_MAX_DECODED_BYTES = 8192

# Small, reviewed UTS #39-style skeleton for the Latin lookalikes most useful
# in policy-word downgrade attempts. Mixed-script tokens are also rejected, so
# this table need not attempt to mirror the full Unicode confusables database.
_CONFUSABLE_ASCII = {
    "а": "a",  # Cyrillic
    "в": "b",
    "с": "c",
    "ԁ": "d",
    "е": "e",
    "һ": "h",
    "і": "i",
    "ј": "j",
    "к": "k",
    "м": "m",
    "о": "o",
    "р": "p",
    "ѕ": "s",
    "т": "t",
    "у": "y",
    "х": "x",
    "α": "a",  # Greek
    "β": "b",
    "ϲ": "c",
    "ε": "e",
    "η": "n",
    "ι": "i",
    "κ": "k",
    "μ": "m",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "y",
    "χ": "x",
}
_BASE64_TOKEN_PATTERN = re.compile(
    rf"(?<![A-Za-z0-9_+/=-])"
    rf"[A-Za-z0-9_+/-]{{{_MIN_ENCODED_TOKEN_CHARS},}}={{0,2}}"
    rf"(?![A-Za-z0-9_+/=-])"
)
_HEX_TOKEN_PATTERN = re.compile(
    rf"(?<![0-9A-Fa-f])[0-9A-Fa-f]{{{_MIN_ENCODED_TOKEN_CHARS},}}(?![0-9A-Fa-f])"
)


class _LimitExceeded(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _TextAnalysis:
    variants: tuple[str, ...]
    mixed_script: bool
    limit_exceeded: bool


def _plain_text(value: str) -> str:
    return _normalized_text(value).casefold()


def _normalized_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    return "".join(
        character
        for character in normalized
        if unicodedata.category(character) != "Cf"
    )


def _script(character: str) -> str | None:
    if not character.isalpha():
        return None
    name = unicodedata.name(character, "")
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if script in name:
            return script
    return "OTHER"


def _contains_suspicious_unicode_token(value: str) -> bool:
    scripts: set[str] = set()
    for index, character in enumerate(value):
        if character.isalnum() or character == "_":
            script = _script(character)
            if script is not None:
                scripts.add(script)
            continue
        if (
            unicodedata.category(character).startswith("M")
            and index > 0
            and index + 1 < len(value)
            and value[index - 1].isalnum()
            and value[index + 1].isalnum()
            and scripts.intersection({"LATIN", "CYRILLIC", "GREEK"})
        ):
            return True
        if "LATIN" in scripts and ("CYRILLIC" in scripts or "GREEK" in scripts):
            return True
        scripts.clear()
    return "LATIN" in scripts and (
        "CYRILLIC" in scripts or "GREEK" in scripts
    )


def _confusable_skeleton(value: str) -> str:
    return "".join(
        _CONFUSABLE_ASCII.get(character, character)
        for character in value
        if not unicodedata.category(character).startswith("M")
    )


def _encoded_tokens(value: str) -> tuple[tuple[str, str], ...] | None:
    """Return bounded ``(encoding, token)`` candidates, or ``None`` on overflow."""

    candidates: set[tuple[str, str]] = set()
    for encoding, pattern in (
        ("hex", _HEX_TOKEN_PATTERN),
        ("base64", _BASE64_TOKEN_PATTERN),
    ):
        for match in pattern.finditer(value):
            token = match.group(0)
            if len(token) > _MAX_ENCODED_TOKEN_CHARS:
                return None
            candidates.add((encoding, token))
            if len(candidates) > _MAX_ENCODED_TOKENS_PER_VARIANT:
                return None
    return tuple(sorted(candidates))


def _decode_token(encoding: str, token: str) -> str | None:
    try:
        if encoding == "hex":
            if len(token) % 2:
                return None
            decoded = bytes.fromhex(token)
        else:
            padded = token + "=" * (-len(token) % 4)
            decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return None
    if not 4 <= len(decoded) <= _MAX_DECODED_BYTES:
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not all(character.isprintable() or character in "\r\n\t" for character in text):
        return None
    return text


def _text_variants(value: str) -> _TextAnalysis:
    """Return bounded, stable views that expose common encoding tricks."""

    pending = [value]
    variants: list[str] = []
    seen: set[str] = set()
    mixed_script = False
    limit_exceeded = False
    decoded_variants = 0
    for round_index in range(_MAX_DECODE_ROUNDS):
        next_pending: list[str] = []
        for candidate in pending:
            plain = _plain_text(candidate)
            if plain in seen:
                continue
            seen.add(plain)
            variants.append(plain)
            if _contains_suspicious_unicode_token(plain):
                mixed_script = True
            skeleton = _confusable_skeleton(plain)
            if skeleton != plain and skeleton not in seen:
                seen.add(skeleton)
                variants.append(skeleton)
            for decoded in (html.unescape(candidate), unquote(candidate)):
                if decoded != candidate:
                    next_pending.append(decoded)
            encoded = _encoded_tokens(_normalized_text(candidate))
            if encoded is None:
                limit_exceeded = True
                continue
            for encoding, token in encoded:
                decoded = _decode_token(encoding, token)
                if decoded is None:
                    continue
                decoded_variants += 1
                if decoded_variants > _MAX_DECODED_VARIANTS:
                    limit_exceeded = True
                    break
                next_pending.append(decoded)
        if limit_exceeded:
            break
        if round_index == _MAX_DECODE_ROUNDS - 1 and next_pending:
            limit_exceeded = True
            break
        pending = next_pending
    return _TextAnalysis(tuple(variants), mixed_script, limit_exceeded)


def _canonicalize(
    value: object,
    *,
    depth: int = 0,
    nodes: list[int] | None = None,
) -> object:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > _MAX_NODES:
        raise _LimitExceeded("nodes")
    if depth > _MAX_DEPTH:
        raise _LimitExceeded("depth")
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, str) and len(value.encode("utf-8")) > _MAX_STRING_BYTES:
            raise _LimitExceeded("string bytes")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite float")
        return value
    if type(value) is list:
        return [
            _canonicalize(child, depth=depth + 1, nodes=nodes)
            for child in value
        ]
    if type(value) is dict:
        if not all(isinstance(key, str) for key in value):
            raise TypeError("mapping keys must be strings")
        return {
            key: _canonicalize(value[key], depth=depth + 1, nodes=nodes)
            for key in sorted(value)
        }
    raise TypeError("content must contain only JSON values")


def _content_hash(value: object) -> tuple[str, object | None, FindingCode | None]:
    try:
        canonical = _canonicalize(value)
        encoded = json.dumps(
            canonical,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(encoded) > _MAX_CONTENT_BYTES:
            raise _LimitExceeded("content bytes")
    except _LimitExceeded:
        marker = {"limit_exceeded": True}
        encoded = json.dumps(marker, separators=(",", ":"), sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest(), None, FindingCode.LIMIT_EXCEEDED
    except (TypeError, ValueError):
        marker = {
            "invalid_type": f"{type(value).__module__}.{type(value).__qualname__}"
        }
        encoded = json.dumps(marker, separators=(",", ":"), sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest(), None, FindingCode.INVALID_STRUCTURE
    return hashlib.sha256(encoded).hexdigest(), canonical, None


def _safe_path_component(key: str) -> str:
    """Identify a field location without copying attacker-controlled key text."""

    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"key-{digest}"


def scan_content(value: object) -> ScanResult:
    """Scan JSON task content without retaining or echoing matched material."""

    content_hash, canonical, failure = _content_hash(value)
    if canonical is None:
        finding = ScanFinding(failure or FindingCode.INVALID_STRUCTURE, "$")
        return ScanResult(False, content_hash, (finding,))

    findings: set[tuple[FindingCode, str, RiskCategory | None]] = set()
    nodes = 0

    def visit(child: object, path: str, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_NODES or depth > _MAX_DEPTH:
            findings.add((FindingCode.LIMIT_EXCEEDED, path, None))
            return
        if isinstance(child, dict):
            for key in sorted(child):
                key_path = f"{path}/{_safe_path_component(key)}"
                key_analysis = _text_variants(key)
                if key_analysis.mixed_script:
                    findings.add((FindingCode.CONFUSABLE_TEXT, key_path, None))
                if key_analysis.limit_exceeded:
                    findings.add((FindingCode.LIMIT_EXCEEDED, key_path, None))
                if any(
                    marker
                    in "".join(
                        character for character in variant if character.isalnum()
                    )
                    for marker in _SENSITIVE_KEY_MARKERS
                    for variant in key_analysis.variants
                ):
                    findings.add(
                        (
                            FindingCode.SENSITIVE_FIELD,
                            key_path,
                            RiskCategory.CREDENTIAL,
                        )
                    )
                visit(child[key], key_path, depth + 1)
            return
        if isinstance(child, list):
            for index, item in enumerate(child):
                visit(item, f"{path}/{index}", depth + 1)
            return
        if not isinstance(child, str):
            return
        if "\x00" in child or len(child.encode("utf-8")) > _MAX_STRING_BYTES:
            findings.add((FindingCode.INVALID_STRUCTURE, path, None))
            return
        analysis = _text_variants(child)
        if analysis.mixed_script:
            findings.add((FindingCode.CONFUSABLE_TEXT, path, None))
        if analysis.limit_exceeded:
            findings.add((FindingCode.LIMIT_EXCEEDED, path, None))
        for variant in analysis.variants:
            compact = "".join(character for character in variant if character.isalnum())
            if any(re.search(pattern, variant, re.IGNORECASE) for pattern in _SECRET_PATTERNS):
                findings.add((FindingCode.SECRET_MATERIAL, path, RiskCategory.SENSITIVE))
            if any(marker in compact for marker in _SENSITIVE_KEY_MARKERS):
                # Only field names are intrinsically sensitive; values require a
                # secret pattern or prohibited task-language match.
                pass
            for category, patterns in _RISK_PATTERNS:
                if any(re.search(pattern, variant, re.IGNORECASE) for pattern in patterns):
                    findings.add((FindingCode.RISK_LANGUAGE, path, category))

    visit(canonical, "$", 0)
    ordered = tuple(
        ScanFinding(code, path, category)
        for code, path, category in sorted(
            findings,
            key=lambda finding: (
                finding[0].value,
                finding[1],
                finding[2].value if finding[2] is not None else "",
            ),
        )
    )
    return ScanResult(not ordered, content_hash, ordered)


def scanner_policy_material() -> dict[str, object]:
    """Return declarative scanner material included in the policy hash."""

    return {
        "sensitive_key_markers": _SENSITIVE_KEY_MARKERS,
        "secret_patterns": _SECRET_PATTERNS,
        "risk_patterns": [
            [category.value, list(patterns)]
            for category, patterns in _RISK_PATTERNS
        ],
        "limits": {
            "max_depth": _MAX_DEPTH,
            "max_nodes": _MAX_NODES,
            "max_string_bytes": _MAX_STRING_BYTES,
            "max_content_bytes": _MAX_CONTENT_BYTES,
            "max_decode_rounds": _MAX_DECODE_ROUNDS,
            "min_encoded_token_chars": _MIN_ENCODED_TOKEN_CHARS,
            "max_encoded_token_chars": _MAX_ENCODED_TOKEN_CHARS,
            "max_encoded_tokens_per_variant": _MAX_ENCODED_TOKENS_PER_VARIANT,
            "max_decoded_variants": _MAX_DECODED_VARIANTS,
            "max_decoded_bytes": _MAX_DECODED_BYTES,
        },
        "unicode_normalization": "NFKC+remove-Cf+casefold+mixed-script+skeleton",
        "confusable_ascii": dict(sorted(_CONFUSABLE_ASCII.items())),
        "encoded_substrings": ["base64", "base64url", "hex"],
    }
