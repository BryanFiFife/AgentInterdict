from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import unicodedata
from urllib.parse import unquote_to_bytes
from dataclasses import asdict, dataclass

DEMO_SECRET = b"agentinterdict-demo-secret-change-me"

# Common confusables used in prompt-injection evasion. This is deliberately small and
# auditable; higher tiers can add model-based or threat-feed classifiers without making
# them the authority boundary.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ο": "o", "ρ": "p", "τ": "t", "χ": "x",
})

from .threats import COMPACT_PATTERNS, SIGNALS, THREAT_UPDATED_AT, THREAT_VERSION


@dataclass
class RiskResult:
    score: int
    severity: str
    signals: list[dict]
    normalized_changed: bool = False

    def as_dict(self):
        return asdict(self)


def _secret() -> bytes:
    raw = os.getenv("AGENTINTERDICT_SECRET", DEMO_SECRET.decode()).encode("utf-8")
    allow_demo = os.getenv("AGENTINTERDICT_ALLOW_INSECURE_DEMO", "").strip().lower() in {"1", "true", "yes"}
    if raw == DEMO_SECRET and not allow_demo:
        raise RuntimeError("AGENTINTERDICT_SECRET is not configured; run the installer or provide a random 32+ byte secret")
    if len(raw) < 32:
        raise RuntimeError("AGENTINTERDICT_SECRET must be at least 32 bytes")
    return raw


def signing_secret_status() -> dict:
    raw = os.getenv("AGENTINTERDICT_SECRET", DEMO_SECRET.decode()).encode("utf-8")
    allow_demo = os.getenv("AGENTINTERDICT_ALLOW_INSECURE_DEMO", "").strip().lower() in {"1", "true", "yes"}
    return {
        "configured": raw != DEMO_SECRET,
        "length_ok": len(raw) >= 32,
        "demo_allowed": allow_demo,
        "usable": len(raw) >= 32 and (raw != DEMO_SECRET or allow_demo),
    }


def normalize_for_scan(content: str) -> tuple[str, bool, int]:
    original = content
    nfkc = unicodedata.normalize("NFKC", content).translate(CONFUSABLES)
    removed = sum(1 for ch in nfkc if unicodedata.category(ch) in {"Cf", "Cc"} and ch not in "\n\r\t")
    nfkc = "".join(ch for ch in nfkc if unicodedata.category(ch) not in {"Cf", "Cc"} or ch in "\n\r\t")
    # Normalise unusual whitespace while retaining sentence boundaries for regexes.
    nfkc = re.sub(r"[^\S\r\n]+", " ", nfkc)
    return nfkc, nfkc != original, removed


def _printable_utf8(raw: bytes) -> str | None:
    if not raw or len(raw) > 8192:
        return None
    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in decoded) / max(1, len(decoded))
    return decoded[:4096] if printable > 0.85 else None


def _decoded_base64_previews(text: str) -> list[str]:
    # Decode only bounded, plausible contiguous blobs to avoid CPU/memory amplification.
    previews: list[str] = []
    pattern = re.compile(r"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{80,4096}={0,2})(?![A-Za-z0-9+/_-])")
    for match in list(pattern.finditer(text))[:4]:
        token = match.group(1)
        padded = token + "=" * ((4 - len(token) % 4) % 4)
        for altchars in (None, b"-_"):
            try:
                raw = base64.b64decode(padded, altchars=altchars, validate=True)
            except Exception:
                continue
            decoded = _printable_utf8(raw)
            if decoded and decoded not in previews:
                previews.append(decoded)
                break
    return previews


def _decoded_escape_previews(text: str) -> list[tuple[str, str]]:
    """Bounded decode of percent and backslash-hex runs used to hide instruction text."""
    previews: list[tuple[str, str]] = []
    # Decode only runs with at least 8 escaped bytes and cap their size.
    for match in list(re.finditer(r"(?:%[0-9a-fA-F]{2}){8,2048}", text))[:4]:
        try:
            decoded = _printable_utf8(unquote_to_bytes(match.group(0)))
        except Exception:
            decoded = None
        if decoded:
            previews.append(("percent", decoded))
    for match in list(re.finditer(r"(?:\\x[0-9a-fA-F]{2}){8,2048}", text))[:4]:
        token = match.group(0)
        try:
            raw = bytes(int(x, 16) for x in re.findall(r"\\x([0-9a-fA-F]{2})", token))
            decoded = _printable_utf8(raw)
        except Exception:
            decoded = None
        if decoded:
            previews.append(("hex", decoded))
    return previews


def score_content(content: str, source_type: str) -> RiskResult:
    normalized, changed, removed_invisibles = normalize_for_scan(content)
    score = 0
    found: list[dict] = []
    seen = set()

    def add(name: str, weight: int, reason: str):
        nonlocal score
        if name in seen:
            return
        seen.add(name)
        score += weight
        found.append({"name": name, "weight": weight, "reason": reason})

    if removed_invisibles:
        add("invisible_obfuscation", 15, f"Removed {removed_invisibles} invisible/control character(s) before scanning")
    elif changed and content != normalized:
        add("unicode_normalized", 3, "Unicode/compatibility normalization changed the scanned representation")

    for name, pattern, weight, reason in SIGNALS:
        if pattern.search(normalized):
            add(name, weight, reason)

    compact = re.sub(r"[^a-z0-9]", "", normalized.lower())[:100_000]
    for name, pattern, weight, reason in COMPACT_PATTERNS:
        if pattern.search(compact):
            add(name, weight, reason)

    for decoded in _decoded_base64_previews(normalized):
        decoded_normalized, _, _ = normalize_for_scan(decoded)
        for name, pattern, weight, reason in SIGNALS[:6]:
            if pattern.search(decoded_normalized):
                add(f"decoded_{name}", min(weight, 35), f"Base64-decoded content: {reason}")
        decoded_compact = re.sub(r"[^a-z0-9]", "", decoded_normalized.lower())[:4096]
        for name, pattern, weight, reason in COMPACT_PATTERNS:
            if pattern.search(decoded_compact):
                add(f"decoded_{name}", min(weight, 30), f"Base64-decoded content: {reason}")

    for encoding, decoded in _decoded_escape_previews(normalized):
        decoded_normalized, _, _ = normalize_for_scan(decoded)
        for name, pattern, weight, reason in SIGNALS[:6]:
            if pattern.search(decoded_normalized):
                add(f"decoded_{encoding}_{name}", min(weight, 35), f"{encoding}-decoded content: {reason}")
        decoded_compact = re.sub(r"[^a-z0-9]", "", decoded_normalized.lower())[:4096]
        for name, pattern, weight, reason in COMPACT_PATTERNS:
            if pattern.search(decoded_compact):
                add(f"decoded_{encoding}_{name}", min(weight, 30), f"{encoding}-decoded content: {reason}")

    if source_type in {"web", "email", "document", "api", "tool", "unknown_external"}:
        add("external_origin", 8, "Origin is external/untrusted by default")
    if len(content) > 12_000:
        add("oversized", 8, "Large memory item increases review surface")

    score = min(score, 100)
    severity = "critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20 else "low"
    return RiskResult(score=score, severity=severity, signals=found, normalized_changed=changed)


DEFINITE_SECRET_SIGNALS = {"private_key_material", "known_api_token", "bearer_or_jwt", "credential_assignment"}
SENSITIVE_SECRET_SIGNALS = set(DEFINITE_SECRET_SIGNALS)

def _signal_matches_family(name: str | None, families: set[str]) -> bool:
    """Match direct and bounded decoded signal names (e.g. decoded_base64_known_api_token)."""
    if not name:
        return False
    return any(name == family or name.endswith("_" + family) for family in families)

def contains_definite_secret(result: RiskResult) -> bool:
    return any(_signal_matches_family(item.get("name"), DEFINITE_SECRET_SIGNALS) for item in result.signals)

def contains_sensitive_secret(result: RiskResult) -> bool:
    return any(_signal_matches_family(item.get("name"), SENSITIVE_SECRET_SIGNALS) for item in result.signals)


def canonical_json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def sign_record(data: dict) -> str:
    return hmac.new(_secret(), canonical_json(data), hashlib.sha256).hexdigest()


def verify_signature(data: dict, signature: str) -> bool:
    if not isinstance(signature, str) or len(signature) != 64:
        return False
    return hmac.compare_digest(sign_record(data), signature)



def sign_state(data: dict) -> str:
    return hmac.new(_secret(), b"state:" + canonical_json(data), hashlib.sha256).hexdigest()


def verify_state(data: dict, signature: str) -> bool:
    if not isinstance(signature, str) or len(signature) != 64:
        return False
    return hmac.compare_digest(sign_state(data), signature)

def chain_hash(prev_hash: str, payload: dict) -> str:
    return hashlib.sha256(prev_hash.encode("ascii", errors="ignore") + canonical_json(payload)).hexdigest()


def sign_audit_hash(event_hash: str) -> str:
    return hmac.new(_secret(), b"audit:" + event_hash.encode("ascii"), hashlib.sha256).hexdigest()


def verify_audit_hash(event_hash: str, signature: str) -> bool:
    if not signature:
        return False
    return hmac.compare_digest(sign_audit_hash(event_hash), signature)
