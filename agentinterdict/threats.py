"""Threat-list loading and paid-feed hardening for AgentInterdict.

The baked-in Community list is always the minimum enforcement baseline. A valid
paid entitlement can add a remotely supplied threat overlay, but remote failure,
invalid signatures, wrong-tier data, expiry, redirects, or incompatible versions
can never remove the local baseline.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from packaging.version import InvalidVersion, Version

from .licensing import get_entitlement_token, get_license_status
from .version import VERSION

PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_THREAT_FILE = PACKAGE_ROOT / "threats" / "community.json"
DEFAULT_FEED_PUBLIC_KEY = PACKAGE_ROOT / "license_public_key.pem"
DEFAULT_CONTROL_PLANE = "https://agentinterdict-funnel.bryansmall26.workers.dev"
MAX_THREAT_BYTES = 4_000_000
PAID_TIERS = {"pro", "business", "enterprise"}

_FLAG_MAP = {"i": re.IGNORECASE, "s": re.DOTALL, "m": re.MULTILINE, "x": re.VERBOSE}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def _compile_flags(flags: str) -> int:
    out = 0
    for ch in flags or "":
        out |= _FLAG_MAP.get(ch, 0)
    return out


def _load_threat_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"threat list not found: {path}")
    if path.stat().st_size > MAX_THREAT_BYTES:
        raise ValueError("threat list is unexpectedly large")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("threat list has an invalid schema")
    if data.get("remote_url"):
        return data
    if not isinstance(data.get("signals"), list):
        raise ValueError("threat list has an invalid schema")
    if not isinstance(data.get("compact_patterns", []), list):
        raise ValueError("threat compact-pattern list has an invalid schema")
    return data


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _b64u_decode(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError("invalid threat-feed signature")
    value += "=" * (-len(value) % 4)
    return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)


def _load_feed_public_key() -> Ed25519PublicKey:
    path = Path(os.getenv("AGENTINTERDICT_THREAT_PUBLIC_KEY_FILE", str(DEFAULT_FEED_PUBLIC_KEY))).expanduser()
    if not path.is_file() or path.stat().st_size > 16_384:
        raise ValueError("threat-feed public key is missing or unexpectedly large")
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("threat-feed public key is not Ed25519")
    return key


def _parse_expiry(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("signed threat feed is missing expires_at")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("threat-feed expires_at must include a timezone")
    return dt.astimezone(timezone.utc)


def _verify_signed_bundle(data: dict[str, Any], expected_tier: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("threat-feed response must be an object")
    signature = data.get("signature")
    if not isinstance(signature, str) or not signature:
        raise ValueError("remote threat feed is unsigned")
    payload = {k: v for k, v in data.items() if k != "signature"}
    if payload.get("tier") != expected_tier:
        raise ValueError("remote threat feed tier does not match the signed entitlement")
    if not isinstance(payload.get("signals"), list) or not isinstance(payload.get("compact_patterns", []), list):
        raise ValueError("remote threat feed has an invalid schema")
    if int(payload.get("version", 0)) < 1:
        raise ValueError("remote threat feed version is invalid")
    if datetime.now(timezone.utc) > _parse_expiry(payload.get("expires_at")):
        raise ValueError("remote threat feed has expired")
    minimum = payload.get("minimum_agentinterdict_version")
    if minimum:
        try:
            if Version(VERSION) < Version(str(minimum)):
                raise ValueError(f"remote threat feed requires AgentInterdict >= {minimum}")
        except InvalidVersion as exc:
            raise ValueError("remote threat feed has an invalid minimum runtime version") from exc
    try:
        _load_feed_public_key().verify(_b64u_decode(signature), _canonical_json(payload))
    except (InvalidSignature, binascii.Error, UnicodeError, ValueError, OSError) as exc:
        raise ValueError("remote threat feed signature verification failed") from exc
    return payload


def _control_plane_base() -> str:
    return os.getenv("AGENTINTERDICT_CONTROL_PLANE_URL", DEFAULT_CONTROL_PLANE).strip().rstrip("/") or DEFAULT_CONTROL_PLANE


def _validate_remote_url(url: str) -> None:
    parsed = urlparse(url)
    local = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme != "https" and not (local and parsed.scheme == "http"):
        raise ValueError("threat-feed URL must use HTTPS except for localhost development")
    expected = urlparse(_control_plane_base()).hostname
    if not local and parsed.hostname != expected:
        raise ValueError("threat-feed URL host does not match the configured control plane")


def _fetch_remote_threats(url: str, *, expected_tier: str, token: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        _validate_remote_url(url)
        if not token or len(token.encode("utf-8", errors="ignore")) > 32_768:
            raise ValueError("valid bounded entitlement token is required for the paid threat feed")
        req = urllib.request.Request(url, headers={
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "User-Agent": f"AgentInterdict/{VERSION}",
        })
        with _OPENER.open(req, timeout=10) as resp:
            if getattr(resp, "status", 200) != 200:
                raise ValueError(f"threat-feed HTTP status {getattr(resp, 'status', 'unknown')}")
            raw = resp.read(MAX_THREAT_BYTES + 1)
        if len(raw) > MAX_THREAT_BYTES:
            raise ValueError("remote threat feed exceeded the size limit")
        data = json.loads(raw.decode("utf-8"))
        return _verify_signed_bundle(data, expected_tier), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _merge_additive(baseline: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Add paid signals without permitting the remote feed to weaken baked-in rules."""
    merged = dict(baseline)
    for field in ("signals", "compact_patterns"):
        base_items = [x for x in baseline.get(field, []) if isinstance(x, dict)]
        names = {str(x.get("name", "")) for x in base_items}
        additions = [x for x in overlay.get(field, []) if isinstance(x, dict) and str(x.get("name", "")) not in names]
        merged[field] = base_items + additions
    merged["version"] = max(int(baseline.get("version", 1)), int(overlay.get("version", 1)))
    merged["updated_at"] = str(overlay.get("updated_at") or baseline.get("updated_at", ""))
    merged["tier"] = str(overlay.get("tier") or baseline.get("tier", "community"))
    return merged


def _compile(data: dict[str, Any], status: dict[str, Any]) -> dict[str, Any]:
    def compile_list(items: list[Any]) -> list[tuple[str, re.Pattern[str], int, str]]:
        out = []
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", ""))
            pattern = str(item.get("pattern", ""))
            flags = str(item.get("flags", ""))
            try:
                weight = int(item.get("weight", 0))
            except (TypeError, ValueError):
                continue
            reason = str(item.get("reason", ""))
            if not name or not pattern or not 0 <= weight <= 100:
                continue
            try:
                compiled = re.compile(pattern, _compile_flags(flags))
            except re.error:
                continue
            out.append((name, compiled, weight, reason))
        return out

    signals = compile_list(data.get("signals", []))
    compact = compile_list(data.get("compact_patterns", []))
    status = {**status, "version": int(data.get("version", 1)), "updated_at": str(data.get("updated_at", "")),
              "signal_count": len(signals), "compact_pattern_count": len(compact)}
    return {
        "version": int(data.get("version", 1)), "updated_at": str(data.get("updated_at", "")),
        "tier": str(data.get("tier", "community")), "signals": signals,
        "compact_patterns": compact, "status": status,
    }


def load_threats(path: Path | None = None) -> dict[str, Any]:
    baseline = _load_threat_file(DEFAULT_THREAT_FILE)
    data = baseline
    status: dict[str, Any] = {"source": "community-baseline", "tier": "community", "degraded": False, "reason": ""}

    selected_path = path
    if selected_path is None:
        explicit = os.getenv("AGENTINTERDICT_THREAT_FILE", "").strip()
        selected_path = Path(explicit).expanduser() if explicit else None

    if selected_path is not None:
        selected = _load_threat_file(Path(selected_path))
        if selected.get("remote_url"):
            tier = str(selected.get("tier", ""))
            license_status = get_license_status()
            token = get_entitlement_token()
            if tier not in PAID_TIERS or not license_status.valid or license_status.plan != tier or "threat_feed" not in license_status.features or not token:
                status = {"source": "community-baseline", "tier": "community", "degraded": True, "reason": "paid entitlement required for configured remote threat feed"}
            else:
                overlay, error = _fetch_remote_threats(str(selected["remote_url"]), expected_tier=tier, token=token)
                if overlay:
                    data = _merge_additive(baseline, overlay)
                    status = {"source": "signed-remote-overlay", "tier": tier, "degraded": False, "reason": ""}
                else:
                    status = {"source": "community-baseline", "tier": "community", "degraded": True, "reason": error or "remote threat feed unavailable"}
        else:
            data = _merge_additive(baseline, selected)
            status = {"source": "local-overlay", "tier": str(selected.get("tier", "community")), "degraded": False, "reason": ""}
    else:
        license_status = get_license_status()
        token = get_entitlement_token()
        if license_status.valid and license_status.plan in PAID_TIERS and "threat_feed" in license_status.features and token:
            tier = license_status.plan
            url = _control_plane_base() + "/v1/threats?tier=" + quote(tier, safe="")
            overlay, error = _fetch_remote_threats(url, expected_tier=tier, token=token)
            if overlay:
                data = _merge_additive(baseline, overlay)
                status = {"source": "signed-remote-overlay", "tier": tier, "degraded": False, "reason": ""}
            else:
                status = {"source": "community-baseline", "tier": "community", "degraded": True, "reason": error or "remote threat feed unavailable"}

    return _compile(data, status)


ACTIVE_THREATS = load_threats()
SIGNALS: list[tuple[str, re.Pattern[str], int, str]] = ACTIVE_THREATS["signals"]
COMPACT_PATTERNS: list[tuple[str, re.Pattern[str], int, str]] = ACTIVE_THREATS["compact_patterns"]
THREAT_VERSION: int = ACTIVE_THREATS["version"]
THREAT_UPDATED_AT: str = ACTIVE_THREATS["updated_at"]
THREAT_STATUS: dict[str, Any] = ACTIVE_THREATS["status"]
