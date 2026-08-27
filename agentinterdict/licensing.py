from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_PUBLIC_KEY = PACKAGE_ROOT / "license_public_key.pem"
MAX_TOKEN_BYTES = 32_768

PLAN_FEATURES = {
    "community": ["core_gateway", "static_risk_rules", "single_operator_gui", "audit_verify"],
    "pro": ["core_gateway", "static_risk_rules", "single_operator_gui", "audit_verify", "threat_feed", "advanced_classifier", "integrations", "audit_export"],
    "business": ["core_gateway", "static_risk_rules", "single_operator_gui", "audit_verify", "threat_feed", "advanced_classifier", "integrations", "audit_export", "team_rbac", "multi_agent", "policy_packs"],
    "enterprise": ["core_gateway", "static_risk_rules", "single_operator_gui", "audit_verify", "threat_feed", "advanced_classifier", "integrations", "audit_export", "team_rbac", "multi_agent", "policy_packs", "sso_saml", "offline_lease", "priority_support"],
}


def _b64u_decode(value: str) -> bytes:
    if len(value) > MAX_TOKEN_BYTES:
        raise ValueError("license component too large")
    value += "=" * (-len(value) % 4)
    return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)


@dataclass
class LicenseStatus:
    valid: bool
    plan: str
    features: list[str]
    source: str
    reason: str = ""
    customer_id: str | None = None
    license_id: str | None = None
    expires_at: str | None = None
    offline_until: str | None = None
    installation_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _community(source: str, reason: str, valid: bool = False) -> LicenseStatus:
    return LicenseStatus(valid, "community", PLAN_FEATURES["community"], source, reason)


def _load_public_key() -> Ed25519PublicKey | None:
    path = Path(os.getenv("AGENTINTERDICT_LICENSE_PUBLIC_KEY_FILE", str(DEFAULT_PUBLIC_KEY))).expanduser()
    if not path.exists() or not path.is_file():
        return None
    if path.stat().st_size > 16_384:
        raise ValueError("license public key file is unexpectedly large")
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("AgentInterdict license public key is not Ed25519")
    return key


def _read_token() -> tuple[str | None, str]:
    direct = os.getenv("AGENTINTERDICT_LICENSE_TOKEN", "").strip()
    if direct:
        return direct[:MAX_TOKEN_BYTES + 1], "environment"
    p = Path(os.getenv("AGENTINTERDICT_LICENSE_FILE", str(Path.home() / ".agentinterdict" / "license.mglic"))).expanduser()
    try:
        if p.exists() and p.is_file():
            if p.stat().st_size > MAX_TOKEN_BYTES:
                return "X" * (MAX_TOKEN_BYTES + 1), str(p)
            return p.read_text(encoding="utf-8").strip(), str(p)
    except OSError:
        return None, str(p)
    return None, "community-default"


def _parse_time(value: Any, field: str) -> datetime | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO-8601 string")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return dt.astimezone(timezone.utc)


def _installation_id() -> str | None:
    direct = os.getenv("AGENTINTERDICT_INSTALLATION_ID", "").strip()
    if direct:
        return direct
    install_file = Path.home() / ".agentinterdict" / "installation_id"
    try:
        if install_file.exists() and install_file.is_file() and install_file.stat().st_size < 1024:
            return install_file.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None
    return None


def verify_license_token(token: str, *, source: str = "provided-token", installation_id: str | None = None) -> LicenseStatus:
    """Verify one signed entitlement without mutating local state.

    This is shared by normal licence loading and activation so an activation response
    is cryptographically checked *before* it replaces a known-good local lease.
    """
    if not isinstance(token, str) or not token:
        return _community(source, "Invalid license: empty token")
    if len(token.encode("utf-8", errors="ignore")) > MAX_TOKEN_BYTES:
        return _community(source, "Invalid license: token too large")

    try:
        if token.count(".") != 1:
            raise ValueError("token format")
        payload_b64, sig_b64 = token.split(".", 1)
        payload_raw = _b64u_decode(payload_b64)
        signature = _b64u_decode(sig_b64)
        if len(payload_raw) > 16_384 or len(signature) != 64:
            raise ValueError("invalid payload/signature size")
        public_key = _load_public_key()
        if public_key is None:
            return _community(source, "License public key is missing")
        public_key.verify(signature, payload_raw)
        payload = json.loads(payload_raw)
        if not isinstance(payload, dict):
            raise ValueError("license payload must be an object")
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, InvalidSignature, binascii.Error, OSError) as exc:
        return _community(source, f"Invalid license: {type(exc).__name__}")

    try:
        now = datetime.now(timezone.utc)
        nbf = _parse_time(payload.get("not_before"), "not_before")
        exp = _parse_time(payload.get("expires_at"), "expires_at")
        offline_until = _parse_time(payload.get("offline_until"), "offline_until")
        if exp is None:
            return _community(source, "Paid license is missing expires_at")
        if nbf and now < nbf:
            return _community(source, "License is not active yet")
        if now > exp:
            return _community(source, "License has expired")
        if offline_until and now > offline_until:
            return _community(source, "Offline lease must be refreshed")

        install_expected = payload.get("installation_id")
        install_actual = installation_id if installation_id is not None else _installation_id()
        if install_expected:
            if not isinstance(install_expected, str) or not install_actual or install_expected != install_actual:
                return _community(source, "License is bound to another installation")

        plan = payload.get("plan", "community")
        if not isinstance(plan, str) or plan not in PLAN_FEATURES:
            return _community(source, "Unknown plan")
        requested = payload.get("features")
        allowed = PLAN_FEATURES[plan]
        if requested is not None and not isinstance(requested, list):
            return _community(source, "Invalid features claim")
        features = [f for f in (requested or allowed) if isinstance(f, str) and f in allowed]
        return LicenseStatus(
            True, plan, features, source, "Entitlement signature and lease are valid",
            customer_id=payload.get("customer_id") if isinstance(payload.get("customer_id"), str) else None,
            license_id=payload.get("license_id") if isinstance(payload.get("license_id"), str) else None,
            expires_at=payload.get("expires_at"), offline_until=payload.get("offline_until"),
            installation_id=install_expected,
        )
    except (ValueError, TypeError, OverflowError):
        return _community(source, "Invalid license claims")


def get_entitlement_token() -> str | None:
    """Return the locally installed signed entitlement token, if it is bounded.

    Callers must still verify the token with get_license_status()/verify_license_token
    before trusting any claims. This accessor exists so authenticated control-plane
    requests can present the same signed lease without duplicating file/env logic.
    """
    token, _source = _read_token()
    if not token or len(token.encode("utf-8", errors="ignore")) > MAX_TOKEN_BYTES:
        return None
    return token


def get_license_status() -> LicenseStatus:
    token, source = _read_token()
    if not token:
        return _community(source, "No paid entitlement installed", valid=True)
    return verify_license_token(token, source=source)


def has_feature(feature: str) -> bool:
    s = get_license_status()
    return s.valid and feature in s.features
