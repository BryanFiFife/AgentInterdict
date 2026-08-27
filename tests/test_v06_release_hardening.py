from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentinterdict import config, threats
from scripts import build_packages


def _signed_feed(private: Ed25519PrivateKey, *, tier: str = "pro", expires_delta: timedelta = timedelta(hours=1)) -> dict:
    payload = {
        "version": 3,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + expires_delta).isoformat(),
        "minimum_agentinterdict_version": "0.6.0",
        "tier": tier,
        "signals": [{"name": "paid_test_signal", "pattern": r"paid\\s+threat", "flags": "i", "weight": 50, "reason": "paid feed test"}],
        "compact_patterns": [],
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload["signature"] = base64.urlsafe_b64encode(private.sign(raw)).decode().rstrip("=")
    return payload


def test_release_version_is_single_source_v061():
    assert config.VERSION == "0.6.1"
    import agentinterdict
    assert agentinterdict.__version__ == config.VERSION


def test_remote_profile_without_paid_entitlement_falls_back_to_full_community_baseline(tmp_path, monkeypatch):
    stub = tmp_path / "remote.json"
    stub.write_text(json.dumps({"tier": "pro", "remote_url": "https://agentinterdict-funnel.bryansmall26.workers.dev/v1/threats?tier=pro"}), encoding="utf-8")
    monkeypatch.setattr(threats, "get_license_status", lambda: SimpleNamespace(valid=True, plan="community", features=[]))
    monkeypatch.setattr(threats, "get_entitlement_token", lambda: None)
    loaded = threats.load_threats(stub)
    baseline = threats._compile(threats._load_threat_file(threats.DEFAULT_THREAT_FILE), {"source":"test","tier":"community","degraded":False,"reason":""})
    assert loaded["status"]["degraded"] is True
    assert loaded["status"]["source"] == "community-baseline"
    assert {x[0] for x in baseline["signals"]}.issubset({x[0] for x in loaded["signals"]})
    assert loaded["signals"], "remote failure must never result in a zero-rule detector"


def test_signed_paid_feed_verifies_and_is_additive(tmp_path, monkeypatch):
    private = Ed25519PrivateKey.generate()
    pub = tmp_path / "threat-pub.pem"
    pub.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setenv("AGENTINTERDICT_THREAT_PUBLIC_KEY_FILE", str(pub))
    verified = threats._verify_signed_bundle(_signed_feed(private), "pro")
    baseline = threats._load_threat_file(threats.DEFAULT_THREAT_FILE)
    merged = threats._merge_additive(baseline, verified)
    base_names = {str(x.get("name")) for x in baseline["signals"]}
    merged_names = {str(x.get("name")) for x in merged["signals"]}
    assert base_names.issubset(merged_names)
    assert "paid_test_signal" in merged_names


def test_signed_feed_rejects_wrong_tier_and_expiry(tmp_path, monkeypatch):
    private = Ed25519PrivateKey.generate()
    pub = tmp_path / "threat-pub.pem"
    pub.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setenv("AGENTINTERDICT_THREAT_PUBLIC_KEY_FILE", str(pub))
    with pytest.raises(ValueError, match="tier"):
        threats._verify_signed_bundle(_signed_feed(private, tier="business"), "pro")
    with pytest.raises(ValueError, match="expired"):
        threats._verify_signed_bundle(_signed_feed(private, expires_delta=timedelta(seconds=-1)), "pro")


def test_valid_paid_entitlement_selects_authenticated_tier_overlay(monkeypatch):
    captured = {}
    monkeypatch.delenv("AGENTINTERDICT_THREAT_FILE", raising=False)
    monkeypatch.setattr(threats, "get_license_status", lambda: SimpleNamespace(valid=True, plan="business", features=["threat_feed"]))
    monkeypatch.setattr(threats, "get_entitlement_token", lambda: "signed.lease")
    def fake_fetch(url, *, expected_tier, token):
        captured.update(url=url, expected_tier=expected_tier, token=token)
        return ({
            "version": 9, "tier": "business", "updated_at": "now",
            "signals": [{"name":"paid_extra","pattern":"paid-extra","flags":"","weight":10,"reason":"test"}],
            "compact_patterns": [],
        }, None)
    monkeypatch.setattr(threats, "_fetch_remote_threats", fake_fetch)
    loaded = threats.load_threats()
    assert captured["expected_tier"] == "business"
    assert captured["token"] == "signed.lease"
    assert "tier=business" in captured["url"]
    assert loaded["status"]["source"] == "signed-remote-overlay"
    assert any(name == "paid_extra" for name, *_ in loaded["signals"])


def test_release_package_contains_manifest_and_verifies(tmp_path):
    out = tmp_path / "dist"
    out.mkdir()
    archive = build_packages.build_package("pro", out)
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(extracted)
    manifest = json.loads((extracted / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["version"] == "0.6.1"
    assert manifest["tier"] == "pro"
    assert "agentinterdict/threats/community.json" in manifest["files"]
    # Paid builds no longer replace the baseline with a fail-open remote stub.
    assert not (extracted / "agentinterdict" / "threats" / "pro.json").exists()
    result = subprocess.run([sys.executable, "scripts/verify_release.py"], cwd=extracted, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK: verified" in result.stdout


def test_multi_tier_build_inside_repo_never_nests_prior_archives():
    out = build_packages.ROOT / ".agentinterdict-package-recursion-test"
    shutil.rmtree(out, ignore_errors=True)
    try:
        archives = [build_packages.build_package(tier, out) for tier in ("community", "pro", "business", "enterprise")]
        assert len(archives) == 4
        for archive in archives:
            with zipfile.ZipFile(archive) as zf:
                names = zf.namelist()
            assert not any(name.lower().endswith(".zip") for name in names), f"{archive.name} recursively contains another ZIP"
            assert not any(".agentinterdict-package-recursion-test" in name for name in names)
    finally:
        shutil.rmtree(out, ignore_errors=True)
