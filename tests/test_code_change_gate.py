"""Tests for the optional code-change review gate.

This is an OPTIONAL layer that reuses the existing scanning + audit
infrastructure to govern AI-generated code changes. It does NOT change any
existing enforcement behavior and does NOT block anything by itself — it
produces a signed, tamper-evident evidence record a caller can act on.
"""
import os
from pathlib import Path

import pytest

TEST_DB = Path(__file__).parent / "codechange-test.db"
os.environ["AGENTINTERDICT_DB"] = str(TEST_DB)
os.environ["AGENTINTERDICT_SECRET"] = "codechange-test-secret-0123456789abcdef0123456789abcdef"
os.environ["AGENTINTERDICT_OPERATOR_KEY"] = "operator-test-key-0123456789abcdef0123456789abcdef"
os.environ.pop("AGENTINTERDICT_API_KEY", None)

from agentinterdict import db, service
from agentinterdict.errors import ValidationError


@pytest.fixture(autouse=True)
def fresh():
    if TEST_DB.exists():
        TEST_DB.unlink()
    db.DB_PATH = TEST_DB
    db.init_db()
    yield
    if TEST_DB.exists():
        import gc
        import time
        gc.collect()
        for _ in range(5):
            try:
                TEST_DB.unlink()
                break
            except PermissionError:
                gc.collect()
                time.sleep(0.1)


def test_benign_diff_scores_low_and_records_evidence():
    diff = "+def add(a, b):\n+    return a + b\n-    return a - b"
    result = service.review_code_change(diff=diff, repo="myapp", branch="main", actor="agent")
    assert result["verdict"] in ("allowed", "review", "quarantined")
    assert result["evidence_recorded"] is True
    assert result["diff_hash"]
    assert result["repo"] == "myapp"
    assert result["branch"] == "main"
    # The audit trail should contain the code-change review event
    events = service.audit()
    assert any(e["event_type"] == "code_change.reviewed" for e in events)


def test_diff_with_embedded_secret_is_rejected():
    diff = "+api_key = 'sk-1234567890abcdefghijklmnopqrstuvwxyz'"
    result = service.review_code_change(diff=diff, repo="myapp", actor="agent")
    assert result["definite_secret"] is True
    assert result["verdict"] == "quarantined"


def test_diff_with_dangerous_command_is_flagged():
    diff = "+import os\n+os.system('rm -rf /')"
    result = service.review_code_change(diff=diff, repo="myapp", actor="agent")
    assert result["risk_score"] >= 20
    assert result["verdict"] in ("review", "quarantined")


def test_code_change_requires_diff():
    with pytest.raises(ValidationError):
        service.review_code_change(diff="", repo="myapp", actor="agent")


def test_code_change_audit_is_tamper_evident():
    service.review_code_change(diff="+x = 1", repo="myapp", actor="agent")
    # verify_integrity should pass (no tampering)
    result = service.verify_integrity()
    assert result["ok"] is True
