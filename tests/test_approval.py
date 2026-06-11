"""Tests for the intrusive-action approval gate (C1) — fully offline."""

import pytest

from core.approval import AuthorizationRequired, approval
from core.evidence_store import evidence


def test_blocks_without_written_authorization():
    with pytest.raises(AuthorizationRequired):
        approval.require("web_active_scan", authorized=False, target="10.0.0.5", agent="webapp")


def test_allows_with_written_authorization():
    # Should not raise
    approval.require("web_active_scan", authorized=True, target="10.0.0.5",
                     approver="operator", agent="webapp")


def test_is_authorized_reflects_flag():
    assert approval.is_authorized(authorized=True) is True
    assert approval.is_authorized(authorized=False) is False


def test_block_is_logged_to_evidence():
    before = len(evidence.get_all())
    with pytest.raises(AuthorizationRequired):
        approval.require("phishing_send", authorized=False, target="client.com", agent="social_eng")
    records = evidence.get_all()
    assert len(records) == before + 1
    assert records[-1]["operation"] == "approval_block"
    assert records[-1]["severity"] == "high"


def test_grant_is_logged_to_evidence():
    before = len(evidence.get_all())
    approval.require("web_active_scan", authorized=True, target="10.0.0.5",
                     approver="alice", agent="webapp")
    records = evidence.get_all()
    assert len(records) == before + 1
    assert records[-1]["operation"] == "approval_grant"
    assert "alice" in records[-1]["action"]
