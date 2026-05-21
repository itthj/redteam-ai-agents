"""Tests for the engagement authorization gate."""

import pytest

from config.authorization import AuthorizationError, OperationType, scope


def test_ip_in_authorized_cidr():
    assert scope.is_authorized("192.168.56.10", OperationType.ACTIVE_SCAN)
    assert scope.is_authorized("192.168.56.254", OperationType.ACTIVE_SCAN)


def test_exact_ip_authorized():
    assert scope.is_authorized("10.0.0.5", OperationType.EXPLOITATION)


def test_ip_outside_scope_rejected():
    assert not scope.is_authorized("8.8.8.8", OperationType.PASSIVE_RECON)
    assert not scope.is_authorized("10.0.0.6", OperationType.ACTIVE_SCAN)


def test_hostname_wildcard_match():
    assert scope.is_authorized("dc01.lab.internal", OperationType.ACTIVE_SCAN)
    assert not scope.is_authorized("dc01.prod.internal", OperationType.ACTIVE_SCAN)


def test_authorize_raises_for_out_of_scope():
    with pytest.raises(AuthorizationError):
        scope.authorize("203.0.113.1", OperationType.EXPLOITATION, agent_name="test")


def test_authorize_passes_for_in_scope():
    # Should not raise
    scope.authorize("192.168.56.20", OperationType.VULNERABILITY_SCAN, agent_name="test")


def test_summary_shape():
    s = scope.summary()
    assert s["engagement_id"] == "ENG-TEST-001"
    assert "192.168.56.0/24" in s["authorized_targets"]
    assert s["expired"] is False
