"""Tests for the multi-tenant store (C7) — tenant isolation + audit chain, offline."""

import pytest

from saas.store import SaasStore


@pytest.fixture
def store(tmp_path):
    return SaasStore(db_path=str(tmp_path / "saas.db"))


def test_tenant_isolation_on_engagements(store):
    t1 = store.create_tenant("Acme")
    t2 = store.create_tenant("Globex")
    e1 = store.create_engagement(t1, "eng-a", targets=["10.0.0.5"])
    store.create_engagement(t2, "eng-b")

    assert len(store.list_engagements(t1)) == 1
    assert len(store.list_engagements(t2)) == 1
    assert store.get_engagement(t1, e1) is not None
    assert store.get_engagement(t2, e1) is None       # cross-tenant fetch blocked


def test_findings_are_tenant_scoped(store):
    t1, t2 = store.create_tenant("A"), store.create_tenant("B")
    e1 = store.create_engagement(t1, "e")
    store.add_finding(t1, e1, "sig1", "SQLi", "high", "confirmed", 8.2)
    assert len(store.list_findings(t1, e1)) == 1
    assert store.list_findings(t2) == []


def test_update_status_only_within_tenant(store):
    t1, t2 = store.create_tenant("A"), store.create_tenant("B")
    e1 = store.create_engagement(t1, "e")
    assert store.update_engagement_status(t2, e1, "running") is False   # wrong tenant
    assert store.update_engagement_status(t1, e1, "running") is True
    assert store.get_engagement(t1, e1)["status"] == "running"


def test_audit_chain_appends_and_verifies(store):
    t = store.create_tenant("Acme")
    store.audit(t, "alice", "login", "token issued")
    store.audit(t, "alice", "engagement:create", "e1")
    assert len(store.get_audit(t)) == 2
    assert store.verify_audit_chain(t) is True


def test_tenant_budget_stored(store):
    t = store.create_tenant("Acme", budget_usd=250.0)
    assert store.get_tenant(t)["budget_usd"] == 250.0
