"""Tests for the SaaS API — JWT auth, RBAC, tenant isolation (C7) — offline."""

import pytest
from fastapi.testclient import TestClient

from api.server import app
from config.settings import settings
from saas import auth
from saas.store import store

client = TestClient(app)


@pytest.fixture(autouse=True)
def _signing_key(monkeypatch):
    # A ≥32-byte JWT signing key (token issue + verify both read jwt_secret()).
    monkeypatch.setattr(settings, "jwt_secret", "saas-api-test-signing-key-32-bytes-min!!")


def _seed(role: str, username: str) -> str:
    tid = store.create_tenant(f"T-{username}")
    store.create_user(tid, username, auth.hash_password("pw"), role)
    return tid


def _token(username: str) -> str:
    r = client.post("/saas/auth/token", json={"username": username, "password": "pw"})
    assert r.status_code == 200
    return r.json()["access_token"]


def _hdr(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


def test_login_bad_credentials_401():
    _seed("operator", "op_bad")
    r = client.post("/saas/auth/token", json={"username": "op_bad", "password": "nope"})
    assert r.status_code == 401


def test_operator_can_create_and_list():
    _seed("operator", "op1")
    tok = _token("op1")
    r = client.post("/saas/engagements", json={"name": "E1", "targets": ["10.0.0.5"]}, headers=_hdr(tok))
    assert r.status_code == 201
    listed = client.get("/saas/engagements", headers=_hdr(tok)).json()["engagements"]
    assert any(e["name"] == "E1" for e in listed)


def test_client_viewer_cannot_create():
    _seed("client_viewer", "cv1")
    tok = _token("cv1")
    r = client.post("/saas/engagements", json={"name": "X"}, headers=_hdr(tok))
    assert r.status_code == 403


def test_missing_token_401():
    assert client.get("/saas/engagements").status_code == 401


def test_tenant_isolation_via_api():
    _seed("operator", "opa")
    _seed("operator", "opb")
    tok_a, tok_b = _token("opa"), _token("opb")
    eid = client.post("/saas/engagements", json={"name": "secret"}, headers=_hdr(tok_a)).json()["id"]
    # Tenant B cannot fetch or see tenant A's engagement.
    assert client.get(f"/saas/engagements/{eid}", headers=_hdr(tok_b)).status_code == 404
    assert client.get("/saas/engagements", headers=_hdr(tok_b)).json()["engagements"] == []


def test_audit_log_records_and_verifies():
    _seed("operator", "opaud")
    tok = _token("opaud")
    client.post("/saas/engagements", json={"name": "E"}, headers=_hdr(tok))
    r = client.get("/saas/audit", headers=_hdr(tok))
    assert r.status_code == 200
    assert r.json()["chain_valid"] is True
    assert len(r.json()["audit"]) >= 2     # login + engagement:create
