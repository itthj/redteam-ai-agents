"""Tests for the finding approval-queue API (C2) — fully offline (FastAPI TestClient)."""

from fastapi.testclient import TestClient

from api.server import app
from config.settings import settings
from core.finding_state import finding_state

# Present the configured API key so the auth gate (verify_token) passes regardless of
# whether the environment leaves it at the "change_me" default or sets a real value.
client = TestClient(app)
client.headers.update({"X-API-Key": settings.api_secret_key})


def test_queue_and_approve_flow():
    sig = finding_state.register_candidate({
        "target": "10.0.0.5", "title": "API approve case", "severity": "high",
        "url": "https://10.0.0.5/api1", "template": "t-api-1",
    })
    finding_state.confirm(sig, validation={"reproduced": True}, cvss=7.5)

    queue = client.get("/findings/queue").json()["queue"]
    assert any(e["signature"] == sig for e in queue)

    r = client.post(f"/findings/{sig}/approve", json={"approver": "tester"})
    assert r.status_code == 200 and r.json()["approved"] is True

    approved = client.get("/findings", params={"state": "approved"}).json()["findings"]
    assert any(e["signature"] == sig for e in approved)


def test_approve_unknown_returns_409():
    r = client.post("/findings/deadbeef/approve", json={})
    assert r.status_code == 409


def test_cannot_approve_a_candidate_via_api():
    sig = finding_state.register_candidate({
        "target": "10.0.0.5", "title": "API candidate not approvable", "severity": "low",
        "url": "https://10.0.0.5/api3",
    })
    r = client.post(f"/findings/{sig}/approve", json={})
    assert r.status_code == 409   # must be confirmed first


def test_reject_flow():
    sig = finding_state.register_candidate({
        "target": "10.0.0.5", "title": "API reject case", "severity": "low",
        "url": "https://10.0.0.5/api2",
    })
    r = client.post(f"/findings/{sig}/reject", json={"reason": "false positive"})
    assert r.status_code == 200 and r.json()["rejected"] is True
