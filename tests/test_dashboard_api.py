"""Tests for the dashboard API (C4) — fully offline (FastAPI TestClient)."""

import asyncio
import json
from pathlib import Path

from fastapi.testclient import TestClient

import api.server as server
from api.server import _event_payload, _is_safe_report_name, app
from config.settings import settings

client = TestClient(app)
client.headers.update({"X-API-Key": settings.api_secret_key})


# ── Engagements ──────────────────────────────────────────────────────────────────

def test_engagements_list_and_detail():
    lst = client.get("/engagements").json()["engagements"]
    assert lst and lst[0]["id"] == settings.engagement_id
    detail = client.get(f"/engagements/{settings.engagement_id}").json()
    for key in ("scope", "state", "run", "telemetry", "findings"):
        assert key in detail


def test_engagement_unknown_404():
    assert client.get("/engagements/ENG-NOPE").status_code == 404


def test_run_unknown_404():
    r = client.post("/engagements/ENG-NOPE/run", json={"targets": ["10.0.0.5"]})
    assert r.status_code == 404


def test_run_and_stop(monkeypatch):
    async def stub(objective, targets, **kwargs):
        await asyncio.sleep(30)   # stays "running" until cancelled

    monkeypatch.setattr(server._orchestrator, "run_autonomous", stub)
    eid = settings.engagement_id
    try:
        with TestClient(app) as c:
            c.headers.update({"X-API-Key": settings.api_secret_key})
            r = c.post(f"/engagements/{eid}/run", json={"objective": "x", "targets": ["10.0.0.5"]})
            assert r.status_code == 202 and r.json()["status"] == "running"
            # A second run while one is in flight is rejected.
            assert c.post(f"/engagements/{eid}/run", json={"targets": ["10.0.0.5"]}).status_code == 409
            assert c.post(f"/engagements/{eid}/stop").status_code == 200
    finally:
        server._RUNS.clear()


def test_stop_when_idle_409():
    server._RUNS.clear()
    assert client.post(f"/engagements/{settings.engagement_id}/stop").status_code == 409


# ── Reports ──────────────────────────────────────────────────────────────────────

def test_reports_list_and_get():
    reports_dir = Path(settings.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "c4_test_report.md").write_text("# C4 report", encoding="utf-8")

    listed = client.get("/reports").json()["reports"]
    assert any(r["file"] == "c4_test_report.md" for r in listed)

    got = client.get("/reports/c4_test_report.md").json()
    assert got["content"] == "# C4 report"


def test_report_missing_404():
    assert client.get("/reports/does_not_exist.md").status_code == 404


def test_safe_report_name_guard():
    assert _is_safe_report_name("report.md") is True
    assert _is_safe_report_name("../../etc/passwd") is False
    assert _is_safe_report_name("a\\b") is False
    assert _is_safe_report_name("") is False


# ── Live streams ─────────────────────────────────────────────────────────────────

def test_event_payload_enriched():
    payload = _event_payload()
    for key in ("phase", "telemetry", "finding_states", "run", "activity", "graph"):
        assert key in payload


def test_ws_streams_payload():
    with TestClient(app) as c:
        with c.websocket_connect("/ws") as ws:
            data = json.loads(ws.receive_text())
            assert "telemetry" in data and "finding_states" in data
