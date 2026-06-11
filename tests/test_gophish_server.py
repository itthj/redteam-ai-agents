"""Tests for the phishing / social-engineering MCP server (C6) — fully offline."""

import asyncio

import pytest

import mcp_layer.servers.gophish_server as srv
from config.authorization import scope
from config.settings import settings


@pytest.fixture(autouse=True)
def _domains(monkeypatch):
    # Authorize a client email domain for the duration of each test.
    monkeypatch.setattr(settings, "authorized_email_domains", "acme.co.ke,*.acme.com")
    # Stub the GoPhish API so nothing hits the network.
    monkeypatch.setattr(srv, "_gophish_request",
                        lambda method, path, payload=None: {"id": 1, "name": "ok"})


def test_handlers_exposed():
    names = {h.__name__ for h in srv._HANDLERS}
    assert "gp_launch_campaign" in names and "gp_create_group" in names


# ── Email-domain gate ────────────────────────────────────────────────────────────

def test_email_domain_authorization():
    assert scope.is_email_authorized("ceo@acme.co.ke") is True
    assert scope.is_email_authorized("user@sub.acme.com") is True   # wildcard suffix
    assert scope.is_email_authorized("victim@gmail.com") is False


def test_group_rejects_out_of_domain_targets():
    out = asyncio.run(srv.gp_create_group("wave1", ["ceo@acme.co.ke", "victim@gmail.com"]))
    assert out["blocked"] is True
    assert "gmail.com" in out["error"]


def test_group_accepts_in_domain_targets():
    out = asyncio.run(srv.gp_create_group("wave1", ["ceo@acme.co.ke", "cfo@acme.co.ke"]))
    assert "blocked" not in out


# ── Campaign launch gates ────────────────────────────────────────────────────────

def test_campaign_blocked_without_written_authorization(monkeypatch):
    monkeypatch.setattr(settings, "phishing_authorized", False)
    out = asyncio.run(srv.gp_launch_campaign("c1", "t", "p", "http://x", "smtp",
                                             ["wave1"], approved_by="ciso"))
    assert out["blocked"] is True


def test_campaign_blocked_without_human_approver(monkeypatch):
    monkeypatch.setattr(settings, "phishing_authorized", True)
    out = asyncio.run(srv.gp_launch_campaign("c1", "t", "p", "http://x", "smtp",
                                             ["wave1"], approved_by=None))
    assert out["blocked"] is True
    assert "human approver" in out["error"]


def test_campaign_launches_with_flag_and_approver(monkeypatch):
    monkeypatch.setattr(settings, "phishing_authorized", True)
    out = asyncio.run(srv.gp_launch_campaign("c1", "t", "p", "http://x", "smtp",
                                             ["wave1"], approved_by="ciso"))
    assert "blocked" not in out


# ── Metrics + degradation ────────────────────────────────────────────────────────

def test_campaign_results_records_metrics(monkeypatch):
    monkeypatch.setattr(srv, "_gophish_request", lambda method, path, payload=None: {
        "results": [{"status": "Email Opened"}, {"status": "Clicked Link"},
                    {"status": "Submitted Data"}, {"status": "Sent"}]})
    out = asyncio.run(srv.gp_campaign_results(7))
    assert out["stats"]["clicked"] == 1
    assert out["stats"]["submitted"] == 1


def test_degrades_when_gophish_unreachable(monkeypatch):
    monkeypatch.setattr(srv, "_gophish_request",
                        lambda method, path, payload=None: {"_degraded": "connection refused"})
    out = asyncio.run(srv.gp_list_campaigns())
    assert out.get("degraded") is True


def test_build_server_constructs():
    if not srv._mcp_available():
        pytest.skip("mcp SDK not installed")
    assert srv.build_server() is not None
