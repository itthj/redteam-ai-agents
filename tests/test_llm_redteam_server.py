"""Tests for the LLM red-team MCP server (C8) — fully offline (garak/PyRIT mocked)."""

import asyncio

import pytest

import mcp_layer.servers.llm_redteam_server as srv
from config.settings import settings


@pytest.fixture(autouse=True)
def _authorized_endpoint(monkeypatch):
    monkeypatch.setattr(settings, "authorized_llm_endpoints", "https://chat.acme.co.ke,api.acme.com")


def test_handlers_exposed():
    assert {h.__name__ for h in srv._HANDLERS} == {"garak_scan", "pyrit_probe"}


# ── Scope + authorization gates ──────────────────────────────────────────────────

def test_out_of_scope_endpoint_blocked(monkeypatch):
    monkeypatch.setattr(settings, "llm_redteam_authorized", True)
    out = asyncio.run(srv.garak_scan("https://evil.example.com/chat"))
    assert out["blocked"] is True


def test_blocked_without_written_authorization(monkeypatch):
    monkeypatch.setattr(settings, "llm_redteam_authorized", False)
    out = asyncio.run(srv.garak_scan("https://chat.acme.co.ke"))
    assert out["blocked"] is True
    assert "not authorized" in out["error"]


def test_garak_scan_records_candidates(monkeypatch):
    monkeypatch.setattr(settings, "llm_redteam_authorized", True)
    monkeypatch.setattr(srv, "_garak_available", lambda: True)
    monkeypatch.setattr(srv, "_run_garak", lambda endpoint, probes: {"jsonl":
        '{"entry_type":"eval","probe":"promptinject.HijackHateHumans","detector":"mitigation",'
        '"passed":2,"total":10}\n'
        '{"entry_type":"eval","probe":"leakreplay.System","detector":"leak","passed":9,"total":10}\n'})
    out = asyncio.run(srv.garak_scan("https://chat.acme.co.ke"))
    assert out["count"] == 2
    ids = {f["llm_id"] for f in out["findings"]}
    assert "LLM01" in ids and "LLM07" in ids
    # high failure rate → high severity
    assert any(f["severity"] == "high" for f in out["findings"])


def test_garak_degrades_when_absent(monkeypatch):
    monkeypatch.setattr(settings, "llm_redteam_authorized", True)
    monkeypatch.setattr(srv, "_garak_available", lambda: False)
    out = asyncio.run(srv.garak_scan("https://chat.acme.co.ke"))
    assert out.get("degraded") is True


def test_pyrit_degrades_when_absent(monkeypatch):
    monkeypatch.setattr(settings, "llm_redteam_authorized", True)
    monkeypatch.setattr(srv, "_pyrit_available", lambda: False)
    out = asyncio.run(srv.pyrit_probe("https://chat.acme.co.ke"))
    assert out.get("degraded") is True


def test_pyrit_records_candidates(monkeypatch):
    monkeypatch.setattr(settings, "llm_redteam_authorized", True)
    monkeypatch.setattr(srv, "_pyrit_available", lambda: True)
    monkeypatch.setattr(srv, "_run_pyrit", lambda endpoint, scenario: {"findings": [
        {"title": "multi-turn jailbreak succeeded", "severity": "high", "category": "jailbreak"}]})
    out = asyncio.run(srv.pyrit_probe("https://chat.acme.co.ke", scenario="prompt_injection"))
    assert out["count"] == 1 and out["findings"][0]["llm_id"] == "LLM01"


def test_parse_garak_ignores_non_eval_and_passing():
    text = ('{"entry_type":"start"}\n'
            '{"entry_type":"eval","probe":"p","detector":"d","passed":10,"total":10}\n'
            'garbage\n'
            '{"entry_type":"eval","probe":"p2","detector":"d2","passed":0,"total":5}\n')
    findings = srv._parse_garak(text)
    assert len(findings) == 1 and findings[0]["probe"] == "p2"


def test_build_server_constructs():
    if not srv._mcp_available():
        pytest.skip("mcp SDK not installed")
    assert srv.build_server() is not None
