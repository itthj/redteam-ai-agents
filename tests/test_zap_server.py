"""Tests for the ZAP/Nuclei web-app MCP server (C1) — fully offline.

The ZAP client and the nuclei subprocess are mocked, so no daemon, no binary, no
network, and no API key are needed — same guarantee as the rest of the suite.
"""

import asyncio
import subprocess

import pytest

import mcp_layer.servers.zap_server as srv
from config.settings import settings

# ── Fake ZAP client ──────────────────────────────────────────────────────────────

class _FakeSpider:
    def __init__(self, urls):
        self._urls = urls

    def scan(self, url):
        return "1"

    def status(self, sid):
        return "100"

    def results(self, sid):
        return self._urls


class _FakeAjax:
    status = "stopped"

    def scan(self, url):
        return "OK"

    def results(self):
        return ["https://x/ajax"]


class _FakeAscan:
    def scan(self, url):
        return "1"

    def status(self, sid):
        return "100"


class _FakeCore:
    def __init__(self, alerts):
        self._alerts = alerts

    def alerts(self, baseurl=None):
        return self._alerts


class FakeZap:
    def __init__(self, urls=None, alerts=None):
        self.spider = _FakeSpider(urls if urls is not None else ["https://10.0.0.5/a"])
        self.ajaxSpider = _FakeAjax()
        self.ascan = _FakeAscan()
        self.core = _FakeCore(alerts if alerts is not None else [])


def _use_fake_zap(monkeypatch, **kwargs):
    monkeypatch.setattr(srv, "_zap_available", lambda: True)
    monkeypatch.setattr(srv, "_get_zap_client", lambda: FakeZap(**kwargs))


# ── Handler roster ───────────────────────────────────────────────────────────────

def test_handlers_exposed():
    names = {h.__name__ for h in srv._HANDLERS}
    assert names == {"zap_spider", "zap_ajax_spider", "zap_active_scan",
                     "zap_alerts", "nuclei_scan"}


# ── Scope gate ───────────────────────────────────────────────────────────────────

def test_out_of_scope_url_blocked(monkeypatch):
    _use_fake_zap(monkeypatch)
    out = asyncio.run(srv.zap_spider("https://8.8.8.8/login"))
    assert out["blocked"] is True
    assert "NOT in the authorized scope" in out["error"]


def test_in_scope_spider_runs(monkeypatch):
    _use_fake_zap(monkeypatch, urls=["https://10.0.0.5/a", "https://10.0.0.5/b"])
    out = asyncio.run(srv.zap_spider("https://10.0.0.5/"))
    assert out["progress"] == 100
    assert out["urls_found"] == 2


def test_unparseable_url_blocked(monkeypatch):
    _use_fake_zap(monkeypatch)
    out = asyncio.run(srv.zap_spider(""))
    assert out["blocked"] is True


# ── Active-scan written-authorization gate ───────────────────────────────────────

def test_active_scan_blocked_without_authorization(monkeypatch):
    monkeypatch.setattr(settings, "webapp_active_scan_authorized", False)
    _use_fake_zap(monkeypatch)
    out = asyncio.run(srv.zap_active_scan("https://10.0.0.5/"))
    assert out["blocked"] is True
    assert "not authorized" in out["error"]


def test_active_scan_runs_with_authorization(monkeypatch):
    monkeypatch.setattr(settings, "webapp_active_scan_authorized", True)
    _use_fake_zap(monkeypatch, alerts=[
        {"alert": "Reflected XSS", "risk": "High", "url": "https://10.0.0.5/q", "cweid": "79"},
    ])
    out = asyncio.run(srv.zap_active_scan("https://10.0.0.5/"))
    assert out["progress"] == 100
    assert out["alert_count"] == 1
    assert out["alerts"][0]["cwe"] == "79"


def test_nuclei_blocked_without_authorization(monkeypatch):
    monkeypatch.setattr(settings, "webapp_active_scan_authorized", False)
    monkeypatch.setattr(srv, "_nuclei_available", lambda: True)
    out = asyncio.run(srv.nuclei_scan("https://10.0.0.5/"))
    assert out["blocked"] is True


# ── Alerts parsing ───────────────────────────────────────────────────────────────

def test_alerts_parsed(monkeypatch):
    _use_fake_zap(monkeypatch, alerts=[
        {"alert": "SQL Injection", "risk": "High", "confidence": "Medium",
         "url": "https://10.0.0.5/q", "cweid": "89", "param": "id",
         "evidence": "syntax error", "solution": "parameterize"},
    ])
    out = asyncio.run(srv.zap_alerts("https://10.0.0.5/"))
    assert out["count"] == 1
    a = out["alerts"][0]
    assert a["name"] == "SQL Injection" and a["cwe"] == "89"


# ── Nuclei parsing + degradation ─────────────────────────────────────────────────

def test_nuclei_parses_jsonl(monkeypatch):
    monkeypatch.setattr(settings, "webapp_active_scan_authorized", True)
    monkeypatch.setattr(srv, "_nuclei_available", lambda: True)
    jsonl = (
        '{"template-id":"CVE-2021-1234","matched-at":"https://10.0.0.5/x","host":"10.0.0.5",'
        '"info":{"name":"Example RCE","severity":"high","tags":["cve","rce"],'
        '"classification":{"cwe-id":["CWE-94"]}}}\n'
        'garbage-not-json\n'
    )

    def fake_run(cmd, capture_output=True, text=True, timeout=None):
        return subprocess.CompletedProcess(cmd, 0, stdout=jsonl, stderr="")

    monkeypatch.setattr(srv.subprocess, "run", fake_run)
    out = asyncio.run(srv.nuclei_scan("https://10.0.0.5/", severity="high"))
    assert out["count"] == 1
    f = out["findings"][0]
    assert f["template"] == "CVE-2021-1234" and f["severity"] == "high" and f["cwe"] == "CWE-94"


def test_zap_degrades_when_client_absent(monkeypatch):
    monkeypatch.setattr(srv, "_zap_available", lambda: False)
    out = asyncio.run(srv.zap_spider("https://10.0.0.5/"))
    assert out.get("degraded") is True


def test_nuclei_degrades_when_binary_absent(monkeypatch):
    monkeypatch.setattr(settings, "webapp_active_scan_authorized", True)
    monkeypatch.setattr(srv, "_nuclei_available", lambda: False)
    out = asyncio.run(srv.nuclei_scan("https://10.0.0.5/"))
    assert out.get("degraded") is True


def test_build_server_constructs():
    if not srv._mcp_available():
        pytest.skip("mcp SDK not installed")
    assert srv.build_server() is not None
