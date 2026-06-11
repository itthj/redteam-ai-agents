"""Tests for the deterministic re-test (C2) — fully offline (nuclei/HTTP mocked)."""

import asyncio
import types

import core.retest as retest_mod
import mcp_layer.servers.zap_server as zap_server
from core.retest import retest


def test_nuclei_reproduced(monkeypatch):
    async def fake_nuclei(url, severity=None, templates=None):
        return {"findings": [{"template": templates}], "count": 1}

    monkeypatch.setattr(zap_server, "nuclei_scan", fake_nuclei)
    out = asyncio.run(retest({"target": "10.0.0.5", "url": "https://10.0.0.5/x",
                              "template": "CVE-2021-1", "severity": "high"}))
    assert out["reproduced"] is True
    assert out["method"] == "nuclei"


def test_nuclei_not_reproduced(monkeypatch):
    async def fake_nuclei(url, severity=None, templates=None):
        return {"findings": [], "count": 0}

    monkeypatch.setattr(zap_server, "nuclei_scan", fake_nuclei)
    out = asyncio.run(retest({"target": "10.0.0.5", "url": "https://10.0.0.5/x",
                              "template": "CVE-2021-1", "severity": "high"}))
    assert out["reproduced"] is False


def test_nuclei_degraded_is_not_reproduced(monkeypatch):
    async def fake_nuclei(url, severity=None, templates=None):
        return {"degraded": True, "error": "nuclei not found"}

    monkeypatch.setattr(zap_server, "nuclei_scan", fake_nuclei)
    out = asyncio.run(retest({"target": "10.0.0.5", "url": "https://10.0.0.5/x",
                              "template": "t1", "severity": "high"}))
    assert out["reproduced"] is False


def test_http_signal_present(monkeypatch):
    def fake_get(url, timeout=None, verify=True):
        return types.SimpleNamespace(text="...<script>alert(1)</script>...", status_code=200)

    monkeypatch.setattr(retest_mod.requests, "get", fake_get)
    out = asyncio.run(retest({"target": "10.0.0.5", "url": "https://10.0.0.5/q",
                              "repro_signal": "<script>alert(1)</script>", "severity": "high"}))
    assert out["reproduced"] is True
    assert out["method"] == "http"


def test_http_signal_absent(monkeypatch):
    def fake_get(url, timeout=None, verify=True):
        return types.SimpleNamespace(text="clean page", status_code=200)

    monkeypatch.setattr(retest_mod.requests, "get", fake_get)
    out = asyncio.run(retest({"target": "10.0.0.5", "url": "https://10.0.0.5/q",
                              "repro_signal": "<script>alert(1)</script>", "severity": "high"}))
    assert out["reproduced"] is False


def test_http_without_signal_not_reproduced():
    out = asyncio.run(retest({"target": "10.0.0.5", "url": "https://10.0.0.5/q",
                              "severity": "high"}))
    assert out["reproduced"] is False
    assert "no reproduction signal" in out["evidence"]


def test_out_of_scope_http_blocked():
    out = asyncio.run(retest({"target": "8.8.8.8", "url": "https://8.8.8.8/q",
                              "repro_signal": "x", "severity": "high"}))
    assert out["reproduced"] is False


def test_no_artifact_returns_grade():
    out = asyncio.run(retest({"target": "10.0.0.5", "title": "vague finding",
                              "severity": "medium"}))
    assert out["reproduced"] is False
    assert out["method"] == "none"
    assert "verdict" in out
