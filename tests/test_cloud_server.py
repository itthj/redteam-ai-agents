"""Tests for the cloud & container posture MCP server (C9) — offline (prowler/trivy mocked)."""

import asyncio

import pytest

import mcp_layer.servers.cloud_server as srv
from config.settings import settings


@pytest.fixture(autouse=True)
def _authorized_accounts(monkeypatch):
    monkeypatch.setattr(settings, "authorized_cloud_accounts",
                        "123456789012,acme-prod,registry.acme.co.ke/app")


def test_handlers_exposed():
    assert {h.__name__ for h in srv._HANDLERS} == {"prowler_scan", "trivy_scan"}


# ── Scope gate ───────────────────────────────────────────────────────────────────

def test_prowler_out_of_scope_blocked(monkeypatch):
    monkeypatch.setattr(srv.shutil, "which", lambda b: "/usr/bin/prowler")
    out = asyncio.run(srv.prowler_scan("aws", "999999999999"))
    assert out["blocked"] is True


def test_prowler_in_scope_records_candidates(monkeypatch):
    monkeypatch.setattr(srv.shutil, "which", lambda b: "/usr/bin/prowler")
    monkeypatch.setattr(srv, "_run_prowler", lambda provider, account: {"json":
        '[{"check_id":"iam_root_mfa","service_name":"iam","status":"FAIL","severity":"critical",'
        '"compliance":{"CIS":["1.5"],"NIST":["AC-2"]},"status_extended":"root has no MFA"},'
        '{"check_id":"s3_public","service_name":"s3","status":"PASS","severity":"high"}]'})
    out = asyncio.run(srv.prowler_scan("aws", "123456789012"))
    assert out["count"] == 1                      # only the FAIL
    f = out["findings"][0]
    assert f["severity"] == "critical" and "CIS:1.5" in f["compliance"]


def test_prowler_degrades_when_absent(monkeypatch):
    monkeypatch.setattr(srv.shutil, "which", lambda b: None)
    out = asyncio.run(srv.prowler_scan("aws", "123456789012"))
    assert out.get("degraded") is True


# ── Trivy ────────────────────────────────────────────────────────────────────────

def test_trivy_in_scope_parses(monkeypatch):
    monkeypatch.setattr(srv.shutil, "which", lambda b: "/usr/bin/trivy")
    monkeypatch.setattr(srv, "_run_trivy", lambda target, scan_type: {"json":
        '{"Results":[{"Misconfigurations":[{"ID":"AVD-AWS-0086","Title":"public bucket",'
        '"Severity":"HIGH"}],"Vulnerabilities":[{"VulnerabilityID":"CVE-2023-1","PkgName":"openssl",'
        '"Severity":"CRITICAL"}]}]}'})
    out = asyncio.run(srv.trivy_scan("registry.acme.co.ke/app", scan_type="image"))
    assert out["count"] == 2
    sevs = {f["severity"] for f in out["findings"]}
    assert "high" in sevs and "critical" in sevs


def test_trivy_out_of_scope_blocked(monkeypatch):
    monkeypatch.setattr(srv.shutil, "which", lambda b: "/usr/bin/trivy")
    out = asyncio.run(srv.trivy_scan("evilcorp/image"))
    assert out["blocked"] is True


def test_trivy_degrades_when_absent(monkeypatch):
    monkeypatch.setattr(srv.shutil, "which", lambda b: None)
    out = asyncio.run(srv.trivy_scan("registry.acme.co.ke/app"))
    assert out.get("degraded") is True


# ── Parser units ─────────────────────────────────────────────────────────────────

def test_parse_prowler_severity_normalized():
    findings = srv._parse_prowler(
        '[{"check_id":"c","service_name":"s","status":"FAIL","severity":"informational"}]')
    assert findings[0]["severity"] == "info"


def test_build_server_constructs():
    if not srv._mcp_available():
        pytest.skip("mcp SDK not installed")
    assert srv.build_server() is not None
