"""Tests for the AD/Windows MCP server (C5) — fully offline (subprocess + BHCE mocked)."""

import asyncio
import subprocess

import pytest

import mcp_layer.servers.ad_server as srv
from config.settings import settings


def _tools_present(monkeypatch, stdout="ok", rc=0):
    """Make every external binary 'present' and stub subprocess.run."""
    monkeypatch.setattr(srv, "_which", lambda b: f"/usr/bin/{b}")

    def fake_run(cmd, capture_output=True, text=True, timeout=None):
        return subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr="")

    monkeypatch.setattr(srv.subprocess, "run", fake_run)


def test_handlers_exposed():
    names = {h.__name__ for h in srv._HANDLERS}
    assert names == {"bh_collect", "bh_shortest_path", "nxc_enum",
                     "secretsdump", "certipy_find", "nxc_exec"}


# ── Scope gate (read/enum) ───────────────────────────────────────────────────────

def test_nxc_enum_out_of_scope_blocked(monkeypatch):
    _tools_present(monkeypatch)
    out = asyncio.run(srv.nxc_enum("8.8.8.8", username="a", password="b"))
    assert out["blocked"] is True


def test_nxc_enum_in_scope_runs(monkeypatch):
    _tools_present(monkeypatch, stdout="SHARE  READ")
    out = asyncio.run(srv.nxc_enum("10.0.0.5", username="a", password="b", what="shares"))
    assert "output" in out and out["exit_code"] == 0


def test_secretsdump_sanitizes_and_counts(monkeypatch):
    _tools_present(monkeypatch, stdout="admin:500:aad3b:31d6:::\nguest:501:aad3b:31d6:::")
    out = asyncio.run(srv.secretsdump("10.0.0.5", "admin", "pw", domain="ACME"))
    assert out["hash_count"] == 2


def test_certipy_find_scope_gated(monkeypatch):
    _tools_present(monkeypatch)
    assert asyncio.run(srv.certipy_find("8.8.8.8", "u", "p", "ACME"))["blocked"] is True
    assert "output" in asyncio.run(srv.certipy_find("10.0.0.5", "u", "p", "ACME"))


# ── State-change gate (nxc_exec) ─────────────────────────────────────────────────

def test_nxc_exec_blocked_without_authorization(monkeypatch):
    monkeypatch.setattr(settings, "ad_state_change_authorized", False)
    _tools_present(monkeypatch)
    out = asyncio.run(srv.nxc_exec("10.0.0.5", "u", "p", "whoami"))
    assert out["blocked"] is True
    assert "not authorized" in out["error"]


def test_nxc_exec_destructive_command_blocked_by_guardrail(monkeypatch):
    monkeypatch.setattr(settings, "ad_state_change_authorized", True)
    _tools_present(monkeypatch)
    out = asyncio.run(srv.nxc_exec("10.0.0.5", "u", "p", "rm -rf /"))
    assert out["blocked"] is True
    assert "GUARDRAIL" in out["error"]


def test_nxc_exec_runs_with_authorization(monkeypatch):
    monkeypatch.setattr(settings, "ad_state_change_authorized", True)
    _tools_present(monkeypatch, stdout="nt authority\\system")
    out = asyncio.run(srv.nxc_exec("10.0.0.5", "u", "p", "whoami"))
    assert out["exit_code"] == 0


# ── BloodHound CE attack path ────────────────────────────────────────────────────

def test_bh_shortest_path_records_path(monkeypatch):
    monkeypatch.setattr(srv, "_bhce_request",
                        lambda path, payload: {"data": {"nodes": {
                            "1": {"label": "J.DOE@ACME.CO.KE"}, "2": {"label": "DC01$"}}}})
    out = asyncio.run(srv.bh_shortest_path(goal="Domain Admins"))
    assert out["length"] == 2
    assert "DC01$" in out["path"]


def test_bh_shortest_path_degraded_when_bhce_down(monkeypatch):
    monkeypatch.setattr(srv, "_bhce_request", lambda path, payload: {"_degraded": "refused"})
    out = asyncio.run(srv.bh_shortest_path())
    assert out.get("degraded") is True


# ── Graceful degradation ─────────────────────────────────────────────────────────

def test_nxc_enum_degrades_when_binary_absent(monkeypatch):
    monkeypatch.setattr(srv, "_which", lambda b: None)
    out = asyncio.run(srv.nxc_enum("10.0.0.5", username="a", password="b"))
    assert out.get("degraded") is True


def test_bh_collect_scope_then_degrade(monkeypatch):
    monkeypatch.setattr(srv, "_which", lambda b: None)
    # in scope but tool absent → degraded (not blocked)
    out = asyncio.run(srv.bh_collect("ACME", "10.0.0.5", "u", "p"))
    assert out.get("degraded") is True
    # out of scope → blocked before the tool check
    assert asyncio.run(srv.bh_collect("ACME", "8.8.8.8", "u", "p"))["blocked"] is True


def test_build_server_constructs():
    if not srv._mcp_available():
        pytest.skip("mcp SDK not installed")
    assert srv.build_server() is not None
