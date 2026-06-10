"""Tests for the outbound agents-as-MCP server (5E) — fully offline."""

import asyncio

import pytest

import mcp_layer.redteam_mcp_server as srv
from config.authorization import OperationType, scope


def test_handlers_exposed():
    names = {h.__name__ for h in srv._HANDLERS}
    assert names == {"run_recon", "run_mission", "run_autonomous",
                     "get_findings", "get_evidence", "verify_chain"}


def test_run_recon_routes_through_orchestrator(monkeypatch):
    from core.orchestrator import Orchestrator
    captured = {}

    async def fake_dispatch(self, agent, task, context=None):
        captured["agent"], captured["task"] = agent, task
        return "recon-done"

    monkeypatch.setattr(Orchestrator, "dispatch", fake_dispatch)
    out = asyncio.run(srv.run_recon("10.0.0.5"))
    assert captured["agent"] == "recon"
    assert "10.0.0.5" in captured["task"]
    assert out["findings"] == "recon-done"


def test_read_handlers_offline():
    assert isinstance(srv.verify_chain()["chain_valid"], bool)
    assert "findings" in srv.get_findings()
    assert "records" in srv.get_evidence()


def test_out_of_scope_rejected_by_gate():
    # The MCP handlers route through Orchestrator/agents, which enforce this gate.
    assert scope.is_authorized("10.0.0.5", OperationType.ACTIVE_SCAN) is True
    assert scope.is_authorized("8.8.8.8", OperationType.ACTIVE_SCAN) is False


def test_build_server_constructs():
    if not srv._mcp_available():
        pytest.skip("mcp SDK not installed")
    assert srv.build_server() is not None
