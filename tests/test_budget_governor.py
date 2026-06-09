"""
Tests for the budget governor (5A).

Covers the telemetry budget math and the BaseAgent.run per-turn gate in both
modes (downgrade / halt), plus the orchestrator status surface. Fully offline:
the model client is never called — `_stream_turn` is patched and usage is faked.
"""

import asyncio
from types import SimpleNamespace

from config.settings import settings
from core.base_agent import BaseAgent
from core.orchestrator import OrchestratorAgent
from core.telemetry import telemetry


def _usage(inp=0, out=0):
    """Minimal stand-in for an Anthropic SDK Usage object."""
    return SimpleNamespace(
        input_tokens=inp,
        output_tokens=out,
        cache_creation_input_tokens=0,
        cache_read_input_tokens=0,
    )


def _spend_half_a_dollar():
    """100k Opus input tokens = $0.50 at $5/M (claude-opus-4-7 is priced)."""
    telemetry.record("seed", "claude-opus-4-7", _usage(100_000, 0))


# ── telemetry budget math ──────────────────────────────────────────────────────

def test_no_budget_means_unlimited(monkeypatch):
    telemetry.reset()
    monkeypatch.setattr(settings, "engagement_budget_usd", 0.0)
    _spend_half_a_dollar()
    assert telemetry.budget_remaining() is None   # None signals "no ceiling"
    assert telemetry.over_budget() is False


def test_budget_remaining_tracks_spend(monkeypatch):
    telemetry.reset()
    monkeypatch.setattr(settings, "engagement_budget_usd", 1.0)
    _spend_half_a_dollar()
    assert abs(telemetry.total_cost() - 0.50) < 1e-6
    assert abs(telemetry.budget_remaining() - 0.50) < 1e-6
    assert telemetry.over_budget() is False


def test_over_budget_trips_when_exceeded(monkeypatch):
    telemetry.reset()
    monkeypatch.setattr(settings, "engagement_budget_usd", 0.01)
    _spend_half_a_dollar()                          # $0.50 >> $0.01
    assert telemetry.over_budget() is True
    assert telemetry.budget_remaining() < 0


# ── BaseAgent.run budget gate ──────────────────────────────────────────────────

def _fake_turn(text="done"):
    return SimpleNamespace(
        usage=_usage(1, 1),
        content=[SimpleNamespace(type="text", text=text)],
        stop_reason="end_turn",
    )


def test_run_halts_when_over_budget(monkeypatch):
    telemetry.reset()
    monkeypatch.setattr(settings, "engagement_budget_usd", 0.01)
    monkeypatch.setattr(settings, "on_budget_exceeded", "halt")
    _spend_half_a_dollar()                          # already over budget

    agent = BaseAgent()
    calls = {"n": 0}

    async def _never(*args, **kwargs):
        calls["n"] += 1
        return _fake_turn()

    monkeypatch.setattr(agent, "_stream_turn", _never)

    out = asyncio.run(agent.run("do something"))
    assert "halted" in out.lower()
    assert calls["n"] == 0                          # not a single model turn was made


def test_run_downgrades_when_over_budget(monkeypatch):
    telemetry.reset()
    monkeypatch.setattr(settings, "engagement_budget_usd", 0.01)
    monkeypatch.setattr(settings, "on_budget_exceeded", "downgrade")
    _spend_half_a_dollar()

    agent = BaseAgent()
    assert agent._model == settings.claude_model    # starts on Opus

    async def _ok(*args, **kwargs):
        return _fake_turn()

    monkeypatch.setattr(agent, "_stream_turn", _ok)

    out = asyncio.run(agent.run("do something"))
    assert agent._model == settings.claude_fast_model   # downgraded to Haiku
    assert agent._effort == "low"
    assert agent._downgraded is True
    assert "done" in out                            # the run still completed


def test_run_is_unaffected_when_no_budget(monkeypatch):
    telemetry.reset()
    monkeypatch.setattr(settings, "engagement_budget_usd", 0.0)
    _spend_half_a_dollar()

    agent = BaseAgent()

    async def _ok(*args, **kwargs):
        return _fake_turn()

    monkeypatch.setattr(agent, "_stream_turn", _ok)

    out = asyncio.run(agent.run("do something"))
    assert agent._model == settings.claude_model    # never downgraded
    assert agent._downgraded is False
    assert "done" in out


# ── orchestrator status surface ────────────────────────────────────────────────

def test_orchestrator_status_includes_budget(monkeypatch):
    telemetry.reset()
    monkeypatch.setattr(settings, "engagement_budget_usd", 2.0)
    agent = OrchestratorAgent(get_agent=lambda name: None)

    status = agent._get_status()
    assert "budget" in status
    assert status["budget"]["limit_usd"] == 2.0
    assert status["budget"]["remaining_usd"] == 2.0     # nothing spent after reset
    assert status["budget"]["over_budget"] is False
