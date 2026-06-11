"""Tests for the Validation Agent (C2) — fully offline (re-test mocked)."""

import asyncio

import agents.validation_agent as va
from agents.validation_agent import ValidationAgent
from core.finding_state import finding_state


def test_constructs_and_never_approves():
    agent = ValidationAgent()
    names = {t["name"] for t in agent.TOOLS}
    assert names == set(agent._tool_map())
    # The validation agent has NO approve/confirm-by-fiat tool — confirmation is
    # decided by the deterministic re-test, approval is a human action.
    assert "approve" not in names


def test_revalidate_confirms_reproduced(monkeypatch):
    sig = finding_state.register_candidate({
        "target": "10.0.0.5", "title": "VA reproduced case", "severity": "high",
        "url": "https://10.0.0.5/va1", "template": "t-va-1",
    })

    async def fake_retest(finding):
        return {"reproduced": True, "method": "nuclei", "evidence": "hit",
                "grade": {"confidence": 0.9, "verdict": "validated", "issues": []},
                "verdict": "validated", "confidence": 0.9}

    monkeypatch.setattr(va, "retest", fake_retest)
    out = asyncio.run(ValidationAgent()._revalidate(sig))
    assert out["promoted"] is True
    assert out["state"] == "confirmed"
    assert finding_state.get(sig)["state"] == "confirmed"


def test_revalidate_leaves_unreproduced_as_candidate(monkeypatch):
    sig = finding_state.register_candidate({
        "target": "10.0.0.5", "title": "VA unreproduced case", "severity": "medium",
        "url": "https://10.0.0.5/va2",
    })

    async def fake_retest(finding):
        return {"reproduced": False, "method": "http", "evidence": "absent",
                "grade": {"confidence": 0.4, "verdict": "needs-review", "issues": []},
                "verdict": "needs-review", "confidence": 0.4}

    monkeypatch.setattr(va, "retest", fake_retest)
    out = asyncio.run(ValidationAgent()._revalidate(sig))
    assert out["promoted"] is False
    assert finding_state.get(sig)["state"] == "candidate"


def test_revalidate_unknown_signature():
    out = asyncio.run(ValidationAgent()._revalidate("nope"))
    assert "error" in out


def test_list_and_summary():
    agent = ValidationAgent()
    assert "candidates" in agent._list_candidates()
    assert "by_state" in agent._validation_summary()
