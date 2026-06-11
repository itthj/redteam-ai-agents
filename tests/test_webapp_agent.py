"""Tests for the Web Application Testing agent (C1) — fully offline."""

from agents.webapp_agent import WebAppAgent
from core.evidence_store import evidence
from core.knowledge_base import kb
from core.orchestrator import _ALL_AGENTS, _DEEP_AGENTS


def test_agent_constructs_and_tool_map_complete():
    agent = WebAppAgent()
    assert agent.NAME == "webapp"
    tool_names = {t["name"] for t in agent.TOOLS}
    assert tool_names == set(agent._tool_map())
    assert "record_web_finding" in tool_names


def test_webapp_in_orchestrator_roster():
    assert "webapp" in _DEEP_AGENTS
    assert "webapp" in _ALL_AGENTS


def test_record_finding_writes_candidate_with_owasp_mapping():
    agent = WebAppAgent()
    res = agent._record_web_finding(
        target="appc1.lab.internal",
        title="Reflected XSS in search box",
        severity="high",
        cwe="79",
        url="https://appc1.lab.internal/search?q=x",
        proof="<script>alert(1)</script> reflected",
    )
    assert res["recorded"] is True
    assert res["state"] == "candidate"
    assert res["owasp"] == "A03"

    # KB has the vuln, mapped to OWASP, with no breaking schema change
    target = kb.get_target("appc1.lab.internal")
    assert target is not None
    vulns = target["vulnerabilities"]
    assert any(v.get("owasp_id") == "A03" and v.get("title", "").startswith("Reflected XSS")
               for v in vulns)

    # Evidence chain recorded the candidate finding
    recs = [r for r in evidence.get_all(target="appc1.lab.internal")
            if r["operation"] == "web_finding"]
    assert recs and "[candidate]" in recs[-1]["action"]


def test_record_finding_maps_by_title_when_no_cwe():
    agent = WebAppAgent()
    res = agent._record_web_finding(
        target="appc2.lab.internal",
        title="Missing Content Security Policy header",
        severity="low",
    )
    assert res["owasp"] == "A05"
