"""
Tests for the graph-driven planner tools (2B) — fully offline.

Exercise query_attack_graph + next_best_action on the OrchestratorAgent, plus a
scripted integration run proving the planner delegates to a suggested action.
The model client is never called: `_stream_turn` is scripted, usage is faked.
"""

import asyncio
from types import SimpleNamespace

from core.attack_graph import graph
from core.orchestrator import OrchestratorAgent
from core.telemetry import telemetry


def _usage(inp=1, out=1):
    return SimpleNamespace(input_tokens=inp, output_tokens=out,
                           cache_creation_input_tokens=0, cache_read_input_tokens=0)


def _tool_use(name, inputs, bid):
    return SimpleNamespace(type="tool_use", name=name, input=inputs, id=bid)


def _resp(content, stop):
    return SimpleNamespace(usage=_usage(), content=content, stop_reason=stop)


def _orch():
    return OrchestratorAgent(get_agent=lambda name: None)


# ── tool surface ────────────────────────────────────────────────────────────────

def test_planner_exposes_graph_tools():
    orch = _orch()
    tool_names = {t["name"] for t in orch.TOOLS}
    assert {"query_attack_graph", "next_best_action"} <= tool_names
    tmap = orch._tool_map()
    assert "query_attack_graph" in tmap and "next_best_action" in tmap


def test_system_prompt_mentions_graph_tools():
    assert "next_best_action" in OrchestratorAgent.SYSTEM_PROMPT
    assert "query_attack_graph" in OrchestratorAgent.SYSTEM_PROMPT


# ── next_best_action ranking ────────────────────────────────────────────────────

def test_next_best_action_ranks_dominant_first():
    graph.reset()
    graph.upsert_service("10.0.0.5", 80, product="nginx")
    graph.add_vuln("10.0.0.5", "CVE-low", 4.0, port=80)
    graph.upsert_service("10.0.0.9", 445, product="smb")
    graph.add_vuln("10.0.0.9", "CVE-crit", 9.8, port=445)

    nba = _orch()._next_best_action()
    top = nba["suggestions"][0]
    assert top["agent"] == "exploit"
    assert top["target"] == "10.0.0.9"               # the 9.8, not the 4.0
    assert top["score"] >= nba["suggestions"][1]["score"]
    assert nba["count"] == len(nba["suggestions"])


def test_next_best_action_suggests_lateral_for_da_path():
    graph.reset()
    graph.add_session("10.0.0.5")
    graph.link_pivot("10.0.0.5", "10.0.0.9", via="smb")
    graph.add_credential({"username": "administrator", "domain_admin": True}, "10.0.0.9")

    suggestions = _orch()._next_best_action()["suggestions"]
    lateral = [s for s in suggestions if s["agent"] == "lateral_movement"]
    assert lateral
    assert lateral[0]["target"] == "10.0.0.9"
    assert lateral[0]["score"] == 0.9
    assert suggestions[0]["agent"] == "lateral_movement"   # outranks the scan frontier


# ── query_attack_graph routing ──────────────────────────────────────────────────

def test_query_attack_graph_path_question():
    graph.reset()
    graph.add_session("10.0.0.5")
    graph.link_pivot("10.0.0.5", "10.0.0.9", via="smb")
    graph.add_credential({"username": "administrator", "domain_admin": True}, "10.0.0.9")

    r = _orch()._query_attack_graph("what is the shortest path to domain admin?")
    path = r["shortest_path_to_domain_admin"]
    assert path[0] == "session:10.0.0.5"
    assert path[-1] == "goal:domain_admin"


def test_query_attack_graph_reach_question():
    graph.reset()
    graph.upsert_host("10.0.0.5")
    graph.upsert_host("10.0.0.9")
    graph.add_session("10.0.0.5")

    r = _orch()._query_attack_graph("which hosts are reachable but unowned?")
    assert r["reachable_unowned_hosts"] == ["10.0.0.9"]


# ── integration: the planner delegates to a suggested action ────────────────────

def test_orchestrator_delegates_to_suggested_action(monkeypatch):
    telemetry.reset()
    graph.reset()
    graph.upsert_service("10.0.0.9", 445, product="smb")
    graph.add_vuln("10.0.0.9", "CVE-2017-0144", 9.3, port=445)

    ran = {}

    class _Fake:
        async def run(self, task, context=None):
            ran["task"] = task
            return "sub-agent done"

    def get_agent(name):
        ran["agent"] = name
        return _Fake()

    orch = OrchestratorAgent(get_agent=get_agent)
    top = orch._next_best_action()["suggestions"][0]
    assert top["agent"] == "exploit" and top["target"] == "10.0.0.9"

    turns = iter([
        _resp([_tool_use("next_best_action", {}, "u1")], "tool_use"),
        _resp([_tool_use("delegate",
                         {"agent": top["agent"], "task": f"Exploit {top['target']} via SMB"},
                         "u2")], "tool_use"),
        _resp([SimpleNamespace(type="text", text="engagement complete")], "end_turn"),
    ])

    async def fake_stream(system, tools, messages):
        return next(turns)

    monkeypatch.setattr(orch, "_stream_turn", fake_stream)

    out = asyncio.run(orch.run("plan and execute"))
    assert ran["agent"] == "exploit"
    assert "10.0.0.9" in ran["task"]
    assert "complete" in out.lower()


# ── graceful: empty graph ────────────────────────────────────────────────────────

def test_graph_tools_safe_when_graph_empty():
    graph.reset()
    orch = _orch()
    assert orch._next_best_action() == {"suggestions": [], "count": 0}
    q = orch._query_attack_graph("give me a full picture")
    assert q["high_value_unexploited"] == []
    assert q["reachable_unowned_hosts"] == []
    assert q["shortest_path_to_domain_admin"] is None
