"""
Tests for the attack graph (2A) — networkx backend, fully offline.

Neo4j is never touched (no driver, no server): these exercise the in-process
computation engine, the KnowledgeBase sink, and graceful degradation.
"""

import pytest

import core.attack_graph as ag
from core.attack_graph import AttackGraph
from core.knowledge_base import kb


def _g():
    return AttackGraph(backend="networkx")


# ── backend / writes ────────────────────────────────────────────────────────────

def test_default_backend_is_networkx():
    g = _g()
    assert g.backend == "networkx"
    assert g.stats()["neo4j_mirror"] is False


def test_upsert_service_creates_host_and_service():
    g = _g()
    g.upsert_service("10.0.0.5", 22, product="OpenSSH", version="8.2")
    kinds = g.stats()["by_kind"]
    assert kinds.get("host") == 1
    assert kinds.get("service") == 1


def test_add_vuln_makes_service_high_value():
    g = _g()
    g.upsert_service("10.0.0.5", 80, product="nginx")
    g.add_vuln("10.0.0.5", "CVE-2021-1234", 9.8, port=80)
    hv = g.high_value_unexploited()
    assert len(hv) == 1
    assert hv[0]["ip"] == "10.0.0.5"
    assert hv[0]["port"] == 80
    assert hv[0]["max_cvss"] == 9.8


def test_session_excludes_host_from_high_value():
    g = _g()
    g.upsert_service("10.0.0.5", 80)
    g.add_vuln("10.0.0.5", "CVE-1", 7.5, port=80)
    assert g.high_value_unexploited()            # present before a foothold
    g.add_session("10.0.0.5")
    assert g.high_value_unexploited() == []       # owned → no longer "unexploited"


def test_reachable_unowned_hosts():
    g = _g()
    g.upsert_host("10.0.0.5")
    g.upsert_host("10.0.0.9")
    g.add_session("10.0.0.5")
    assert g.reachable_unowned_hosts() == ["10.0.0.9"]


# ── shortest path ────────────────────────────────────────────────────────────────

def test_shortest_path_to_domain_admin_on_seeded_fixture():
    g = _g()
    g.add_session("10.0.0.5")                                  # foothold
    g.link_pivot("10.0.0.5", "10.0.0.9", via="smb")            # reach 10.0.0.9
    g.add_credential({"username": "administrator", "domain_admin": True}, "10.0.0.9")
    path = g.shortest_path_to("domain_admin")
    assert path is not None
    assert path[0] == "session:10.0.0.5"
    assert path[-1] == "goal:domain_admin"


def test_shortest_path_none_when_no_goal():
    g = _g()
    g.add_session("10.0.0.5")
    assert g.shortest_path_to("domain_admin") is None


def test_shortest_path_none_without_foothold():
    g = _g()
    g.add_credential({"username": "admin", "domain_admin": True}, "10.0.0.9")
    assert g.shortest_path_to("domain_admin") is None         # goal exists, no session


# ── on_kb_event + KB sink ────────────────────────────────────────────────────────

def test_on_kb_event_dispatch():
    g = _g()
    g.on_kb_event("service_added",
                  {"ip": "10.0.0.7", "port": 443, "info": {"product": "Apache"}})
    g.on_kb_event("vuln_added",
                  {"ip": "10.0.0.7", "vuln": {"cve": "CVE-2", "cvss": 8.1, "port": 443}})
    hv = g.high_value_unexploited()
    assert hv and hv[0]["ip"] == "10.0.0.7"
    assert hv[0]["service"] == "Apache"


def test_kb_sink_mirrors_writes():
    g = _g()
    saved = list(kb._sinks)
    kb.attach_sink(g.on_kb_event)
    try:
        ip = "172.31.7.250"                       # unique IP → no cross-test bleed
        kb.add_port(ip, 445, "tcp")
        kb.add_service(ip, 445, {"product": "Samba", "version": "4.10"})
        kb.add_vulnerability(ip, {"cve": "CVE-2017-7494", "cvss": 9.8, "port": 445})
        hv = [r for r in g.high_value_unexploited() if r["ip"] == ip]
        assert len(hv) == 1
        assert hv[0]["port"] == 445
        assert hv[0]["max_cvss"] == 9.8
    finally:
        kb._sinks = saved                         # restore — never leak the sink


# ── named queries ────────────────────────────────────────────────────────────────

def test_named_query_dispatch():
    g = _g()
    g.upsert_service("10.0.0.5", 80)
    g.add_vuln("10.0.0.5", "CVE-1", 9.0, port=80)
    assert g.query("high_value_unexploited") == g.high_value_unexploited()
    assert g.query("reachable_unowned_hosts") == g.reachable_unowned_hosts()


def test_unknown_named_query_raises():
    g = _g()
    with pytest.raises(ValueError):
        g.query("DROP DATABASE")


# ── graceful degradation ─────────────────────────────────────────────────────────

def test_disabled_when_networkx_missing(monkeypatch):
    monkeypatch.setattr(ag, "_NX", None)
    g = AttackGraph()
    assert g.backend == "disabled"
    g.upsert_service("10.0.0.5", 80)              # all no-ops, must not raise
    g.add_vuln("10.0.0.5", "CVE-1", 9.0, port=80)
    g.add_session("10.0.0.5")
    assert g.high_value_unexploited() == []
    assert g.reachable_unowned_hosts() == []
    assert g.shortest_path_to("domain_admin") is None
    assert g.stats()["backend"] == "disabled"
