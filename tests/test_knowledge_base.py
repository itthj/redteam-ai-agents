"""Tests for the shared knowledge base."""

import json

from core.knowledge_base import kb


def test_ensure_target_creates_entry():
    t = kb.ensure_target("10.0.0.5")
    assert t["ip"] == "10.0.0.5"
    assert kb.get_target("10.0.0.5") is not None


def test_add_port_recorded():
    kb.add_port("10.0.0.5", 22, "tcp")
    t = kb.get_target("10.0.0.5")
    assert any(p["port"] == 22 for p in t["open_ports"])


def test_add_hostname_deduplicates():
    kb.add_hostname("10.0.0.5", "host.lab.internal")
    kb.add_hostname("10.0.0.5", "host.lab.internal")
    t = kb.get_target("10.0.0.5")
    assert t["hostnames"].count("host.lab.internal") == 1


def test_add_vulnerability_recorded():
    kb.add_vulnerability("10.0.0.5", {"cve": "CVE-2021-44228", "severity": "critical"})
    t = kb.get_target("10.0.0.5")
    assert any(v.get("cve") == "CVE-2021-44228" for v in t["vulnerabilities"])


def test_mission_state_roundtrip():
    kb.set_state("scanning")
    assert kb.get_state() == "scanning"


def test_snapshot_is_json_serializable():
    snapshot = kb.snapshot()
    json.dumps(snapshot, default=str)  # must not raise
    assert "targets" in snapshot
    assert "10.0.0.5" in snapshot["targets"]
