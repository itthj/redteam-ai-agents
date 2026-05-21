"""Tests for the MITRE ATT&CK knowledge module."""

from core.attack_framework import TACTICS, attack


def test_map_action_finds_technique():
    matches = attack.map_action("ran an nmap port scan against the host")
    ids = [m["technique_id"] for m in matches]
    assert "T1595" in ids  # Active Scanning


def test_map_credential_dumping():
    matches = attack.map_action("used mimikatz to dump lsass credentials")
    ids = [m["technique_id"] for m in matches]
    assert "T1003" in ids  # OS Credential Dumping


def test_map_returns_tactic():
    matches = attack.map_action("brute force the ssh login")
    assert matches
    assert matches[0]["tactic"] in TACTICS


def test_unknown_action_returns_empty():
    assert attack.map_action("had a pleasant lunch break") == []


def test_get_technique_by_id():
    t = attack.get("T1046")
    assert t is not None
    assert t.name == "Network Service Discovery"


def test_coverage_report():
    actions = [
        "nmap active scan of the subnet",
        "sudo privilege escalation via misconfigured sudoers",
        "smb lateral movement with psexec",
    ]
    cov = attack.coverage(actions)
    assert cov["technique_count"] >= 3
    assert "Reconnaissance" in cov["tactics_covered"]
    assert "Privilege Escalation" in cov["tactics_covered"]
    assert "Lateral Movement" in cov["tactics_covered"]
    assert cov["tactics_total"] == 14


def test_navigator_layer_shape():
    layer = attack.navigator_layer(["nmap scan", "mimikatz dump"], name="Test")
    assert layer["name"] == "Test"
    assert layer["domain"] == "enterprise-attack"
    assert len(layer["techniques"]) >= 2
