"""
Tests for the deterministic finding validator (anti-hallucination). Fully offline,
no model call — pure grading of findings against KB/evidence facts.
"""

from agents.reporting_agent import ReportingAgent
from core.finding_validator import finding_validator

_OPEN = [{"port": 22, "state": "open"}, {"port": 80, "state": "open"}]
_EV = [{"target": "10.0.0.5", "action": "vuln_scan",
        "result": "CVE-2021-1234 found on port 22", "severity": "high"}]


def test_grounded_finding_is_validated():
    f = {"severity": "high", "cve": "CVE-2021-1234", "port": 22, "description": "OpenSSH RCE"}
    r = finding_validator.validate(f, open_ports=_OPEN, target_evidence=_EV)
    assert r["verdict"] == "validated"
    assert r["confidence"] >= 0.9
    assert r["issues"] == []


def test_port_not_open_is_flagged():
    f = {"severity": "high", "cve": "CVE-2021-1234", "port": 8443, "description": "x"}
    r = finding_validator.validate(f, open_ports=_OPEN, target_evidence=_EV)
    assert any("not among scanned" in i for i in r["issues"])
    assert r["confidence"] < 0.7


def test_malformed_cve_is_flagged():
    f = {"severity": "medium", "cve": "CVE-bogus", "port": 80, "description": "x"}
    r = finding_validator.validate(f, open_ports=_OPEN, target_evidence=_EV)
    assert any("malformed CVE" in i for i in r["issues"])


def test_high_severity_without_cve_is_flagged():
    f = {"severity": "critical", "port": 22, "description": "x"}
    r = finding_validator.validate(f, open_ports=_OPEN, target_evidence=_EV)
    assert any("cites no CVE" in i for i in r["issues"])


def test_no_evidence_is_flagged():
    f = {"severity": "low", "cve": "CVE-2020-1111", "port": 22, "description": "x"}
    r = finding_validator.validate(f, open_ports=_OPEN, target_evidence=[])
    assert any("no evidence records" in i for i in r["issues"])
    assert r["confidence"] < 1.0


def test_unknown_severity_is_flagged():
    f = {"severity": "spicy", "cve": "CVE-2020-1111", "port": 22, "description": "x"}
    r = finding_validator.validate(f, open_ports=_OPEN, target_evidence=_EV)
    assert any("unknown severity" in i for i in r["issues"])


def test_cve_not_in_evidence_is_flagged():
    f = {"severity": "medium", "cve": "CVE-1999-9999", "port": 22, "description": "x"}
    r = finding_validator.validate(f, open_ports=_OPEN, target_evidence=_EV)
    assert any("not referenced in any evidence" in i for i in r["issues"])


def test_validate_all_summary():
    targets = {
        "10.0.0.5": {
            "open_ports": _OPEN,
            "vulnerabilities": [
                {"severity": "high", "cve": "CVE-2021-1234", "port": 22, "description": "real"},
                {"severity": "critical", "cve": "CVE-bogus", "port": 9999, "description": "halluc"},
            ],
        },
    }
    out = finding_validator.validate_all(targets, _EV)
    assert out["total_findings"] == 2
    assert out["by_verdict"]["validated"] == 1
    assert len(out["flagged"]) == 1
    assert out["flagged"][0]["port"] == 9999
    assert 0 <= out["validated_pct"] <= 100


def test_validate_all_empty_is_clean():
    out = finding_validator.validate_all({}, [])
    assert out["total_findings"] == 0
    assert out["validated_pct"] == 100.0


def test_reporting_agent_validate_tool_shape():
    out = ReportingAgent()._validate_findings()
    assert {"total_findings", "by_verdict", "validated_pct", "flagged", "results"} <= out.keys()
