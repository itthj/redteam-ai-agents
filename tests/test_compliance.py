"""Tests for compliance-mapped reporting + retest tracking (5F) — fully offline."""

from core.compliance import FindingsLedger, finding_signature, map_finding, rollup


def test_map_finding():
    m = map_finding("T1110")
    assert "AC-7" in m["nist_800_53"]
    assert m["pci_dss"]                          # has a PCI requirement
    assert "AC-17" in map_finding("T1021.001")["nist_800_53"]   # sub-technique → base
    assert map_finding("T9999")["nist_800_53"] == []            # unknown → empty


def test_rollup_counts_by_family():
    r = rollup(["T1078", "T1078", "T1190"])
    assert r["techniques"] == 3
    assert r["nist_800_53"].get("AC-2") == 2     # T1078 twice → AC-2 x2
    assert "SI-2" in r["nist_800_53"]            # from T1190


def test_finding_signature_stable():
    a = finding_signature("10.0.0.5", 445, "CVE-1", "T1190")
    b = finding_signature("10.0.0.5", 445, "CVE-1", "T1190")
    c = finding_signature("10.0.0.5", 80, "CVE-1", "T1190")
    assert a == b and a != c


def test_ledger_diff_new_still_open_resolved(tmp_path):
    led = FindingsLedger(path=str(tmp_path / "ledger.json"))
    f1 = {"target": "10.0.0.5", "port": 445, "cve": "CVE-1", "technique": "T1190"}
    f2 = {"target": "10.0.0.5", "port": 80, "cve": "CVE-2", "technique": "T1190"}

    first = led.diff([f1, f2])
    assert len(first["new"]) == 2 and not first["still_open"] and not first["resolved"]

    second = led.diff([f2])                      # f1 fixed, f2 remains
    assert any(r["cve"] == "CVE-1" for r in second["resolved"])
    assert any(s["cve"] == "CVE-2" for s in second["still_open"])
    assert not second["new"]


def test_reporting_compliance_rollup_tool():
    from agents.reporting_agent import ReportingAgent
    from core.knowledge_base import kb

    kb.add_vulnerability("172.31.9.9", {"cve": "CVE-2024-1", "cvss": 9.0,
                                        "severity": "high", "port": 445,
                                        "technique": "T1190"})
    out = ReportingAgent()._compliance_rollup()
    assert out["findings"] >= 1
    assert "nist_800_53" in out["compliance"]
    assert "retest" in out
