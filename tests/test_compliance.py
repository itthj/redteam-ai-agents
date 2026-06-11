"""Tests for compliance-mapped reporting + retest tracking (5F + C3) — fully offline."""

from core.compliance import (
    ATTACK_TO_CBK,
    ATTACK_TO_ISO27001,
    ATTACK_TO_KDPA,
    ATTACK_TO_NIST,
    FRAMEWORKS,
    FindingsLedger,
    compliance_appendix,
    finding_signature,
    map_finding,
    rollup,
)


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


# ── C3: ISO 27001 / CBK / Kenya DPA mapping + compliance appendix ────────────────

def test_map_finding_includes_new_frameworks():
    m = map_finding("T1190")
    assert "A.8.8" in m["iso_27001"]      # exploit public-facing → ISO Annex A.8.8
    assert m["cbk"] == ["CBK-PR"]          # Protect function
    assert "s.41" in m["kenya_dpa"]        # technical & organisational measures duty


def test_kdpa_data_exposure_maps_to_breach_section():
    assert "s.43" in map_finding("T1041")["kenya_dpa"]   # exfiltration → breach notification
    assert "s.43" in map_finding("T1486")["kenya_dpa"]   # impact/availability


def test_every_mapped_technique_covers_all_named_frameworks():
    # Full coverage (decision: full compliance) — every technique we score for NIST is
    # also mapped to ISO 27001, CBK, and Kenya DPA.
    base = set(ATTACK_TO_NIST)
    assert base <= set(ATTACK_TO_ISO27001)
    assert base <= set(ATTACK_TO_CBK)
    assert base <= set(ATTACK_TO_KDPA)


def test_rollup_includes_all_frameworks():
    r = rollup(["T1078", "T1190", "T1041"])
    for fw in FRAMEWORKS:
        assert fw in r
    assert r["iso_27001"]          # non-empty


def test_compliance_appendix_builds_rows_and_rollup():
    findings = [
        {"target": "10.0.0.5", "technique": "T1190", "severity": "high", "cvss": 9.1},
        {"target": "10.0.0.6", "technique": "T1041", "severity": "high", "cvss": 7.5},
    ]
    app = compliance_appendix(findings)
    assert app["frameworks"] == list(FRAMEWORKS)
    assert len(app["rows"]) == 2
    assert "Exploitation" in app["ptes_phases"]
    assert any("A.8.8" in row["iso_27001"] for row in app["rows"])
    assert "techniques" in app["rollup"]


def test_reporting_compliance_appendix_tool():
    from agents.reporting_agent import ReportingAgent
    from core.knowledge_base import kb

    kb.add_vulnerability("172.31.9.10", {"cve": "CVE-2024-2", "cvss": 8.1,
                                         "severity": "high", "port": 443,
                                         "technique": "T1190"})
    out = ReportingAgent()._compliance_appendix()
    assert "kenya_dpa" in out["frameworks"]
    assert out["rows"]
    assert any("A.8.8" in r["iso_27001"] for r in out["rows"])
