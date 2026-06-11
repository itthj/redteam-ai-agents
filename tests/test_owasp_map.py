"""Tests for the OWASP Top 10 / WSTG mapping (C1) — fully offline."""

from core.owasp_map import OWASP_2021, classify


def test_cwe_takes_priority_and_maps_correctly():
    # SQLi by CWE → A03 Injection
    res = classify(alert_name="something vague", cwe="89")
    assert res["owasp_id"] == "A03"
    assert res["wstg"] == "WSTG-INPV-05"


def test_cwe_accepts_prefixed_form():
    assert classify(cwe="CWE-79")["owasp_id"] == "A03"   # XSS
    assert classify(cwe=918)["owasp_id"] == "A10"        # SSRF (int form)


def test_alert_name_substring_match():
    assert classify(alert_name="Reflected Cross Site Scripting")["owasp_id"] == "A03"
    assert classify(alert_name="Missing Security Header")["owasp_id"] == "A05"
    assert classify(alert_name="Path Traversal")["owasp_id"] == "A01"


def test_tags_match():
    assert classify(tags=["cve", "rce"])["owasp_id"] == "A03"
    assert classify(tags="ssrf")["owasp_id"] == "A10"


def test_unknown_falls_back_to_a04_unmapped():
    res = classify(alert_name="completely novel issue with no keywords")
    assert res["owasp_id"] == "A04"
    assert res["wstg"] == "unmapped"


def test_every_result_has_human_name():
    for cwe in ("89", "79", "22", "918", None):
        res = classify(alert_name="x", cwe=cwe)
        assert res["owasp"] in OWASP_2021.values()
