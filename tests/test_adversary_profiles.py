"""Tests for named-adversary emulation (2D) — fully offline."""

from config.settings import settings
from core.adversary_profiles import get_profile, list_profiles
from core.attack_framework import attack


def test_get_profile_by_name_and_id():
    assert get_profile("APT29").group_id == "G0016"
    assert get_profile("g0016").name == "APT29"
    assert get_profile("") is None
    assert get_profile("nope") is None


def test_list_profiles():
    rows = list_profiles()
    assert any(r["name"] == "APT29" for r in rows)
    assert all(r["techniques"] > 0 for r in rows)


def test_map_action_reranks_to_profile():
    # "password spray" gives T1110 more keyword hits than T1486, but Lazarus has
    # T1486 (not T1110), so the profile technique is ranked first regardless.
    res = attack.map_action("data encrypted and password spray",
                            active_profile=get_profile("Lazarus"))
    assert res[0]["technique_id"] == "T1486"        # in-profile wins over raw hits
    assert res[0]["in_profile"] is True
    assert any(r["technique_id"] == "T1110" and r["in_profile"] is False for r in res)


def test_map_action_unchanged_without_profile():
    res = attack.map_action("nmap port scan")
    assert res and "in_profile" not in res[0]        # output shape unchanged


def test_playbook_includes_actor(monkeypatch):
    from agents.phase_agents import PhaseAgent
    monkeypatch.setattr(settings, "engagement_actor", "APT29")
    pb = PhaseAgent("credential_access")._get_playbook()
    assert pb["emulating_actor"] == "APT29"
    assert pb["actor_preferred_tools"]


def test_off_profile_finding_logged(monkeypatch):
    from agents.phase_agents import PhaseAgent
    from core.evidence_store import evidence
    monkeypatch.setattr(settings, "engagement_actor", "APT29")
    PhaseAgent("credential_access")._record_finding(
        "10.0.0.5", "did a thing", technique="T1486")   # T1486 not in APT29
    assert any(r["operation"] == "off_profile_technique" for r in evidence.get_all())


def test_first_message_injects_actor_notes(monkeypatch):
    from core.base_agent import BaseAgent
    monkeypatch.setattr(settings, "engagement_actor", "APT29")
    msg = BaseAgent()._build_first_message("do recon", None)
    assert "APT29" in msg and "G0016" in msg


def test_no_actor_no_injection(monkeypatch):
    from core.base_agent import BaseAgent
    monkeypatch.setattr(settings, "engagement_actor", "")
    msg = BaseAgent()._build_first_message("do recon", None)
    assert "Adversary emulation" not in msg
