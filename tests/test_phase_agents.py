"""Tests for the Kali-aligned kill-chain phase agents."""

import pytest

from agents.phase_agents import KALI_PHASES, PhaseAgent, PhaseSpec, list_phases


def test_registry_has_eleven_phases():
    assert len(KALI_PHASES) == 11


def test_every_phase_well_formed():
    for _key, spec in KALI_PHASES.items():
        assert isinstance(spec, PhaseSpec)
        assert 1 <= spec.kali_no <= 15
        assert spec.name and spec.tactic and spec.mission
        assert spec.kali_tools  # non-empty tool list


def test_kali_numbers_unique():
    nums = [s.kali_no for s in KALI_PHASES.values()]
    assert len(nums) == len(set(nums))


def test_list_phases_sorted_by_kali_number():
    nums = [p["kali_no"] for p in list_phases()]
    assert nums == sorted(nums)


def test_phase_agent_instantiates():
    agent = PhaseAgent("privilege_escalation")
    assert agent.NAME == "privilege_escalation"
    assert "Privilege Escalation" in agent.SYSTEM_PROMPT
    assert len(agent.TOOLS) == 3


def test_unknown_phase_rejected():
    with pytest.raises(ValueError):
        PhaseAgent("nonsense_phase")


def test_get_playbook_returns_attack_data():
    pb = PhaseAgent("credential_access")._get_playbook()
    assert pb["attack_tactic"] == "Credential Access"
    assert pb["recommended_kali_tools"]
    assert "kali_category" in pb


def test_impact_phase_is_non_destructive():
    spec = KALI_PHASES["impact"]
    assert "WITHOUT executing any destructive action" in spec.mission
