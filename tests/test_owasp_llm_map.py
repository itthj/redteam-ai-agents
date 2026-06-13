"""Tests for the OWASP Top 10 for LLM Apps mapping (C8) — offline."""

from core.owasp_llm_map import OWASP_LLM_2025, classify


def test_prompt_injection_is_llm01():
    assert classify(probe="promptinject")["llm_id"] == "LLM01"
    assert classify(probe="dan.Dan_11_0")["llm_id"] == "LLM01"


def test_system_prompt_leak_is_llm07():
    assert classify(probe="leakreplay", category="system prompt")["llm_id"] == "LLM07"


def test_output_handling_is_llm05():
    assert classify(probe="xss", category="markdown")["llm_id"] == "LLM05"


def test_fallback_is_llm01():
    res = classify(probe="totally-unknown-probe")
    assert res["llm_id"] == "LLM01"
    assert res["llm"] in OWASP_LLM_2025.values()
