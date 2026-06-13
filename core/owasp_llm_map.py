"""
core/owasp_llm_map.py
──────────────────────
Map LLM red-team findings (garak probes / PyRIT scenarios) to the OWASP Top 10 for
LLM Applications (2025). Prompt injection is LLM01 — the headline risk.
"""

from __future__ import annotations

OWASP_LLM_2025: dict[str, str] = {
    "LLM01": "LLM01:2025 Prompt Injection",
    "LLM02": "LLM02:2025 Sensitive Information Disclosure",
    "LLM03": "LLM03:2025 Supply Chain",
    "LLM04": "LLM04:2025 Data and Model Poisoning",
    "LLM05": "LLM05:2025 Improper Output Handling",
    "LLM06": "LLM06:2025 Excessive Agency",
    "LLM07": "LLM07:2025 System Prompt Leakage",
    "LLM08": "LLM08:2025 Vector and Embedding Weaknesses",
    "LLM09": "LLM09:2025 Misinformation",
    "LLM10": "LLM10:2025 Unbounded Consumption",
}

# Lower-cased substring in a garak probe / detector / PyRIT scenario → LLM id.
_KEYWORD_TO_LLM: list[tuple[str, str]] = [
    ("promptinject", "LLM01"), ("injection", "LLM01"), ("latentinjection", "LLM01"),
    ("jailbreak", "LLM01"), ("dan", "LLM01"), ("encoding", "LLM01"),
    ("suffix", "LLM01"), ("grandma", "LLM01"), ("goodside", "LLM01"),
    ("systemprompt", "LLM07"), ("system prompt", "LLM07"), ("leakreplay", "LLM07"),
    ("promptleak", "LLM07"),
    ("pii", "LLM02"), ("privacy", "LLM02"), ("sensitive", "LLM02"), ("leak", "LLM02"),
    ("package", "LLM03"), ("hallucinatedpackage", "LLM03"), ("supply", "LLM03"),
    ("poison", "LLM04"),
    ("xss", "LLM05"), ("output", "LLM05"), ("markdown", "LLM05"), ("htmltag", "LLM05"),
    ("agency", "LLM06"), ("tool", "LLM06"), ("function", "LLM06"),
    ("embedding", "LLM08"), ("vector", "LLM08"), ("rag", "LLM08"),
    ("misinfo", "LLM09"), ("misleading", "LLM09"), ("hallucination", "LLM09"),
    ("snowball", "LLM09"), ("toxicity", "LLM09"),
    ("dos", "LLM10"), ("resource", "LLM10"), ("unbounded", "LLM10"), ("flood", "LLM10"),
]

_FALLBACK = "LLM01"   # garak/PyRIT findings are injection-flavored by default


def classify(probe: str | None = None, category: str | None = None) -> dict:
    """Classify an LLM finding into an OWASP LLM Top 10 (2025) category."""
    blob = " ".join(str(x).lower() for x in (probe, category) if x)
    for needle, llm_id in _KEYWORD_TO_LLM:
        if needle in blob:
            return {"llm_id": llm_id, "llm": OWASP_LLM_2025[llm_id]}
    return {"llm_id": _FALLBACK, "llm": OWASP_LLM_2025[_FALLBACK]}
