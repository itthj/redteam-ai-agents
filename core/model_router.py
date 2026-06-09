"""
core/model_router.py
─────────────────────
Cost-aware model routing (workstream 5A).

The system runs on Claude Opus for high-stakes reasoning (planning, exploit
decisions), but most of an engagement is mechanical: parsing an nmap dump,
summarising a scan, classifying a banner. Paying Opus prices for that is waste.
The router maps a *task class* to the right (model, effort) pair so cheap work
runs on the fast model (Haiku) and only the decisions that matter run on Opus.

It is deliberately tiny and policy-only. It reads model names from `settings`
at call time, so an operator's CLAUDE_MODEL / CLAUDE_FAST_MODEL overrides apply,
and returns a (model, effort) tuple. Callers decide how to use it; today the
tool-output compression path in BaseAgent is its first consumer, and the
debate / distill / report steps in later workstreams reuse it.
"""

from __future__ import annotations

from config.settings import settings

# Tiers: "heavy" → Opus (settings.claude_model), "fast" → Haiku
# (settings.claude_fast_model). Effort follows the project's scale:
# low | medium | high | xhigh | max.
_HEAVY = "heavy"
_FAST = "fast"

_POLICY: dict[str, tuple[str, str]] = {
    # High-stakes reasoning — worth Opus.
    "planning":         (_HEAVY, "xhigh"),
    "exploit_decision": (_HEAVY, "high"),
    # Mechanical text work — Haiku is plenty.
    "parse":            (_FAST,  "low"),
    "summarize":        (_FAST,  "low"),
    "classify":         (_FAST,  "low"),
}


class ModelRouter:
    """Maps a task class to the (model, effort) that should handle it."""

    def pick(self, task_class: str) -> tuple[str, str]:
        """
        Return (model, effort) for ``task_class``.

        Unknown classes fall back to the default agent model/effort — the safe,
        unsurprising choice (an unrecognised task is never silently downgraded
        to the cheap model).
        """
        tier, effort = _POLICY.get(task_class, (None, None))
        if tier == _HEAVY:
            return settings.claude_model, effort
        if tier == _FAST:
            return settings.claude_fast_model, effort
        return settings.claude_model, settings.agent_effort


# Module-level singleton — mirrors kb / telemetry / guardrails.
router = ModelRouter()
