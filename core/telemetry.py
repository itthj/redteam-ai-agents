"""
core/telemetry.py
──────────────────
Token-usage, cost, and cache-efficiency tracking across the engagement.

Every Claude API call routes its `usage` object through here so the
operator can see — per agent and in total — how many tokens were spent,
how well prompt caching is working, and the running dollar cost.

Pricing reference (USD per 1M tokens, cached 2026-05):
    claude-opus-4-7    input $5.00   output $25.00
    claude-haiku-4-5   input $1.00   output $5.00
Cache writes cost 1.25x base input; cache reads cost 0.1x base input.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from config.settings import settings

log = logging.getLogger(__name__)

# Base input / output price per 1M tokens
_PRICING: dict[str, tuple[float, float]] = {
    "claude-opus-4-7": (5.00, 25.00),
    "claude-opus-4-6": (5.00, 25.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
}
_DEFAULT_PRICE = (5.00, 25.00)  # assume Opus if unknown


@dataclass
class AgentUsage:
    """Accumulated usage for one agent."""

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0
    cost_usd: float = 0.0
    models: set[str] = field(default_factory=set)

    @property
    def cache_hit_rate(self) -> float:
        """Fraction of cacheable input served from cache."""
        cacheable = self.input_tokens + self.cache_write_tokens + self.cache_read_tokens
        return (self.cache_read_tokens / cacheable) if cacheable else 0.0


class Telemetry:
    """Thread-safe usage + cost tracker."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_agent: dict[str, AgentUsage] = defaultdict(AgentUsage)
        self._started = time.time()

    # ── Recording ─────────────────────────────────────────────────────────────

    def record(self, agent: str, model: str, usage: object) -> float:
        """
        Record one API call's usage. `usage` is an Anthropic SDK Usage object.
        Returns the cost of this single call in USD.
        """
        in_tok = getattr(usage, "input_tokens", 0) or 0
        out_tok = getattr(usage, "output_tokens", 0) or 0
        cache_write = getattr(usage, "cache_creation_input_tokens", 0) or 0
        cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0

        in_price, out_price = _PRICING.get(model, _DEFAULT_PRICE)
        call_cost = (
            in_tok / 1_000_000 * in_price
            + out_tok / 1_000_000 * out_price
            + cache_write / 1_000_000 * in_price * 1.25
            + cache_read / 1_000_000 * in_price * 0.10
        )

        with self._lock:
            u = self._by_agent[agent]
            u.calls += 1
            u.input_tokens += in_tok
            u.output_tokens += out_tok
            u.cache_write_tokens += cache_write
            u.cache_read_tokens += cache_read
            u.cost_usd += call_cost
            u.models.add(model)

        log.debug(
            "[TELEMETRY] %s: +%d in / +%d out / cache r%d w%d → $%.4f",
            agent, in_tok, out_tok, cache_read, cache_write, call_cost,
        )
        return call_cost

    # ── Reporting ─────────────────────────────────────────────────────────────

    def agent_summary(self, agent: str) -> dict:
        with self._lock:
            u = self._by_agent.get(agent)
            if not u:
                return {}
            return self._fmt(agent, u)

    def summary(self) -> dict:
        """Full engagement telemetry snapshot."""
        with self._lock:
            agents = {name: self._fmt(name, u) for name, u in self._by_agent.items()}
            total = AgentUsage()
            for u in self._by_agent.values():
                total.calls += u.calls
                total.input_tokens += u.input_tokens
                total.output_tokens += u.output_tokens
                total.cache_write_tokens += u.cache_write_tokens
                total.cache_read_tokens += u.cache_read_tokens
                total.cost_usd += u.cost_usd
            return {
                "elapsed_seconds": round(time.time() - self._started, 1),
                "total": self._fmt("TOTAL", total),
                "by_agent": agents,
            }

    @staticmethod
    def _fmt(name: str, u: AgentUsage) -> dict:
        return {
            "agent": name,
            "api_calls": u.calls,
            "input_tokens": u.input_tokens,
            "output_tokens": u.output_tokens,
            "cache_read_tokens": u.cache_read_tokens,
            "cache_write_tokens": u.cache_write_tokens,
            "cache_hit_rate": round(u.cache_hit_rate, 3),
            "cost_usd": round(u.cost_usd, 4),
        }

    # ── Budget governor (5A) ───────────────────────────────────────────────────

    def total_cost(self) -> float:
        """Total USD spent across all agents so far this engagement."""
        with self._lock:
            return sum(u.cost_usd for u in self._by_agent.values())

    def budget_remaining(self) -> Optional[float]:
        """
        USD remaining under `engagement_budget_usd`.

        Returns None when no budget is set (0 = unlimited), so callers can
        distinguish "no ceiling" from "exactly nothing left".
        """
        budget = settings.engagement_budget_usd
        if not budget or budget <= 0:
            return None
        return budget - self.total_cost()

    def over_budget(self) -> bool:
        """True only when a budget is set and it has been reached or exceeded."""
        remaining = self.budget_remaining()
        return remaining is not None and remaining <= 0

    def reset(self) -> None:
        with self._lock:
            self._by_agent.clear()
            self._started = time.time()


# Module-level singleton
telemetry = Telemetry()
