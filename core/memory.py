"""
core/memory.py
───────────────
Cross-engagement tradecraft memory (workstream 2C).

The system remembers what worked on similar targets in past engagements and
surfaces it at planning time. A `Lesson` records a reusable observation — e.g.
"vsftpd 2.3.4 on :21 → CVE-2011-2523 backdoor via the exploit agent → root shell".

Privacy first: lessons store target *profiles* (service versions, OS, topology
shape) and techniques — NEVER credentials, hostnames, or client-identifying data.
Every field is redacted (guardrails secret-redaction + IP stripping) before it is
written. The store is per-operator and lives under data/ (gitignored).

Backend: a JSONL store with keyword recall — zero infrastructure, fully offline,
and what the tests run against. (A chromadb/embedding backend can layer on later
behind the same interface; this is the graceful-degradation fallback.)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from config.settings import settings
from core.guardrails import guardrails

log = logging.getLogger(__name__)

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_TOKEN_RE = re.compile(r"[a-z0-9.]+")


def _redact(text: str) -> str:
    """Strip secrets (guardrails) and IPv4 addresses from a lesson field."""
    if not text:
        return text
    return _IP_RE.sub("[redacted-ip]", guardrails.sanitize(text))


def _tokens(text: str) -> set:
    return set(_TOKEN_RE.findall((text or "").lower()))


def _extract_json_array(text: str) -> str:
    start, end = text.find("["), text.rfind("]")
    return text[start:end + 1] if start != -1 and end != -1 else "[]"


def _summarize(prompt: str, model: str) -> str:
    """One-shot fast-model completion (sync, post-engagement). Isolated so tests
    can monkeypatch it — no network in the suite."""
    import anthropic
    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    msg = client.messages.create(
        model=model, max_tokens=1500,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(b.text for b in msg.content if getattr(b, "type", None) == "text")


@dataclass
class Lesson:
    situation: str
    action: str
    technique_id: str = ""
    outcome: str = ""
    target_profile: str = ""

    def redacted(self) -> "Lesson":
        return Lesson(_redact(self.situation), _redact(self.action), self.technique_id,
                      _redact(self.outcome), _redact(self.target_profile))

    def search_text(self) -> str:
        return " ".join([self.situation, self.action, self.technique_id,
                         self.target_profile]).lower()

    @classmethod
    def from_dict(cls, d: dict) -> "Lesson":
        return cls(
            situation=d.get("situation", ""),
            action=d.get("action", ""),
            technique_id=d.get("technique_id", ""),
            outcome=d.get("outcome", ""),
            target_profile=d.get("target_profile", ""),
        )


class TradecraftMemory:
    """Per-operator JSONL store of distilled lessons with keyword recall."""

    def __init__(self, store_path: Optional[str] = None) -> None:
        self._path = (
            Path(store_path) if store_path
            else Path(settings.knowledge_dir).parent / "memory" / "tradecraft.jsonl"
        )

    # ── write ──────────────────────────────────────────────────────────────────

    def store(self, lessons) -> int:
        """Append lessons (redacted) to the store. Returns how many were written."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        n = 0
        with open(self._path, "a", encoding="utf-8") as f:
            for lesson in lessons:
                f.write(json.dumps(asdict(lesson.redacted())) + "\n")
                n += 1
        return n

    def all(self) -> list[Lesson]:
        if not self._path.exists():
            return []
        out: list[Lesson] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(Lesson.from_dict(json.loads(line)))
            except Exception:  # noqa: BLE001
                pass
        return out

    # ── read ───────────────────────────────────────────────────────────────────

    def recall(self, context, k: int = 3) -> list[Lesson]:
        """Top-k lessons by keyword overlap with the context (target profile +
        services + objective). The JSONL fallback's similarity function."""
        ctx = context if isinstance(context, str) else json.dumps(context, default=str)
        ctx_tokens = _tokens(ctx)
        if not ctx_tokens:
            return []
        scored = []
        for lesson in self.all():
            overlap = len(ctx_tokens & _tokens(lesson.search_text()))
            if overlap:
                scored.append((overlap, lesson))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [lesson for _, lesson in scored[:k]]

    # ── distillation (post-engagement, fast model) ──────────────────────────────

    def distill(self, engagement_id: str, kb_snapshot: dict,
                model: Optional[str] = None) -> list[Lesson]:
        """Summarise a finished engagement into reusable lessons (Haiku)."""
        model = model or settings.claude_fast_model
        prompt = (
            "You are distilling reusable red-team tradecraft from a finished "
            "engagement. From the knowledge base below, extract lessons that would "
            "help on a SIMILAR future target. Return ONLY a JSON array of objects "
            "with keys: situation, action, technique_id, outcome, target_profile. "
            "Store target *profiles* (service versions, OS, topology shape) and "
            "techniques — NEVER IPs, hostnames, or credentials.\n\n"
            f"Knowledge base:\n{json.dumps(kb_snapshot, default=str)[:6000]}"
        )
        try:
            raw = _summarize(prompt, model)
            data = json.loads(_extract_json_array(raw))
            return [Lesson.from_dict(d) for d in data if isinstance(d, dict)]
        except Exception as e:  # noqa: BLE001 — distillation is best-effort
            log.warning("[MEMORY] distill failed: %s", e)
            return []


# Module-level singleton
memory = TradecraftMemory()
