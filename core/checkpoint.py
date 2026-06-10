"""
core/checkpoint.py
───────────────────
Resumable engagement checkpoints (workstream 5B).

The autonomous planner's conversation lives only inside BaseAgent.run. To survive
a crash / Ctrl-C / API outage we externalise it: after each delegation the
orchestrator writes a JSON checkpoint (planner messages + KB snapshot + telemetry
+ graph export) under data/checkpoints/<engagement_id>/<seq>.json, and `resume`
rehydrates the latest one. The KB and the SHA-256 evidence chain already persist
on their own; this adds the planner state on top. Replaying the last delegated
task on resume is safe — the graph and KB use MERGE/dedup semantics.
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Optional

from config.settings import settings

log = logging.getLogger(__name__)


def _ser(obj):
    """JSON fallback — serialise Anthropic SDK content blocks (pydantic) to plain
    dicts so a planner conversation round-trips and can be replayed on resume."""
    if hasattr(obj, "model_dump"):
        try:
            return obj.model_dump(mode="json")
        except Exception:  # noqa: BLE001
            return str(obj)
    return str(obj)


def _safe(engagement_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", engagement_id or "engagement")


class Checkpoint:
    """Reads/writes engagement checkpoints as sequential JSON files."""

    def __init__(self, base_dir: Optional[str] = None) -> None:
        self._dir = (
            Path(base_dir) if base_dir
            else Path(settings.knowledge_dir).parent / "checkpoints"
        )

    def _eng_dir(self, engagement_id: str) -> Path:
        return self._dir / _safe(engagement_id)

    @staticmethod
    def _next_seq(eng_dir: Path) -> int:
        existing = sorted(eng_dir.glob("*.json"))
        return (int(existing[-1].stem) + 1) if existing else 1

    def save(self, engagement_id: str, *, kb_snapshot, mission_state,
             orchestrator_messages, telemetry, graph_export,
             objective: str = "", targets=None) -> Path:
        eng_dir = self._eng_dir(engagement_id)
        eng_dir.mkdir(parents=True, exist_ok=True)
        seq = self._next_seq(eng_dir)
        payload = {
            "seq": seq,
            "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "engagement_id": engagement_id,
            "objective": objective,
            "targets": list(targets or []),
            "mission_state": mission_state,
            "kb_snapshot": kb_snapshot,
            "orchestrator_messages": orchestrator_messages,
            "telemetry": telemetry,
            "graph_export": graph_export,
        }
        path = eng_dir / f"{seq:04d}.json"
        path.write_text(json.dumps(payload, default=_ser, indent=2), encoding="utf-8")
        log.info("[CHECKPOINT] saved %s", path)
        return path

    def load(self, engagement_id: str) -> Optional[dict]:
        """Return the latest checkpoint for an engagement, or None."""
        eng_dir = self._eng_dir(engagement_id)
        files = sorted(eng_dir.glob("*.json")) if eng_dir.exists() else []
        if not files:
            return None
        return json.loads(files[-1].read_text(encoding="utf-8"))

    def list(self) -> list[dict]:
        """Summarise every engagement that has checkpoints."""
        out: list[dict] = []
        if not self._dir.exists():
            return out
        for eng_dir in sorted(self._dir.iterdir()):
            if not eng_dir.is_dir():
                continue
            files = sorted(eng_dir.glob("*.json"))
            if not files:
                continue
            try:
                latest = json.loads(files[-1].read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                latest = {}
            out.append({
                "engagement_id": latest.get("engagement_id", eng_dir.name),
                "checkpoints": len(files),
                "latest_seq": latest.get("seq", len(files)),
                "saved_at": latest.get("saved_at"),
                "mission_state": latest.get("mission_state"),
                "objective": latest.get("objective", ""),
            })
        return out


# Module-level singleton
checkpoint = Checkpoint()
