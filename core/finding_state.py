"""
core/finding_state.py
──────────────────────
The finding lifecycle (capability C2): **candidate → confirmed → approved**.

Why this exists: the #1 failure mode of autonomous offensive-security agents is the
*hallucinated finding*. So the lifecycle is enforced architecturally:

  • AI agents only ever REGISTER candidates (they have no confirm/approve tool).
  • candidate → confirmed happens ONLY through a deterministic re-test that
    actually reproduced the issue (see `core/retest.py`), with bound evidence + CVSS.
  • confirmed → approved happens ONLY by a human (CLI / API) — never an agent.
  • Reporting / sending is gated on `approved` when `require_finding_approval` is on.

The store is a signature-keyed JSON file SEPARATE from the KnowledgeBase, so the KB
JSON schema is untouched (the lifecycle is additive). It mirrors the persistence
pattern of `core/compliance.py::FindingsLedger`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from enum import Enum
from pathlib import Path
from typing import Optional

from config.settings import settings

log = logging.getLogger(__name__)


class FindingState(str, Enum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    APPROVED = "approved"
    REJECTED = "rejected"


# Representative CVSS base score per severity band (used when a finding carries no
# explicit CVSS — confirmation binds a number so the report can rank consistently).
_SEVERITY_CVSS: dict[str, float] = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 0.0,
}

_SIG_FIELDS = ("target", "port", "cve", "cwe", "technique", "url", "title")


def severity_to_cvss(severity: str) -> float:
    return _SEVERITY_CVSS.get(str(severity).lower(), 0.0)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def signature(finding: dict) -> str:
    """Stable 16-char signature over the identifying fields of a finding.

    Richer than `compliance.finding_signature` (adds cwe/url/title) so web findings
    — which often have no CVE/port — don't collide on the same target.
    """
    raw = "|".join(str(finding.get(k) or "") for k in _SIG_FIELDS)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class FindingStateStore:
    """Signature-keyed lifecycle store. Thread-safe, JSON-persisted."""

    def __init__(self, path: Optional[str] = None) -> None:
        self._lock = threading.RLock()
        self._path = (
            Path(path) if path
            else Path(settings.knowledge_dir).parent / "finding_states.json"
        )

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text(encoding="utf-8"))
            except Exception as e:  # noqa: BLE001
                log.warning("finding_states load failed (%s) — starting fresh", e)
        return {}

    def _save(self, store: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(store, indent=2, default=str), encoding="utf-8")

    # ── Write side ────────────────────────────────────────────────────────────

    def register_candidate(self, finding: dict) -> str:
        """Register a finding as a candidate (idempotent; never downgrades state).

        This is the ONLY mutation an AI agent performs on the lifecycle. Returns the
        finding signature.
        """
        sig = signature(finding)
        with self._lock:
            store = self._load()
            entry = store.get(sig)
            if entry is None:
                store[sig] = {
                    "signature": sig,
                    "state": FindingState.CANDIDATE.value,
                    "target": finding.get("target"),
                    "title": finding.get("title") or finding.get("description"),
                    "severity": str(finding.get("severity", "info")).lower(),
                    "cve": finding.get("cve"),
                    "cwe": finding.get("cwe"),
                    "port": finding.get("port"),
                    "technique": finding.get("technique"),
                    "url": finding.get("url"),
                    "owasp": finding.get("owasp_id") or finding.get("owasp"),
                    "source": finding.get("source"),
                    "cvss": finding.get("cvss"),
                    # Reproduction artifacts so the candidate can be deterministically
                    # re-tested later (nuclei template id / a signal to look for).
                    "template": finding.get("template") or finding.get("template_id"),
                    "repro_signal": (finding.get("repro_signal") or finding.get("proof")
                                     or finding.get("evidence")),
                    "first_seen": _now(),
                    "last_seen": _now(),
                    "history": [{"state": FindingState.CANDIDATE.value, "ts": _now(),
                                 "by": finding.get("source") or "agent"}],
                }
            else:
                entry["last_seen"] = _now()
            self._save(store)
        return sig

    def confirm(self, sig: str, *, validation: dict, cvss: Optional[float] = None,
                by: str = "validator") -> dict:
        """Promote candidate → confirmed. ONLY succeeds when the re-test reproduced
        the issue. Binds the validation evidence + a CVSS score."""
        with self._lock:
            store = self._load()
            entry = store.get(sig)
            if entry is None:
                return {"promoted": False, "reason": "unknown signature"}
            if entry["state"] == FindingState.APPROVED.value:
                return {"promoted": False, "reason": "already approved"}
            if not validation.get("reproduced"):
                entry["last_seen"] = _now()
                entry.setdefault("validation", validation)
                self._save(store)
                return {"promoted": False, "reason": "not reproduced",
                        "state": entry["state"]}
            entry["state"] = FindingState.CONFIRMED.value
            entry["validation"] = validation
            entry["cvss"] = (cvss if cvss is not None
                             else entry.get("cvss") or severity_to_cvss(entry["severity"]))
            entry["confirmed_at"] = _now()
            entry["last_seen"] = _now()
            entry["history"].append({"state": FindingState.CONFIRMED.value,
                                     "ts": _now(), "by": by})
            self._save(store)
            return {"promoted": True, "state": entry["state"], "cvss": entry["cvss"]}

    def approve(self, sig: str, *, approver: str) -> dict:
        """Promote confirmed → approved. Human-only. A candidate cannot be approved
        without first being deterministically confirmed."""
        with self._lock:
            store = self._load()
            entry = store.get(sig)
            if entry is None:
                return {"approved": False, "reason": "unknown signature"}
            if entry["state"] != FindingState.CONFIRMED.value:
                return {"approved": False,
                        "reason": f"can only approve a confirmed finding "
                                  f"(state={entry['state']})"}
            entry["state"] = FindingState.APPROVED.value
            entry["approved_by"] = approver
            entry["approved_at"] = _now()
            entry["history"].append({"state": FindingState.APPROVED.value,
                                     "ts": _now(), "by": approver})
            self._save(store)
            return {"approved": True, "signature": sig, "approver": approver}

    def reject(self, sig: str, *, by: str, reason: str = "") -> dict:
        """Mark a non-approved finding as rejected (false positive / won't report)."""
        with self._lock:
            store = self._load()
            entry = store.get(sig)
            if entry is None:
                return {"rejected": False, "reason": "unknown signature"}
            if entry["state"] == FindingState.APPROVED.value:
                return {"rejected": False, "reason": "already approved"}
            entry["state"] = FindingState.REJECTED.value
            entry["history"].append({"state": FindingState.REJECTED.value,
                                     "ts": _now(), "by": by, "reason": reason})
            self._save(store)
            return {"rejected": True, "signature": sig}

    # ── Read side ─────────────────────────────────────────────────────────────

    def get(self, sig: str) -> Optional[dict]:
        return self._load().get(sig)

    def list(self, state: Optional[str] = None) -> list[dict]:
        entries = list(self._load().values())
        if state:
            entries = [e for e in entries if e.get("state") == state]
        return sorted(entries, key=lambda e: e.get("first_seen", ""))

    def queue(self) -> list[dict]:
        """The human-approval queue — confirmed findings awaiting approval."""
        return self.list(FindingState.CONFIRMED.value)

    def is_approved(self, sig: str) -> bool:
        entry = self._load().get(sig)
        return bool(entry and entry["state"] == FindingState.APPROVED.value)

    def can_report(self, finding_or_sig) -> bool:
        """Gate for report/send actions. When `require_finding_approval` is off
        (default), everything passes (non-breaking). When on, only approved passes."""
        if not settings.require_finding_approval:
            return True
        sig = finding_or_sig if isinstance(finding_or_sig, str) else signature(finding_or_sig)
        return self.is_approved(sig)

    def summary(self) -> dict:
        counts = {s.value: 0 for s in FindingState}
        for e in self._load().values():
            counts[e.get("state", "candidate")] = counts.get(e.get("state"), 0) + 1
        return {"total": sum(counts.values()), "by_state": counts,
                "require_approval": settings.require_finding_approval}


# Module-level singleton — mirrors kb / evidence / ledger.
finding_state = FindingStateStore()
