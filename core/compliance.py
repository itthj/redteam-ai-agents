"""
core/compliance.py
───────────────────
Compliance-mapped reporting + retest tracking (workstream 5F).

Two deliverables clients actually audit against:

  1. map findings (by MITRE ATT&CK technique) to the control frameworks —
     NIST 800-53, PCI DSS, SOC 2 — and roll them up by control family.
  2. track each finding across engagements with a stable `finding_signature`
     and a status (open | retest | resolved), so re-running against the same
     target labels findings new / still-open / resolved — turning one-off
     pentests into a remediation program.

The mappings are a **curated subset** keyed to this project's technique registry.
Seed the full set from MITRE's official ATT&CK↔800-53 control mappings.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Optional

from config.settings import settings

log = logging.getLogger(__name__)


# ── ATT&CK → control mappings (curated subset, keyed by base technique id) ───────

ATTACK_TO_NIST: dict[str, list[str]] = {
    "T1595": ["SC-7", "SI-4"], "T1590": ["RA-5"], "T1592": ["RA-5"],
    "T1596": ["RA-5"], "T1589": ["RA-5"],
    "T1190": ["SI-2", "RA-5", "SC-7"], "T1133": ["AC-17", "AC-3"],
    "T1078": ["AC-2", "AC-3", "IA-2"],
    "T1059": ["CM-7", "SI-3"], "T1203": ["SI-2", "SI-3"],
    "T1053": ["CM-7", "AC-6"], "T1098": ["AC-2", "AC-6"], "T1547": ["CM-7", "SI-4"],
    "T1548": ["AC-6"], "T1068": ["SI-2", "AC-6"], "T1574": ["CM-7", "SI-7"],
    "T1070": ["AU-9", "AU-6"], "T1027": ["SI-3", "SI-4"], "T1562": ["SI-4", "CM-7", "AU-9"],
    "T1110": ["AC-7", "IA-5"], "T1003": ["IA-5", "AC-6"], "T1555": ["IA-5"],
    "T1552": ["IA-5", "SC-28"],
    "T1046": ["CM-7", "SC-7"], "T1018": ["CM-7"], "T1087": ["AC-6"],
    "T1083": ["AC-6"], "T1082": ["CM-7"],
    "T1021": ["AC-17", "AC-3"], "T1570": ["SC-7", "SI-3"],
    "T1005": ["AC-6", "SC-28"], "T1119": ["AC-6"],
    "T1071": ["SC-7", "SI-4"], "T1572": ["SC-7", "SI-4"], "T1041": ["SC-7", "AC-4"],
    "T1486": ["CP-9", "SI-7"],
}

ATTACK_TO_PCI: dict[str, list[str]] = {
    "T1078": ["7.2", "8.2"], "T1110": ["8.3.6"], "T1003": ["8.3", "3.5"],
    "T1552": ["8.3", "3.5"], "T1555": ["8.3"],
    "T1190": ["6.2", "11.3"], "T1046": ["11.3", "11.4"], "T1595": ["11.3"],
    "T1021": ["8.3", "1.3"], "T1133": ["1.3"],
    "T1041": ["1.3", "1.4"], "T1071": ["1.3"], "T1572": ["1.3"],
    "T1486": ["12.10"], "T1562": ["10.7"], "T1070": ["10.5", "10.7"],
}

ATTACK_TO_SOC2: dict[str, list[str]] = {
    "T1078": ["CC6.1"], "T1110": ["CC6.1"], "T1003": ["CC6.1"], "T1021": ["CC6.1"],
    "T1133": ["CC6.1"], "T1190": ["CC7.1"], "T1068": ["CC7.1"], "T1203": ["CC7.1"],
    "T1070": ["CC7.2"], "T1562": ["CC7.2"], "T1027": ["CC7.2"],
}


def _base(technique_id: str) -> str:
    return (technique_id or "").split(".")[0]


def map_finding(technique_id: str) -> dict:
    """Map a technique id to its NIST 800-53 / PCI DSS / SOC 2 controls."""
    base = _base(technique_id)
    return {
        "technique_id": technique_id,
        "nist_800_53": ATTACK_TO_NIST.get(base, []),
        "pci_dss": ATTACK_TO_PCI.get(base, []),
        "soc2": ATTACK_TO_SOC2.get(base, []),
    }


def rollup(technique_ids) -> dict:
    """Aggregate technique ids into control-family counts (for a report table)."""
    technique_ids = list(technique_ids)
    nist: dict[str, int] = {}
    pci: dict[str, int] = {}
    for tid in technique_ids:
        mapped = map_finding(tid)
        for control in mapped["nist_800_53"]:
            nist[control] = nist.get(control, 0) + 1
        for req in mapped["pci_dss"]:
            pci[req] = pci.get(req, 0) + 1
    return {
        "techniques": len(technique_ids),
        "nist_800_53": dict(sorted(nist.items())),
        "pci_dss": dict(sorted(pci.items())),
    }


# ── retest tracking ──────────────────────────────────────────────────────────────

def finding_signature(target, port=None, cve=None, technique=None) -> str:
    raw = f"{target}|{port or ''}|{cve or ''}|{technique or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class FindingsLedger:
    """Persists finding signatures + status across engagements (retest program)."""

    def __init__(self, path: Optional[str] = None) -> None:
        self._path = (
            Path(path) if path
            else Path(settings.knowledge_dir).parent / "findings_ledger.json"
        )

    def _load(self) -> dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                pass
        return {}

    def _save(self, ledger: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(ledger, indent=2), encoding="utf-8")

    def diff(self, findings: list[dict]) -> dict:
        """Label current findings new / still-open, mark absent ones resolved, and
        persist. Each finding: {target, port, cve, technique}."""
        ledger = self._load()
        new, still_open, resolved = [], [], []
        current: dict[str, dict] = {}
        for f in findings:
            sig = finding_signature(f.get("target"), f.get("port"), f.get("cve"),
                                    f.get("technique"))
            current[sig] = f
            label = {"signature": sig, **f}
            entry = ledger.get(sig)
            if entry is None:
                ledger[sig] = {"status": "open", "target": f.get("target"),
                               "cve": f.get("cve"), "technique": f.get("technique"),
                               "first_seen": _now(), "last_seen": _now()}
                new.append(label)
            else:
                entry["status"] = "open"
                entry["last_seen"] = _now()
                still_open.append(label)

        for sig, entry in ledger.items():
            if sig not in current and entry.get("status") != "resolved":
                entry["status"] = "resolved"
                entry["resolved_at"] = _now()
                resolved.append({"signature": sig,
                                 "target": entry.get("target"), "cve": entry.get("cve"),
                                 "technique": entry.get("technique")})

        self._save(ledger)
        return {"new": new, "still_open": still_open, "resolved": resolved}


# Module-level singleton
ledger = FindingsLedger()
