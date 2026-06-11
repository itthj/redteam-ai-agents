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

# ── ISO/IEC 27001:2022 Annex A controls (curated; real Annex A control numbers) ──
ATTACK_TO_ISO27001: dict[str, list[str]] = {
    "T1595": ["A.8.8", "A.5.7"], "T1590": ["A.5.7"], "T1592": ["A.5.7"],
    "T1596": ["A.5.7"], "T1589": ["A.5.7", "A.5.16"],
    "T1190": ["A.8.8", "A.8.25", "A.8.28"], "T1133": ["A.8.20", "A.5.15", "A.8.5"],
    "T1078": ["A.5.15", "A.5.16", "A.8.2", "A.8.5"],
    "T1059": ["A.8.7"], "T1203": ["A.8.8", "A.8.7"],
    "T1053": ["A.8.9", "A.8.2"], "T1098": ["A.5.18", "A.8.2"], "T1547": ["A.8.9"],
    "T1548": ["A.8.2"], "T1068": ["A.8.8", "A.8.2"], "T1574": ["A.8.9"],
    "T1070": ["A.8.15"], "T1027": ["A.8.7", "A.8.16"], "T1562": ["A.8.16", "A.8.7"],
    "T1110": ["A.8.5", "A.5.17"], "T1003": ["A.5.17", "A.8.2"], "T1555": ["A.5.17"],
    "T1552": ["A.5.17", "A.8.24"],
    "T1046": ["A.8.8", "A.8.20"], "T1018": ["A.8.20"], "T1087": ["A.8.2"],
    "T1083": ["A.8.3"], "T1082": ["A.8.9"],
    "T1021": ["A.5.15", "A.8.20"], "T1570": ["A.8.22", "A.8.7"],
    "T1005": ["A.8.12", "A.8.3"], "T1119": ["A.8.12"],
    "T1071": ["A.8.20", "A.8.23"], "T1572": ["A.8.20", "A.8.22"], "T1041": ["A.8.12", "A.8.16"],
    "T1486": ["A.8.13", "A.5.29"],
}

# ── CBK Guidance Note on Cybersecurity (Aug 2017) — NIST-CSF-aligned function domains.
#    ID=Identify PR=Protect DE=Detect RS=Respond RC=Recover (the GN's structure). ──────
ATTACK_TO_CBK: dict[str, list[str]] = {
    "T1595": ["CBK-ID", "CBK-DE"], "T1590": ["CBK-ID"], "T1592": ["CBK-ID"],
    "T1596": ["CBK-ID"], "T1589": ["CBK-ID"],
    "T1190": ["CBK-PR"], "T1133": ["CBK-PR"],
    "T1078": ["CBK-PR"], "T1059": ["CBK-PR"], "T1203": ["CBK-PR"],
    "T1053": ["CBK-PR"], "T1098": ["CBK-PR"], "T1547": ["CBK-PR"],
    "T1548": ["CBK-PR"], "T1068": ["CBK-PR"], "T1574": ["CBK-PR"],
    "T1070": ["CBK-DE"], "T1027": ["CBK-DE"], "T1562": ["CBK-DE"],
    "T1110": ["CBK-PR"], "T1003": ["CBK-PR"], "T1555": ["CBK-PR"], "T1552": ["CBK-PR"],
    "T1046": ["CBK-ID"], "T1018": ["CBK-ID"], "T1087": ["CBK-ID"],
    "T1083": ["CBK-ID"], "T1082": ["CBK-ID"],
    "T1021": ["CBK-PR", "CBK-RS"], "T1570": ["CBK-RS"],
    "T1005": ["CBK-RS"], "T1119": ["CBK-RS"],
    "T1071": ["CBK-DE", "CBK-RS"], "T1572": ["CBK-DE"], "T1041": ["CBK-RS"],
    "T1486": ["CBK-RC"],
}

# ── Kenya Data Protection Act, 2019 (No. 24 of 2019) — section references.
#    s.25 principles (integrity & confidentiality) · s.41 data protection by design /
#    technical & organisational measures · s.42 security safeguards · s.43 breach
#    notification. Verified against the gazetted Act + kenyalaw.org. ──────────────────
ATTACK_TO_KDPA: dict[str, list[str]] = {
    "T1595": ["s.41"], "T1590": ["s.41"], "T1592": ["s.41"], "T1596": ["s.41"],
    "T1589": ["s.25", "s.41"],
    "T1190": ["s.41"], "T1133": ["s.41"], "T1059": ["s.41"], "T1203": ["s.41"],
    "T1053": ["s.41"], "T1547": ["s.41"], "T1574": ["s.41"], "T1082": ["s.41"],
    "T1078": ["s.25", "s.41"], "T1098": ["s.25", "s.41"], "T1548": ["s.41"],
    "T1068": ["s.41"], "T1110": ["s.25", "s.41"], "T1087": ["s.25", "s.41"],
    "T1003": ["s.25", "s.41", "s.42"], "T1555": ["s.25", "s.42"],
    "T1552": ["s.25", "s.41", "s.42"],
    "T1070": ["s.41"], "T1027": ["s.41"], "T1562": ["s.41"],
    "T1046": ["s.41"], "T1018": ["s.41"], "T1083": ["s.41"],
    "T1021": ["s.41"], "T1570": ["s.41"],
    "T1005": ["s.25", "s.42", "s.43"], "T1119": ["s.25", "s.42", "s.43"],
    "T1071": ["s.41"], "T1572": ["s.41"], "T1041": ["s.25", "s.43"],
    "T1486": ["s.41", "s.43"],
}

# Frameworks exposed by map_finding (NIST 800-53 + SOC 2 kept from 5F; ISO/CBK/KDPA add C3).
FRAMEWORKS = ("nist_800_53", "pci_dss", "soc2", "iso_27001", "cbk", "kenya_dpa")

# PTES — the report's structural backbone (Penetration Testing Execution Standard).
PTES_PHASES = (
    "Pre-engagement Interactions", "Intelligence Gathering", "Threat Modeling",
    "Vulnerability Analysis", "Exploitation", "Post-Exploitation", "Reporting",
)


def _base(technique_id: str) -> str:
    return (technique_id or "").split(".")[0]


def map_finding(technique_id: str) -> dict:
    """Map a technique id to its NIST 800-53 / PCI DSS / SOC 2 / ISO 27001 / CBK /
    Kenya DPA controls."""
    base = _base(technique_id)
    return {
        "technique_id": technique_id,
        "nist_800_53": ATTACK_TO_NIST.get(base, []),
        "pci_dss": ATTACK_TO_PCI.get(base, []),
        "soc2": ATTACK_TO_SOC2.get(base, []),
        "iso_27001": ATTACK_TO_ISO27001.get(base, []),
        "cbk": ATTACK_TO_CBK.get(base, []),
        "kenya_dpa": ATTACK_TO_KDPA.get(base, []),
    }


def rollup(technique_ids) -> dict:
    """Aggregate technique ids into per-framework control counts (for a report table)."""
    technique_ids = list(technique_ids)
    counts: dict[str, dict[str, int]] = {fw: {} for fw in FRAMEWORKS}
    for tid in technique_ids:
        mapped = map_finding(tid)
        for fw in FRAMEWORKS:
            for control in mapped[fw]:
                counts[fw][control] = counts[fw].get(control, 0) + 1
    out = {"techniques": len(technique_ids)}
    for fw in FRAMEWORKS:
        out[fw] = dict(sorted(counts[fw].items()))
    return out


def compliance_appendix(findings: list[dict]) -> dict:
    """Build the compliance appendix (C3): per-finding mapping across all frameworks +
    a control-family rollup + the PTES structure. `findings`: list of
    {target, technique, severity, cvss, cve, port}."""
    rows = []
    for f in findings:
        mapped = map_finding(f.get("technique", ""))
        rows.append({
            "target": f.get("target"),
            "technique": f.get("technique"),
            "severity": f.get("severity", "info"),
            "cvss": f.get("cvss"),
            "cve": f.get("cve"),
            **{fw: mapped[fw] for fw in FRAMEWORKS},
        })
    return {
        "frameworks": list(FRAMEWORKS),
        "ptes_phases": list(PTES_PHASES),
        "rows": rows,
        "rollup": rollup([f.get("technique", "") for f in findings]),
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
