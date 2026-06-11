"""
core/finding_validator.py
──────────────────────────
Deterministic anti-hallucination check for reported findings.

The single biggest failure mode of autonomous offensive-security agents is the
*hallucinated finding* — a confident vulnerability claim with nothing behind it.
Industry systems (XBOW, Google Big Sleep) pair the LLM with **deterministic
validators** and human verification for exactly this reason. This module grounds
every finding against the facts already in the KnowledgeBase and EvidenceStore —
no model call, no network — and assigns a confidence + verdict so the reporting
agent can label weak findings "requires manual verification" instead of shipping
them as fact.

Signals (each lowers confidence from a 1.0 baseline):
  • the finding's port is not in the target's scanned open ports;
  • there is no evidence record for the target at all;
  • a referenced CVE is malformed, or a high/critical finding cites none;
  • the CVE never appears in any evidence record for the target;
  • the severity is outside the known set, or there is no description.
"""

from __future__ import annotations

import re
from collections import defaultdict

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _to_int(value: object) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


class FindingValidator:
    """Stateless. Grades a finding against KB/evidence facts (no model call)."""

    @staticmethod
    def validate(finding: dict, *, open_ports: list[dict] | None = None,
                 target_evidence: list[dict] | None = None) -> dict:
        """Return {confidence: float, verdict: str, issues: [str]} for one finding."""
        issues: list[str] = []
        confidence = 1.0
        sev = str(finding.get("severity", "info")).lower()
        cve = finding.get("cve")
        port = finding.get("port")

        if port is not None and open_ports is not None:
            open_nums = {_to_int(p.get("port")) for p in open_ports}
            if _to_int(port) not in open_nums:
                shown = sorted(n for n in open_nums if n is not None)
                issues.append(f"port {port} not among scanned open ports {shown}")
                confidence -= 0.5

        if target_evidence is not None and not target_evidence:
            issues.append("no evidence records for this target")
            confidence -= 0.4
        elif target_evidence and cve:
            hay = " ".join(f"{r.get('action', '')} {r.get('result', '')}" for r in target_evidence).lower()
            if str(cve).lower() not in hay:
                issues.append(f"{cve} is not referenced in any evidence record")
                confidence -= 0.15

        if cve:
            if not _CVE_RE.match(str(cve)):
                issues.append(f"malformed CVE id: {cve}")
                confidence -= 0.2
        elif sev in ("high", "critical"):
            issues.append(f"{sev}-severity finding cites no CVE")
            confidence -= 0.15

        if sev not in _SEVERITIES:
            issues.append(f"unknown severity '{sev}'")
            confidence -= 0.2

        if not (finding.get("description") or finding.get("title") or finding.get("name")):
            issues.append("no description/title")
            confidence -= 0.1

        confidence = max(0.0, min(1.0, round(confidence, 2)))
        if confidence >= 0.7:
            verdict = "validated"
        elif confidence >= 0.4:
            verdict = "needs-review"
        else:
            verdict = "likely-false-positive"
        return {"confidence": confidence, "verdict": verdict, "issues": issues}

    @staticmethod
    def validate_all(targets: dict, evidence_records: list[dict]) -> dict:
        """Validate every finding across all targets; return a summary + details."""
        ev_by_target: dict = defaultdict(list)
        for r in evidence_records:
            ev_by_target[r.get("target")].append(r)

        results: list[dict] = []
        counts = {"validated": 0, "needs-review": 0, "likely-false-positive": 0}
        for ip, data in targets.items():
            for vuln in data.get("vulnerabilities", []):
                res = FindingValidator.validate(
                    vuln,
                    open_ports=data.get("open_ports", []),
                    target_evidence=ev_by_target.get(ip, []),
                )
                counts[res["verdict"]] += 1
                results.append({
                    "target": ip,
                    "cve": vuln.get("cve"),
                    "port": vuln.get("port"),
                    "severity": vuln.get("severity", "info"),
                    **res,
                })

        total = len(results)
        return {
            "total_findings": total,
            "by_verdict": counts,
            "validated_pct": round(100 * counts["validated"] / total, 1) if total else 100.0,
            "flagged": [r for r in results if r["verdict"] != "validated"],
            "results": results,
        }


# Module-level singleton-style access (matches `guardrails`, `content_safety`, …).
finding_validator = FindingValidator()
