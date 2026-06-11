"""
agents/reporting_agent.py
──────────────────────────
Reporting Agent — Final Phase

Responsibilities:
  • Aggregate all findings from KnowledgeBase and EvidenceStore
  • Generate executive summary
  • Generate technical findings report
  • Calculate overall risk score
  • Produce remediation recommendations
  • Export report to Markdown (then optionally PDF/HTML)
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from config.settings import settings
from core.base_agent import BaseAgent
from core.compliance import ledger, map_finding, rollup
from core.evidence_store import evidence
from core.finding_state import finding_state
from core.finding_validator import finding_validator
from core.knowledge_base import kb
from core.report_export import render_html

log = logging.getLogger(__name__)


class ReportingAgent(BaseAgent):
    NAME = "reporting"
    DESCRIPTION = "Report generation — executive summary, technical findings, remediation roadmap"

    # Full pentest reports are long — give the model generous output headroom
    MAX_TOKENS = 32000
    USE_MCP = False          # reporting works from the knowledge base, not external tools

    SYSTEM_PROMPT = """You are the Reporting Agent in an authorized red-team operation.
Your job is to synthesize all engagement findings into a clear, professional pentest report.

REPORT STRUCTURE:
1. Executive Summary (non-technical, risk-focused, for management)
2. Scope & Methodology
3. Findings Summary Table (Critical/High/Medium/Low counts + risk score)
4. Detailed Findings (per vulnerability: description, evidence, impact, remediation)
5. Attack Path Narrative (how the simulated attack progressed)
6. MITRE ATT&CK Coverage Map
7. Remediation Roadmap (prioritised, with effort estimates)
8. Appendices (raw evidence, timeline, tool output)

WRITING RULES:
- Executive summary: no jargon, focus on business risk
- Technical findings: precise, reproducible, with CVE IDs where applicable
- Remediation: specific, actionable, ranked by effort vs risk reduction
- NEVER include real credentials in the report
- Call validate_findings before finalizing; label any finding flagged "needs-review" or
  "likely-false-positive" as "(unverified — requires manual verification)" and do not overstate it
- Findings carry a lifecycle state (candidate → confirmed → approved). Call
  get_findings_by_state to see it. When approval is required, report only APPROVED
  findings as confirmed; clearly mark anything still candidate/confirmed as not yet client-approved.
"""

    TOOLS = [
        {
            "name": "get_all_findings",
            "description": "Get all vulnerability findings from the knowledge base",
            "input_schema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_evidence_timeline",
            "description": "Get the full operation timeline from the evidence store",
            "input_schema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "calculate_risk_score",
            "description": "Calculate overall engagement risk score based on findings",
            "input_schema": {
                "type": "object",
                "properties": {
                    "findings": {"type": "array"},
                },
                "required": ["findings"],
            },
        },
        {
            "name": "save_report",
            "description": "Save the generated report to the reports directory",
            "input_schema": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "content": {"type": "string", "description": "Full report in Markdown"},
                    "format": {"type": "string", "enum": ["markdown", "json", "html"], "description": "Output format"},
                },
                "required": ["title", "content"],
            },
        },
        {
            "name": "map_to_compliance",
            "description": "Map a MITRE ATT&CK technique id to NIST 800-53 / PCI DSS / "
                           "SOC 2 controls.",
            "input_schema": {
                "type": "object",
                "properties": {"technique_id": {"type": "string"}},
                "required": ["technique_id"],
            },
        },
        {
            "name": "compliance_rollup",
            "description": "Roll up all current findings by control family (NIST/PCI) and "
                           "diff them against the findings ledger (new / still-open / "
                           "resolved) for retest tracking.",
            "input_schema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_findings_by_state",
            "description": "List findings by lifecycle state (candidate/confirmed/approved/"
                           "rejected) with a summary. Use to report only client-approved "
                           "findings when approval is required.",
            "input_schema": {
                "type": "object",
                "properties": {"state": {"type": "string",
                                         "enum": ["candidate", "confirmed", "approved", "rejected"]}},
                "required": [],
            },
        },
        {
            "name": "validate_findings",
            "description": "Deterministically validate all findings against scan/evidence "
                           "facts (no model call). Returns a confidence + verdict per "
                           "finding (validated / needs-review / likely-false-positive) to "
                           "catch hallucinated findings before they enter the report.",
            "input_schema": {"type": "object", "properties": {}, "required": []},
        },
    ]

    def _tool_map(self):
        return {
            "get_all_findings": self._get_all_findings,
            "get_evidence_timeline": self._get_evidence_timeline,
            "calculate_risk_score": self._calculate_risk_score,
            "save_report": self._save_report,
            "map_to_compliance": self._map_to_compliance,
            "compliance_rollup": self._compliance_rollup,
            "validate_findings": self._validate_findings,
            "get_findings_by_state": self._get_findings_by_state,
        }

    # ── Tool implementations ──────────────────────────────────────────────────

    def _get_all_findings(self) -> dict:
        targets = kb.get_all_targets()
        summary = {
            "total_targets": len(targets),
            "targets": {},
            "total_vulnerabilities": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }
        for ip, data in targets.items():
            vulns = data.get("vulnerabilities", [])
            summary["targets"][ip] = {
                "hostnames": data.get("hostnames", []),
                "os": data.get("os_guess"),
                "open_ports": len(data.get("open_ports", [])),
                "vulnerability_count": len(vulns),
                "vulnerabilities": vulns,
                "shells_obtained": len(data.get("shells", [])),
                "credentials_found": len(data.get("credentials", [])),
            }
            for v in vulns:
                sev = v.get("severity", "info")
                summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
                summary["total_vulnerabilities"] += 1
        return summary

    def _get_evidence_timeline(self) -> dict:
        records = evidence.get_all()
        return {
            "total_events": len(records),
            "chain_valid": evidence.verify_chain(),
            "events": [
                {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r["timestamp"])),
                    "agent": r["agent"],
                    "action": r["action"],
                    "target": r.get("target"),
                    "severity": r["severity"],
                }
                for r in sorted(records, key=lambda x: x.get("timestamp", 0))
            ],
        }

    def _calculate_risk_score(self, findings: list) -> dict:
        """Simple CVSS-based risk calculation."""
        if not findings:
            return {"score": 0, "rating": "None", "findings_count": 0}

        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        total = sum(weights.get(f.get("severity", "info"), 0) for f in findings)
        max_score = len(findings) * 10
        normalized = (total / max_score * 10) if max_score > 0 else 0

        if normalized >= 8:
            rating = "Critical"
        elif normalized >= 6:
            rating = "High"
        elif normalized >= 4:
            rating = "Medium"
        elif normalized >= 2:
            rating = "Low"
        else:
            rating = "Informational"

        return {
            "score": round(normalized, 1),
            "rating": rating,
            "findings_count": len(findings),
            "raw_score": total,
        }

    def _save_report(self, title: str, content: str, format: str = "markdown") -> dict:
        reports_dir = Path(settings.reports_dir)
        reports_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        if format == "html":
            content = render_html(title, content, meta={
                "Engagement": settings.engagement_id,
                "Operator": settings.operator_name,
            })
            ext = "html"
        else:
            ext = "json" if format == "json" else "md"
        filename = f"{ts}_{title.replace(' ', '_')[:40]}.{ext}"
        out_path = reports_dir / filename
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(content)
        log.info("[REPORTING] Report saved: %s", out_path)
        return {
            "saved": str(out_path),
            "size_bytes": len(content.encode()),
            "title": title,
        }

    # ── Compliance + retest (5F) ──────────────────────────────────────────────

    def _map_to_compliance(self, technique_id: str) -> dict:
        return map_finding(technique_id)

    def _validate_findings(self) -> dict:
        """Deterministic anti-hallucination grading of all current findings."""
        return finding_validator.validate_all(kb.get_all_targets(), evidence.get_all())

    def _get_findings_by_state(self, state: str | None = None) -> dict:
        """Findings by lifecycle state (C2) — lets the report ship only approved findings."""
        return {"summary": finding_state.summary(), "findings": finding_state.list(state)}

    def _compliance_rollup(self) -> dict:
        findings = []
        for ip, data in kb.get_all_targets().items():
            for v in data.get("vulnerabilities", []):
                findings.append({
                    "target": ip,
                    "port": v.get("port"),
                    "cve": v.get("cve"),
                    "technique": v.get("technique", "T1190"),
                    "severity": v.get("severity", "info"),
                })
        return {
            "findings": len(findings),
            "compliance": rollup([f["technique"] for f in findings]),
            "retest": ledger.diff(findings),
        }
