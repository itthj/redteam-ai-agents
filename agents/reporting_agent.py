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

import json
import logging
import time
from pathlib import Path
from typing import Optional

from config.settings import settings
from core.base_agent import BaseAgent
from core.evidence_store import evidence
from core.knowledge_base import kb

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
                    "format": {"type": "string", "enum": ["markdown", "json"], "description": "Output format"},
                },
                "required": ["title", "content"],
            },
        },
    ]

    def _tool_map(self):
        return {
            "get_all_findings": self._get_all_findings,
            "get_evidence_timeline": self._get_evidence_timeline,
            "calculate_risk_score": self._calculate_risk_score,
            "save_report": self._save_report,
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
        ext = "md" if format == "markdown" else "json"
        filename = f"{ts}_{title.replace(' ', '_')[:40]}.{ext}"
        out_path = reports_dir / filename
        with open(out_path, "w") as f:
            f.write(content)
        log.info("[REPORTING] Report saved: %s", out_path)
        return {
            "saved": str(out_path),
            "size_bytes": len(content.encode()),
            "title": title,
        }
