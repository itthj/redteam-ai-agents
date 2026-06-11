"""
agents/webapp_agent.py
───────────────────────
Web Application Testing Agent (capability C1).

Drives an authorized web-app assessment with OWASP ZAP (spider, AJAX spider,
active scan, alerts) and Nuclei, then records findings mapped to the OWASP Top 10
(2021) and the Web Security Testing Guide (WSTG).

The scanning tools are the SAME gated handlers exposed by the `webapp` MCP server
(`mcp_layer/servers/zap_server.py`), so scope authorization, the active-scan
written-authorization gate, and evidence logging apply identically whether a tool
is driven by this agent or by an external MCP client. `record_web_finding` is the
agent's own tool: it writes a CANDIDATE finding to the knowledge base + evidence
chain (the candidate → confirmed → approved lifecycle is formalised in C2).
"""

from __future__ import annotations

import logging
from typing import Optional

from core.base_agent import BaseAgent
from core.evidence_store import evidence
from core.finding_state import finding_state
from core.knowledge_base import kb
from core.owasp_map import classify as owasp_classify
from mcp_layer.servers import zap_server
from mcp_layer.servers.zap_server import _host

log = logging.getLogger(__name__)


class WebAppAgent(BaseAgent):
    NAME = "webapp"
    DESCRIPTION = "Web application testing — OWASP ZAP + Nuclei, mapped to OWASP Top 10 / WSTG"

    SYSTEM_PROMPT = """You are the Web Application Testing Agent in an authorized red-team operation.

Your job is to assess in-scope web applications for OWASP Top 10 weaknesses using
OWASP ZAP and Nuclei, and to record reproducible findings.

RULES:
- Operate only on authorized targets. Every tool is scope-authorized on the URL's host.
- Spidering and reading alerts are passive-ish and always allowed in scope.
- ACTIVE scanning (zap_active_scan, nuclei_scan) sends attack traffic and is INTRUSIVE.
  It additionally requires written authorization for this engagement; if it is blocked,
  report that it needs operator sign-off — do NOT try to work around the gate.
- Record every significant finding with record_web_finding, providing the CWE id when the
  tool reports one so it maps cleanly to the OWASP Top 10 and a WSTG test id.
- Findings you record are CANDIDATES — they are re-tested and confirmed later. Never
  overstate confidence.

WORKFLOW:
1. Spider the target (zap_spider, and zap_ajax_spider for JS-heavy apps) to map content.
2. If active scanning is authorized, run zap_active_scan and/or nuclei_scan.
3. Pull alerts with zap_alerts and review the findings.
4. For each real issue, call record_web_finding with a clear title, severity, and CWE.
5. Summarise the application's risk posture and the top issues for the report.
"""

    TOOLS = [
        {
            "name": "zap_spider",
            "description": "Crawl a target URL with the ZAP spider to discover content "
                           "(scope-gated, non-intrusive).",
            "input_schema": {
                "type": "object",
                "properties": {"target_url": {"type": "string", "description": "Full URL, e.g. https://app.lab.internal"}},
                "required": ["target_url"],
            },
        },
        {
            "name": "zap_ajax_spider",
            "description": "Crawl a JavaScript-heavy target with the ZAP AJAX spider "
                           "(scope-gated, non-intrusive).",
            "input_schema": {
                "type": "object",
                "properties": {"target_url": {"type": "string"}},
                "required": ["target_url"],
            },
        },
        {
            "name": "zap_active_scan",
            "description": "Run a ZAP ACTIVE scan (INTRUSIVE — sends attack traffic). "
                           "Requires scope + written authorization for the engagement.",
            "input_schema": {
                "type": "object",
                "properties": {"target_url": {"type": "string"}},
                "required": ["target_url"],
            },
        },
        {
            "name": "zap_alerts",
            "description": "Return ZAP alerts (findings) as JSON, optionally filtered to a base URL.",
            "input_schema": {
                "type": "object",
                "properties": {"target_url": {"type": "string", "description": "Optional base URL filter"}},
                "required": [],
            },
        },
        {
            "name": "nuclei_scan",
            "description": "Run Nuclei templated DAST against a target (INTRUSIVE). "
                           "Requires scope + written authorization for the engagement.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string"},
                    "severity": {"type": "string", "description": "Optional comma list, e.g. 'critical,high'"},
                    "templates": {"type": "string", "description": "Optional template path/tag"},
                },
                "required": ["target_url"],
            },
        },
        {
            "name": "record_web_finding",
            "description": "Record a CANDIDATE web finding to the knowledge base and the "
                           "tamper-evident evidence chain, auto-mapped to OWASP Top 10 / WSTG.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target host or URL"},
                    "title": {"type": "string", "description": "Short finding title, e.g. 'Reflected XSS in search'"},
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                    "cwe": {"type": "string", "description": "CWE id if known, e.g. 'CWE-79' or '79'"},
                    "url": {"type": "string", "description": "Affected URL"},
                    "port": {"type": "integer"},
                    "description": {"type": "string"},
                    "proof": {"type": "string", "description": "Reproduction evidence (request/response snippet)"},
                    "template": {"type": "string", "description": "Nuclei template id, if this came from a nuclei hit (enables deterministic re-test)"},
                },
                "required": ["target", "title", "severity"],
            },
        },
    ]

    def _tool_map(self):
        return {
            "zap_spider": zap_server.zap_spider,
            "zap_ajax_spider": zap_server.zap_ajax_spider,
            "zap_active_scan": zap_server.zap_active_scan,
            "zap_alerts": zap_server.zap_alerts,
            "nuclei_scan": zap_server.nuclei_scan,
            "record_web_finding": self._record_web_finding,
        }

    # ── Tool implementations ──────────────────────────────────────────────────

    def _record_web_finding(
        self,
        target: str,
        title: str,
        severity: str = "medium",
        cwe: Optional[str] = None,
        url: Optional[str] = None,
        port: Optional[int] = None,
        description: Optional[str] = None,
        proof: Optional[str] = None,
        template: Optional[str] = None,
    ) -> dict:
        mapping = owasp_classify(alert_name=title, cwe=cwe)
        host = _host(target) or target
        vuln = {
            "title": title,
            "severity": severity,
            "description": description or title,
            "cwe": cwe,
            "owasp": mapping["owasp"],
            "owasp_id": mapping["owasp_id"],
            "wstg": mapping["wstg"],
            "url": url,
            "port": port,
        }
        kb.add_vulnerability(host, vuln)
        evidence.log(
            self.NAME, "web_finding", f"[candidate] {title} ({mapping['owasp_id']})",
            target=host,
            result={**vuln, "proof": (proof or "")[:500], "candidate": True},
            severity=severity,
        )
        # C2: register as a CANDIDATE in the finding-state store (separate from the KB
        # — no KB-schema change). AI agents only ever produce candidates.
        sig = finding_state.register_candidate({
            "target": host, "title": title, "severity": severity, "cwe": cwe,
            "url": url, "port": port, "owasp_id": mapping["owasp_id"],
            "source": self.NAME, "template": template, "proof": proof,
        })
        return {
            "recorded": True, "target": host, "title": title,
            "owasp": mapping["owasp_id"], "wstg": mapping["wstg"],
            "state": "candidate", "signature": sig,
        }
