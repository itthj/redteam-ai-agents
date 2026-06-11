"""
agents/vuln_agent.py
─────────────────────
Vulnerability Assessment Agent — Phase 3

Responsibilities:
  • Query NVD/CVE for services discovered by the scanner
  • Correlate service versions with known CVEs
  • Run targeted nmap NSE vulnerability scripts
  • Assess exploitability (CVSS, public PoC availability)
  • Rank vulnerabilities by severity / exploitability
  • Save findings to KnowledgeBase
"""

from __future__ import annotations

import logging
import subprocess
from typing import Optional

import requests

from config.authorization import OperationType
from config.settings import settings
from core.base_agent import BaseAgent
from core.evidence_store import evidence
from core.finding_state import finding_state
from core.knowledge_base import kb
from core.message_bus import bus

log = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class VulnAgent(BaseAgent):
    NAME = "vuln"
    DESCRIPTION = "Vulnerability assessment — CVE correlation, CVSS scoring, nmap vuln scripts"

    SYSTEM_PROMPT = """You are the Vulnerability Assessment Agent in an authorized red-team operation.

Your job is to identify exploitable vulnerabilities in discovered services.

RULES:
- Cross-reference service/version data from the knowledge base with known CVEs
- Prioritise based on CVSS score AND exploitability (public exploit available?)
- Run nmap NSE vuln scripts for targeted service checks
- Always record CVE IDs and CVSS scores in the knowledge base
- Output a ranked list of vulnerabilities for the exploitation agent

WORKFLOW:
1. Read the knowledge base for all discovered services and versions
2. Query NVD for each service/version combination
3. Run targeted nmap vuln scripts for high-value services (SMB, HTTP, SSH)
4. Score and rank all findings
5. Recommend top 3-5 exploitation paths to the exploitation agent
"""

    TOOLS = [
        {
            "name": "search_nvd",
            "description": "Search NIST NVD for CVEs matching a product/version",
            "input_schema": {
                "type": "object",
                "properties": {
                    "keyword": {"type": "string", "description": "Product name, e.g. 'openssh 7.4'"},
                    "cvss_min": {"type": "number", "description": "Minimum CVSS v3 base score, e.g. 7.0"},
                },
                "required": ["keyword"],
            },
        },
        {
            "name": "run_vuln_scripts",
            "description": "Run nmap NSE vulnerability scripts against a target service",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "port": {"type": "integer"},
                    "scripts": {
                        "type": "string",
                        "description": "NSE script pattern, e.g. 'smb-vuln*' or 'http-vuln*'",
                    },
                },
                "required": ["target", "scripts"],
            },
        },
        {
            "name": "check_default_creds",
            "description": "Check if a service uses default/common credentials",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "port": {"type": "integer"},
                    "service": {"type": "string", "description": "Service name, e.g. 'ssh', 'ftp', 'http'"},
                },
                "required": ["target", "port", "service"],
            },
        },
        {
            "name": "save_vulnerability",
            "description": "Save a confirmed or suspected vulnerability to the knowledge base",
            "input_schema": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string"},
                    "cve": {"type": "string", "description": "CVE ID, e.g. CVE-2021-44228"},
                    "cvss": {"type": "number"},
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                    },
                    "description": {"type": "string"},
                    "port": {"type": "integer"},
                    "exploit_available": {"type": "boolean"},
                },
                "required": ["ip", "severity", "description"],
            },
        },
    ]

    def _tool_map(self):
        return {
            "search_nvd": self._search_nvd,
            "run_vuln_scripts": self._run_vuln_scripts,
            "check_default_creds": self._check_default_creds,
            "save_vulnerability": self._save_vulnerability,
        }

    # ── Tool implementations ──────────────────────────────────────────────────

    def _search_nvd(self, keyword: str, cvss_min: float = 0.0) -> dict:
        params = {"keywordSearch": keyword, "resultsPerPage": 10}
        if settings.nvd_api_key:
            params["apiKey"] = settings.nvd_api_key

        try:
            r = requests.get(NVD_API, params=params, timeout=15)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            return {"error": str(e)}

        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
            metrics = cve.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
            score = 0.0
            severity = "unknown"
            if cvss_v3:
                cvss_data = cvss_v3[0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "unknown")
            if score >= cvss_min:
                results.append({
                    "cve": cve_id,
                    "cvss": score,
                    "severity": severity.lower(),
                    "description": desc[:300],
                })

        return {"keyword": keyword, "count": len(results), "vulnerabilities": results}

    def _run_vuln_scripts(self, target: str, scripts: str, port: Optional[int] = None) -> dict:
        try:
            self._authorize(target, OperationType.VULNERABILITY_SCAN)
        except Exception as e:
            return {"error": str(e)}

        cmd = ["nmap", "-sV", f"--script={scripts}", "--script-timeout", "30s"]
        if port:
            cmd += ["-p", str(port)]
        cmd.append(target)

        log.info("[VULN] Running NSE: %s on %s:%s", scripts, target, port or "all")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {"target": target, "scripts": scripts, "output": result.stdout[-3000:]}
        except FileNotFoundError:
            return {"error": "nmap not found"}
        except subprocess.TimeoutExpired:
            return {"error": "NSE scan timed out"}

    def _check_default_creds(self, target: str, port: int, service: str) -> dict:
        """Use nmap's brute scripts for common default credential checks."""
        try:
            self._authorize(target, OperationType.VULNERABILITY_SCAN)
        except Exception as e:
            return {"error": str(e)}

        script_map = {
            "ftp": "ftp-brute",
            "ssh": "ssh-brute",
            "http": "http-default-accounts",
            "telnet": "telnet-brute",
            "snmp": "snmp-brute",
        }
        script = script_map.get(service.lower())
        if not script:
            return {"error": f"No default-cred script for service '{service}'"}

        cmd = ["nmap", f"--script={script}", "--script-args=brute.mode=user", "-p", str(port), target]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return {"target": target, "service": service, "output": result.stdout[-2000:]}
        except Exception as e:
            return {"error": str(e)}

    def _save_vulnerability(
        self,
        ip: str,
        severity: str,
        description: str,
        cve: Optional[str] = None,
        cvss: Optional[float] = None,
        port: Optional[int] = None,
        exploit_available: bool = False,
    ) -> dict:
        vuln = {
            "cve": cve,
            "cvss": cvss,
            "severity": severity,
            "description": description,
            "port": port,
            "exploit_available": exploit_available,
        }
        kb.add_vulnerability(ip, vuln)
        evidence.log(
            agent=self.NAME,
            operation="vulnerability_found",
            action=f"Vulnerability: {cve or description[:50]}",
            target=ip,
            result=vuln,
            severity=severity,
        )
        # C2: register as a CANDIDATE finding (AI agents only ever produce candidates).
        sig = finding_state.register_candidate({
            "target": ip, "title": description, "severity": severity, "cve": cve,
            "cvss": cvss, "port": port, "source": self.NAME,
        })
        return {"saved": True, "ip": ip, "cve": cve, "signature": sig, "state": "candidate"}

    async def run(self, task: str, context=None) -> str:
        result = await super().run(task, context)
        vulns = [
            v
            for t in kb.get_all_targets().values()
            for v in t.get("vulnerabilities", [])
        ]
        await bus.publish("vuln.assessment_complete", {"total_vulns": len(vulns)}, source=self.NAME)
        return result
