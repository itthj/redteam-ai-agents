"""
agents/forensics_agent.py
──────────────────────────
Digital Forensics & Incident Response Agent — Phase 6

Responsibilities:
  • Collect volatile data (running processes, network connections, memory artifacts)
  • Analyze log files for indicators of compromise
  • Build a timeline of attacker activity
  • Preserve evidence with proper chain of custody
  • Identify attacker TTPs (MITRE ATT&CK mapping)
  • Generate forensic artifact inventory
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Optional

from config.settings import settings
from core.attack_framework import attack
from core.base_agent import BaseAgent
from core.evidence_store import evidence

log = logging.getLogger(__name__)


class ForensicsAgent(BaseAgent):
    NAME = "forensics"
    DESCRIPTION = "Digital forensics — artifact collection, timeline analysis, MITRE ATT&CK mapping"

    SYSTEM_PROMPT = """You are the Digital Forensics & Incident Response Agent in an authorized red-team operation.

Your job is to:
1. Document all attacker actions taken during this engagement for the final report
2. Identify what artifacts would be left on compromised systems
3. Map findings to MITRE ATT&CK techniques
4. Build a timeline of the operation
5. Help the client understand what a defender would see

RULES:
- Preserve chain of custody — hash every artifact
- Document IOCs (indicators of compromise) that defenders should monitor
- Map each finding to ATT&CK techniques where possible
- Everything is logged to the tamper-evident evidence store

WORKFLOW:
1. Collect all evidence from the knowledge base
2. Build an operation timeline
3. Map techniques to MITRE ATT&CK
4. Identify detectable artifacts (IOCs)
5. Hash and seal all evidence
"""

    TOOLS = [
        {
            "name": "collect_volatile_data",
            "description": "Generate commands to collect volatile forensic data from a target host",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "platform": {"type": "string", "enum": ["linux", "windows"]},
                },
                "required": ["target", "platform"],
            },
        },
        {
            "name": "analyze_logs",
            "description": "Parse and analyze log file content for indicators of compromise",
            "input_schema": {
                "type": "object",
                "properties": {
                    "log_content": {"type": "string", "description": "Raw log file content"},
                    "log_type": {
                        "type": "string",
                        "enum": ["auth", "syslog", "apache", "nginx", "windows_event", "firewall"],
                    },
                },
                "required": ["log_content", "log_type"],
            },
        },
        {
            "name": "map_to_attack",
            "description": "Map a technique or finding to MITRE ATT&CK framework",
            "input_schema": {
                "type": "object",
                "properties": {
                    "technique_description": {"type": "string"},
                },
                "required": ["technique_description"],
            },
        },
        {
            "name": "build_timeline",
            "description": "Build a chronological operation timeline from all evidence records",
            "input_schema": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
        {
            "name": "hash_artifact",
            "description": "Hash a file or string artifact for evidence chain of custody",
            "input_schema": {
                "type": "object",
                "properties": {
                    "content": {"type": "string", "description": "File content or artifact data"},
                    "label": {"type": "string", "description": "Artifact label/description"},
                },
                "required": ["content", "label"],
            },
        },
        {
            "name": "save_forensic_artifact",
            "description": "Save a forensic artifact to the evidence directory with chain of custody",
            "input_schema": {
                "type": "object",
                "properties": {
                    "label": {"type": "string"},
                    "content": {"type": "string"},
                    "target": {"type": "string"},
                    "artifact_type": {"type": "string", "enum": ["log", "hash", "screenshot", "command_output", "ioc", "timeline"]},
                },
                "required": ["label", "content", "artifact_type"],
            },
        },
    ]

    def _tool_map(self):
        return {
            "collect_volatile_data": self._collect_volatile_data,
            "analyze_logs": self._analyze_logs,
            "map_to_attack": self._map_to_attack,
            "build_timeline": self._build_timeline,
            "hash_artifact": self._hash_artifact,
            "save_forensic_artifact": self._save_forensic_artifact,
        }

    # ── Tool implementations ──────────────────────────────────────────────────

    def _collect_volatile_data(self, target: str, platform: str) -> dict:
        linux_cmds = [
            "date",                             # Timestamp
            "hostname && uname -a",             # System info
            "ps aux --sort=-%cpu",              # Running processes
            "ss -tlnp && netstat -an",          # Network connections
            "last -20",                         # Recent logins
            "who",                              # Logged in users
            "lastlog",                          # Last login per user
            "w",                                # Who + what they're doing
            "history",                          # Shell history
            "find /tmp /var/tmp -type f",       # Files in tmp dirs
            "ls -la /root/.ssh/",              # SSH keys
            "crontab -l 2>/dev/null",           # Crontabs
            "cat /etc/passwd",                  # User accounts
            "find / -mtime -1 -type f 2>/dev/null | head -50",  # Recently modified files
            "dmesg | tail -50",                 # Kernel messages
        ]
        windows_cmds = [
            "date /t && time /t",
            "hostname && systeminfo",
            "tasklist /v",
            "netstat -ano",
            "net session",
            "net user",
            "query user",
            "type %userprofile%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
            "dir %temp%",
            "reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "schtasks /query /fo LIST /v",
            "ipconfig /all",
            "arp -a",
            "net share",
        ]
        cmds = linux_cmds if platform == "linux" else windows_cmds
        return {
            "target": target,
            "platform": platform,
            "commands": cmds,
            "note": "Run these on the target host — preferably via your shell/meterpreter session",
        }

    def _analyze_logs(self, log_content: str, log_type: str) -> dict:
        """Simple pattern-based log analysis for common IOCs."""
        iocs = []
        lines = log_content.splitlines()

        patterns = {
            "auth": [
                (r"Failed password for", "failed_login"),
                (r"Accepted password for root", "root_login"),
                (r"Accepted publickey", "ssh_key_auth"),
                (r"Invalid user", "invalid_user"),
                (r"sudo:.*COMMAND=", "sudo_command"),
            ],
            "apache": [
                (r'"\s*(GET|POST)\s+.*\.php.*" (4|5)\d\d', "web_error"),
                (r"\.\.\/", "path_traversal"),
                (r"(union|select|insert|drop)\s", "sql_injection"),
                (r"<script|javascript:", "xss_attempt"),
            ],
        }

        import re
        relevant_patterns = patterns.get(log_type, [])
        for line in lines:
            for pattern, ioc_type in relevant_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    iocs.append({"type": ioc_type, "line": line.strip()})

        return {
            "log_type": log_type,
            "lines_analyzed": len(lines),
            "iocs_found": len(iocs),
            "iocs": iocs[:50],
        }

    def _map_to_attack(self, technique_description: str) -> dict:
        """Map a described technique to MITRE ATT&CK via the framework module."""
        matches = attack.map_action(technique_description)
        return {
            "description": technique_description,
            "matched_techniques": matches,
            "reference": "https://attack.mitre.org",
        }

    def _build_timeline(self) -> dict:
        """Pull all evidence records, sort by time, and map ATT&CK coverage."""
        records = evidence.get_all()
        timeline = sorted(records, key=lambda r: r.get("timestamp", 0))
        coverage = attack.coverage([r.get("action", "") for r in timeline])
        return {
            "total_events": len(timeline),
            "chain_valid": evidence.verify_chain(),
            "attack_coverage": coverage,
            "timeline": [
                {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r["timestamp"])),
                    "agent": r["agent"],
                    "action": r["action"],
                    "target": r["target"],
                    "severity": r["severity"],
                }
                for r in timeline
            ],
        }

    def _hash_artifact(self, content: str, label: str) -> dict:
        sha256 = hashlib.sha256(content.encode()).hexdigest()
        md5 = hashlib.md5(content.encode()).hexdigest()
        return {"label": label, "sha256": sha256, "md5": md5, "size_bytes": len(content.encode())}

    def _save_forensic_artifact(
        self,
        label: str,
        content: str,
        artifact_type: str,
        target: Optional[str] = None,
    ) -> dict:
        artifact_dir = Path(settings.evidence_dir) / "artifacts"
        artifact_dir.mkdir(exist_ok=True)
        filename = f"{int(time.time())}_{label.replace(' ', '_')[:40]}.txt"
        artifact_path = artifact_dir / filename
        with open(artifact_path, "w") as f:
            f.write(content)
        hashes = self._hash_artifact(content, label)
        evidence.log(
            agent=self.NAME,
            operation="forensics",
            action=f"Artifact collected: {label}",
            target=target,
            result={**hashes, "file": str(artifact_path)},
            severity="info",
        )
        return {"saved": str(artifact_path), **hashes}
