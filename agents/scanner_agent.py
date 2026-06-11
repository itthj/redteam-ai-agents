"""
agents/scanner_agent.py
────────────────────────
Port Scanner & Service Fingerprinting Agent — Phase 2

Responsibilities:
  • Nmap port scanning (TCP SYN, TCP connect, UDP)
  • Service version detection (-sV)
  • OS fingerprinting (-O)
  • Script scanning for common services (--script=default)
  • Banner grabbing
  • All results saved to KnowledgeBase

REQUIRES: nmap installed on host (`apt install nmap`)
AUTHORIZATION: Active scan — must check target scope before every scan.
"""

from __future__ import annotations

import logging
import socket
import subprocess
from typing import Optional

from config.authorization import OperationType
from core.base_agent import BaseAgent
from core.knowledge_base import kb
from core.message_bus import bus

log = logging.getLogger(__name__)


class ScannerAgent(BaseAgent):
    NAME = "scanner"
    DESCRIPTION = "Port scanning and service fingerprinting using nmap"

    SYSTEM_PROMPT = """You are the Port Scanner & Service Fingerprinting Agent in an authorized red-team operation.

Your job is to discover open ports and running services on authorized targets.

RULES:
- ALWAYS verify the target is in the authorized scope before scanning
- Start with a light SYN scan, escalate to version/script detection
- Look for high-value services: SSH, HTTP/S, SMB, RDP, FTP, databases, management interfaces
- Record every finding in the knowledge base
- Flag services that are unusual, old versions, or typically vulnerable

WORKFLOW:
1. Run TCP SYN scan on common ports first (fast)
2. Run targeted version detection on discovered open ports
3. Run default NSE scripts on interesting services
4. Summarise and rank services by attack surface value
5. Notify the vulnerability assessment agent
"""

    TOOLS = [
        {
            "name": "nmap_scan",
            "description": "Run an nmap scan on a target IP or range",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address, hostname, or CIDR range"},
                    "ports": {"type": "string", "description": "Port range, e.g. '1-1024' or 'top1000' (default)"},
                    "scan_type": {
                        "type": "string",
                        "enum": ["syn", "connect", "udp", "version", "script", "aggressive"],
                        "description": "Scan type: syn=SYN scan, version=service detection, script=NSE scripts, aggressive=all",
                    },
                    "extra_args": {"type": "string", "description": "Additional nmap args, e.g. '--script=smb-vuln*'"},
                },
                "required": ["target"],
            },
        },
        {
            "name": "banner_grab",
            "description": "Grab the service banner from a specific port",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "port": {"type": "integer"},
                    "timeout": {"type": "number", "description": "Seconds to wait, default 3"},
                },
                "required": ["target", "port"],
            },
        },
        {
            "name": "save_scan_results",
            "description": "Save scan results to the knowledge base",
            "input_schema": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string"},
                    "ports": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "integer"},
                                "state": {"type": "string"},
                                "service": {"type": "string"},
                                "version": {"type": "string"},
                            },
                        },
                    },
                    "os_guess": {"type": "string"},
                },
                "required": ["ip"],
            },
        },
    ]

    def _tool_map(self):
        return {
            "nmap_scan": self._nmap_scan,
            "banner_grab": self._banner_grab,
            "save_scan_results": self._save_scan_results,
        }

    # ── Tool implementations ──────────────────────────────────────────────────

    def _nmap_scan(
        self,
        target: str,
        ports: str = "top1000",
        scan_type: str = "syn",
        extra_args: str = "",
    ) -> dict:
        # Authorization gate
        try:
            self._authorize(target, OperationType.ACTIVE_SCAN)
        except Exception as e:
            return {"error": str(e)}

        scan_flags = {
            "syn": ["-sS"],
            "connect": ["-sT"],
            "udp": ["-sU"],
            "version": ["-sV", "--version-intensity", "5"],
            "script": ["-sC"],
            "aggressive": ["-A"],
        }.get(scan_type, ["-sS"])

        port_args = ["--top-ports", "1000"] if ports == "top1000" else ["-p", ports]
        extra = extra_args.split() if extra_args else []

        cmd = (
            ["nmap", "-oX", "-", "--open"]
            + scan_flags
            + port_args
            + extra
            + [target]
        )

        log.info("[SCANNER] Running: %s", " ".join(cmd))
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return self._parse_nmap_xml(result.stdout, target)
        except FileNotFoundError:
            return {"error": "nmap not found — install with: apt install nmap"}
        except subprocess.TimeoutExpired:
            return {"error": "nmap scan timed out after 300s"}
        except Exception as e:
            return {"error": str(e)}

    def _parse_nmap_xml(self, xml_output: str, target: str) -> dict:
        """Parse nmap XML output into a structured dict."""
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_output)
            hosts = []
            for host in root.findall("host"):
                addr_el = host.find("address[@addrtype='ipv4']")
                ip = addr_el.get("addr") if addr_el is not None else target

                ports_data = []
                for port in host.findall(".//port"):
                    state = port.find("state")
                    service = port.find("service")
                    ports_data.append({
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", "tcp"),
                        "state": state.get("state") if state is not None else "unknown",
                        "service": service.get("name") if service is not None else "",
                        "product": service.get("product", "") if service is not None else "",
                        "version": service.get("version", "") if service is not None else "",
                        "extrainfo": service.get("extrainfo", "") if service is not None else "",
                    })

                os_guess = None
                os_el = host.find(".//osmatch")
                if os_el is not None:
                    os_guess = f"{os_el.get('name')} ({os_el.get('accuracy')}%)"

                # Save to KB
                self._save_scan_results(ip=ip, ports=ports_data, os_guess=os_guess)

                hosts.append({"ip": ip, "ports": ports_data, "os": os_guess})

            return {"hosts": hosts, "raw_xml": xml_output[:2000]}
        except ET.ParseError:
            return {"raw": xml_output[:3000]}

    def _banner_grab(self, target: str, port: int, timeout: float = 3.0) -> dict:
        try:
            self._authorize(target, OperationType.ACTIVE_SCAN)
        except Exception as e:
            return {"error": str(e)}
        try:
            with socket.create_connection((target, port), timeout=timeout) as s:
                s.settimeout(timeout)
                # Send a basic probe
                s.sendall(b"\r\n")
                banner = s.recv(1024).decode("utf-8", errors="replace").strip()
            return {"target": target, "port": port, "banner": banner}
        except Exception as e:
            return {"target": target, "port": port, "error": str(e)}

    def _save_scan_results(
        self,
        ip: str,
        ports: Optional[list] = None,
        os_guess: Optional[str] = None,
    ) -> dict:
        if ports:
            for p in ports:
                if p.get("state") == "open":
                    kb.add_port(ip, p["port"], p.get("protocol", "tcp"))
                    if p.get("service"):
                        kb.add_service(ip, p["port"], {
                            "name": p["service"],
                            "product": p.get("product", ""),
                            "version": p.get("version", ""),
                        })
        target_data = kb.ensure_target(ip)
        if os_guess:
            target_data["os_guess"] = os_guess
            kb.save()
        return {"saved": True, "ip": ip}

    async def run(self, task: str, context=None) -> str:
        result = await super().run(task, context)
        await bus.publish("scan.complete", {"targets": list(kb.get_all_targets().keys())}, source=self.NAME)
        return result
