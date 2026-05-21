"""
agents/recon_agent.py
──────────────────────
Reconnaissance Agent — Phase 1: Passive & Active Recon

Responsibilities:
  • DNS enumeration (A, MX, NS, TXT, CNAME records)
  • Reverse DNS lookups
  • Shodan lookups (passive — no packets to target)
  • WHOIS lookups
  • Subdomain discovery
  • Port connectivity checks (light active touch)
  • Populate KnowledgeBase with discovered assets

All passive operations are allowed on ANY target.
Active operations (port knocks, etc.) require authorization check.
"""

from __future__ import annotations

import json
import logging
import socket
import subprocess
from typing import Optional

import dns.resolver
import dns.reversename
import requests

from config.authorization import OperationType
from config.settings import settings
from core.base_agent import BaseAgent
from core.knowledge_base import kb
from core.message_bus import bus

log = logging.getLogger(__name__)


class ReconAgent(BaseAgent):
    NAME = "recon"
    DESCRIPTION = "Passive and active reconnaissance — DNS, OSINT, Shodan, subdomain enumeration"

    SYSTEM_PROMPT = """You are the Reconnaissance Agent in an authorized red-team operation.
Your job is to map the attack surface of the target scope.

RULES:
- ONLY use passive recon (Shodan, DNS, WHOIS) unless explicitly told to do active recon
- NEVER connect to systems outside the authorized scope
- Always explain what you found and why it matters
- Pass all structured findings to the knowledge base via tools

WORKFLOW:
1. Start with DNS lookups on all provided targets/domains
2. Run Shodan lookup if API key available
3. Enumerate subdomains
4. Check for publicly exposed services
5. Summarise findings and recommend next phase (scanning)
"""

    TOOLS = [
        {
            "name": "dns_lookup",
            "description": "Perform DNS lookups (A, MX, NS, TXT, CNAME) on a hostname",
            "input_schema": {
                "type": "object",
                "properties": {
                    "hostname": {"type": "string", "description": "Target hostname or domain"},
                    "record_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "DNS record types to query, e.g. ['A','MX','TXT']",
                    },
                },
                "required": ["hostname"],
            },
        },
        {
            "name": "reverse_dns",
            "description": "Reverse DNS lookup for an IP address",
            "input_schema": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address to reverse-lookup"},
                },
                "required": ["ip"],
            },
        },
        {
            "name": "shodan_lookup",
            "description": "Passive Shodan lookup for an IP or hostname (no packets sent to target)",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "IP address or hostname"},
                },
                "required": ["query"],
            },
        },
        {
            "name": "whois_lookup",
            "description": "WHOIS lookup for a domain or IP",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Domain name or IP"},
                },
                "required": ["target"],
            },
        },
        {
            "name": "enumerate_subdomains",
            "description": "Enumerate common subdomains for a domain using a wordlist",
            "input_schema": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Base domain, e.g. example.com"},
                },
                "required": ["domain"],
            },
        },
        {
            "name": "save_recon_finding",
            "description": "Save a recon finding to the knowledge base",
            "input_schema": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string"},
                    "hostname": {"type": "string"},
                    "finding_type": {
                        "type": "string",
                        "enum": ["hostname", "port", "service", "note"],
                    },
                    "data": {"type": "object", "description": "Finding details"},
                },
                "required": ["finding_type", "data"],
            },
        },
    ]

    def _tool_map(self):
        return {
            "dns_lookup": self._dns_lookup,
            "reverse_dns": self._reverse_dns,
            "shodan_lookup": self._shodan_lookup,
            "whois_lookup": self._whois_lookup,
            "enumerate_subdomains": self._enumerate_subdomains,
            "save_recon_finding": self._save_recon_finding,
        }

    # ── Tool implementations ──────────────────────────────────────────────────

    def _dns_lookup(self, hostname: str, record_types: Optional[list] = None) -> dict:
        record_types = record_types or ["A", "MX", "NS", "TXT"]
        results = {}
        resolver = dns.resolver.Resolver()
        for rtype in record_types:
            try:
                answers = resolver.resolve(hostname, rtype, raise_on_no_answer=False)
                results[rtype] = [str(r) for r in answers]
                # Save A records to KB
                if rtype == "A":
                    for ip in results[rtype]:
                        kb.add_hostname(ip, hostname)
            except Exception as e:
                results[rtype] = {"error": str(e)}
        log.info("[RECON] DNS %s → %s", hostname, list(results.keys()))
        return {"hostname": hostname, "records": results}

    def _reverse_dns(self, ip: str) -> dict:
        try:
            addr = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(addr, "PTR")
            hostnames = [str(r) for r in answers]
            for h in hostnames:
                kb.add_hostname(ip, h.rstrip("."))
            return {"ip": ip, "hostnames": hostnames}
        except Exception as e:
            return {"ip": ip, "error": str(e)}

    def _shodan_lookup(self, query: str) -> dict:
        if not settings.shodan_api_key:
            return {"error": "SHODAN_API_KEY not set — skipping Shodan lookup"}
        try:
            import shodan
            api = shodan.Shodan(settings.shodan_api_key)
            result = api.host(query)
            # Save to KB
            ports = [item["port"] for item in result.get("data", [])]
            for port in ports:
                kb.add_port(result.get("ip_str", query), port)
            return {
                "ip": result.get("ip_str"),
                "org": result.get("org"),
                "os": result.get("os"),
                "ports": ports,
                "hostnames": result.get("hostnames", []),
                "vulns": list(result.get("vulns", {}).keys()),
                "last_update": result.get("last_update"),
            }
        except Exception as e:
            return {"error": str(e)}

    def _whois_lookup(self, target: str) -> dict:
        try:
            result = subprocess.run(
                ["whois", target],
                capture_output=True, text=True, timeout=15
            )
            # Trim to first 60 lines to avoid noise
            lines = result.stdout.splitlines()[:60]
            return {"target": target, "whois": "\n".join(lines)}
        except FileNotFoundError:
            return {"error": "whois not installed (apt install whois)"}
        except Exception as e:
            return {"error": str(e)}

    def _enumerate_subdomains(self, domain: str) -> dict:
        """Try common subdomain prefixes."""
        prefixes = [
            "www", "mail", "smtp", "pop", "imap", "ftp", "sftp", "ssh",
            "vpn", "remote", "admin", "portal", "dev", "staging", "test",
            "api", "app", "auth", "login", "beta", "secure", "internal",
            "intranet", "git", "gitlab", "jenkins", "jira", "confluence",
        ]
        found = []
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 2.0  # fast timeout

        for prefix in prefixes:
            fqdn = f"{prefix}.{domain}"
            try:
                answers = resolver.resolve(fqdn, "A", raise_on_no_answer=False)
                ips = [str(r) for r in answers]
                if ips:
                    found.append({"subdomain": fqdn, "ips": ips})
                    for ip in ips:
                        kb.add_hostname(ip, fqdn)
            except Exception:
                pass

        return {"domain": domain, "found": found, "total": len(found)}

    def _save_recon_finding(
        self,
        finding_type: str,
        data: dict,
        ip: Optional[str] = None,
        hostname: Optional[str] = None,
    ) -> dict:
        target_ip = ip or data.get("ip")
        if target_ip:
            if finding_type == "hostname" and hostname:
                kb.add_hostname(target_ip, hostname)
            elif finding_type == "port":
                kb.add_port(target_ip, data.get("port", 0))
            elif finding_type == "service":
                kb.add_service(target_ip, data.get("port", 0), data)
            elif finding_type == "note":
                kb.add_note(target_ip, str(data))
        return {"saved": True, "type": finding_type}

    # ── Post-run hook ─────────────────────────────────────────────────────────

    async def run(self, task: str, context=None) -> str:
        result = await super().run(task, context)
        # Notify other agents that recon is done
        await bus.publish(
            "recon.complete",
            {"targets": list(kb.get_all_targets().keys())},
            source=self.NAME,
        )
        return result
