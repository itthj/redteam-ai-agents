"""
mcp_layer/mcp_config.py
────────────────────────
Registry of MCP (Model Context Protocol) servers the agents may connect to.

Each agent gains the tools of every connected server *in addition to* its
own native tools. Enable servers by name via MCP_ENABLED_SERVERS in .env,
e.g.  MCP_ENABLED_SERVERS=web,filesystem

Two transports are supported:
  • stdio — the bridge spawns a local process and talks over stdin/stdout
  • sse   — the bridge connects to a remote HTTP/SSE endpoint

Unreachable / not-installed servers are skipped with a warning (graceful
degradation — the engagement still runs on the agents' native tools).
"""

from __future__ import annotations

import sys

from config.settings import settings

# Absolute path to the running interpreter — guarantees Python-based MCP
# servers launch under the same environment that has their packages installed.
_PY = sys.executable

# ──────────────────────────────────────────────────────────────────────────────
# Server registry.
#   transport="stdio": requires `command` + `args` (+ optional `env`)
#   transport="sse"  : requires `url` (+ optional `headers`)
# ──────────────────────────────────────────────────────────────────────────────
MCP_SERVERS: dict[str, dict] = {

    # ── Web fetch — READY TO USE ──────────────────────────────────────────────
    # Official MCP fetch server. Pure Python, no Node/uv needed.
    # Install:  pip install mcp-server-fetch
    # Gives agents a `fetch` tool — pull CVE advisories, vendor security
    # bulletins, and exploit write-ups straight into the engagement.
    "web": {
        "transport": "stdio",
        "command": _PY,
        "args": ["-m", "mcp_server_fetch"],
        "description": "Fetch web pages (CVE advisories, vendor docs, PoCs)",
        "tool_prefix": "web",
    },

    # ── Filesystem access scoped to the evidence directory ────────────────────
    # Official Node server. Requires Node + npx.
    # On Windows, PowerShell's execution policy can block npx.ps1 — if so:
    #   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
    # Install is automatic via `npx -y`.
    "filesystem": {
        "transport": "stdio",
        "command": "npx",
        "args": [
            "-y",
            "@modelcontextprotocol/server-filesystem",
            str(settings.evidence_dir),
        ],
        "description": "Read/list files in the evidence directory",
        "tool_prefix": "fs",
        # READ-ONLY subset only — keeps the tool surface lean and prevents
        # agents from writing/editing/moving files in the evidence chain.
        "tool_allowlist": [
            "read_text_file",
            "read_multiple_files",
            "list_directory",
            "directory_tree",
            "search_files",
            "get_file_info",
        ],
    },

    # ── Shodan OSINT (optional — needs `uv` + SHODAN_API_KEY) ─────────────────
    # Install uv:  pip install uv     (then uvx fetches the server on demand)
    "shodan": {
        "transport": "stdio",
        "command": "uvx",
        "args": ["shodan-mcp-server"],
        "env": {"SHODAN_API_KEY": settings.shodan_api_key},
        "description": "Passive host intelligence via Shodan",
        "tool_prefix": "shodan",
    },

    # ── CVE intelligence (template — remote SSE server you run separately) ────
    "cve": {
        "transport": "sse",
        "url": "http://127.0.0.1:8900/sse",
        "description": "Local CVE intelligence MCP server",
        "tool_prefix": "cve",
    },

    # ── Web application testing (C1) — OWASP ZAP + Nuclei, in-repo server ─────
    # Spider / AJAX spider / active scan / alerts (via the zaproxy client) + Nuclei
    # (subprocess). Active scan & nuclei are intrusive → gated by scope + the
    # WEBAPP_ACTIVE_SCAN_AUTHORIZED written-authorization flag inside the handlers.
    # Degrades gracefully if ZAP/nuclei are absent. Also used natively by webapp_agent.
    "webapp": {
        "transport": "stdio",
        "command": _PY,
        "args": ["-m", "mcp_layer.servers.zap_server"],
        "description": "Web app testing — OWASP ZAP (spider/active scan/alerts) + Nuclei",
        "tool_prefix": "webapp",
        "tool_allowlist": ["zap_spider", "zap_ajax_spider", "zap_active_scan",
                           "zap_alerts", "nuclei_scan"],
    },

    # ── Phishing / social engineering (C6) — in-repo GoPhish server ───────────
    # Strongly gated: campaigns need PHISHING_AUTHORIZED + a named human approver, and
    # every recipient must be inside an authorized client email domain. Degrades cleanly.
    "social_eng": {
        "transport": "stdio",
        "command": _PY,
        "args": ["-m", "mcp_layer.servers.gophish_server"],
        "description": "Phishing / social engineering — GoPhish (authorized, gated)",
        "tool_prefix": "phish",
        "tool_allowlist": ["gp_list_campaigns", "gp_campaign_results", "gp_create_template",
                           "gp_create_landing_page", "gp_create_sending_profile",
                           "gp_create_group", "gp_launch_campaign"],
    },

    # ── Custom security-tool server (template — you build this) ───────────────
    "sectools": {
        "transport": "stdio",
        "command": _PY,
        "args": ["-m", "mcp_sectools_server"],
        "description": "Custom MCP server wrapping local security tooling",
        "tool_prefix": "sec",
    },

    # ── 5D fleet — each entry mirrors shodan/cve; tight tool_allowlist per the
    #    "right tools, not more tools" principle. Unreachable servers skip cleanly.

    # Nuclei — templated vuln scanning (feeds the vuln agent).
    "nuclei": {
        "transport": "stdio",
        "command": "uvx",
        "args": ["nuclei-mcp-server"],
        "description": "Templated vulnerability scanning (Nuclei)",
        "tool_prefix": "nuclei",
        "tool_allowlist": ["nuclei_scan", "list_templates"],
    },

    # theHarvester — OSINT emails / subdomains / hosts (feeds recon).
    "theharvester": {
        "transport": "stdio",
        "command": "uvx",
        "args": ["theharvester-mcp-server"],
        "description": "OSINT — emails, subdomains, hosts (theHarvester)",
        "tool_prefix": "osint",
        "tool_allowlist": ["harvest_emails", "harvest_subdomains", "harvest_hosts"],
    },

    # BloodHound / AD — read-only attack-path data to enrich the 2A graph.
    "bloodhound": {
        "transport": "sse",
        "url": "http://127.0.0.1:8910/sse",
        "description": "Active Directory attack paths (BloodHound, read-only)",
        "tool_prefix": "bh",
        "tool_allowlist": ["query_paths", "shortest_path_to_da", "list_owned"],
    },

    # ── Active Directory / Windows testing (C5) — in-repo server ──────────────
    # BloodHound CE (REST) + bloodhound-python + NetExec + Impacket + Certipy, for
    # the credential_access / lateral_movement phase agents. Read/enumeration is
    # scope-gated; state-changing nxc_exec is additionally written-authorization-gated
    # (AD_STATE_CHANGE_AUTHORIZED) and guardrail-checked. Degrades gracefully.
    "ad": {
        "transport": "stdio",
        "command": _PY,
        "args": ["-m", "mcp_layer.servers.ad_server"],
        "description": "AD/Windows — BloodHound CE, NetExec, Impacket, Certipy",
        "tool_prefix": "ad",
        "tool_allowlist": ["bh_collect", "bh_shortest_path", "nxc_enum",
                           "secretsdump", "certipy_find", "nxc_exec"],
    },

    # Threat intel — GreyNoise / VirusTotal CVE & IP enrichment (read-only).
    "threatintel": {
        "transport": "stdio",
        "command": "uvx",
        "args": ["threatintel-mcp-server"],
        "env": {"GREYNOISE_API_KEY": settings.greynoise_api_key,
                "VIRUSTOTAL_API_KEY": settings.virustotal_api_key},
        "description": "GreyNoise / VirusTotal enrichment (read-only)",
        "tool_prefix": "ti",
        "tool_allowlist": ["greynoise_ip", "virustotal_hash", "virustotal_domain"],
    },

    # SIEM — read-only query (Splunk/Elastic/Sentinel); future detection scorecard.
    "siem": {
        "transport": "sse",
        "url": "http://127.0.0.1:8920/sse",
        "headers": {"Authorization": f"Bearer {settings.siem_token}"},
        "description": "SIEM read-only query (Splunk/Elastic/Sentinel)",
        "tool_prefix": "siem",
        "tool_allowlist": ["search", "list_indexes"],
    },
}


def get_enabled_servers() -> dict[str, dict]:
    """Return only the server configs named in MCP_ENABLED_SERVERS."""
    import logging

    enabled = {}
    for name in settings.mcp_server_list:
        if name in MCP_SERVERS:
            enabled[name] = MCP_SERVERS[name]
        else:
            logging.getLogger(__name__).warning(
                "MCP server '%s' is enabled but not in the registry", name
            )
    return enabled
