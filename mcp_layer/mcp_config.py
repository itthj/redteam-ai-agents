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

    # ── Custom security-tool server (template — you build this) ───────────────
    "sectools": {
        "transport": "stdio",
        "command": _PY,
        "args": ["-m", "mcp_sectools_server"],
        "description": "Custom MCP server wrapping local security tooling",
        "tool_prefix": "sec",
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
