"""
mcp/mcp_config.py
──────────────────
Registry of MCP (Model Context Protocol) servers the agents may connect to.

Each agent gains the tools of every connected server *in addition to* its
own native tools. Enable servers by name via MCP_ENABLED_SERVERS in .env,
e.g.  MCP_ENABLED_SERVERS=filesystem,shodan

Two transports are supported:
  • stdio — the bridge spawns a local process and talks over stdin/stdout
  • sse   — the bridge connects to a remote HTTP/SSE endpoint

These entries are EXAMPLES. Point them at servers you actually have
installed; unreachable servers are skipped with a warning (graceful
degradation — the engagement still runs).
"""

from __future__ import annotations

from config.settings import settings

# ──────────────────────────────────────────────────────────────────────────────
# Server registry.
#
#  transport = "stdio":  requires `command` + `args` (+ optional `env`)
#  transport = "sse":    requires `url` (+ optional `headers`)
# ──────────────────────────────────────────────────────────────────────────────
MCP_SERVERS: dict[str, dict] = {
    # ── Filesystem access scoped to the evidence directory ────────────────────
    # Lets agents read collected artifacts, logs, and prior scan output.
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

    # ── Shodan OSINT (community MCP server) ───────────────────────────────────
    "shodan": {
        "transport": "stdio",
        "command": "uvx",
        "args": ["shodan-mcp-server"],
        "env": {"SHODAN_API_KEY": settings.shodan_api_key},
        "description": "Passive host intelligence via Shodan",
        "tool_prefix": "shodan",
    },

    # ── Web search / fetch — recon enrichment, CVE write-ups ──────────────────
    "web": {
        "transport": "stdio",
        "command": "uvx",
        "args": ["mcp-server-fetch"],
        "description": "Fetch web pages (CVE advisories, vendor docs)",
        "tool_prefix": "web",
    },

    # ── CVE / vulnerability intelligence (remote SSE example) ─────────────────
    "cve": {
        "transport": "sse",
        "url": "http://127.0.0.1:8900/sse",
        "description": "Local CVE intelligence MCP server",
        "tool_prefix": "cve",
    },

    # ── Custom security-tool server (you build this — wraps nmap, etc.) ───────
    "sectools": {
        "transport": "stdio",
        "command": "python",
        "args": ["-m", "mcp_sectools_server"],
        "description": "Custom MCP server wrapping local security tooling",
        "tool_prefix": "sec",
    },
}


def get_enabled_servers() -> dict[str, dict]:
    """Return only the server configs named in MCP_ENABLED_SERVERS."""
    enabled = {}
    for name in settings.mcp_server_list:
        if name in MCP_SERVERS:
            enabled[name] = MCP_SERVERS[name]
        else:
            import logging
            logging.getLogger(__name__).warning(
                "MCP server '%s' is enabled but not in the registry", name
            )
    return enabled
