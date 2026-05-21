"""
mcp/mcp_bridge.py
──────────────────
The MCP integration layer — connects agents to external tools, databases,
and services through the Model Context Protocol.

Design:
  • connect()            — for every enabled server, open a session, discover
                           its tools, cache the schemas, close the session.
  • get_anthropic_tools() — returns discovered tools in Anthropic tool-use
                           format, namespaced  mcp_<prefix>_<tool>  so they
                           never collide with an agent's native tools.
  • call_tool()           — routes a namespaced call to the owning server,
                           opens a short-lived session, executes, returns.

Why short-lived sessions: MCP's transport uses anyio task scopes that do not
survive being opened in one task and closed in another. Ephemeral sessions
(open → call → close, all in one task) are bulletproof. For a security
engagement the per-call spawn cost is negligible.

Graceful degradation: if the `mcp` package is missing, or a server is
unreachable, the bridge logs a warning and continues — the engagement still
runs on the agents' native tools.
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import AsyncExitStack
from typing import Any

from mcp_layer.mcp_config import get_enabled_servers

log = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 45.0   # seconds to wait for a server handshake (cold npx installs are slow)
_CALL_TIMEOUT = 90.0      # seconds to wait for a tool call


def _mcp_available() -> bool:
    """True if the `mcp` Python SDK is importable."""
    try:
        import mcp  # noqa: F401
        return True
    except ImportError:
        return False


class MCPBridge:
    """Connects agents to MCP servers and routes their tool calls."""

    def __init__(self) -> None:
        # server name → config dict
        self._servers: dict[str, dict] = {}
        # exposed (namespaced) tool name → (server_name, real_tool_name)
        self._routes: dict[str, tuple[str, str]] = {}
        # cached Anthropic-format tool schemas
        self._tool_schemas: list[dict] = []
        self._connected = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self) -> dict:
        """
        Discover tools from every enabled MCP server.
        Returns a summary dict. Safe to call once at engagement start.
        """
        if self._connected:
            return self.summary()

        self._connected = True  # mark attempted even if nothing connects

        if not _mcp_available():
            log.warning("[MCP] `mcp` package not installed — MCP layer disabled. "
                        "Install with: pip install mcp")
            return self.summary()

        self._servers = get_enabled_servers()
        if not self._servers:
            log.info("[MCP] No MCP servers enabled (set MCP_ENABLED_SERVERS in .env)")
            return self.summary()

        for name, cfg in self._servers.items():
            try:
                await asyncio.wait_for(self._discover(name, cfg), timeout=_CONNECT_TIMEOUT)
            except asyncio.TimeoutError:
                log.warning("[MCP] Server '%s' timed out during discovery — skipped", name)
            except Exception as e:
                log.warning("[MCP] Server '%s' unavailable (%s) — skipped", name, e)

        log.info("[MCP] Connected: %d servers, %d tools discovered",
                 len({s for s, _ in self._routes.values()}), len(self._tool_schemas))
        return self.summary()

    async def _discover(self, name: str, cfg: dict) -> None:
        """Open a session, list tools, cache namespaced schemas, close.

        If the server config defines `tool_allowlist`, only those tools are
        exposed — keeps the agents' tool surface lean and drops capabilities
        we don't want (e.g. filesystem write tools near the evidence chain).
        """
        prefix = cfg.get("tool_prefix", name)
        allowlist = cfg.get("tool_allowlist")  # None → expose every tool
        async with AsyncExitStack() as stack:
            session = await self._open_session(stack, cfg)
            tools_result = await session.list_tools()
            for tool in tools_result.tools:
                if allowlist is not None and tool.name not in allowlist:
                    continue
                exposed = f"mcp_{prefix}_{tool.name}"
                self._routes[exposed] = (name, tool.name)
                self._tool_schemas.append({
                    "name": exposed,
                    "description": f"[MCP:{name}] {tool.description or tool.name}",
                    "input_schema": tool.inputSchema or {"type": "object", "properties": {}},
                })
        log.info("[MCP] '%s' → %d tools", name,
                 sum(1 for s, _ in self._routes.values() if s == name))

    async def _open_session(self, stack: AsyncExitStack, cfg: dict):
        """Open and initialize an MCP ClientSession over the configured transport."""
        from mcp import ClientSession

        transport = cfg.get("transport", "stdio")

        if transport == "stdio":
            from mcp import StdioServerParameters
            from mcp.client.stdio import stdio_client

            env = {**os.environ}
            env.update({k: v for k, v in cfg.get("env", {}).items() if v})
            params = StdioServerParameters(
                command=cfg["command"],
                args=cfg.get("args", []),
                env=env,
            )
            read, write = await stack.enter_async_context(stdio_client(params))

        elif transport == "sse":
            from mcp.client.sse import sse_client

            read, write = await stack.enter_async_context(
                sse_client(cfg["url"], headers=cfg.get("headers"))
            )
        else:
            raise ValueError(f"Unknown MCP transport: {transport}")

        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        return session

    # ── Tool surface ──────────────────────────────────────────────────────────

    def get_anthropic_tools(self) -> list[dict]:
        """Return discovered MCP tools as Anthropic tool-use definitions."""
        return list(self._tool_schemas)

    def owns_tool(self, tool_name: str) -> bool:
        """True if `tool_name` is an MCP-routed tool."""
        return tool_name in self._routes

    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """
        Execute a namespaced MCP tool call. Opens a short-lived session,
        runs the tool, returns {content, is_error}.
        """
        if tool_name not in self._routes:
            return {"content": f"Unknown MCP tool: {tool_name}", "is_error": True}

        server_name, real_tool = self._routes[tool_name]
        cfg = self._servers[server_name]
        try:
            return await asyncio.wait_for(
                self._invoke(cfg, real_tool, arguments),
                timeout=_CALL_TIMEOUT,
            )
        except asyncio.TimeoutError:
            return {"content": f"MCP tool '{tool_name}' timed out", "is_error": True}
        except Exception as e:
            log.error("[MCP] Tool '%s' failed: %s", tool_name, e)
            return {"content": f"MCP tool error: {e}", "is_error": True}

    async def _invoke(self, cfg: dict, real_tool: str, arguments: dict) -> dict:
        async with AsyncExitStack() as stack:
            session = await self._open_session(stack, cfg)
            result = await session.call_tool(real_tool, arguments)

        # Flatten MCP content blocks into text
        parts: list[str] = []
        for block in getattr(result, "content", []) or []:
            text = getattr(block, "text", None)
            if text is not None:
                parts.append(text)
            elif getattr(block, "type", None) == "image":
                parts.append("[image content omitted]")
        return {
            "content": "\n".join(parts) if parts else "(no output)",
            "is_error": bool(getattr(result, "isError", False)),
        }

    # ── Info ──────────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        servers = sorted({s for s, _ in self._routes.values()})
        return {
            "mcp_available": _mcp_available(),
            "connected_servers": servers,
            "tool_count": len(self._tool_schemas),
            "tools": [t["name"] for t in self._tool_schemas],
        }


# Module-level singleton — shared by all agents
bridge = MCPBridge()
