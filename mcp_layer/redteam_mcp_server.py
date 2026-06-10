"""
mcp_layer/redteam_mcp_server.py
────────────────────────────────
Expose the red-team system AS an MCP server (workstream 5E) — the inverse of the
inbound bridge. Other tools (Claude Desktop, CI, another orchestrator) can drive
this platform over MCP.

The surface is deliberately small. Every handler routes through `Orchestrator`
(dispatch / run_mission / run_autonomous) and the evidence store, so scope
authorization, guardrails, and evidence logging ALL still apply — an external
caller gets no privileged path around the safety layer.

Graceful degradation: the `mcp` SDK is imported lazily, so this module imports
fine without it; `serve()` reports cleanly if it's missing.
"""

from __future__ import annotations

import logging

from core.evidence_store import evidence
from core.orchestrator import Orchestrator

log = logging.getLogger(__name__)


# ── Handlers (plain + testable; all route through the same gated paths) ──────────

async def run_recon(target: str) -> dict:
    """Recon a single in-scope target. Out-of-scope targets are rejected by the
    authorization gate exactly as on the CLI path."""
    result = await Orchestrator().dispatch("recon", f"Perform reconnaissance on {target}")
    return {"agent": "recon", "target": target, "findings": result}


async def run_mission(targets: list[str], phases: list[str] | None = None) -> dict:
    """Run a deterministic kill-chain mission."""
    return await Orchestrator().run_mission(targets, phases)


async def run_autonomous(objective: str, targets: list[str]) -> dict:
    """Run an autonomous engagement — the orchestrator plans and delegates."""
    return await Orchestrator().run_autonomous(objective, targets)


def get_findings(min_severity: str = "medium") -> dict:
    """Findings at or above a severity level."""
    return {"findings": evidence.get_findings(min_severity=min_severity)}


def get_evidence(min_severity: str = "info") -> dict:
    """Evidence records at or above a severity level."""
    return {"records": evidence.get_findings(min_severity=min_severity)}


def verify_chain() -> dict:
    """Verify the tamper-evident evidence chain."""
    return {"chain_valid": evidence.verify_chain()}


_HANDLERS = (run_recon, run_mission, run_autonomous, get_findings, get_evidence, verify_chain)


# ── MCP server wiring (lazy import — graceful degradation) ───────────────────────

def _mcp_available() -> bool:
    try:
        import mcp.server.fastmcp  # noqa: F401
        return True
    except ImportError:
        return False


def build_server():
    """Build a FastMCP server exposing the handlers. Requires the `mcp` SDK."""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("redteam-agents")
    for handler in _HANDLERS:
        server.tool()(handler)
    return server


def serve(transport: str = "stdio") -> None:
    """Run the MCP server over stdio (local) or sse (network)."""
    if not _mcp_available():
        log.error("[MCP-SERVER] `mcp` SDK not installed — run: pip install mcp")
        return
    log.info("[MCP-SERVER] serving red-team agents over %s", transport)
    build_server().run(transport=transport)
