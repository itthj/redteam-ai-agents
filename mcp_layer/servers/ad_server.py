"""
mcp_layer/servers/ad_server.py
───────────────────────────────
Active Directory / Windows testing MCP server (capability C5) — wraps **BloodHound CE**
(REST API), **bloodhound-python** (collector), **NetExec (nxc)**, **Impacket**, and
**Certipy**, for the existing `credential_access` and `lateral_movement` phase agents.

Read-first by design: collection, enumeration, attack-path queries, and ESC discovery
are allowed in scope. STATE-CHANGING actions (NetExec command execution, Certipy
certificate requests) are intrusive — they route through the same gates as the rest of
the platform:

  • `scope.authorize(host, op)` — the engagement scope gate, on the target host.
  • `approval.require(...)`     — state-changing actions need the per-engagement
                                  AD_STATE_CHANGE_AUTHORIZED written-authorization flag.
  • `guardrails.check_command` — destructive commands are blocked.
  • `evidence.log(...)`         — every action + recovered attack path is chained.

Graceful degradation: missing tool / unreachable BHCE ⇒ a `degraded` result, never a
crash. Attack paths are recorded as evidence and mirrored into the KB (which feeds the
2A attack graph via its sink).
"""

from __future__ import annotations

import logging
import shutil
import subprocess

import requests

from config.authorization import AuthorizationError, OperationType, scope
from config.settings import settings
from core.approval import AuthorizationRequired, approval
from core.evidence_store import evidence
from core.guardrails import GuardrailViolation, guardrails
from core.knowledge_base import kb

log = logging.getLogger(__name__)

_AGENT = "ad"
_SUBPROC_TIMEOUT = 300
_HTTP_TIMEOUT = 30


# ── Availability helpers (graceful degradation) ─────────────────────────────────

def _which(binary: str) -> str | None:
    return shutil.which(binary)


def _authorize(host: str, op: OperationType) -> dict | None:
    """Run the scope gate; return a blocked-result dict on failure, else None."""
    try:
        scope.authorize(host, op, agent_name=_AGENT)
        return None
    except AuthorizationError as e:
        evidence.log(_AGENT, "scope_block", str(e), target=host, severity="high")
        return {"error": str(e), "blocked": True}


def _run(cmd: list[str]) -> dict:
    """Run a subprocess with graceful degradation. Returns {output|degraded|error}."""
    if not _which(cmd[0]):
        log.warning("[AD] %s not found — install it on the run host", cmd[0])
        return {"error": f"{cmd[0]} not found on host", "degraded": True}
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=_SUBPROC_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"error": f"{cmd[0]} timed out", "degraded": True}
    except Exception as e:  # noqa: BLE001 — graceful degradation
        return {"error": f"{cmd[0]} failed: {e}", "degraded": True}
    return {"exit_code": result.returncode, "output": (result.stdout + result.stderr)[-4000:]}


# ── Read / enumeration handlers ─────────────────────────────────────────────────

async def bh_collect(domain: str, dc_ip: str, username: str, password: str) -> dict:
    """Collect AD data with bloodhound-python (ce branch). Read-only enumeration."""
    blocked = _authorize(dc_ip, OperationType.POST_EXPLOITATION)
    if blocked:
        return blocked
    res = _run(["bloodhound-python", "-d", domain, "-u", username, "-p", password,
                "-dc", dc_ip, "-c", "all", "--zip"])
    if not res.get("degraded"):
        evidence.log(_AGENT, "bh_collect", f"Collected AD data for {domain}",
                     target=dc_ip, result={"exit_code": res.get("exit_code")}, severity="info")
    return res


def _bhce_request(path: str, payload: dict) -> dict:
    """POST to the BloodHound CE API. Degrades gracefully when unreachable."""
    headers = {"Content-Type": "application/json"}
    if settings.bloodhound_ce_token:
        headers["Authorization"] = f"Bearer {settings.bloodhound_ce_token}"
    try:
        r = requests.post(f"{settings.bloodhound_ce_url}{path}", headers=headers,
                          json=payload, timeout=_HTTP_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:  # noqa: BLE001 — graceful degradation
        log.warning("[AD] BloodHound CE request failed: %s", e)
        return {"_degraded": str(e)}


async def bh_shortest_path(goal: str = "Domain Admins", start: str | None = None) -> dict:
    """Query BloodHound CE for the shortest path to a high-value target, record it as
    evidence, and mirror the involved hosts into the KB (→ 2A attack graph)."""
    cypher = (
        "MATCH p=shortestPath((s)-[*1..]->(t:Group)) "
        f"WHERE t.name STARTS WITH '{goal.upper()}' "
        + (f"AND s.name = '{start.upper()}' " if start else "")
        + "RETURN p LIMIT 1"
    )
    data = _bhce_request("/api/v2/graphs/cypher", {"query": cypher})
    if data.get("_degraded"):
        return {"error": "BloodHound CE unreachable", "degraded": True}

    nodes = _extract_path_nodes(data)
    evidence.log(_AGENT, "bh_shortest_path",
                 f"Attack path to {goal}: {' -> '.join(nodes) if nodes else 'none found'}",
                 result={"goal": goal, "path": nodes, "length": len(nodes)},
                 severity="high" if nodes else "info")
    # Mirror computers on the path into the KB so the 2A graph/planner sees them.
    for node in nodes:
        if node and node.endswith("$"):       # a computer account
            kb.add_note(node.rstrip("$"), f"[ad] on attack path to {goal}")
    return {"goal": goal, "path": nodes, "length": len(nodes)}


def _extract_path_nodes(data: dict) -> list[str]:
    """Pull node labels from a BHCE graph response (best-effort across shapes)."""
    nodes = data.get("data", {}).get("nodes") or data.get("nodes") or {}
    if isinstance(nodes, dict):
        return [v.get("label") or v.get("name") or k for k, v in nodes.items()]
    if isinstance(nodes, list):
        return [n.get("label") or n.get("name") or str(n.get("id")) for n in nodes]
    return []


async def nxc_enum(target: str, protocol: str = "smb", username: str | None = None,
                   password: str | None = None, what: str = "shares") -> dict:
    """Enumerate a host with NetExec (read-only): shares, users, or sessions."""
    blocked = _authorize(target, OperationType.POST_EXPLOITATION)
    if blocked:
        return blocked
    flag = {"shares": "--shares", "users": "--users", "sessions": "--sessions",
            "loggedon": "--loggedon-users", "pass-pol": "--pass-pol"}.get(what, "--shares")
    cmd = [settings.netexec_path, protocol, target]
    if username is not None:
        cmd += ["-u", username, "-p", password or ""]
    cmd.append(flag)
    res = _run(cmd)
    if not res.get("degraded"):
        evidence.log(_AGENT, "nxc_enum", f"NetExec {protocol} {what} on {target}",
                     target=target, result={"exit_code": res.get("exit_code")}, severity="info")
    return res


async def secretsdump(target: str, username: str, password: str,
                      domain: str | None = None) -> dict:
    """Dump secrets from a host with impacket-secretsdump (credential access)."""
    blocked = _authorize(target, OperationType.POST_EXPLOITATION)
    if blocked:
        return blocked
    binary = "impacket-secretsdump" if _which("impacket-secretsdump") else "secretsdump.py"
    creds = f"{domain + '/' if domain else ''}{username}:{password}@{target}"
    res = _run([binary, creds])
    if not res.get("degraded"):
        # Record only that secrets were dumped + a count, never plaintext (guardrails).
        n = res.get("output", "").count(":::")
        evidence.log(_AGENT, "secretsdump", f"Dumped {n} secret hash(es) from {target}",
                     target=target, result={"hash_count": n}, severity="high")
        res["hash_count"] = n
        res["output"] = guardrails.sanitize(res.get("output", ""))
    return res


async def certipy_find(target: str, username: str, password: str, domain: str) -> dict:
    """Find vulnerable AD CS templates (ESC1-8) with Certipy. Read-only discovery."""
    blocked = _authorize(target, OperationType.POST_EXPLOITATION)
    if blocked:
        return blocked
    res = _run(["certipy", "find", "-u", f"{username}@{domain}", "-p", password,
                "-dc-ip", target, "-vulnerable", "-stdout"])
    if not res.get("degraded"):
        evidence.log(_AGENT, "certipy_find", f"AD CS template discovery on {target}",
                     target=target, result={"exit_code": res.get("exit_code")}, severity="info")
    return res


# ── State-changing handler (gated) ──────────────────────────────────────────────

async def nxc_exec(target: str, username: str, password: str, command: str,
                   protocol: str = "smb") -> dict:
    """Execute a command on a host via NetExec — STATE-CHANGING. Scope-gated, written-
    authorization-gated, and guardrail-checked."""
    blocked = _authorize(target, OperationType.AD_STATE_CHANGE)
    if blocked:
        return blocked
    try:
        approval.require("ad_state_change",
                         authorized=settings.ad_state_change_authorized,
                         target=target, agent=_AGENT)
    except AuthorizationRequired as e:
        return {"error": str(e), "blocked": True}
    try:
        guardrails.check_command(command, context="ad.nxc_exec")
    except GuardrailViolation as e:
        evidence.log(_AGENT, "guardrail_block", str(e), target=target, severity="high")
        return {"error": f"GUARDRAIL BLOCK: {e}", "blocked": True}
    res = _run([settings.netexec_path, protocol, target, "-u", username, "-p", password,
                "-x", command])
    if not res.get("degraded"):
        evidence.log(_AGENT, "nxc_exec", f"Executed on {target}: {command[:80]}",
                     target=target, result={"exit_code": res.get("exit_code")}, severity="medium")
    return res


_HANDLERS = (bh_collect, bh_shortest_path, nxc_enum, secretsdump, certipy_find, nxc_exec)


# ── MCP server wiring (lazy import — graceful degradation) ───────────────────────

def _mcp_available() -> bool:
    try:
        import mcp.server.fastmcp  # noqa: F401
        return True
    except ImportError:
        return False


def build_server():
    """Build a FastMCP server exposing the AD handlers. Requires the `mcp` SDK."""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("redteam-ad")
    for handler in _HANDLERS:
        server.tool()(handler)
    return server


def serve(transport: str = "stdio") -> None:
    """Run the AD MCP server over stdio (local) or sse (network)."""
    if not _mcp_available():
        log.error("[AD-MCP] `mcp` SDK not installed — run: pip install mcp")
        return
    log.info("[AD-MCP] serving BloodHound CE / NetExec / Impacket / Certipy over %s", transport)
    build_server().run(transport=transport)


if __name__ == "__main__":
    serve()
