"""
mcp_layer/servers/llm_redteam_server.py
─────────────────────────────────────────
AI / LLM red-teaming MCP server (capability C8) — wraps **garak** (baseline
vulnerability scan) and **PyRIT** (multi-turn / indirect prompt-injection scenarios)
against a client-AUTHORIZED LLM endpoint. Findings map to the OWASP Top 10 for LLM
Applications (prompt injection = LLM01).

Assessment / discovery only, scoped to the client's own app:
  • `scope.authorize_endpoint(url)` — the endpoint must be on the authorized list.
  • `approval.require(...)`         — active probing needs the LLM_REDTEAM_AUTHORIZED flag.
  • findings are recorded as CANDIDATES (the C2 lifecycle) + evidence-logged.

Graceful degradation: garak/PyRIT absent ⇒ a `degraded` result, never a crash.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess

from config.authorization import AuthorizationError, scope
from config.settings import settings
from core.approval import AuthorizationRequired, approval
from core.evidence_store import evidence
from core.finding_state import finding_state
from core.owasp_llm_map import classify as llm_classify

log = logging.getLogger(__name__)

_AGENT = "llm_redteam"
_GARAK_TIMEOUT = 1800


# ── Gates + availability ─────────────────────────────────────────────────────────

def _gate(endpoint: str) -> dict | None:
    """Scope + written-authorization gate for an LLM endpoint. Blocked-dict or None."""
    try:
        scope.authorize_endpoint(endpoint, agent_name=_AGENT)
    except AuthorizationError as e:
        evidence.log(_AGENT, "scope_block", str(e), target=endpoint, severity="high")
        return {"error": str(e), "blocked": True}
    try:
        approval.require("llm_redteam", authorized=settings.llm_redteam_authorized,
                         target=endpoint, agent=_AGENT)
    except AuthorizationRequired as e:
        return {"error": str(e), "blocked": True}
    return None


def _garak_available() -> bool:
    return shutil.which(settings.garak_path) is not None


def _pyrit_available() -> bool:
    try:
        import pyrit  # noqa: F401
        return True
    except ImportError:
        return False


def _record(endpoint: str, title: str, llm_id: str, llm: str, severity: str) -> str:
    """Record a candidate LLM finding to the KB lifecycle store + evidence chain."""
    sig = finding_state.register_candidate({
        "target": endpoint, "title": title, "severity": severity,
        "owasp": llm_id, "source": _AGENT,
    })
    evidence.log(_AGENT, "llm_finding", f"[candidate] {title} ({llm_id})",
                 target=endpoint, result={"llm": llm, "candidate": True}, severity=severity)
    return sig


# ── Handlers ────────────────────────────────────────────────────────────────────

async def garak_scan(endpoint: str, probes: str = "promptinject,dan,encoding") -> dict:
    """Run a garak baseline scan against an authorized LLM endpoint."""
    blocked = _gate(endpoint)
    if blocked:
        return blocked
    if not _garak_available():
        log.warning("[LLM_REDTEAM] garak not found — pip install garak on the run host")
        return {"error": "garak not found on host", "degraded": True}

    report = _run_garak(endpoint, probes)
    if report.get("_degraded"):
        return {"error": report["_degraded"], "degraded": True}

    findings = []
    for f in _parse_garak(report.get("jsonl", "")):
        mapping = llm_classify(probe=f.get("probe"), category=f.get("detector"))
        sig = _record(endpoint, f"garak: {f.get('probe')} / {f.get('detector')}",
                      mapping["llm_id"], mapping["llm"], f.get("severity", "medium"))
        findings.append({**f, **mapping, "signature": sig})
    return {"endpoint": endpoint, "count": len(findings), "findings": findings}


async def pyrit_probe(endpoint: str, scenario: str = "prompt_injection") -> dict:
    """Run a PyRIT multi-turn / indirect prompt-injection scenario against an endpoint."""
    blocked = _gate(endpoint)
    if blocked:
        return blocked
    if not _pyrit_available():
        log.warning("[LLM_REDTEAM] PyRIT not installed — pip install pyrit-ai on the run host")
        return {"error": "PyRIT not installed", "degraded": True}

    result = _run_pyrit(endpoint, scenario)
    if result.get("_degraded"):
        return {"error": result["_degraded"], "degraded": True}

    findings = []
    for f in result.get("findings", []):
        mapping = llm_classify(probe=scenario, category=f.get("category"))
        sig = _record(endpoint, f"PyRIT: {scenario} — {f.get('title', 'finding')}",
                      mapping["llm_id"], mapping["llm"], f.get("severity", "medium"))
        findings.append({**f, **mapping, "signature": sig})
    return {"endpoint": endpoint, "scenario": scenario, "count": len(findings),
            "findings": findings}


# ── Tool runners (mockable; degrade gracefully) ──────────────────────────────────

def _run_garak(endpoint: str, probes: str) -> dict:
    """Run garak and return its report jsonl text. Degrades on any failure."""
    import tempfile
    from pathlib import Path
    prefix = Path(tempfile.gettempdir()) / "garak_redteam"
    cmd = [settings.garak_path, "--model_type", "rest", "--model_name", endpoint,
           "--probes", probes, "--report_prefix", str(prefix)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=_GARAK_TIMEOUT)
    except Exception as e:  # noqa: BLE001 — graceful degradation
        return {"_degraded": f"garak failed: {e}"}
    report = prefix.with_suffix(".report.jsonl")
    try:
        return {"jsonl": report.read_text(encoding="utf-8")}
    except OSError:
        return {"jsonl": ""}


def _parse_garak(jsonl: str) -> list[dict]:
    """Parse garak report jsonl → findings (eval records where the probe was not fully passed)."""
    findings: list[dict] = []
    for line in (jsonl or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("entry_type") != "eval":
            continue
        total = obj.get("total") or 0
        passed = obj.get("passed") or 0
        if total and passed < total:
            rate = passed / total
            findings.append({
                "probe": obj.get("probe"), "detector": obj.get("detector"),
                "passed": passed, "total": total,
                "severity": "high" if rate < 0.5 else "medium",
            })
    return findings


def _run_pyrit(endpoint: str, scenario: str) -> dict:
    """Run a PyRIT scenario. Lazily imported; returns findings or degrades.

    The real orchestration is environment-specific (targets, converters); this is the
    integration seam, mocked in tests and filled in per deployment on the run host.
    """
    try:
        import pyrit  # noqa: F401
    except ImportError as e:
        return {"_degraded": f"PyRIT unavailable: {e}"}
    return {"findings": []}


_HANDLERS = (garak_scan, pyrit_probe)


# ── MCP server wiring (lazy import — graceful degradation) ───────────────────────

def _mcp_available() -> bool:
    try:
        import mcp.server.fastmcp  # noqa: F401
        return True
    except ImportError:
        return False


def build_server():
    """Build a FastMCP server exposing the garak/PyRIT handlers. Requires the `mcp` SDK."""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("redteam-llm")
    for handler in _HANDLERS:
        server.tool()(handler)
    return server


def serve(transport: str = "stdio") -> None:
    """Run the LLM red-team MCP server over stdio (local) or sse (network)."""
    if not _mcp_available():
        log.error("[LLM_REDTEAM-MCP] `mcp` SDK not installed — run: pip install mcp")
        return
    log.info("[LLM_REDTEAM-MCP] serving garak/PyRIT tools over %s", transport)
    build_server().run(transport=transport)


if __name__ == "__main__":
    serve()
