"""
mcp_layer/servers/cloud_server.py
──────────────────────────────────
Cloud & container posture MCP server (capability C9) — wraps **Prowler**
(AWS/Azure/GCP/Kubernetes CSPM, compliance-framework-aware) and **Trivy**
(container / image / IaC / cloud misconfig), with READ-ONLY client credentials.

Each failed check becomes a CANDIDATE finding (the C2 lifecycle) carrying a normalized
severity AND the compliance controls the tool tagged it with (CIS / NIST / PCI / …),
which feeds the compliance reporting in C3.

Read-only assessment, scoped to an authorized account/image:
  • `scope.authorize_cloud(resource)` — the account/subscription/project/image must be
    on the authorized list.
  • findings are recorded as candidates + evidence-logged.

Graceful degradation: prowler/trivy absent ⇒ a `degraded` result, never a crash.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from config.authorization import AuthorizationError, scope
from config.settings import settings
from core.evidence_store import evidence
from core.finding_state import finding_state

log = logging.getLogger(__name__)

_AGENT = "cloud"
_TIMEOUT = 1800
_SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
            "informational": "info", "info": "info", "unknown": "info", "negligible": "info"}


def _norm_sev(value) -> str:
    return _SEV_MAP.get(str(value or "").lower(), "medium")


def _gate(resource: str) -> dict | None:
    try:
        scope.authorize_cloud(resource, agent_name=_AGENT)
        return None
    except AuthorizationError as e:
        evidence.log(_AGENT, "scope_block", str(e), target=resource, severity="high")
        return {"error": str(e), "blocked": True}


def _record(resource: str, title: str, severity: str, compliance: list) -> str:
    sig = finding_state.register_candidate({
        "target": resource, "title": title, "severity": severity, "source": _AGENT,
    })
    evidence.log(_AGENT, "cloud_finding", f"[candidate] {title}", target=resource,
                 result={"compliance": compliance, "candidate": True}, severity=severity)
    return sig


# ── Handlers ────────────────────────────────────────────────────────────────────

async def prowler_scan(provider: str, account: str) -> dict:
    """Run Prowler CSPM against an authorized account (provider: aws/azure/gcp/kubernetes)."""
    blocked = _gate(account)
    if blocked:
        return blocked
    if not shutil.which(settings.prowler_path):
        log.warning("[CLOUD] prowler not found — pip install prowler on the run host")
        return {"error": "prowler not found on host", "degraded": True}

    out = _run_prowler(provider, account)
    if out.get("_degraded"):
        return {"error": out["_degraded"], "degraded": True}

    findings = []
    for f in _parse_prowler(out.get("json", "")):
        sig = _record(account, f"prowler: {f['check_id']} ({f['service']})",
                      f["severity"], f["compliance"])
        findings.append({**f, "signature": sig})
    return {"provider": provider, "account": account, "count": len(findings),
            "findings": findings}


async def trivy_scan(target: str, scan_type: str = "config") -> dict:
    """Run Trivy against an authorized target (scan_type: config/image/fs/repo)."""
    blocked = _gate(target)
    if blocked:
        return blocked
    if not shutil.which(settings.trivy_path):
        log.warning("[CLOUD] trivy not found — install trivy on the run host")
        return {"error": "trivy not found on host", "degraded": True}

    out = _run_trivy(target, scan_type)
    if out.get("_degraded"):
        return {"error": out["_degraded"], "degraded": True}

    findings = []
    for f in _parse_trivy(out.get("json", "")):
        sig = _record(target, f"trivy: {f['id']} — {f['title']}", f["severity"], [])
        findings.append({**f, "signature": sig})
    return {"target": target, "scan_type": scan_type, "count": len(findings),
            "findings": findings}


# ── Tool runners (mockable; degrade gracefully) ──────────────────────────────────

def _run_prowler(provider: str, account: str) -> dict:
    out_dir = Path(tempfile.gettempdir()) / "prowler_out"
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [settings.prowler_path, provider, "-M", "json", "-o", str(out_dir)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT)
    except Exception as e:  # noqa: BLE001 — graceful degradation
        return {"_degraded": f"prowler failed: {e}"}
    reports = sorted(out_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        return {"json": ""}
    try:
        return {"json": reports[0].read_text(encoding="utf-8")}
    except OSError:
        return {"json": ""}


def _parse_prowler(text: str) -> list[dict]:
    """Parse Prowler JSON → failed checks with severity + compliance controls."""
    try:
        data = json.loads(text or "[]")
    except json.JSONDecodeError:
        return []
    checks = data if isinstance(data, list) else data.get("findings", [])
    findings: list[dict] = []
    for c in checks:
        status = str(c.get("status") or c.get("status_code") or "").upper()
        if not status.startswith("FAIL"):
            continue
        compliance = c.get("compliance") or {}
        controls = []
        if isinstance(compliance, dict):
            for fw, ctrls in compliance.items():
                controls += [f"{fw}:{x}" for x in (ctrls if isinstance(ctrls, list) else [ctrls])]
        findings.append({
            "check_id": c.get("check_id") or c.get("CheckID") or "unknown",
            "service": c.get("service_name") or c.get("ServiceName") or "",
            "severity": _norm_sev(c.get("severity")),
            "region": c.get("region") or c.get("Region"),
            "compliance": controls,
            "detail": (c.get("status_extended") or "")[:200],
        })
    return findings


def _run_trivy(target: str, scan_type: str) -> dict:
    cmd = [settings.trivy_path, scan_type, "--format", "json", "--quiet", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT)
    except Exception as e:  # noqa: BLE001
        return {"_degraded": f"trivy failed: {e}"}
    return {"json": result.stdout}


def _parse_trivy(text: str) -> list[dict]:
    """Parse Trivy JSON → misconfigurations + vulnerabilities, normalized."""
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return []
    findings: list[dict] = []
    for result in data.get("Results", []) or []:
        for m in result.get("Misconfigurations", []) or []:
            findings.append({"id": m.get("ID", "misconfig"), "title": m.get("Title", ""),
                             "severity": _norm_sev(m.get("Severity")), "kind": "misconfig"})
        for v in result.get("Vulnerabilities", []) or []:
            findings.append({"id": v.get("VulnerabilityID", "vuln"),
                             "title": v.get("PkgName", ""),
                             "severity": _norm_sev(v.get("Severity")), "kind": "vuln"})
    return findings


_HANDLERS = (prowler_scan, trivy_scan)


# ── MCP server wiring (lazy import — graceful degradation) ───────────────────────

def _mcp_available() -> bool:
    try:
        import mcp.server.fastmcp  # noqa: F401
        return True
    except ImportError:
        return False


def build_server():
    """Build a FastMCP server exposing the Prowler/Trivy handlers. Requires the `mcp` SDK."""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("redteam-cloud")
    for handler in _HANDLERS:
        server.tool()(handler)
    return server


def serve(transport: str = "stdio") -> None:
    """Run the cloud-posture MCP server over stdio (local) or sse (network)."""
    if not _mcp_available():
        log.error("[CLOUD-MCP] `mcp` SDK not installed — run: pip install mcp")
        return
    log.info("[CLOUD-MCP] serving Prowler/Trivy tools over %s", transport)
    build_server().run(transport=transport)


if __name__ == "__main__":
    serve()
