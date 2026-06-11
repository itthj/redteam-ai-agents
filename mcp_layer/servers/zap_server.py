"""
mcp_layer/servers/zap_server.py
────────────────────────────────
Web-application testing MCP server (capability C1) — wraps **OWASP ZAP** (daemon
via the `zaproxy` Python client) and **Nuclei** (subprocess).

The handlers are plain async functions (like `redteam_mcp_server._HANDLERS`) so they
are unit-testable offline with the ZAP client / nuclei subprocess mocked. They are
ALSO the implementation the `webapp_agent` calls natively, so there is a single,
gated code path no matter whether a tool is invoked by our agent or by an external
MCP client.

Every handler routes through the SAME safety layer as the rest of the platform:
  • `scope.authorize(host, op)` — the engagement scope gate, on the URL's host.
  • `approval.require(...)`     — active scan / DAST is intrusive → needs the
                                  per-engagement written-authorization flag.
  • `evidence.log(...)`         — every scope decision + scan is chained.

Graceful degradation: if the `zaproxy` client or the ZAP daemon is unreachable, or
the `nuclei` binary is absent, the handler logs a warning and returns a `degraded`
result — it never raises into the agent loop and never crashes the engagement.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
from urllib.parse import urlparse

from config.authorization import AuthorizationError, OperationType, scope
from config.settings import settings
from core.approval import AuthorizationRequired, approval
from core.evidence_store import evidence

log = logging.getLogger(__name__)

_AGENT = "webapp"
_POLL_INTERVAL = 1.0    # seconds between ZAP scan status polls
_SPIDER_TIMEOUT = 120   # max polls for spider / ajax spider
_ASCAN_TIMEOUT = 600    # max polls for an active scan (can be long)
_NUCLEI_TIMEOUT = 600   # subprocess timeout (seconds)


# ── Availability + helpers (graceful degradation) ───────────────────────────────

def _zap_available() -> bool:
    """True if a ZAP Python client library is importable."""
    try:
        import zapv2  # noqa: F401
        return True
    except ImportError:
        try:
            import zaproxy  # noqa: F401
            return True
        except ImportError:
            return False


def _nuclei_available() -> bool:
    """True if the nuclei binary is on PATH / at the configured path."""
    return shutil.which(settings.nuclei_path) is not None


def _get_zap_client():
    """Construct a ZAP API client, or return None if the library is missing.

    Construction does not open a connection (the first API call does), so this is
    cheap and only the call sites need try/except for an unreachable daemon.
    """
    proxies = {"http": settings.zap_api_url, "https": settings.zap_api_url}
    try:
        from zapv2 import ZAPv2
        return ZAPv2(apikey=settings.zap_api_key or None, proxies=proxies)
    except ImportError:
        pass
    try:
        from zaproxy import ZAPv2  # some distributions expose it here
        return ZAPv2(apikey=settings.zap_api_key or None, proxies=proxies)
    except ImportError:
        return None


def _host(target_url: str) -> str | None:
    """Extract the host from a URL (or accept a bare host/IP)."""
    if not target_url:
        return None
    parsed = urlparse(target_url if "//" in target_url else f"//{target_url}")
    return parsed.hostname or None


def _authorize(host: str, op: OperationType) -> dict | None:
    """Run the scope gate; return a blocked-result dict on failure, else None."""
    try:
        scope.authorize(host, op, agent_name=_AGENT)
        return None
    except AuthorizationError as e:
        evidence.log(_AGENT, "scope_block", str(e), target=host, severity="high")
        return {"error": str(e), "blocked": True}


async def _poll_zap(status_fn, scan_id, max_polls: int) -> int:
    """Poll a ZAP status function until it reports 100% or max_polls is reached.

    Returns the last observed percentage (0–100). ZAP status calls are synchronous;
    we await between polls so the event loop is not blocked.
    """
    pct = 0
    for _ in range(max_polls):
        try:
            pct = int(status_fn(scan_id))
        except (ValueError, TypeError):
            pct = 0
        if pct >= 100:
            return 100
        await asyncio.sleep(_POLL_INTERVAL)
    return pct


# ── Handlers ────────────────────────────────────────────────────────────────────

async def zap_spider(target_url: str) -> dict:
    """Crawl a target with the ZAP spider to discover content. Scope-gated."""
    host = _host(target_url)
    if host is None:
        return {"error": f"could not parse a host from '{target_url}'", "blocked": True}
    blocked = _authorize(host, OperationType.VULNERABILITY_SCAN)
    if blocked:
        return blocked
    if not _zap_available():
        log.warning("[WEBAPP] ZAP client unavailable — install `zaproxy` and run the ZAP daemon")
        return {"error": "ZAP client unavailable — install zaproxy and run the ZAP daemon",
                "degraded": True}
    client = _get_zap_client()
    try:
        scan_id = client.spider.scan(target_url)
        pct = await _poll_zap(client.spider.status, scan_id, _SPIDER_TIMEOUT)
        urls = list(client.spider.results(scan_id) or [])
    except Exception as e:  # noqa: BLE001 — graceful degradation
        log.warning("[WEBAPP] ZAP spider failed on %s: %s", target_url, e)
        return {"error": f"ZAP spider failed: {e}", "degraded": True}
    evidence.log(_AGENT, "zap_spider", f"Spidered {target_url}", target=host,
                 result={"urls_found": len(urls), "progress": pct}, severity="info")
    return {"target": target_url, "progress": pct, "urls_found": len(urls),
            "urls": urls[:100]}


async def zap_ajax_spider(target_url: str) -> dict:
    """Crawl a JS-heavy target with the ZAP AJAX spider. Scope-gated."""
    host = _host(target_url)
    if host is None:
        return {"error": f"could not parse a host from '{target_url}'", "blocked": True}
    blocked = _authorize(host, OperationType.VULNERABILITY_SCAN)
    if blocked:
        return blocked
    if not _zap_available():
        return {"error": "ZAP client unavailable — install zaproxy and run the ZAP daemon",
                "degraded": True}
    client = _get_zap_client()
    try:
        client.ajaxSpider.scan(target_url)
        for _ in range(_SPIDER_TIMEOUT):
            if client.ajaxSpider.status != "running":
                break
            await asyncio.sleep(_POLL_INTERVAL)
        results = list(client.ajaxSpider.results() or [])
    except Exception as e:  # noqa: BLE001
        log.warning("[WEBAPP] ZAP AJAX spider failed on %s: %s", target_url, e)
        return {"error": f"ZAP AJAX spider failed: {e}", "degraded": True}
    evidence.log(_AGENT, "zap_ajax_spider", f"AJAX-spidered {target_url}", target=host,
                 result={"results": len(results)}, severity="info")
    return {"target": target_url, "results_found": len(results)}


async def zap_active_scan(target_url: str) -> dict:
    """Run a ZAP ACTIVE scan (intrusive). Scope-gated AND written-authorization-gated."""
    host = _host(target_url)
    if host is None:
        return {"error": f"could not parse a host from '{target_url}'", "blocked": True}
    blocked = _authorize(host, OperationType.WEB_ACTIVE_SCAN)
    if blocked:
        return blocked
    try:
        approval.require("web_active_scan",
                         authorized=settings.webapp_active_scan_authorized,
                         target=host, agent=_AGENT)
    except AuthorizationRequired as e:
        return {"error": str(e), "blocked": True}
    if not _zap_available():
        return {"error": "ZAP client unavailable — install zaproxy and run the ZAP daemon",
                "degraded": True}
    client = _get_zap_client()
    try:
        scan_id = client.ascan.scan(target_url)
        pct = await _poll_zap(client.ascan.status, scan_id, _ASCAN_TIMEOUT)
    except Exception as e:  # noqa: BLE001
        log.warning("[WEBAPP] ZAP active scan failed on %s: %s", target_url, e)
        return {"error": f"ZAP active scan failed: {e}", "degraded": True}
    evidence.log(_AGENT, "zap_active_scan", f"Active-scanned {target_url}", target=host,
                 result={"progress": pct}, severity="medium")
    # Pull the alerts the active scan raised
    alerts = await zap_alerts(target_url)
    return {"target": target_url, "progress": pct,
            "alerts": alerts.get("alerts", []), "alert_count": alerts.get("count", 0)}


async def zap_alerts(target_url: str | None = None) -> dict:
    """Return ZAP alerts (findings) as JSON, optionally filtered to a base URL."""
    if target_url:
        host = _host(target_url)
        if host is not None:
            blocked = _authorize(host, OperationType.VULNERABILITY_SCAN)
            if blocked:
                return blocked
    if not _zap_available():
        return {"error": "ZAP client unavailable — install zaproxy and run the ZAP daemon",
                "degraded": True}
    client = _get_zap_client()
    try:
        raw = client.core.alerts(baseurl=target_url) if target_url else client.core.alerts()
    except Exception as e:  # noqa: BLE001
        log.warning("[WEBAPP] ZAP alerts fetch failed: %s", e)
        return {"error": f"ZAP alerts fetch failed: {e}", "degraded": True}
    alerts = [
        {
            "name": a.get("alert") or a.get("name"),
            "risk": a.get("risk"),
            "confidence": a.get("confidence"),
            "url": a.get("url"),
            "cwe": a.get("cweid"),
            "wascid": a.get("wascid"),
            "param": a.get("param"),
            "evidence": (a.get("evidence") or "")[:200],
            "solution": (a.get("solution") or "")[:300],
        }
        for a in (raw or [])
    ]
    return {"target": target_url, "count": len(alerts), "alerts": alerts}


async def nuclei_scan(target_url: str, severity: str | None = None,
                      templates: str | None = None) -> dict:
    """Run Nuclei against a target (intrusive DAST). Scope-gated AND auth-gated.

    severity: optional comma-list (e.g. "critical,high"). templates: optional path/tag.
    """
    host = _host(target_url)
    if host is None:
        return {"error": f"could not parse a host from '{target_url}'", "blocked": True}
    blocked = _authorize(host, OperationType.WEB_ACTIVE_SCAN)
    if blocked:
        return blocked
    try:
        approval.require("web_active_scan",
                         authorized=settings.webapp_active_scan_authorized,
                         target=host, agent=_AGENT)
    except AuthorizationRequired as e:
        return {"error": str(e), "blocked": True}
    if not _nuclei_available():
        log.warning("[WEBAPP] nuclei not found at '%s' — install it on the run host",
                    settings.nuclei_path)
        return {"error": f"nuclei not found at '{settings.nuclei_path}'", "degraded": True}

    cmd = [settings.nuclei_path, "-u", target_url, "-jsonl", "-silent", "-disable-update-check"]
    if severity:
        cmd += ["-severity", severity]
    if templates:
        cmd += ["-t", templates]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=_NUCLEI_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"error": f"nuclei timed out after {_NUCLEI_TIMEOUT}s", "degraded": True}
    except Exception as e:  # noqa: BLE001
        return {"error": f"nuclei failed: {e}", "degraded": True}

    findings = _parse_nuclei_jsonl(result.stdout)
    evidence.log(_AGENT, "nuclei_scan", f"Nuclei scan of {target_url}", target=host,
                 result={"findings": len(findings)}, severity="medium")
    return {"target": target_url, "count": len(findings), "findings": findings}


def _parse_nuclei_jsonl(stdout: str) -> list[dict]:
    """Parse nuclei -jsonl output into a compact finding list (ignores blank/garbage lines)."""
    findings: list[dict] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {})
        classification = info.get("classification") or {}
        cwes = classification.get("cwe-id") or []
        findings.append({
            "template": obj.get("template-id"),
            "name": info.get("name"),
            "severity": (info.get("severity") or "info").lower(),
            "matched_at": obj.get("matched-at") or obj.get("host"),
            "cwe": (cwes[0] if isinstance(cwes, list) and cwes else None),
            "tags": info.get("tags"),
        })
    return findings


_HANDLERS = (zap_spider, zap_ajax_spider, zap_active_scan, zap_alerts, nuclei_scan)


# ── MCP server wiring (lazy import — graceful degradation) ───────────────────────

def _mcp_available() -> bool:
    try:
        import mcp.server.fastmcp  # noqa: F401
        return True
    except ImportError:
        return False


def build_server():
    """Build a FastMCP server exposing the ZAP/Nuclei handlers. Requires the `mcp` SDK."""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("redteam-webapp")
    for handler in _HANDLERS:
        server.tool()(handler)
    return server


def serve(transport: str = "stdio") -> None:
    """Run the web-app testing MCP server over stdio (local) or sse (network)."""
    if not _mcp_available():
        log.error("[WEBAPP-MCP] `mcp` SDK not installed — run: pip install mcp")
        return
    log.info("[WEBAPP-MCP] serving ZAP/Nuclei tools over %s", transport)
    build_server().run(transport=transport)


if __name__ == "__main__":
    serve()
