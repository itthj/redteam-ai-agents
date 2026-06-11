"""
mcp_layer/servers/gophish_server.py
────────────────────────────────────
Phishing / social-engineering MCP server (capability C6) — wraps the **GoPhish** REST
API (templates, landing pages, sending profiles, target groups, campaigns, metrics).

This is the most sensitive capability in the platform, so it carries the strongest
gates. A campaign cannot be launched unless ALL of these hold:

  1. `settings.phishing_authorized` is True — the per-engagement WRITTEN-AUTHORIZATION
     flag (a deliberate operator opt-in, default off).
  2. a human approver is named at launch (`approved_by`) — the human-approval step.
  3. every recipient is inside an authorized client email domain — enforced when a
     target group is created (`scope.authorize_email`), so a group can never contain
     an out-of-domain address.

Every action is logged to the evidence chain; campaign metrics are written to the KB.
Graceful degradation: if GoPhish is unreachable / unconfigured, handlers return a
`degraded` result instead of raising.
"""

from __future__ import annotations

import logging

import requests

from config.authorization import scope
from config.settings import settings
from core.approval import AuthorizationRequired, approval
from core.evidence_store import evidence
from core.knowledge_base import kb

log = logging.getLogger(__name__)

_AGENT = "social_eng"
_HTTP_TIMEOUT = 30


def _gophish_request(method: str, path: str, payload: dict | None = None) -> dict:
    """Call the GoPhish REST API. Degrades gracefully when unreachable/unconfigured."""
    if not settings.gophish_api_url:
        return {"_degraded": "GOPHISH_API_URL not set"}
    headers = {"Authorization": f"Bearer {settings.gophish_api_key}",
               "Content-Type": "application/json"}
    try:
        r = requests.request(method, f"{settings.gophish_api_url}{path}", headers=headers,
                             json=payload, timeout=_HTTP_TIMEOUT, verify=False)  # noqa: S501
        r.raise_for_status()
        return r.json()
    except Exception as e:  # noqa: BLE001 — graceful degradation
        log.warning("[SOCIAL_ENG] GoPhish request failed: %s", e)
        return {"_degraded": str(e)}


def _degraded(data: dict) -> dict | None:
    if isinstance(data, dict) and data.get("_degraded"):
        return {"error": f"GoPhish unavailable: {data['_degraded']}", "degraded": True}
    return None


# ── Read handlers ────────────────────────────────────────────────────────────────

async def gp_list_campaigns() -> dict:
    data = _gophish_request("GET", "/api/campaigns/")
    return _degraded(data) or {"campaigns": data}


async def gp_campaign_results(campaign_id: int) -> dict:
    """Pull click/submit metrics for a campaign and record them to the KB + evidence."""
    data = _gophish_request("GET", f"/api/campaigns/{campaign_id}/results")
    deg = _degraded(data)
    if deg:
        return deg
    results = data.get("results", []) if isinstance(data, dict) else []
    stats = {"targets": len(results), "opened": 0, "clicked": 0, "submitted": 0}
    for r in results:
        status = (r.get("status") or "").lower()
        if "opened" in status:
            stats["opened"] += 1
        if "clicked" in status:
            stats["clicked"] += 1
        if "submitted" in status:
            stats["submitted"] += 1
    metrics = kb.get("phishing_metrics", {}) or {}
    metrics[str(campaign_id)] = stats
    kb.set("phishing_metrics", metrics)
    evidence.log(_AGENT, "campaign_results", f"Campaign {campaign_id} metrics",
                 result=stats, severity="info")
    return {"campaign_id": campaign_id, "stats": stats}


# ── Create handlers (infrastructure) ─────────────────────────────────────────────

async def gp_create_template(name: str, subject: str, html: str) -> dict:
    data = _gophish_request("POST", "/api/templates/",
                            {"name": name, "subject": subject, "html": html})
    deg = _degraded(data)
    if deg:
        return deg
    evidence.log(_AGENT, "create_template", f"Created phishing template '{name}'", severity="info")
    return data


async def gp_create_landing_page(name: str, html: str, capture_credentials: bool = False) -> dict:
    data = _gophish_request("POST", "/api/pages/",
                            {"name": name, "html": html,
                             "capture_credentials": capture_credentials})
    deg = _degraded(data)
    if deg:
        return deg
    evidence.log(_AGENT, "create_landing_page", f"Created landing page '{name}'", severity="info")
    return data


async def gp_create_sending_profile(name: str, from_address: str, host: str,
                                    username: str = "", password: str = "") -> dict:
    data = _gophish_request("POST", "/api/smtp/",
                            {"name": name, "from_address": from_address, "host": host,
                             "username": username, "password": password})
    deg = _degraded(data)
    if deg:
        return deg
    evidence.log(_AGENT, "create_sending_profile", f"Created sending profile '{name}'", severity="info")
    return data


async def gp_create_group(name: str, targets: list) -> dict:
    """Create a target group. EVERY recipient must be inside an authorized client email
    domain — the group is rejected as a whole if any address is out of scope."""
    emails = [t if isinstance(t, str) else (t or {}).get("email", "") for t in targets]
    out_of_scope = [e for e in emails if not scope.is_email_authorized(e)]
    if out_of_scope:
        evidence.log(_AGENT, "scope_block",
                     f"Phishing group '{name}' rejected — {len(out_of_scope)} target(s) "
                     f"outside the authorized domain", severity="high")
        return {"error": f"targets outside the authorized email domain: {out_of_scope}",
                "blocked": True}
    payload = {"name": name, "targets": [
        ({"email": t} if isinstance(t, str) else t) for t in targets
    ]}
    data = _gophish_request("POST", "/api/groups/", payload)
    deg = _degraded(data)
    if deg:
        return deg
    evidence.log(_AGENT, "create_group",
                 f"Created target group '{name}' ({len(emails)} in-domain recipients)",
                 severity="info")
    return data


# ── Campaign launch (the strongly-gated action) ──────────────────────────────────

async def gp_launch_campaign(name: str, template: str, page: str, url: str,
                             smtp: str, groups: list, approved_by: str | None = None) -> dict:
    """Launch a phishing campaign — requires the written-authorization flag AND a named
    human approver. Recipients are already domain-validated at group creation."""
    # Gate 1 — written authorization for this engagement.
    try:
        approval.require("phishing", authorized=settings.phishing_authorized,
                         target=name, approver=approved_by, agent=_AGENT)
    except AuthorizationRequired as e:
        return {"error": str(e), "blocked": True}
    # Gate 2 — explicit human approval for THIS campaign.
    if not approved_by:
        evidence.log(_AGENT, "approval_block",
                     f"Phishing campaign '{name}' blocked — no human approver named",
                     severity="high")
        return {"error": "A phishing campaign requires an explicit human approver "
                         "(approved_by). Refusing to launch.", "blocked": True}

    payload = {"name": name, "template": {"name": template}, "page": {"name": page},
               "url": url, "smtp": {"name": smtp},
               "groups": [{"name": g} for g in groups]}
    data = _gophish_request("POST", "/api/campaigns/", payload)
    deg = _degraded(data)
    if deg:
        return deg
    evidence.log(_AGENT, "launch_campaign",
                 f"Launched phishing campaign '{name}' (approved by {approved_by})",
                 result={"groups": groups}, severity="high")
    return data


_HANDLERS = (gp_list_campaigns, gp_campaign_results, gp_create_template,
             gp_create_landing_page, gp_create_sending_profile, gp_create_group,
             gp_launch_campaign)


# ── MCP server wiring (lazy import — graceful degradation) ───────────────────────

def _mcp_available() -> bool:
    try:
        import mcp.server.fastmcp  # noqa: F401
        return True
    except ImportError:
        return False


def build_server():
    """Build a FastMCP server exposing the GoPhish handlers. Requires the `mcp` SDK."""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("redteam-social-eng")
    for handler in _HANDLERS:
        server.tool()(handler)
    return server


def serve(transport: str = "stdio") -> None:
    """Run the social-engineering MCP server over stdio (local) or sse (network)."""
    if not _mcp_available():
        log.error("[SOCIAL_ENG-MCP] `mcp` SDK not installed — run: pip install mcp")
        return
    log.info("[SOCIAL_ENG-MCP] serving GoPhish tools over %s", transport)
    build_server().run(transport=transport)


if __name__ == "__main__":
    serve()
