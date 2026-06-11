"""
api/server.py
──────────────
FastAPI REST API — exposes all agents and mission control
over HTTP so you can drive the system from Burp, a web UI,
or any HTTP client.

Endpoints:
  GET  /health                    — system health + engagement info
  GET  /scope                     — current engagement scope
  GET  /knowledge                 — full knowledge base snapshot
  GET  /evidence                  — evidence records
  GET  /evidence/verify           — verify evidence chain integrity
  POST /mission/run               — run a full or partial mission
  POST /agent/{name}/run          — dispatch to a specific agent
  GET  /report/latest             — return the latest generated report
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from config.authorization import scope
from config.settings import settings
from core.attack_graph import graph
from core.evidence_store import evidence
from core.knowledge_base import kb
from core.orchestrator import _ALL_AGENTS, Orchestrator
from core.telemetry import telemetry
from core.tracing import init_tracing

log = logging.getLogger(__name__)

# Initialise tracing — no-op unless OTel + OTEL_EXPORTER_OTLP_ENDPOINT are set (5C)
init_tracing()

app = FastAPI(
    title="Red Team AI Agent System",
    description="Multi-agent cybersecurity operations platform — authorized use only",
    version="1.0.0",
)

# CORS — configurable via API_CORS_ORIGINS (comma-separated). Default "*" keeps
# the original open behavior for localhost use; set explicit origins to lock down
# a networked deployment. With the "*" wildcard, allow_credentials is disabled:
# the CORS spec forbids a credentialed wildcard response and browsers reject it,
# so the previous allow_origins=["*"] + allow_credentials=True was a no-op at best.
# Credentials are enabled automatically once explicit origins are configured.
_cors_origins = [o.strip() for o in settings.api_cors_origins.split(",") if o.strip()] or ["*"]
_cors_wildcard = _cors_origins == ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=not _cors_wildcard,
    allow_methods=["*"],
    allow_headers=["*"],
)

_orchestrator = Orchestrator()


# ── Auth ──────────────────────────────────────────────────────────────────────

def verify_token(x_api_key: Optional[str] = Header(None)) -> None:
    if settings.api_secret_key != "change_me" and x_api_key != settings.api_secret_key:
        raise HTTPException(status_code=401, detail="Invalid API key")


# ── Request models ────────────────────────────────────────────────────────────

class MissionRequest(BaseModel):
    targets: list[str]
    phases: Optional[list[str]] = None
    note: str = ""


class AutonomousRequest(BaseModel):
    targets: list[str]
    objective: str


class AgentRequest(BaseModel):
    task: str
    context: Optional[dict] = None


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "engagement": settings.engagement_id,
        "operator": settings.operator_name,
        "scope": scope.summary(),
    }


@app.get("/scope")
async def get_scope(_=Depends(verify_token)):
    return scope.summary()


@app.get("/knowledge")
async def get_knowledge(_=Depends(verify_token)):
    return kb.snapshot()


@app.get("/knowledge/target/{ip}")
async def get_target(_=Depends(verify_token), ip: str = ""):
    data = kb.get_target(ip)
    if not data:
        raise HTTPException(status_code=404, detail=f"Target {ip} not found in knowledge base")
    return data


@app.get("/evidence")
async def get_evidence(min_severity: str = "info", _=Depends(verify_token)):
    return {"records": evidence.get_findings(min_severity=min_severity)}


@app.get("/evidence/verify")
async def verify_evidence(_=Depends(verify_token)):
    valid = evidence.verify_chain()
    return {"chain_valid": valid, "status": "intact" if valid else "TAMPERED"}


@app.post("/mission/run")
async def run_mission(req: MissionRequest, _=Depends(verify_token)):
    """Run a full or partial red team mission."""
    log.info("[API] Mission request: targets=%s phases=%s", req.targets, req.phases)
    result = await _orchestrator.run_mission(
        targets=req.targets,
        phases=req.phases,
        mission_note=req.note,
    )
    return result


@app.post("/mission/autonomous")
async def run_autonomous(req: AutonomousRequest, _=Depends(verify_token)):
    """Run an autonomous mission — the orchestrator agent plans and delegates."""
    log.info("[API] Autonomous request: targets=%s", req.targets)
    return await _orchestrator.run_autonomous(req.objective, req.targets)


@app.post("/agent/{agent_name}/run")
async def run_agent(agent_name: str, req: AgentRequest, _=Depends(verify_token)):
    """Dispatch a task directly to a named agent."""
    if agent_name not in _ALL_AGENTS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown agent '{agent_name}'. Valid: {_ALL_AGENTS}",
        )
    result = await _orchestrator.dispatch(agent_name, req.task, req.context)
    return {"agent": agent_name, "result": result}


@app.get("/report/latest")
async def get_latest_report(_=Depends(verify_token)):
    reports_dir = Path(settings.reports_dir)
    reports = sorted(reports_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        raise HTTPException(status_code=404, detail="No reports generated yet")
    return {"report": reports[0].read_text(), "file": reports[0].name}


# ── Live dashboard (5C) ─────────────────────────────────────────────────────────

def _event_payload() -> dict:
    """A snapshot of live engagement state for the dashboard."""
    return {
        "phase": kb.get_state(),
        "telemetry": telemetry.summary(),
        "findings": evidence.get_findings(min_severity="medium")[-25:],
        "graph": graph.stats(),
        "ts": time.time(),
    }


async def _event_stream(interval: float = 2.0, max_iterations: Optional[int] = None):
    """Server-sent-events generator — emits the live payload every `interval` s."""
    count = 0
    while max_iterations is None or count < max_iterations:
        yield f"data: {json.dumps(_event_payload(), default=str)}\n\n"
        count += 1
        if max_iterations is not None and count >= max_iterations:
            break
        await asyncio.sleep(interval)


def _dashboard_html() -> str:
    return _DASHBOARD_HTML


@app.get("/events")
async def events():
    """Live SSE stream of phase, telemetry, findings, and graph stats. Open (no
    header auth) so a browser EventSource can connect, like /health."""
    return StreamingResponse(_event_stream(), media_type="text/event-stream")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """A single static page that renders the live engagement (no build step)."""
    return _dashboard_html()


_DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Red Team — Live Engagement</title>
<style>
  body { background:#0b0e14; color:#cdd6f4; font:14px/1.5 ui-monospace,Menlo,Consolas,monospace; margin:0; padding:20px; }
  h1 { color:#f38ba8; font-size:18px; margin:0 0 16px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px; margin-bottom:16px; }
  .card { background:#11151c; border:1px solid #1e2530; border-radius:8px; padding:12px 14px; }
  .card .k { color:#7f849c; font-size:11px; text-transform:uppercase; letter-spacing:.05em; }
  .card .v { color:#a6e3a1; font-size:22px; margin-top:4px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:4px 8px; border-bottom:1px solid #1e2530; }
  th { color:#7f849c; font-weight:normal; }
  .sev-critical{color:#f38ba8;font-weight:bold} .sev-high{color:#fab387} .sev-medium{color:#f9e2af}
  h2 { color:#89b4fa; font-size:13px; text-transform:uppercase; letter-spacing:.05em; margin:18px 0 8px; }
  #conn { float:right; font-size:12px; color:#7f849c; }
</style>
</head>
<body>
<h1>RED TEAM — LIVE ENGAGEMENT <span id="conn">connecting…</span></h1>
<div class="grid">
  <div class="card"><div class="k">Phase</div><div class="v" id="phase">—</div></div>
  <div class="card"><div class="k">Cost (USD)</div><div class="v" id="cost">—</div></div>
  <div class="card"><div class="k">API calls</div><div class="v" id="calls">—</div></div>
  <div class="card"><div class="k">Cache hit</div><div class="v" id="cache">—</div></div>
  <div class="card"><div class="k">Graph nodes</div><div class="v" id="nodes">—</div></div>
</div>
<h2>Per-agent</h2>
<table><thead><tr><th>Agent</th><th>Calls</th><th>Tokens in/out</th><th>Cost</th></tr></thead><tbody id="agents"></tbody></table>
<h2>Recent findings</h2>
<table><thead><tr><th>Time</th><th>Agent</th><th>Target</th><th>Action</th><th>Severity</th></tr></thead><tbody id="findings"></tbody></table>
<script>
const $ = id => document.getElementById(id);
const es = new EventSource('/events');
es.onopen = () => { $('conn').textContent = 'live'; $('conn').style.color = '#a6e3a1'; };
es.onerror = () => { $('conn').textContent = 'reconnecting…'; $('conn').style.color = '#f38ba8'; };
es.onmessage = e => {
  const d = JSON.parse(e.data);
  const t = (d.telemetry && d.telemetry.total) || {};
  $('phase').textContent = d.phase || '—';
  $('cost').textContent = '$' + (t.cost_usd || 0).toFixed(4);
  $('calls').textContent = t.api_calls || 0;
  $('cache').textContent = Math.round((t.cache_hit_rate || 0) * 100) + '%';
  $('nodes').textContent = (d.graph && d.graph.nodes) || 0;
  const ba = (d.telemetry && d.telemetry.by_agent) || {};
  $('agents').innerHTML = Object.values(ba).map(a =>
    `<tr><td>${a.agent}</td><td>${a.api_calls}</td><td>${a.input_tokens}/${a.output_tokens}</td><td>$${(a.cost_usd||0).toFixed(4)}</td></tr>`).join('');
  $('findings').innerHTML = (d.findings || []).slice().reverse().map(f => {
    const ts = new Date((f.timestamp||0)*1000).toLocaleTimeString();
    return `<tr><td>${ts}</td><td>${f.agent||''}</td><td>${f.target||'-'}</td><td>${(f.action||'').slice(0,60)}</td><td class="sev-${f.severity}">${f.severity||''}</td></tr>`;
  }).join('');
};
</script>
</body>
</html>"""
