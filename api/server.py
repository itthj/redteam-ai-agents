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

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from config.authorization import scope
from config.settings import settings
from core.attack_graph import graph
from core.evidence_store import evidence
from core.finding_state import finding_state
from core.knowledge_base import kb
from core.message_bus import bus
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

# Multi-tenant SaaS layer (C7) — mounted additively under /saas. Guarded so the core
# API keeps working even if the optional layer fails to import.
try:
    from saas.api import router as _saas_router
    app.include_router(_saas_router)
    log.info("[API] SaaS layer mounted at /saas")
except Exception as e:  # noqa: BLE001 — graceful degradation
    log.warning("[API] SaaS layer not mounted: %s", e)


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


class ApproveRequest(BaseModel):
    approver: Optional[str] = None


class RejectRequest(BaseModel):
    reason: str = ""


class RunRequest(BaseModel):
    objective: str = ""
    targets: list[str] = []
    mode: str = "autonomous"   # "autonomous" | "mission"


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


# ── Finding lifecycle / approval queue (C2) ─────────────────────────────────────

@app.get("/findings")
async def list_findings(state: Optional[str] = None, _=Depends(verify_token)):
    """List findings by lifecycle state (candidate/confirmed/approved/rejected)."""
    return {"summary": finding_state.summary(), "findings": finding_state.list(state)}


@app.get("/findings/queue")
async def findings_queue(_=Depends(verify_token)):
    """The human-approval queue — confirmed findings awaiting approval."""
    return {"queue": finding_state.queue()}


@app.post("/findings/{signature}/approve")
async def approve_finding(signature: str, req: ApproveRequest, _=Depends(verify_token)):
    """Human-approve a confirmed finding so it may be reported/sent."""
    res = finding_state.approve(signature, approver=req.approver or settings.operator_name)
    if not res.get("approved"):
        raise HTTPException(status_code=409, detail=res.get("reason", "cannot approve"))
    return res


@app.post("/findings/{signature}/reject")
async def reject_finding(signature: str, req: RejectRequest, _=Depends(verify_token)):
    """Reject a finding (false positive / will not be reported)."""
    res = finding_state.reject(signature, by=settings.operator_name, reason=req.reason)
    if not res.get("rejected"):
        raise HTTPException(status_code=409, detail=res.get("reason", "cannot reject"))
    return res


# ── Engagements + run control (C4 dashboard) ────────────────────────────────────
# Single-engagement today (the configured engagement); the shape is a list so the
# multi-tenant SaaS layer (C7) can extend it without changing the dashboard contract.

_RUNS: dict[str, dict] = {}   # engagement_id → {status, mode, started_at, finished_at, task, error}


def _run_status(engagement_id: str) -> dict:
    rec = _RUNS.get(engagement_id)
    if not rec:
        return {"status": "idle"}
    return {k: v for k, v in rec.items() if k != "task"}


def _engagement_detail() -> dict:
    return {
        "id": settings.engagement_id,
        "name": settings.engagement_name,
        "operator": settings.operator_name,
        "scope": scope.summary(),
        "state": kb.get_state(),
        "run": _run_status(settings.engagement_id),
        "telemetry": telemetry.summary(),
        "findings": finding_state.summary(),
        "targets": len(kb.get_all_targets()),
    }


@app.get("/engagements")
async def list_engagements(_=Depends(verify_token)):
    return {"engagements": [_engagement_detail()]}


@app.get("/engagements/{engagement_id}")
async def get_engagement(engagement_id: str, _=Depends(verify_token)):
    if engagement_id != settings.engagement_id:
        raise HTTPException(status_code=404, detail=f"Unknown engagement {engagement_id}")
    return _engagement_detail()


@app.post("/engagements/{engagement_id}/run", status_code=202)
async def run_engagement(engagement_id: str, req: RunRequest, _=Depends(verify_token)):
    """Start the engagement as a background task (observe it via /events or /ws)."""
    if engagement_id != settings.engagement_id:
        raise HTTPException(status_code=404, detail=f"Unknown engagement {engagement_id}")
    rec = _RUNS.get(engagement_id)
    if rec and rec.get("status") == "running":
        raise HTTPException(status_code=409, detail="Engagement is already running")

    targets = req.targets or scope.summary()["authorized_targets"]
    if not targets:
        raise HTTPException(status_code=400, detail="No targets and none configured in scope")
    _RUNS[engagement_id] = {"status": "running", "mode": req.mode,
                            "objective": req.objective, "started_at": time.time()}

    async def _runner():
        try:
            if req.mode == "mission":
                await _orchestrator.run_mission(targets)
            else:
                await _orchestrator.run_autonomous(req.objective, targets)
            _RUNS[engagement_id]["status"] = "complete"
        except asyncio.CancelledError:
            _RUNS[engagement_id]["status"] = "stopped"
            raise
        except Exception as e:  # noqa: BLE001 — surface the error in status, don't crash the API
            _RUNS[engagement_id]["status"] = "error"
            _RUNS[engagement_id]["error"] = str(e)
        finally:
            _RUNS[engagement_id]["finished_at"] = time.time()

    _RUNS[engagement_id]["task"] = asyncio.create_task(_runner())
    return _run_status(engagement_id)


@app.post("/engagements/{engagement_id}/stop")
async def stop_engagement(engagement_id: str, _=Depends(verify_token)):
    """Cooperatively stop a running engagement (cancels the background task)."""
    rec = _RUNS.get(engagement_id)
    if not rec or rec.get("status") != "running":
        raise HTTPException(status_code=409, detail="No running engagement to stop")
    task = rec.get("task")
    if task is not None:
        task.cancel()
    return {"stopping": True, "engagement": engagement_id}


# ── Reports ──────────────────────────────────────────────────────────────────────

@app.get("/reports")
async def list_reports(_=Depends(verify_token)):
    reports_dir = Path(settings.reports_dir)
    files = sorted(reports_dir.glob("*.*"), key=lambda p: p.stat().st_mtime, reverse=True)
    return {"reports": [
        {"file": p.name, "size_bytes": p.stat().st_size, "modified": p.stat().st_mtime}
        for p in files if p.suffix in (".md", ".html", ".json")
    ]}


def _is_safe_report_name(name: str) -> bool:
    """Only a bare filename inside the reports dir — blocks path traversal."""
    return bool(name) and not ("/" in name or "\\" in name or ".." in name)


@app.get("/reports/{name}")
async def get_report(name: str, _=Depends(verify_token)):
    if not _is_safe_report_name(name):
        raise HTTPException(status_code=400, detail="Invalid report name")
    path = Path(settings.reports_dir) / name
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"Report {name} not found")
    return {"file": name, "content": path.read_text(encoding="utf-8")}


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
        "finding_states": finding_state.summary(),
        "run": _run_status(settings.engagement_id),
        "activity": bus.get_history()[-15:],
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


@app.websocket("/ws")
async def ws_events(websocket: WebSocket):
    """Live WebSocket stream of the same dashboard payload (phase, telemetry, findings,
    finding states, run status, agent activity). Open, like /events."""
    await websocket.accept()
    try:
        while True:
            await websocket.send_text(json.dumps(_event_payload(), default=str))
            await asyncio.sleep(2.0)
    except WebSocketDisconnect:
        return
    except Exception as e:  # noqa: BLE001 — never let a stream error crash the worker
        log.debug("[WS] stream closed: %s", e)


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
