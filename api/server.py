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

import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from config.authorization import scope
from config.settings import settings
from core.evidence_store import evidence
from core.knowledge_base import kb
from core.orchestrator import Orchestrator, _ALL_AGENTS

log = logging.getLogger(__name__)

app = FastAPI(
    title="Red Team AI Agent System",
    description="Multi-agent cybersecurity operations platform — authorized use only",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
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
