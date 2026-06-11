"""
saas/api.py
────────────
FastAPI router for the multi-tenant SaaS layer (capability C7). Mounted under /saas
into the existing app. Every route is JWT-authenticated, RBAC-guarded, and strictly
tenant-scoped (the tenant comes from the verified token, never from the client), so
one tenant can never read or touch another's data. Every state change is written to
the append-only audit log.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from saas import auth
from saas.store import store
from saas.tasks import enqueue_engagement

log = logging.getLogger(__name__)

router = APIRouter(prefix="/saas", tags=["saas"])


class LoginRequest(BaseModel):
    username: str
    password: str


class EngagementRequest(BaseModel):
    name: str
    objective: str = ""
    targets: list[str] = []


# ── Auth dependencies ────────────────────────────────────────────────────────────

def current_claims(authorization: str | None = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    try:
        return auth.decode_token(authorization.split(" ", 1)[1])
    except Exception as e:  # noqa: BLE001 — any JWT error → 401
        raise HTTPException(status_code=401, detail="Invalid or expired token") from e


def require(permission: str):
    """Dependency factory — 403 unless the token's role holds the permission."""
    def _dep(claims: dict = Depends(current_claims)) -> dict:
        if not auth.has_permission(claims.get("role", ""), permission):
            raise HTTPException(status_code=403,
                                detail=f"Role '{claims.get('role')}' lacks {permission}")
        return claims
    return _dep


# ── Routes ───────────────────────────────────────────────────────────────────────

@router.post("/auth/token")
def issue_token(req: LoginRequest):
    user = store.get_user(req.username)
    if not user or not auth.verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = auth.create_token(user_id=user["id"], tenant_id=user["tenant_id"],
                              role=user["role"])
    store.audit(user["tenant_id"], user["username"], "login", "token issued")
    return {"access_token": token, "token_type": "bearer", "role": user["role"]}


@router.get("/engagements")
def list_engagements(claims: dict = Depends(require("engagement:read"))):
    return {"engagements": store.list_engagements(claims["tenant_id"])}


@router.post("/engagements", status_code=201)
def create_engagement(req: EngagementRequest,
                      claims: dict = Depends(require("engagement:create"))):
    eid = store.create_engagement(claims["tenant_id"], req.name, req.objective, req.targets)
    store.audit(claims["tenant_id"], claims["sub"], "engagement:create", eid)
    return {"id": eid, "status": "created"}


@router.get("/engagements/{engagement_id}")
def get_engagement(engagement_id: str, claims: dict = Depends(require("engagement:read"))):
    eng = store.get_engagement(claims["tenant_id"], engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return eng


@router.post("/engagements/{engagement_id}/run", status_code=202)
def run_engagement(engagement_id: str, claims: dict = Depends(require("engagement:run"))):
    eng = store.get_engagement(claims["tenant_id"], engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    store.audit(claims["tenant_id"], claims["sub"], "engagement:run", engagement_id)
    return enqueue_engagement(claims["tenant_id"], engagement_id, eng.get("objective", ""),
                              json.loads(eng.get("targets") or "[]"))


@router.get("/engagements/{engagement_id}/findings")
def engagement_findings(engagement_id: str, claims: dict = Depends(require("finding:read"))):
    if not store.get_engagement(claims["tenant_id"], engagement_id):
        raise HTTPException(status_code=404, detail="Engagement not found")
    return {"findings": store.list_findings(claims["tenant_id"], engagement_id)}


@router.get("/audit")
def audit_log(claims: dict = Depends(require("audit:read"))):
    return {"audit": store.get_audit(claims["tenant_id"]),
            "chain_valid": store.verify_audit_chain(claims["tenant_id"])}
