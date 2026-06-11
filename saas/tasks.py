"""
saas/tasks.py
──────────────
Long-running scan jobs. In production these run on Celery workers (Redis broker) so a
scan survives a crash, retries, and reports status. When Celery/Redis are not
configured the layer degrades to a synchronous in-process run — the same engine, the
same status transitions in the store — so the platform works out of the box and the
offline tests need no broker.

The actual work routes through the existing `Orchestrator`, so scope authorization,
guardrails, and the evidence chain all still apply.
"""

from __future__ import annotations

import asyncio
import logging

from config.settings import settings
from saas.store import store

log = logging.getLogger(__name__)


def _celery_available() -> bool:
    try:
        import celery  # noqa: F401
        return True
    except ImportError:
        return False


def run_engagement(tenant_id: str, engagement_id: str, objective: str,
                   targets: list, mode: str = "autonomous") -> dict:
    """Run one engagement to completion, recording status transitions in the store.

    queued/created → running → complete | error. Routes through Orchestrator, so all
    safety gates apply. Used directly by the sync fallback and by the Celery task body.
    """
    store.update_engagement_status(tenant_id, engagement_id, "running")
    try:
        from core.orchestrator import Orchestrator
        orch = Orchestrator()
        coro = (orch.run_mission(targets) if mode == "mission"
                else orch.run_autonomous(objective, targets))
        asyncio.run(coro)
        store.update_engagement_status(tenant_id, engagement_id, "complete")
        return {"engagement_id": engagement_id, "status": "complete"}
    except Exception as e:  # noqa: BLE001 — record failure, never crash the worker/API
        log.error("[TASKS] engagement %s failed: %s", engagement_id, e)
        store.update_engagement_status(tenant_id, engagement_id, "error")
        return {"engagement_id": engagement_id, "status": "error", "error": str(e)}


def enqueue_engagement(tenant_id: str, engagement_id: str, objective: str,
                       targets: list, mode: str = "autonomous") -> dict:
    """Enqueue an engagement run. Celery if a broker is configured, else synchronous."""
    if _celery_available() and settings.redis_url:
        try:
            celery_app = make_celery()
            celery_app.send_task(
                "saas.run_engagement",
                args=[tenant_id, engagement_id, objective, targets, mode])
            store.update_engagement_status(tenant_id, engagement_id, "queued")
            return {"engagement_id": engagement_id, "status": "queued", "backend": "celery"}
        except Exception as e:  # noqa: BLE001 — fall back to sync on broker error
            log.warning("[TASKS] Celery enqueue failed (%s) — running synchronously", e)
    return {**run_engagement(tenant_id, engagement_id, objective, targets, mode),
            "backend": "sync"}


def make_celery():
    """Build the Celery app (lazy — only when celery is installed + a broker is set)."""
    from celery import Celery
    app = Celery("redteam", broker=settings.redis_url,
                 backend=settings.redis_url or None)

    @app.task(name="saas.run_engagement")
    def _run(tenant_id, engagement_id, objective, targets, mode="autonomous"):
        return run_engagement(tenant_id, engagement_id, objective, targets, mode)

    return app
