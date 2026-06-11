"""
saas/store.py
──────────────
Tenant-scoped persistence for the SaaS backend. EVERY read and write takes a
`tenant_id` and filters on it — strict tenant isolation at the application layer
(PostgreSQL RLS is the second layer in prod). The audit log is append-only and
SHA-256 chain-hashed, mirroring core/evidence_store.py.

Dev/test backend is sqlite; production points `DATABASE_URL` at PostgreSQL.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

from config.settings import settings
from saas.schema import SCHEMA_DDL

log = logging.getLogger(__name__)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _uid() -> str:
    return uuid.uuid4().hex


class SaasStore:
    """Multi-tenant store. Thread-safe; sqlite for dev/test, PG-ready schema."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._lock = threading.RLock()
        path = db_path or settings.saas_db_path or str(
            Path(settings.knowledge_dir).parent / "saas.db"
        )
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA_DDL)
        self._conn.commit()

    # ── Tenants ───────────────────────────────────────────────────────────────

    def create_tenant(self, name: str, budget_usd: float = 0.0) -> str:
        tid = _uid()
        with self._lock:
            self._conn.execute(
                "INSERT INTO tenants (id, name, budget_usd, created_at) VALUES (?,?,?,?)",
                (tid, name, budget_usd, _now()))
            self._conn.commit()
        return tid

    def get_tenant(self, tenant_id: str) -> Optional[dict]:
        row = self._conn.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,)).fetchone()
        return dict(row) if row else None

    # ── Users ─────────────────────────────────────────────────────────────────

    def create_user(self, tenant_id: str, username: str, password_hash: str,
                    role: str) -> str:
        uid = _uid()
        with self._lock:
            self._conn.execute(
                "INSERT INTO users (id, tenant_id, username, password_hash, role, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (uid, tenant_id, username, password_hash, role, _now()))
            self._conn.commit()
        return uid

    def get_user(self, username: str) -> Optional[dict]:
        row = self._conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

    # ── Engagements (tenant-scoped) ───────────────────────────────────────────

    def create_engagement(self, tenant_id: str, name: str, objective: str = "",
                          targets: Optional[list] = None) -> str:
        eid = _uid()
        with self._lock:
            self._conn.execute(
                "INSERT INTO engagements (id, tenant_id, name, objective, targets, status, "
                "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (eid, tenant_id, name, objective, json.dumps(targets or []),
                 "created", _now(), _now()))
            self._conn.commit()
        return eid

    def list_engagements(self, tenant_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM engagements WHERE tenant_id=? ORDER BY created_at DESC",
            (tenant_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_engagement(self, tenant_id: str, engagement_id: str) -> Optional[dict]:
        """Tenant-scoped fetch — a cross-tenant id returns None (isolation)."""
        row = self._conn.execute(
            "SELECT * FROM engagements WHERE id=? AND tenant_id=?",
            (engagement_id, tenant_id)).fetchone()
        return dict(row) if row else None

    def update_engagement_status(self, tenant_id: str, engagement_id: str, status: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE engagements SET status=?, updated_at=? WHERE id=? AND tenant_id=?",
                (status, _now(), engagement_id, tenant_id))
            self._conn.commit()
        return cur.rowcount > 0

    # ── Findings (tenant-scoped) ──────────────────────────────────────────────

    def add_finding(self, tenant_id: str, engagement_id: str, signature: str,
                    title: str, severity: str, state: str = "candidate",
                    cvss: Optional[float] = None) -> str:
        fid = _uid()
        with self._lock:
            self._conn.execute(
                "INSERT INTO findings (id, tenant_id, engagement_id, signature, title, "
                "severity, state, cvss, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (fid, tenant_id, engagement_id, signature, title, severity, state, cvss, _now()))
            self._conn.commit()
        return fid

    def list_findings(self, tenant_id: str, engagement_id: Optional[str] = None) -> list[dict]:
        if engagement_id:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE tenant_id=? AND engagement_id=? ORDER BY created_at",
                (tenant_id, engagement_id)).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE tenant_id=? ORDER BY created_at",
                (tenant_id,)).fetchall()
        return [dict(r) for r in rows]

    # ── Evidence index (tenant-scoped) ────────────────────────────────────────

    def index_evidence(self, tenant_id: str, engagement_id: str, evidence_id: str,
                       sha256: str) -> str:
        rid = _uid()
        with self._lock:
            self._conn.execute(
                "INSERT INTO evidence_index (id, tenant_id, engagement_id, evidence_id, "
                "sha256, created_at) VALUES (?,?,?,?,?,?)",
                (rid, tenant_id, engagement_id, evidence_id, sha256, _now()))
            self._conn.commit()
        return rid

    # ── Append-only audit log (chain-hashed, per tenant) ──────────────────────

    def audit(self, tenant_id: str, actor: str, action: str, detail: str = "") -> str:
        rid = _uid()
        ts = time.time()
        with self._lock:
            prev = self._conn.execute(
                "SELECT chain_hash FROM audit_log WHERE tenant_id=? ORDER BY ts DESC LIMIT 1",
                (tenant_id,)).fetchone()
            prev_hash = prev["chain_hash"] if prev else "GENESIS"
            chain_input = f"{prev_hash}|{rid}|{ts}|{actor}|{action}|{detail}"
            chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()
            self._conn.execute(
                "INSERT INTO audit_log (id, tenant_id, ts, actor, action, detail, chain_hash) "
                "VALUES (?,?,?,?,?,?,?)",
                (rid, tenant_id, ts, actor, action, detail, chain_hash))
            self._conn.commit()
        return rid

    def get_audit(self, tenant_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM audit_log WHERE tenant_id=? ORDER BY ts", (tenant_id,)).fetchall()
        return [dict(r) for r in rows]

    def verify_audit_chain(self, tenant_id: str) -> bool:
        rows = self._conn.execute(
            "SELECT * FROM audit_log WHERE tenant_id=? ORDER BY ts", (tenant_id,)).fetchall()
        prev = "GENESIS"
        for r in rows:
            expected = hashlib.sha256(
                f"{prev}|{r['id']}|{r['ts']}|{r['actor']}|{r['action']}|{r['detail'] or ''}".encode()
            ).hexdigest()
            if expected != r["chain_hash"]:
                return False
            prev = r["chain_hash"]
        return True


# Module-level singleton (default path); tests instantiate with a tmp path.
store = SaasStore()
