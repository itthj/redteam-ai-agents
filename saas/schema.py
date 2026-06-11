"""
saas/schema.py
───────────────
Relational schema for the multi-tenant backend. `tenant_id` is on every non-tenant
row — the basis for strict tenant isolation (enforced in the store layer for every
query, and by PostgreSQL row-level security in production).

The DDL is portable between sqlite (dev/test) and PostgreSQL (prod). RLS is
PostgreSQL-only and applied separately via `postgres_rls_sql()`.
"""

from __future__ import annotations

# Tables carrying tenant_id (everything except `tenants`) — the RLS-protected set.
TENANT_SCOPED_TABLES = ("users", "engagements", "findings", "evidence_index", "audit_log")

SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS tenants (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    budget_usd  REAL NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS engagements (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    objective   TEXT,
    targets     TEXT,
    status      TEXT NOT NULL DEFAULT 'created',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    signature     TEXT,
    title         TEXT,
    severity      TEXT,
    state         TEXT,
    cvss          REAL,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_index (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    evidence_id   TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    ts          REAL NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      TEXT,
    chain_hash  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_eng_tenant ON engagements(tenant_id);
CREATE INDEX IF NOT EXISTS idx_find_tenant ON findings(tenant_id, engagement_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id, ts);
"""


def postgres_rls_sql() -> str:
    """Return PostgreSQL row-level-security DDL for the tenant-scoped tables.

    Applied once in production after the schema is created. Each connection then sets
    `SET app.tenant_id = '<id>'` and the policy restricts every row to that tenant —
    defense-in-depth beneath the store's per-query tenant filtering.
    """
    stmts = []
    for table in TENANT_SCOPED_TABLES:
        stmts.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        stmts.append(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
        stmts.append(
            f"CREATE POLICY tenant_isolation ON {table} USING "
            f"(tenant_id = current_setting('app.tenant_id', true));"
        )
    return "\n".join(stmts)
