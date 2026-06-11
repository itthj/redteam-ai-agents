"""
saas/ — multi-tenant SaaS backend (capability C7).

An ADDITIVE layer on top of the single-engagement core. The core singletons
(`kb`, `evidence`, `scope`, `telemetry`) are untouched: one engagement runs per
worker with the existing engine as its execution context, while this layer is the
multi-tenant system-of-record (tenants, users, engagements, findings, evidence
index, audit log) that enforces tenant isolation + RBAC at the API edge.

Dev/test persistence is sqlite (mirroring core/evidence_store.py); production uses
PostgreSQL with row-level security (see saas/schema.py). Celery/Redis, Vault, and
Fernet are optional and degrade gracefully, exactly like the MCP layer.
"""
