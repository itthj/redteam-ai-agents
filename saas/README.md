# Multi-tenant SaaS backend (C7)

An **additive** layer over the single-engagement core. The core singletons
(`kb`, `evidence`, `scope`, `telemetry`) are untouched — one engagement runs per
worker with the existing engine as its execution context, while this layer is the
multi-tenant **system-of-record** and the auth/RBAC edge.

## Pieces

| Module | Responsibility |
|--------|----------------|
| `schema.py` | DDL for `tenants / users / engagements / findings / evidence_index / audit_log` (`tenant_id` on every non-tenant row) + PostgreSQL row-level-security policy |
| `store.py` | Tenant-scoped persistence — every query filters on `tenant_id`; append-only SHA-256-chained audit log; per-tenant budgets |
| `auth.py` | PBKDF2 passwords, JWT (HS256), three roles (operator / analyst / client_viewer) + permission matrix |
| `secrets.py` | Vault (optional) → env secret provider |
| `crypto.py` | Fernet at-rest encryption for stored secrets (optional `cryptography`) |
| `tasks.py` | Celery job runner (Redis broker) with a synchronous fallback when no broker is configured |
| `api.py` | `/saas` router — JWT-authenticated, RBAC-guarded, strictly tenant-scoped; mounted into `api/server.py` |

## Tenant isolation (two layers)

1. **Application** — every `store` read/write takes `tenant_id` from the verified JWT
   (never from the client), so a request can only ever touch its own tenant's rows.
2. **Database (prod)** — PostgreSQL RLS: after creating the schema, run
   `saas.schema.postgres_rls_sql()` and `SET app.tenant_id = '<id>'` per connection.

## Run (production sketch)

```bash
# 1. Postgres + RLS
psql "$DATABASE_URL" -c "$(python -c 'from saas.schema import SCHEMA_DDL; print(SCHEMA_DDL)')"
psql "$DATABASE_URL" -c "$(python -c 'from saas.schema import postgres_rls_sql; print(postgres_rls_sql())')"

# 2. Redis + Celery worker (async scan jobs)
celery -A saas.tasks:make_celery worker --loglevel=info

# 3. API (the /saas router is mounted automatically)
uvicorn api.server:app --port 8000
```

Secrets (JWT key, DB creds, encryption key) come from Vault / a cloud KMS in prod —
never plaintext `.env`. In dev the provider degrades to the environment.

## Deferred (hooks present)

- SQLAlchemy ORM (raw sqlite mirrors `core/evidence_store.py`; Postgres in prod).
- Full evidence-DB-at-rest encryption (SQLCipher / PostgreSQL TDE) — `crypto.py` covers
  application-level secret fields today.
- Celery retry/backoff tuning and a result dashboard.
