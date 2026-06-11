# Changelog

All notable changes to `redteam-ai-agents` are recorded here. This file tracks the
**Epic 6 — Client-grade engagement delivery** capability expansion (C1–C9); see
`IMPLEMENTATION_PLAN.md` (§ EPIC 6) for the design. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project versions by capability.

## [Unreleased]

### C7 — Multi-tenant SaaS backend (`saas/`)
Added an additive multi-tenant layer over the single-engagement core (core singletons
untouched). New `saas/` package:

- **`schema.py` / `store.py`** — tenants / users / engagements / findings / evidence_index /
  audit_log, `tenant_id` on every non-tenant row. Strict **tenant isolation** enforced on
  every query (cross-tenant fetch → None/404) + PostgreSQL **row-level security** DDL for
  prod. Append-only **SHA-256-chained audit log**; per-tenant budgets. sqlite for dev/test
  (mirrors the evidence store), Postgres in prod.
- **`auth.py`** — PBKDF2 passwords, **JWT (HS256)**, **RBAC** (operator / analyst /
  client_viewer) with a permission matrix.
- **`secrets.py` / `crypto.py`** — Vault→env secret provider; Fernet at-rest encryption
  (both optional, degrade gracefully).
- **`tasks.py`** — Celery+Redis job runner with a **synchronous fallback** when no broker
  is configured; status transitions persisted (crash-survivable in prod).
- **`api.py`** — `/saas` router (OAuth2/JWT login, tenant-scoped + RBAC-guarded engagements,
  findings, audit), mounted additively into `api/server.py` (guarded import).
- **Changed** `config/settings.py` / `.env.example` / `requirements.txt` — `DATABASE_URL`,
  `REDIS_URL`, `VAULT_ADDR/TOKEN`, `JWT_SECRET`, `JWT_TTL_SECONDS`, `SAAS_ENCRYPTION_KEY`;
  PyJWT added (celery/redis/psycopg/hvac optional).
- **Tests:** +23 offline tests (`test_saas_store`, `test_saas_auth`, `test_saas_secrets_tasks`,
  `test_saas_api`) — tenant isolation, RBAC, JWT, audit chain, sync job runner. Suite: 273 → **296**.
- **Deferred (hooks present):** SQLAlchemy ORM, full evidence-DB-at-rest encryption (SQLCipher/
  PG TDE), Celery retry tuning. See `saas/README.md`.

### C6 — Phishing / social engineering (`social_eng` GoPhish MCP server)
Added an in-repo `social_eng` MCP server wrapping the GoPhish REST API (templates,
landing pages, sending profiles, target groups, campaigns, click/submit metrics), with
the platform's strongest gates.

- **New** `mcp_layer/servers/gophish_server.py` — handlers for template / landing-page /
  sending-profile / group creation, campaign launch, listing, and results. Campaign
  launch requires `phishing_authorized` (written-authorization flag) AND a named human
  approver; target groups are rejected if any recipient is outside an authorized domain.
  Metrics are written to the KB; every action is evidence-logged. Graceful degradation.
- **New scope concept** `config/authorization.py` — `scope.authorize_email` /
  `is_email_authorized` (domain + wildcard-suffix match) + `OperationType.PHISHING`.
- **Changed** `config/settings.py` / `.env.example` — `GOPHISH_API_URL/KEY`,
  `AUTHORIZED_EMAIL_DOMAINS`, `PHISHING_AUTHORIZED` (default off) + the domains list property.
- **Changed** `mcp_config.py` — registered the `social_eng` stdio server.
- **Tests:** +10 offline tests (`test_gophish_server.py`; GoPhish API mocked). Suite: 263 → **273**.
- **Kali install:** download the GoPhish release binary, run it, set `GOPHISH_API_URL/KEY`.

### C5 — Active Directory / Windows testing (`ad` MCP server)
Added an in-repo `ad` MCP server wrapping BloodHound CE (REST), bloodhound-python,
NetExec, Impacket, and Certipy for the existing `credential_access` and
`lateral_movement` phase agents (via `USE_MCP` — no new agent).

- **New** `mcp_layer/servers/ad_server.py` — gated handlers: `bh_collect`,
  `bh_shortest_path` (BHCE cypher → records the attack path as evidence + mirrors path
  hosts into the KB → 2A attack graph), `nxc_enum`, `secretsdump` (output sanitized,
  hash count only), `certipy_find` (read), and `nxc_exec` (STATE-CHANGING).
- **Changed** `config/authorization.py` — `OperationType.AD_STATE_CHANGE`.
- **Changed** `mcp_config.py` — registered the `ad` stdio server (extends the read-only
  `bloodhound` stub).
- **Changed** `config/settings.py` / `.env.example` — `BLOODHOUND_CE_URL/TOKEN`,
  `NETEXEC_PATH`, `AD_STATE_CHANGE_AUTHORIZED` (default off).
- **Safety:** collection/enumeration/path-query/ESC-discovery are scope-gated; `nxc_exec`
  is scope-gated **and** written-authorization-gated **and** guardrail-checked (destructive
  commands blocked). Recovered secrets are never logged in plaintext.
- **Degradation:** missing tool / unreachable BHCE ⇒ a `degraded` result, never a crash.
- **Tests:** +13 offline tests (`test_ad_server.py`; subprocess + BHCE mocked). Suite: 250 → **263**.
- **Kali install:** `pipx install bloodhound netexec impacket certipy-ad`; BloodHound CE via Docker.

### C4 — Client dashboard (full API + React/Vite frontend)
Turned the FastAPI app into a client-facing API and added a React dashboard that streams
live engagement state.

- **Changed** `api/server.py` — engagements (`GET /engagements`, `GET /engagements/{id}`)
  with background run control (`POST …/run` starts an asyncio task, `POST …/stop` cancels
  it) + run status; reports (`GET /reports`, `GET /reports/{name}` with a path-traversal
  guard); a WebSocket `/ws` live stream; the SSE/WS payload now also carries finding-state
  counts, run status, and recent agent activity (message-bus history).
- **New** `frontend/` — React (Vite) app: KPI overview (phase, live USD cost, cache hit,
  approved count, targets), engagement detail with Start/Stop, findings table with
  candidate/confirmed/approved badges, approval queue (Approve/Reject), and live activity.
  Talks to the backend over REST + SSE; built and run on the Kali host (`npm install && npm run dev`).
- The existing zero-build static `/dashboard` page is unchanged.
- **Tests:** +10 offline API tests (`test_dashboard_api.py`) incl. background run/stop and the
  WebSocket. Suite: 240 → **250** passing. (Frontend is outside the Python gate.)
- **Note:** ships open-on-localhost; OAuth2/JWT + RBAC + multi-engagement selection land in C7.

### C3 — Compliance-mapped reporting (ISO 27001 · PCI · CBK · Kenya DPA)
Extended the reporting layer to map every finding to four named frameworks and to
produce three report tiers from one engagement (structure on PTES, severity on CVSS).

- **Changed** `core/compliance.py` — added `ATTACK_TO_ISO27001` (ISO/IEC 27001:2022
  Annex A), `ATTACK_TO_CBK` (CBK Guidance Note on Cybersecurity, NIST-CSF-aligned
  functions), `ATTACK_TO_KDPA` (Kenya Data Protection Act 2019 — s.25/s.41/s.42/s.43,
  verified against the gazetted Act). `map_finding`/`rollup` now also return iso_27001 /
  cbk / kenya_dpa (additive — existing NIST/PCI/SOC 2 keys unchanged). New
  `compliance_appendix(findings)` + `FRAMEWORKS` + `PTES_PHASES`.
- **Changed** `agents/reporting_agent.py` — new `compliance_appendix` tool; system prompt
  now produces three tiers (Executive Summary / Technical Findings / Compliance Appendix)
  anchored on PTES, each saved separately.
- **Coverage:** every technique scored for NIST is also mapped to ISO 27001, CBK, and
  Kenya DPA (full, per decision).
- **Tests:** +6 offline tests in `test_compliance.py`. Suite: 234 → **240** passing.

### C2 — Finding-validation engine (candidate → confirmed → approved)
Added a deterministic finding lifecycle so AI agents can only ever produce **candidate**
findings; promotion to **confirmed** requires a deterministic re-test that actually
reproduced the issue (bound evidence + CVSS), and **approved** is a human-only action.

- **New** `core/finding_state.py` — signature-keyed lifecycle store (separate from the KB
  — no KB-schema change). `register_candidate` (the only AI mutation), `confirm` (gated on
  `reproduced=True`), `approve` (human, only from confirmed), `reject`, `queue`, `can_report`.
- **New** `core/retest.py` — deterministic re-test: re-run the exact Nuclei template /
  re-issue the request for a recorded signal + grade via the existing `finding_validator`.
  Conservative: if it can't be reproduced, it is NOT confirmed.
- **New** `agents/validation_agent.py` — `ValidationAgent` (in the orchestrator roster);
  re-tests candidates and confirms reproduced ones. Has no approve tool by design.
- **Changed** finding writers register candidates (additive): `webapp_agent`, `vuln_agent`,
  `phase_agents`.
- **Changed** human-approval surfaces: CLI `findings` / `approve` / `reject`; API
  `GET /findings`, `GET /findings/queue`, `POST /findings/{sig}/approve|reject`.
- **Changed** `reporting_agent` gains `get_findings_by_state` + a prompt rule to report only
  approved findings when approval is required.
- **Changed** `config/settings.py` / `.env.example` — `REQUIRE_FINDING_APPROVAL` (default
  off → non-breaking; on → nothing is reported/sent until a human approves).
- **Tests:** +28 offline tests (`test_finding_state`, `test_retest`, `test_validation_agent`,
  `test_finding_approval_api`). Suite: 206 → **234** passing.

### C1 — Web application testing (OWASP ZAP + Nuclei)
Added a `webapp` deep agent and an in-repo `webapp` MCP server that wrap OWASP ZAP
(spider, AJAX spider, active scan, alerts via the `zaproxy` client) and Nuclei
(subprocess, JSONL), mapping findings to the OWASP Top 10 (2021) and WSTG.

- **New** `agents/webapp_agent.py` — `WebAppAgent` deep agent (registered in the
  orchestrator roster + planner prompt + `_ALL_AGENTS`).
- **New** `mcp_layer/servers/zap_server.py` — gated ZAP/Nuclei handlers, also exposed
  as a FastMCP server (`webapp` entry in `MCP_SERVERS`). Lazy imports + graceful
  degradation when ZAP/nuclei are absent.
- **New** `core/owasp_map.py` — CWE / alert-name / tag → OWASP Top 10 + WSTG classifier.
- **New** `core/approval.py` — `ApprovalGate`: intrusive actions (active scan/DAST)
  require a per-engagement written-authorization flag; allow/block both logged to the
  evidence chain. First consumer is C1; reused by C5/C6.
- **Changed** `config/authorization.py` — added `OperationType.WEB_ACTIVE_SCAN`.
- **Changed** `config/settings.py` / `.env.example` — `ZAP_API_URL`, `ZAP_API_KEY`,
  `NUCLEI_PATH`, `WEBAPP_ACTIVE_SCAN_AUTHORIZED` (default off).
- **Safety:** spider/alerts are scope-gated; active scan & nuclei are scope-gated **and**
  blocked unless written authorization is set. Findings are recorded as **candidate**
  (the candidate → confirmed → approved lifecycle is formalised in C2). No change to any
  existing public signature, CLI output, or the KB JSON schema.
- **Tests:** +27 offline tests (`test_approval`, `test_owasp_map`, `test_zap_server`,
  `test_webapp_agent`); ZAP client + nuclei subprocess mocked. Suite: 179 → **206** passing.
- **Kali install:** `sudo apt install -y zaproxy nuclei && nuclei -update-templates`;
  run the ZAP daemon: `zaproxy -daemon -port 8090 -config api.key=<key>`.
