# HANDOFF — `redteam-ai-agents`

**Last updated:** 2026-06-10
**Purpose:** Bring a fresh session/engineer up to speed cold. Read this top to bottom,
then `CLAUDE.md` (standing build protocol) and `IMPLEMENTATION_PLAN.md` (full design).

---

## 1. What this project is

A multi-agent, **authorized** red-team platform on the Anthropic SDK. An orchestrator
plans an engagement and delegates to specialist agents (recon/scanner/vuln/exploit/
post-exploit/forensics/reporting) plus 11 Kali-aligned kill-chain phase agents. Two run
modes: deterministic kill-chain (`run_mission`) and autonomous agents-as-tools
(`run_autonomous`). Shared core: KnowledgeBase, EvidenceStore (SHA-256 chain),
MessageBus, Telemetry, Guardrails, Authorization, AttackFramework (MITRE ATT&CK).

A two-epic, 11-workstream enhancement build-out was executed one-workstream-per-PR.
**10 of 11 are done and merged to `main`** (see §3). The work is **additive and
non-breaking**: every new capability is opt-in via a setting with a safe default,
and degrades gracefully if an optional dependency/backend is missing (the
`MCPBridge`/`_mcp_available()` pattern is the template).

---

## 2. Current state (the single most important section)

- **Branch `main` is at `3547943`** and contains all 10 workstreams (fast-forward
  merge of the stacked `feat/*` branches). Working tree clean.
- **NOT pushed to `origin`.** The merge is local only. `origin/main` is still at the
  pre-build commit `47b3fd8`. Pushing is an outward-facing action — get explicit OK.
- **The 10 `feat/*` branches still exist** locally (merged, safe to delete after push).
- **Test suite: 131 passing, fully offline** (no API key, no network — the Anthropic
  client and all external tools/backends are mocked). One benign Starlette/`TestClient`
  deprecation warning. **This offline guarantee is sacred — never add a test that needs
  network or a key.**
- **NOTHING HAS EVER RUN LIVE.** No real Anthropic API call, no real nmap, no real
  target has been touched. All confidence is from unit tests. This is the central
  caveat — the gap to "working product" is integration + environment, not more code.

### How to work the repo
- **Test venv (lives OUTSIDE OneDrive):**
  `& "C:\Users\james\venvs\redteam-ai-agents\Scripts\python.exe" -m pytest -q`
  It has ONLY the deps the build needed so far: `anthropic, pydantic, pydantic-settings,
  python-dotenv, pytest, pytest-asyncio, networkx, opentelemetry-api, opentelemetry-sdk,
  fastapi, uvicorn, mcp`. It does NOT have the full `requirements.txt` (see §4.3).
- **Runtime is Python 3.14** in that venv. ⚠️ Recommend a **3.12** runtime for production
  — several full-`requirements.txt` packages (cryptography, bcrypt, python-nmap, etc.)
  have spotty 3.14 wheels.
- **Build protocol:** `CLAUDE.md` is auto-loaded each session. To advance, the operator
  says **"continue"** (next workstream) or names one; or runs `/build-next [id]`.
  One workstream = one branch = one stop-and-report. Don't batch workstreams silently.

### ⚠️ Environment landmines
- **The repo lives in a OneDrive-synced folder** (`C:\Users\james\OneDrive\Desktop\red agents`).
  `.env` and `data/` are gitignored but **OneDrive still syncs them to the cloud**.
  A `.env` already exists (created this session from `.env.example`, **placeholder key**).
  **Before any real engagement:** put a real key in `.env` only after de-syncing the
  folder or relocating the repo to a non-OneDrive path. OneDrive can also corrupt `.git`
  during concurrent ops.
- The model is pinned to `claude-opus-4-7`; environment is on 4.8. `telemetry._PRICING`
  has no `claude-opus-4-8` entry (falls back to Opus default pricing) — see §4.11.

---

## 3. What was built (all merged to `main`)

| WS | Capability | Core files | Setting (default) |
|----|-----------|-----------|-------------------|
| **5A** | Model router + budget governor (halt/downgrade) + tool-output compression | `core/model_router.py`, `core/telemetry.py`, `core/base_agent.py` | `engagement_budget_usd=0`, `on_budget_exceeded=downgrade`, `compress_tool_output=false` |
| **2A** | Attack graph (networkx engine + optional neo4j write-mirror), fed by a KB sink | `core/attack_graph.py`, `core/knowledge_base.py` | `neo4j_uri=""` (empty → in-process only) |
| **2B** | Graph-driven planner tools (`query_attack_graph`, `next_best_action`) | `core/orchestrator.py` | — (advisory) |
| **5C** | OTel tracing (3 chokepoints) + live `/dashboard` + `/events` SSE | `core/tracing.py`, `api/server.py` | `otel_exporter_otlp_endpoint=""` |
| **5B** | Resumable checkpoints (`resume`/`checkpoints` CLI) | `core/checkpoint.py`, `core/base_agent.py` | — (always on; writes under `data/checkpoints/`) |
| **2C** | Cross-engagement tradecraft memory (distill→store→recall, redacted) | `core/memory.py` | `enable_tradecraft_memory=false` |
| **2D** | Named-adversary emulation (`--actor APT29`, technique re-rank) | `core/adversary_profiles.py` | `engagement_actor=""` |
| **5D** | MCP fleet (nuclei, theHarvester, BloodHound, threat-intel, SIEM) | `mcp_layer/mcp_config.py` | enable via `MCP_ENABLED_SERVERS` |
| **5E** | Agents-as-MCP server (outbound; `serve-mcp` CLI) | `mcp_layer/redteam_mcp_server.py` | — |
| **5F** | Compliance mapping (NIST/PCI/SOC2) + retest ledger | `core/compliance.py`, `agents/reporting_agent.py` | — |

**Skipped:** 2E (multi-agent debate gate) — deliberately deferred by the operator. Not
included in this handoff's roadmap per instruction. Nothing else depends on it.

New CLI verbs added: `checkpoints`, `resume <id>`, `actors`, `serve-mcp`, plus
`--actor` on `autonomous`/`mission`. New tests: 11 files, +83 tests (48 → 131).

---

## 4. Roadmap to a working product

Ordered by dependency. **Tier 1 is the critical path** — until it's done, "it passes
tests" is the only claim that can be made.

### Tier 1 — Blockers to a first real run

**4.1 — One live smoke test.** Get a real `ANTHROPIC_API_KEY` and a lab target
(Metasploitable2/3, an HTB/TryHackMe box, or a Docker target). Run, in order:
`python main.py scope` → `python main.py mission <ip> --phases recon,scan` →
`python main.py autonomous <ip> -o "..."`. This is the single highest-value task:
it exercises the real API loop, real tools, and the orchestrator end-to-end for the
first time. Everything else is secondary to this.

**4.2 — Validate the live Anthropic call shape.** `core/base_agent.py::_stream_turn`
sends `thinking={"type":"adaptive","display":"summarized"}` and
`output_config={"effort": ...}` to `client.messages.stream(...)`. These are Opus 4.x
controls but the exact call shape has never hit the wire — it's the most likely thing
to break on first contact. Confirm against the installed `anthropic` SDK version and
the model id. Also reconcile the model: bump `claude-opus-4-7` → `4.8` if intended
(see 4.11). Have the SDK/API reference open (the `claude-api` skill) before touching this.

**4.3 — Install + validate the FULL `requirements.txt`.** The venv only has test deps.
Production needs `aiohttp, aiofiles, sqlalchemy, aiosqlite, cryptography, bcrypt,
python-nmap, dnspython, shodan, requests, click, rich, tabulate, jinja2,
mcp-server-fetch`, etc. Several are native-extension packages. **Strongly recommend a
fresh Python 3.12 venv** for this. Confirm every module imports.

**4.4 — Install host tools the agents shell out to:** `nmap` (required by scanner/vuln),
Metasploit RPC (`msfrpcd`, for the exploit agent), Node + `npx` (filesystem MCP),
`uv`/`uvx` (shodan MCP + the 5D fleet). All present on Kali; absent on a stock Windows box.
The intended deployment target is Kali Linux (see README Quick Start).

### Tier 2 — Functional completeness

**4.5 — Verify the 6 deep agents end-to-end.** recon/scanner/vuln/exploit/post_exploit/
forensics predate this build and are **unverified live**. Whether they produce real
findings depends on their tool wrappers + host environment. Walk each one against the
lab target; fix wrappers as needed. (This is likely where the most real bugs hide.)

**4.6 — The 5D MCP fleet entries are templates.** `nuclei-mcp-server`,
`theharvester-mcp-server`, `threatintel-mcp-server`, and the BloodHound/SIEM SSE
endpoints are *registry placeholders* — the actual MCP servers must exist/be installed/
be running to do anything. Same posture as the original shodan/cve templates. Either
wire real ones or document them as bring-your-own.

**4.7 — Wire the optional backends fully (or document as fallback-only):**
- **neo4j** is a *write-only mirror* today; graph reads always come from the in-process
  networkx graph. If a live browser/Cypher reads are wanted, build the read path.
  (`docker-compose up -d neo4j`, set `NEO4J_URI`.)
- **tradecraft memory** uses the JSONL/keyword fallback; the chromadb + embeddings
  path described in the plan is NOT built. Add it behind the same interface if semantic
  recall matters.
- **tracing** needs `pip install opentelemetry-exporter-otlp-proto-http` AND a running
  collector (`docker-compose up -d jaeger`, set `OTEL_EXPORTER_OTLP_ENDPOINT`). Without
  the exporter package the spans are created but not exported.

### Tier 3 — Hardening (before any networked/shared deployment)

**4.8 — API security.** `api/server.py`: `/dashboard` and `/events` are unauthenticated
and CORS is `allow_origins=["*"]`. Fine for localhost; lock both down before exposing
the API on a network. Other routes already require `x-api-key` when `api_secret_key`
is set.

**4.9 — Secrets & OneDrive.** Resolve §2's OneDrive issue: de-sync the folder or move
the repo off the synced path. Rotate any key that has touched the synced `.env`.

**4.10 — CI.** Wire the offline suite into GitHub Actions (`python -m pytest`). The
no-API-key guarantee makes this trivial and high-value — it locks in the 131 tests as a
regression gate. Pin the Python version (3.12).

**4.11 — Model/pricing reconcile.** Decide opus-4-7 vs 4-8 (`config/settings.py::
claude_model`) and add the chosen model to `core/telemetry.py::_PRICING` so the budget
governor (5A) prices it correctly instead of using the Opus default.

### Tier 4 — Polish

**4.12 —** Push `main` to `origin`; delete the 10 merged `feat/*` branches.
**4.13 —** Report export beyond markdown/json (PDF/HTML — `jinja2` is already a dep).
**4.14 —** Per-epic `docs/` pages; update the README architecture diagram to show the
Attack Graph / Memory / Tracing in the SHARED CORE box (partially done).

---

## 5. Recommended first session after this handoff

1. Push to `origin` + branch cleanup (4.12) — get the merge off the local box.
2. Stand up a **Python 3.12** venv with the full `requirements.txt` (4.3) on/towards Kali.
3. Resolve OneDrive (4.9) before putting a real key anywhere.
4. **Live smoke test** (4.1) — this is the milestone that converts the project from
   "well-tested code" to "demonstrably works." Expect 4.2 and 4.5 bugs to surface here.
5. Then CI (4.10) and the model reconcile (4.11).

---

## 6. Key file map (for orientation)

```
core/base_agent.py      agent loop; _stream_turn (LIVE-UNTESTED call shape), budget gate,
                        tool compression, tracing spans, resume/checkpoint seam, actor inject
core/orchestrator.py    planner tools (graph + recall), delegation, checkpointing, memory distill
core/knowledge_base.py  intel store; attach_sink/_emit feed the attack graph
core/attack_graph.py    networkx engine + optional neo4j mirror + export()
core/model_router.py    task-class → (model, effort)
core/telemetry.py       cost + budget (total_cost/budget_remaining/over_budget); _PRICING
core/checkpoint.py      save/load JSON under data/checkpoints/
core/memory.py          TradecraftMemory (JSONL + keyword recall, redaction, distill)
core/adversary_profiles.py  APT29/28/FIN7/Lazarus; get_profile/list_profiles
core/compliance.py      ATT&CK→NIST/PCI/SOC2 + FindingsLedger (retest diff)
core/tracing.py         OTel init + span() no-op-unless-configured
api/server.py           FastAPI; /dashboard + /events (5C); init_tracing()
mcp_layer/mcp_config.py        inbound MCP registry (incl. 5D fleet)
mcp_layer/redteam_mcp_server.py  outbound agents-as-MCP server (5E)
cli/main.py             Click CLI: mission/autonomous/agent/.../resume/checkpoints/actors/serve-mcp
config/settings.py      all settings incl. the new opt-in flags
tests/                  131 offline tests; conftest.py force-sets a fake key + temp dirs
.dev/PLAN_*.md          per-workstream scratch plans (gitignored) incl. out-of-scope notes
```

---

## 7. Hard rules (carried from the build protocol — do not violate)

- **Additive & non-breaking.** No changes to existing public signatures, CLI output, or
  the KB JSON schema. New behavior is opt-in with safe defaults.
- **Offline tests only.** No network, no API key in the suite. Mock the Anthropic client;
  degrade optional backends behind availability flags.
- **Preserve the cache strategy.** Volatile data (KB, recalled memory, actor notes) goes
  in the FIRST USER MESSAGE, never the cached system prompt. Don't reorder the
  system/tools prefix.
- **Don't weaken auth / guardrails / evidence.** New capability routes *through* them
  (the 5E MCP server is the reference example — it reuses Orchestrator + the gates).
- **Stay minimal.** Build only what's specified; note resisted generalizations in
  `.dev/PLAN_<id>.md`.
