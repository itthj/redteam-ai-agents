# Red Team AI Agent System

[![tests](https://github.com/itthj/redteam-ai-agents/actions/workflows/ci.yml/badge.svg)](https://github.com/itthj/redteam-ai-agents/actions/workflows/ci.yml)

A state-of-the-art **multi-agent cybersecurity operations platform** built on the
**Anthropic Claude SDK** (Claude Opus 4.8). **18 specialist AI agents** — 7 deep
agents plus 11 kill-chain phase agents mapped one-to-one to the Kali Linux
operational categories (01–15) — cover the full attack lifecycle, coordinated
by an intelligent orchestrator and connected to external tooling via the
**Model Context Protocol (MCP)**.

> ⚠️ **Authorized penetration testing and red-team operations only.**
> Every action is scope-checked and logged. See *Legal Notice* below.

## Try it in 10 seconds (no API key, no target)

```bash
python scripts/demo.py && start demo_report.html   # macOS/Linux: open / xdg-open
```

Seeds a synthetic engagement and writes an HTML report — demonstrating the
prompt-injection defense, guardrails, and finding-validator with no network or real
host. Full run/usage guide: **[QUICKSTART.md](QUICKSTART.md)**.

---

## Architecture

```
                    ┌──────────────────────────────────────────┐
                    │            ORCHESTRATOR                   │
                    │  • Deterministic kill-chain mode          │
                    │  • Autonomous mode (agents-as-tools,      │
                    │    Claude Opus 4.8 @ xhigh effort)        │
                    └────────────────────┬─────────────────────┘
                                         │ delegates to
        ┌──────┬──────┬──────────┬───────┴────┬────────────┬───────────┐
      RECON  SCANNER  VULN     EXPLOIT   POST-EXPLOIT  FORENSICS   REPORTING
       │       │       │          │           │            │           │
       └───────┴───────┴──────────┴───────────┴────────────┴───────────┘
                                  │
              ┌───────────────────┼────────────────────┐
              │   SHARED CORE SYSTEMS                   │
              │   • KnowledgeBase  — shared intel       │
              │   • EvidenceStore  — SHA-256 chain log  │
              │   • MessageBus     — agent events       │
              │   • Telemetry      — token/cost tracking│
              │   • Guardrails     — destructive-block  │
              │   • AttackFramework— MITRE ATT&CK map   │
              │   • AttackGraph    — attack path graph  │
              │   • Authorization  — scope gate         │
              └───────────────────┬─────────────────────┘
                                  │
                          ┌───────┴────────┐
                          │   MCP LAYER    │  external tools / databases
                          │  (stdio + SSE) │  Shodan · filesystem · CVE · web
                          └────────────────┘
```

### Deep agents (7) — bespoke tooling

| Agent | Responsibility |
|-------|----------------|
| **recon** | DNS, Shodan, WHOIS, subdomain enumeration |
| **scanner** | Nmap port/service scanning, banner grabbing |
| **vuln** | CVE/NVD correlation, NSE vuln scripts, CVSS scoring |
| **exploit** | Metasploit RPC, exploit selection, shell management |
| **post_exploit** | Enumeration, privesc, lateral-movement discovery |
| **forensics** | Timeline, MITRE ATT&CK mapping, artifact collection |
| **reporting** | Executive summary, technical findings, remediation |

### Phase agents (11) — one per Kali category

Built on a single data-driven `PhaseAgent` (`agents/phase_agents.py`), each
specialised by a registry entry. Every phase agent shares a gated toolkit:
`get_playbook` (ATT&CK techniques + Kali tools), `run_command` (guardrail- and
scope-checked execution), `record_finding` (knowledge base + evidence chain).

| Agent | Kali | MITRE ATT&CK tactic |
|-------|------|---------------------|
| **resource_development** | 02 | Resource Development |
| **execution** | 04 | Execution |
| **persistence** | 05 | Persistence |
| **privilege_escalation** | 06 | Privilege Escalation |
| **defense_evasion** | 07 | Defense Evasion |
| **credential_access** | 08 | Credential Access |
| **lateral_movement** | 10 | Lateral Movement |
| **collection** | 11 | Collection |
| **command_and_control** | 12 | Command and Control |
| **exfiltration** | 13 | Exfiltration |
| **impact** | 14 | Impact — *assessment only, non-destructive* |

(Kali 01/03/09/15 are covered by the deep agents recon/exploit/scanner/forensics.)
Run `python main.py agents` to see the full roster.

---

## State-of-the-art Claude integration

Every agent runs on the **`BaseAgent`** foundation, which uses:

- **Claude Opus 4.8** — the orchestrator at `xhigh` effort, sub-agents at `high`
- **Adaptive thinking** — Claude decides reasoning depth per turn; summaries captured
- **Streaming** — every turn streamed, so long analyses never hit HTTP timeouts
- **Prompt caching** — the frozen system prompt + tool schemas are cached across
  every call; a moving breakpoint caches the growing conversation. The volatile
  knowledge base is injected into the *first user message*, never the system
  prompt, so the cache is never silently invalidated
- **Telemetry** — token usage, cache-hit rate, and USD cost tracked per agent
- **Guardrails** — every tool input screened for destructive actions before it runs
- **Content safety** — opt-in defense that detects + spotlights prompt-injection in
  untrusted tool output before it re-enters the model context (`ENABLE_UNTRUSTED_CONTENT_DEFENSE`)

### Cost controls — model router + budget governor

Three opt-in cost levers, all **off by default** so existing engagements run unchanged:

- **Model router** (`core/model_router.py`) maps a task class to the right
  `(model, effort)`: high-stakes reasoning (planning, exploit decisions) stays on
  Opus; mechanical work (parsing/summarising scan output) routes to the fast model
  (Haiku).
- **Tool-output compression** — set `COMPRESS_TOOL_OUTPUT=true` and oversized tool
  dumps (nmap / NSE / linpeas) are summarised to their security-relevant facts by
  the fast model *before* they enter (and grow) the expensive Opus context. Degrades
  gracefully: on any error the raw output is kept.
- **Budget governor** — set `ENGAGEMENT_BUDGET_USD` to cap spend. `BaseAgent.run`
  checks the remaining budget before every turn; on breach it either downgrades to
  the fast model for the rest of the run or halts cleanly (partial findings stay in
  the knowledge base), per `ON_BUDGET_EXCEEDED=downgrade|halt`. Remaining budget is
  surfaced in the orchestrator's `get_engagement_status`.

---

## Quick Start (Kali Linux)

### 1. Install

```bash
sudo apt install nmap whois nodejs npm -y
pip3 install -r requirements.txt        # add --break-system-packages on Kali
```

### 2. Configure the engagement

```bash
cp .env.example .env
nano .env
```

Required:
```
ANTHROPIC_API_KEY=sk-ant-...
AUTHORIZED_TARGETS=192.168.56.0/24
ENGAGEMENT_ID=ENG-2026-001
OPERATOR_NAME=your-name
ENGAGEMENT_EXPIRY=2026-12-31T23:59:59
```

### 3. Run

```bash
# Verify scope first
python main.py scope

# AUTONOMOUS — the orchestrator plans the whole engagement
python main.py autonomous 192.168.56.0/24 \
  -o "full pentest, prioritise web and SMB services"

# DETERMINISTIC — fixed kill-chain
python main.py mission 192.168.56.10 --phases recon,scan,vuln_assessment

# Single agent, ad-hoc
python main.py agent recon "enumerate subdomains of lab.internal"

# Inspect state
python main.py knowledge              # shared knowledge base
python main.py evidence --min-severity high
python main.py evidence --verify      # check chain integrity
python main.py mcp                    # MCP server status
python main.py report --generate      # build the pentest report
```

### 4. REST API

```bash
uvicorn api.server:app --host 0.0.0.0 --port 8000
# docs: http://localhost:8000/docs
```

### 5. Docker

```bash
docker-compose up -d
```

---

## MCP Integration

Agents gain external capabilities through MCP servers. Enable them in `.env`:

```
MCP_ENABLED_SERVERS=web,filesystem
```

Two servers are wired and ready:

- **`web`** — official `mcp-server-fetch` (ships in `requirements.txt`).
  Gives every agent `mcp_web_fetch` to pull CVE advisories and vendor bulletins.
- **`filesystem`** — official `@modelcontextprotocol/server-filesystem` (needs
  Node; auto-fetched by `npx`). Scoped to the evidence directory and exposed
  **read-only** via a `tool_allowlist` — 6 read tools, no write/edit/move, so
  agents can review artefacts without touching the tamper-evident chain.

> **Efficiency note:** MCP tool schemas ride in every agent's context on every
> call. The `filesystem` server offers 13 tools; only the 6 useful read-only
> ones are exposed. More servers is not better — the right tools is.

The registry lives in `mcp_layer/mcp_config.py` — add your own stdio or SSE
servers there (each may set a `tool_allowlist`). Five more are templated —
Nuclei, theHarvester (OSINT), BloodHound (AD), threat-intel (GreyNoise/VirusTotal),
and SIEM (read-only) — enable any via `MCP_ENABLED_SERVERS`. Discovered MCP tools are
namespaced `mcp_<prefix>_<tool>` and merged into every agent's tool surface.
An unreachable server is skipped with a warning — the engagement continues on
native tools (graceful degradation).

**Inverse direction (5E):** expose *this* system to other tools (Claude Desktop,
CI) over MCP with `python main.py serve-mcp` — a small, safe surface (`run_recon`,
`run_mission`, `run_autonomous`, `get_findings`, `get_evidence`, `verify_chain`)
that routes through the same scope / guardrail / evidence gates, so external
callers get no privileged path around the safety layer.

---

## Run Modes

**Deterministic** (`run_mission`) — agents run in a fixed phase order. Predictable
and repeatable; good for recurring assessments.

**Autonomous** (`run_autonomous`) — the `OrchestratorAgent` (Opus 4.8, `xhigh`
effort) treats each specialist agent as a *tool*, reasons about findings between
delegations, and decides what to do next. This is the agents-as-tools multi-agent
pattern.

---

## Attack graph

Every fact the agents learn — hosts, services, vulnerabilities, credentials,
footholds — is mirrored from the `KnowledgeBase` into an in-process **attack
graph** (`core/attack_graph.py`) through a write sink, so the planner can ask
*path* questions instead of re-reading a flat JSON blob:

- `high_value_unexploited()` — crown-jewel services (vulnerable, not yet owned), ranked by CVSS.
- `reachable_unowned_hosts()` — hosts seen but not yet compromised.
- `shortest_path_to("domain_admin")` — the shortest path from a current foothold to the goal.

The autonomous planner reads the graph through two orchestrator tools —
`query_attack_graph` (path/relationship questions) and `next_best_action`
(a ranked list of `{agent, target, rationale, score}` moves) — so delegations
follow attack *paths*, not just the flat KB. It stays advisory: the model still
decides.

The default backend is **networkx** (zero infrastructure, and what the tests run
against). Set `NEO4J_URI` (and `docker-compose up -d neo4j`) to ALSO mirror every
write into Neo4j for a live BloodHound-style browser at http://localhost:7474 —
reads still come from the in-process graph, and if Neo4j is unreachable the
engagement is unaffected (graceful degradation, exactly like the MCP layer).

---

## Observability

A live **dashboard** and distributed **traces**, both opt-in and graceful:

- `uvicorn api.server:app` → **http://localhost:8000/dashboard** — a single static
  page (no build step) that streams the current phase, per-agent token/cost, recent
  findings, and attack-graph size over SSE (`GET /events`). No API key needed.
- Set `OTEL_EXPORTER_OTLP_ENDPOINT` (and `docker-compose up -d jaeger`, then
  `pip install opentelemetry-exporter-otlp-proto-http`) to export OpenTelemetry
  spans for every model turn (`agent.turn`), tool call (`agent.tool`), and
  delegation (`orchestrator.delegate`) — the Jaeger UI at http://localhost:16686
  shows the orchestrator→sub-agent→tool tree. Empty endpoint = tracing off (no-op).

---

## Resumable runs

Autonomous engagements checkpoint the planner's conversation (plus KB snapshot,
telemetry, and graph export) under `data/checkpoints/<engagement>/` after every
delegation. If a run is killed (crash, Ctrl-C, API outage), resume it:

```bash
python main.py checkpoints              # list resumable engagements
python main.py resume ENG-2026-001      # continue from the latest checkpoint
```

The evidence chain and KB persist independently, so a resumed run still verifies
clean (`evidence --verify`).

---

## Tradecraft memory

With `ENABLE_TRADECRAFT_MEMORY=true`, the orchestrator distils reusable lessons
(service profile → technique → outcome) at the end of each engagement and recalls
the relevant ones into the planner's first message on similar future targets.
Lessons are redacted (no IPs, hostnames, or credentials), stored per-operator under
`data/memory/` (JSONL; keyword recall), and exposed to the planner via a
`recall_tradecraft` tool. Off by default.

---

## Adversary emulation

Run an engagement as a named threat group: `--actor APT29` (see `python main.py
actors`). The technique mapper and phase playbooks re-rank toward the actor's
ATT&CK repertoire, and the actor's tradecraft notes are injected into every agent's
first message. It's a *soft* constraint — off-profile technique choices are logged
as evidence, not blocked (destructive actions stay hard-blocked by guardrails).

---

## Compliance & retest tracking

The reporting agent maps each finding's ATT&CK technique to **NIST 800-53 / PCI
DSS / SOC 2** controls (`map_to_compliance`) and rolls findings up by control
family (`compliance_rollup`). Each finding gets a stable `finding_signature`
(target + port + CVE + technique) tracked in `data/findings_ledger.json`, so
re-running against the same target labels findings **new / still-open / resolved**
— a trackable remediation program rather than a one-off test.

---

## Testing

```bash
pip3 install pytest
python -m pytest
```

Covers the safety-critical logic: authorization scope, evidence-chain integrity
(including tamper detection), guardrails, the ATT&CK mapper, and the knowledge
base. 40 tests, no network or API key required.

---

## Project Layout

```
linux/
├── main.py                  entry point
├── config/
│   ├── settings.py           env-driven configuration (Pydantic v2)
│   └── authorization.py      engagement scope gate
├── core/
│   ├── base_agent.py         Claude agent foundation (caching, thinking, MCP)
│   ├── orchestrator.py       deterministic + autonomous mission control
│   ├── knowledge_base.py     shared intelligence store
│   ├── evidence_store.py     tamper-evident SHA-256 chain log
│   ├── message_bus.py        agent-to-agent events
│   ├── telemetry.py          token / cost tracking
│   ├── guardrails.py         destructive-action blocking + secret redaction
│   └── attack_framework.py   MITRE ATT&CK technique registry
├── agents/                   the 7 specialist agents
├── mcp_layer/                MCP integration (bridge + server registry)
├── api/server.py             FastAPI REST interface
├── cli/main.py               rich terminal UI
└── tests/                    pytest suite
```

---

## Security

- Every operation passes the `EngagementScope` gate (target + expiry + op type)
- Every action is appended to a SHA-256 **chain-hashed** evidence log —
  verify with `python main.py evidence --verify`
- Destructive payloads (wipers, ransomware, DoS, mass deletion) are blocked by
  the guardrails layer
- Secrets are redacted from generated reports (raw values stay in the operator's
  evidence store only)
- **Never commit `.env`** — it holds API keys and engagement details

---

## Legal Notice

This tool is for **authorized security testing only**. Unauthorized use against
systems you do not own or have explicit written permission to test is illegal.
Always obtain written authorization before use.
