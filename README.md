# Red Team AI Agent System

A state-of-the-art **multi-agent cybersecurity operations platform** built on the
**Anthropic Claude SDK** (Claude Opus 4.7). Seven specialised AI agents cover the
full attack lifecycle — reconnaissance through forensics — coordinated by an
intelligent orchestrator and connected to external tooling via the
**Model Context Protocol (MCP)**.

> ⚠️ **Authorized penetration testing and red-team operations only.**
> Every action is scope-checked and logged. See *Legal Notice* below.

---

## Architecture

```
                    ┌──────────────────────────────────────────┐
                    │            ORCHESTRATOR                   │
                    │  • Deterministic kill-chain mode          │
                    │  • Autonomous mode (agents-as-tools,      │
                    │    Claude Opus 4.7 @ xhigh effort)        │
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
              │   • Authorization  — scope gate         │
              └───────────────────┬─────────────────────┘
                                  │
                          ┌───────┴────────┐
                          │   MCP LAYER    │  external tools / databases
                          │  (stdio + SSE) │  Shodan · filesystem · CVE · web
                          └────────────────┘
```

### The seven agents

| Agent | Phase | Responsibility |
|-------|-------|----------------|
| **ReconAgent** | 1 | DNS, Shodan, WHOIS, subdomain enumeration |
| **ScannerAgent** | 2 | Nmap port/service scanning, banner grabbing |
| **VulnAgent** | 3 | CVE/NVD correlation, NSE vuln scripts, CVSS scoring |
| **ExploitAgent** | 4 | Metasploit RPC, exploit selection, shell management |
| **PostExploitAgent** | 5 | Enumeration, privesc, lateral-movement discovery |
| **ForensicsAgent** | 6 | Timeline, MITRE ATT&CK mapping, artifact collection |
| **ReportingAgent** | 7 | Executive summary, technical findings, remediation |

---

## State-of-the-art Claude integration

Every agent runs on the **`BaseAgent`** foundation, which uses:

- **Claude Opus 4.7** — the orchestrator at `xhigh` effort, sub-agents at `high`
- **Adaptive thinking** — Claude decides reasoning depth per turn; summaries captured
- **Streaming** — every turn streamed, so long analyses never hit HTTP timeouts
- **Prompt caching** — the frozen system prompt + tool schemas are cached across
  every call; a moving breakpoint caches the growing conversation. The volatile
  knowledge base is injected into the *first user message*, never the system
  prompt, so the cache is never silently invalidated
- **Telemetry** — token usage, cache-hit rate, and USD cost tracked per agent
- **Guardrails** — every tool input screened for destructive actions before it runs

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
MCP_ENABLED_SERVERS=web
```

`web` (the official `mcp-server-fetch`) works out of the box — it ships in
`requirements.txt` and gives every agent an `mcp_web_fetch` tool for pulling
CVE advisories and vendor bulletins. `filesystem` additionally needs Node,
`shodan` needs `uv`.

The registry lives in `mcp_layer/mcp_config.py` — add your own stdio or SSE
servers there. Discovered MCP tools are namespaced `mcp_<prefix>_<tool>` and
merged into every agent's tool surface. If a server is unreachable the bridge
logs a warning and the engagement continues on native tools (graceful
degradation).

---

## Run Modes

**Deterministic** (`run_mission`) — agents run in a fixed phase order. Predictable
and repeatable; good for recurring assessments.

**Autonomous** (`run_autonomous`) — the `OrchestratorAgent` (Opus 4.7, `xhigh`
effort) treats each specialist agent as a *tool*, reasons about findings between
delegations, and decides what to do next. This is the agents-as-tools multi-agent
pattern.

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
