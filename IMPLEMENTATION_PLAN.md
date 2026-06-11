# Implementation Plan — Intelligent Attacker (#2) & Engineering Depth (#5)

**Project:** `itthj/redteam-ai-agents`
**Scope:** Two epics, grounded in the current codebase (`core/base_agent.py`, `core/orchestrator.py`, `core/knowledge_base.py`, `core/telemetry.py`, `mcp_layer/`, `agents/phase_agents.py`, `config/settings.py`).
**Design rule:** every change is additive and non-breaking. The flat-JSON `KnowledgeBase`, the prompt-cache strategy (volatile data in the *first user message*, never the system prompt), and the agents-as-tools orchestrator all stay intact. New capabilities attach at existing seams.

---

## 0. Architectural seams we build on

| Seam (today) | What it gives us | What we attach |
|---|---|---|
| `KnowledgeBase` mutators (`add_port`, `add_service`, `add_credential`, `add_shell`) | Single choke-point for all intel writes | A pluggable **sink** that mirrors every write into the attack graph |
| `OrchestratorAgent.TOOLS` (`delegate`, `get_engagement_status`, `set_mission_phase`) | The planner's tool surface | New planner tools: `query_attack_graph`, `next_best_action`, `recall_tradecraft` |
| `OrchestratorAgent._delegate` | The one place every sub-agent task flows through | **Debate gate** before high-risk delegations |
| `BaseAgent` `MODEL`/`EFFORT` already overridable; `telemetry` already prices Haiku | Per-agent model selection + cost tracking | **Model router** + **budget governor** |
| `BaseAgent.run()` keeps `messages` locally | The agentic loop | Lift `messages` into a **checkpoint store** for resume |
| `MCPBridge` (stdio + sse, `tool_allowlist`, graceful degradation) | Battle-tested external-tool plumbing | New registry entries (5D) + an outbound **agents-as-MCP server** (5E) |
| `attack_framework.py` (ATT&CK registry) + `PhaseAgent.get_playbook` | Technique grounding | **Adversary profiles** filter techniques; **compliance map** translates them |

Two new runtime dependencies, both optional and degrade gracefully like the MCP layer already does:

- `neo4j` (or fall back to an in-process `networkx` graph if the driver/server is absent)
- `chromadb` + an embedding model for tradecraft memory (fall back to keyword search over a JSONL store)

---

# EPIC #2 — An attacker that gets smarter within and across engagements

Four capabilities, sequenced so each builds on the last: **(2A)** attack graph brain → **(2B)** graph-driven next-best-action → **(2C)** cross-engagement tradecraft memory → **(2D)** adversary emulation → **(2E)** multi-agent debate gate.

## 2A. Attack graph as the source of truth

**Goal:** represent the engagement as a property graph — `Host`, `Service`, `Vulnerability`, `Credential`, `Session`, `Domain` nodes with `RUNS`, `HAS_VULN`, `AUTHENTICATES_TO`, `PIVOTS_TO`, `MEMBER_OF` edges — so the planner can ask *path* questions ("what's the shortest credential path from my current foothold to a domain admin?") instead of re-reading a flat JSON blob.

**New module:** `core/attack_graph.py`

```python
class AttackGraph:
    def __init__(self, backend="auto"):     # "neo4j" | "networkx" | "auto"
        ...
    # write side — called by the KB sink, idempotent (MERGE semantics)
    def upsert_host(self, ip, **props): ...
    def upsert_service(self, ip, port, **props): ...
    def add_vuln(self, ip, cve, cvss, **props): ...
    def add_credential(self, cred, source_ip): ...
    def add_session(self, ip, **props): ...
    def link_pivot(self, src_ip, dst_ip, via): ...
    # read side — called by planner tools
    def shortest_path_to(self, goal="domain_admin"): ...
    def reachable_unowned_hosts(self): ...
    def high_value_unexploited(self): ...   # crown-jewel scoring
    def query(self, cypher_or_named): ...    # named canned queries only when networkx backend

graph = AttackGraph()                        # module-level singleton, mirrors kb's pattern
```

**Wiring (non-breaking):** add a sink hook to `KnowledgeBase`.

```python
# core/knowledge_base.py
def attach_sink(self, sink): self._sinks.append(sink)
def _emit(self, event, **payload):
    for s in self._sinks:
        try: s(event, payload)
        except Exception as e: log.warning("graph sink failed: %s", e)
```

Call `self._emit("service_added", ip=ip, port=port, info=service_info)` at the end of each mutator (after `self.save()`). In `main.py` startup: `kb.attach_sink(graph.on_kb_event)`. If Neo4j is unreachable, `AttackGraph` logs a warning and uses the `networkx` backend — the engagement is unaffected (same philosophy as `MCPBridge`).

**Backend choice:** Neo4j via `docker-compose` (add a `neo4j` service) gives you BloodHound-style Cypher and a visual browser for the operator. `networkx` is the zero-dependency fallback and what the unit tests run against.

**Acceptance:** after a recon+scan+vuln run, `graph.high_value_unexploited()` returns the same target/service set that exists in `kb.snapshot()`, and `shortest_path_to("domain_admin")` returns a node path on a seeded fixture.

## 2B. Graph-driven planning tools for the orchestrator

**Goal:** let the autonomous planner consult the graph instead of (or alongside) the KB snapshot, so delegation decisions follow attack *paths*.

**Change:** extend `OrchestratorAgent.TOOLS` with two tools and add their handlers to `_tool_map()`:

- `query_attack_graph(question)` → wraps `graph.query` / named queries; returns paths and node sets.
- `next_best_action()` → a scoring function over the graph (unexploited high-CVSS services on reachable hosts, cred-reuse opportunities, pivot frontiers) returning a ranked list of `{agent, target, rationale, score}` suggestions the planner can choose from.

Update the orchestrator system prompt's METHODOLOGY: "Before each delegation, call `next_best_action` and justify your choice against the returned ranking." Keep it advisory — the model still decides, preserving the autonomous pattern.

**Acceptance:** in a scripted scenario with one obviously-dominant path, `next_best_action()` ranks that path first; an integration test asserts the orchestrator delegates to the suggested agent/target.

## 2C. Cross-engagement tradecraft memory

**Goal:** the system remembers what worked on similar targets in past engagements and surfaces it at planning time.

**New module:** `core/memory.py`

```python
class TradecraftMemory:
    def distill(self, engagement_id) -> list[Lesson]:   # post-engagement summarizer (Haiku)
    def store(self, lessons): ...                        # chromadb upsert w/ metadata
    def recall(self, context) -> list[Lesson]:           # top-k by target profile + services
```

A `Lesson` is `{situation, action, technique_id, outcome, target_profile}` — e.g. *"vsftpd 2.3.4 on :21 → CVE-2011-2523 backdoor via exploit agent → root shell, worked."* Distillation runs in `Orchestrator._finish()` using `settings.claude_fast_model` (Haiku) — cheap, and the engagement is already over so latency is free.

**Retrieval respects the cache strategy:** recalled lessons are injected into the orchestrator's *first user message* (where the volatile KB already goes in `BaseAgent._build_first_message`), never the cached system prompt. Add an optional planner tool `recall_tradecraft(situation)` for mid-engagement lookups.

**Privacy/safety:** lessons store target *profiles* (service versions, OS, topology shape) and techniques — **never** credentials, hostnames, or client-identifying data. Add a redaction pass (reuse `guardrails` secret-redaction) before `store()`. Memory is per-operator and gitignored alongside `.env`.

**Fallback:** no `chromadb`/embeddings → JSONL store with keyword/TF-IDF recall. Same interface.

**Acceptance:** run engagement A against a fixture, then engagement B against a similar fixture; assert `recall()` returns A's relevant lesson and it appears in B's orchestrator first message.

## 2D. Named-adversary emulation ("run as APT29")

**Goal:** constrain the operation to a real threat group's known TTPs for emulation exercises.

**New module:** `core/adversary_profiles.py`

```python
@dataclass(frozen=True)
class AdversaryProfile:
    group_id: str            # e.g. "G0016"
    name: str                # "APT29"
    techniques: frozenset    # ATT&CK IDs the group is known to use
    preferred_tools: tuple
    tradecraft_notes: str    # injected into agent prompts

PROFILES: dict[str, AdversaryProfile] = {...}   # seeded from MITRE ATT&CK Groups
```

Seed `techniques` from MITRE's published group→technique mappings (ATT&CK Navigator layer JSON; ship a small curated subset, document how to regenerate).

**Wiring:**

- New setting `engagement_actor: str = ""` and CLI flag `--actor APT29` on `main.py autonomous`/`mission`.
- `attack_framework.map_action()` and `PhaseAgent._get_playbook()` accept an optional active profile and **filter/re-rank** techniques to the actor's repertoire.
- Inject `tradecraft_notes` into the *first user message* (cache-safe) for every agent when an actor is set.
- **Soft constraint, not a block:** if the planner reaches for a technique outside the profile, log an evidence note ("off-profile technique X chosen") and let it proceed — emulation fidelity is a goal, not a guardrail. (Destructive actions remain hard-blocked by `guardrails`.)

**Acceptance:** `python main.py autonomous <range> --actor APT29` produces a report whose technique IDs are ⊆ profile (or flagged off-profile in evidence); roster command `python main.py actors` lists available profiles.

## 2E. Multi-agent debate gate before risky moves

**Goal:** a devil's-advocate critic and a safety reviewer must sign off before high-impact delegations.

**New module:** `core/debate.py` with two lightweight `BaseAgent` subclasses:

- `PlanCritic` — argues *against* the proposed action (false-positive risk, blast radius, stealth cost, better alternatives).
- `SafetyReviewer` — checks the action against the rules-of-engagement and scope; returns `approve | revise | veto` with reasoning.

**Wiring:** in `OrchestratorAgent._delegate`, when `agent in HIGH_RISK = {exploit, execution, persistence, defense_evasion, credential_access, lateral_movement, command_and_control, exfiltration, impact}`, run the debate first:

```python
verdict = await debate.review(agent, task, kb.snapshot())
evidence.log("debate", "review", verdict.summary, severity="info")
if verdict.decision == "veto":
    return {"agent": agent, "blocked": True, "reason": verdict.reason}
task = verdict.revised_task or task        # critic may tighten scope
```

Runs on `claude_fast_model` (Haiku) to keep cost down; the full reasoning is captured in the evidence chain — a strong governance story for an offensive tool. Add `ENABLE_DEBATE=true` so it can be turned off for speed.

**Acceptance:** a unit test feeds an out-of-scope/over-broad task and asserts `decision == "veto"` and that no sub-agent ran; a benign task passes through unchanged.

---

# EPIC #5 — Engineering depth that signals production seriousness

Six workstreams: **(5A)** model router + budget governor → **(5B)** resumable checkpoints → **(5C)** OTel tracing + live dashboard → **(5D)** MCP fleet expansion → **(5E)** agents-as-MCP server → **(5F)** compliance-mapped reporting.

## 5A. Cost/model router + budget governor

**Goal:** stop paying Opus prices for mechanical work, and never blow a cost ceiling.

**Observation:** `BaseAgent` already supports per-agent `MODEL`/`EFFORT`; `telemetry` already prices `claude-haiku-4-5`; `settings` already defines `claude_fast_model`. The router formalizes routing policy and adds a budget gate.

**New module:** `core/model_router.py`

```python
class ModelRouter:
    def pick(self, task_class: str) -> tuple[str, str]:   # returns (model, effort)
        # planning/exploit-decision → opus xhigh/high
        # parse/summarize/classify scan output → haiku low
```

**Two concrete wins:**

1. **Tool-output compression.** In `BaseAgent._run_tool_calls`, when a tool result exceeds N chars (nmap/NSE/linpeas dumps are huge), pass it through a one-shot Haiku "extract the security-relevant facts" call *before* it enters the Opus context. Large token savings on the most expensive (cached-growing) part of the loop.
2. **Routed sub-tasks.** Reporting prose, finding summarization, and the debate/distill steps already proposed run on Haiku.

**Budget governor:** new setting `engagement_budget_usd: float = 0`. Extend `telemetry` with `budget_remaining()` and `over_budget()`. `BaseAgent.run` checks before each turn; on breach it either (a) downgrades to `claude_fast_model` for the rest of the run, or (b) aborts cleanly and records partial findings — configurable via `ON_BUDGET_EXCEEDED=downgrade|halt`. Orchestrator surfaces remaining budget in `get_engagement_status`.

**Acceptance:** a run with a tiny budget halts/downgrades and logs it; telemetry shows >30% of calls on Haiku with no loss of report fidelity on the lab fixture.

## 5B. Resumable, checkpointed engagements

**Goal:** survive crashes, API outages, and Ctrl-C; resume long autonomous runs.

**Problem:** the autonomous loop's `messages` list lives only inside `BaseAgent.run`. To resume, that state must be externalized.

**New module:** `core/checkpoint.py`

```python
class Checkpoint:
    def save(self, engagement_id, *, kb_snapshot, mission_state,
             orchestrator_messages, telemetry, graph_export): ...
    def load(self, engagement_id) -> dict | None: ...
```

Stored as JSON under `data/checkpoints/<engagement_id>/<seq>.json` (KB and evidence chain already persist; this adds planner state + graph export).

**Wiring:**

- Add optional `resume_messages: list | None = None` to `OrchestratorAgent.run` (and a thin pass-through on `BaseAgent.run`) so a run can rehydrate its conversation.
- `Orchestrator.run_autonomous` / `_run_phase` write a checkpoint at each phase boundary and register a `SIGINT`/`finally` handler to flush one on interruption.
- New CLI: `python main.py resume <engagement_id>` and `python main.py checkpoints`.

**Idempotency:** the graph and KB use MERGE/dedup semantics already, so replaying the last delegated task on resume is safe.

**Acceptance:** start an autonomous run, kill it mid-engagement, `resume` it, and confirm it continues from the last checkpoint with the evidence chain still verifying (`evidence --verify`).

## 5C. OpenTelemetry tracing + live engagement dashboard

**Goal:** see the operation unfold in real time and get distributed traces of every turn, tool call, and delegation.

**New module:** `core/tracing.py` — initialize an OTel tracer with an OTLP exporter; no-op if `opentelemetry` isn't installed (graceful degradation). New setting `otel_exporter_otlp_endpoint: str = ""`.

**Instrument three choke-points** with spans:

- `BaseAgent._stream_turn` → span per model turn (attrs: agent, model, effort, tokens, cost, cache-hit).
- `BaseAgent._execute_tool` → span per tool call (attrs: tool name, target, guardrail result, is_error).
- `OrchestratorAgent._delegate` → parent span wrapping the whole sub-agent run, so traces show the delegation tree.

Spans export to Jaeger/Tempo/Grafana via OTLP (add to `docker-compose`). **Optional managed sinks:** the same OTLP stream can point at a hosted observability connector (Honeycomb, Datadog, and incident.io are all available in your connector registry) if the operator prefers SaaS over self-hosting.

**Live dashboard:** `api/server.py` already runs FastAPI and the project has a `MessageBus`. Add:

- `GET /dashboard` → a single static HTML page (no build step).
- `GET /events` → SSE stream that fans out `MessageBus` events + periodic `telemetry.summary()`.

The page renders the current phase, per-agent token/cost, live findings, and (via the graph export) a simple node-link view of compromised hosts.

**Acceptance:** during a run, `/dashboard` shows findings and cost updating live; a trace in Jaeger shows the orchestrator→sub-agent→tool span tree for one delegation.

## 5D. Expand the MCP fleet

**Goal:** more reach without touching agent code — the bridge already discovers, namespaces, and allowlists tools.

**Change:** add registry entries to `MCP_SERVERS` in `mcp_layer/mcp_config.py`, each with a tight `tool_allowlist` (the README's "right tools, not more tools" principle):

- **Nuclei** — templated vuln scanning (feeds the vuln agent).
- **theHarvester / OSINT** — emails, subdomains, hosts (feeds recon).
- **BloodHound / AD** — ingest data to enrich the 2A graph directly (read-only).
- **Threat intel** — GreyNoise / VirusTotal (enrich CVE and IP context; read-only).
- **SIEM (Splunk/Elastic/Sentinel)** — *read-only* query tools, the foundation for a future purple-team detection-coverage scorecard.

Each entry is ~10 lines mirroring the existing `shodan`/`cve` templates. Document required API keys in `.env.example`. Unreachable servers already skip gracefully.

**Acceptance:** with `MCP_ENABLED_SERVERS=web,nuclei`, `python main.py mcp` lists the namespaced Nuclei tools and the vuln agent can call them.

## 5E. Expose the agents as an MCP server (outbound)

**Goal:** let other tools (Claude Desktop, CI, another orchestrator) drive *your* red-team system over MCP — the inverse of what the bridge does today.

**New module:** `mcp_layer/redteam_mcp_server.py` (FastMCP) exposing a deliberately small, safe surface:

- `run_recon(target)`, `run_mission(targets, phases)`, `run_autonomous(objective, targets)`
- `get_findings()`, `get_evidence(min_severity)`, `verify_chain()`

Each handler reuses `Orchestrator.dispatch` / `run_mission`, so **scope authorization, guardrails, and evidence logging all still apply** — external callers get no privileged path around the safety layer. Expose over stdio (local) and optionally SSE (network) behind the existing `api_secret_key`.

New CLI: `python main.py serve-mcp`. Document a Claude Desktop config snippet in the README.

**Acceptance:** a stdio MCP client lists the tools and `run_recon` against an in-scope target returns findings; an out-of-scope target is rejected by the authorization gate exactly as in the CLI path.

## 5F. Compliance-mapped reporting + retest tracking

**Goal:** deliverables that map findings to the frameworks clients actually audit against, and that track whether a finding was fixed.

**New module:** `core/compliance.py`

```python
ATTACK_TO_NIST: dict[str, list[str]]      # T-id → 800-53 controls (MITRE publishes this mapping)
ATTACK_TO_PCI:  dict[str, list[str]]      # curated subset
def map_finding(technique_id) -> {"nist_800_53": [...], "pci_dss": [...], "soc2": [...]}
```

Seed `ATTACK_TO_NIST` from MITRE's official ATT&CK↔800-53 control mappings (ship the data file, document refresh).

**Reporting wiring:** give the reporting agent a `map_to_compliance(technique_id)` tool and a report section that rolls findings up by control family ("3 findings touch NIST AC-2; 2 touch PCI Req 8").

**Retest tracking:** add a stable `finding_signature` (hash of target+port+CVE+technique) and a `status` field (`open|retest|resolved`) persisted across engagements in `data/findings_ledger.json`. On a new engagement against the same target, the reporting agent diffs current findings against the ledger and labels each **new / still-open / resolved** — turning one-off pentests into a trackable remediation program.

**Acceptance:** the generated report contains a compliance rollup table; running twice against a fixture where one vuln is "fixed" marks that finding `resolved` and the rest `still-open`.

---

# Sequencing, dependencies, and effort

| Order | Workstream | Depends on | Rough effort | Why here |
|---|---|---|---|---|
| 1 | **5A** model router + budget | none | S | Immediate cost win; unblocks cheap Haiku steps used by 2C/2E |
| 2 | **2A** attack graph | 5A (Haiku) optional | M | The data backbone everything intelligent reads from |
| 3 | **2B** planner graph tools | 2A | S | Turns the graph into better decisions |
| 4 | **5C** OTel + dashboard | none (parallelizable) | M | Makes all later work observable while building |
| 5 | **2E** debate gate | 5A | S | Safety + decision quality; small once router exists |
| 6 | **5B** checkpoints | 2A (graph export) | M | Needed before long autonomous runs are practical |
| 7 | **2C** tradecraft memory | 2A, 5A | M | Cross-engagement learning |
| 8 | **2D** adversary emulation | attack_framework | M | High-demo-value, independent |
| 9 | **5D** MCP fleet | none | S each | Incremental, low risk |
| 10 | **5E** agents-as-MCP | stable CLI paths | M | Distribution/integration |
| 11 | **5F** compliance + retest | reporting agent | M | Client-facing polish |

S ≈ 1–2 days, M ≈ 3–5 days for one engineer familiar with the code.

# Cross-cutting requirements

- **Backward compatibility:** every new module is optional and degrades gracefully (the `MCPBridge`/`_mcp_available()` pattern is the template). No change alters existing CLI output or the KB JSON schema; the graph/memory/checkpoint stores are additive files.
- **Config:** new settings (`engagement_budget_usd`, `engagement_actor`, `otel_exporter_otlp_endpoint`, `enable_debate`, `on_budget_exceeded`, `neo4j_uri`) added to `Settings` + `.env.example`, all with safe defaults so existing `.env` files keep working.
- **Testing:** extend the pytest suite (currently 40 tests, no network/key needed). Add unit tests for graph queries (networkx backend), router policy, budget gate, debate veto, compliance mapping, checkpoint round-trip, and memory recall — all runnable offline against fixtures. Keep the "no API key required" guarantee for CI.
- **Safety posture:** the debate gate (2E), off-profile logging (2D), budget halt (5A), and the unchanged guardrail/authorization/evidence layers mean every new capability is *more* auditable, not less. The agents-as-MCP server (5E) deliberately routes through the same gates.
- **Docs:** update `README.md` architecture diagram to show the Attack Graph, Memory, and Tracing in the SHARED CORE box, and add a `docs/` page per epic.

# Suggested first PR

Ship **5A (model router + budget governor)** as the opener: it's self-contained, touches only `telemetry`, `settings`, and `BaseAgent`, delivers an immediate cost reduction you can measure in `telemetry.summary()`, and creates the cheap-inference primitive that 2C, 2E, and 5F all reuse. Then **2A** as the second PR to lay the graph backbone.

---
---

# EPIC 6 — Client-grade engagement delivery (9 new capabilities)

> **Added 2026-06-11** as a *new* kickoff mandate, appended below the (now-complete)
> Epic #2/#5 design above so the original design doc is preserved verbatim — nothing
> above this line was edited. Capabilities are labelled **C1–C9** (collision-free with
> the existing `2A–2E` / `5A–5F` ids). Each capability is executed with the standing
> per-workstream discipline from `CLAUDE.md`: one capability = one branch
> `feat/C<n>-...` = one PR, EXPLORE → PLAN (`​.dev/PLAN_C<n>.md`) → IMPLEMENT → VERIFY
> (full suite green, fully offline) → COMMIT, updating `CHANGELOG.md` and docs as we go.
> **Every hard constraint from the original build still holds** (additive & non-breaking,
> safe-default opt-in settings, graceful degradation, no breaking change to public
> signatures / CLI output / KB JSON schema, offline tests with no key/network, and
> nothing weakens the scope gate / guardrails / evidence chain).

## 6.0 How the existing platform works (the seams these 9 capabilities attach to)

Everything below plugs into patterns that already exist — no new architecture, just
new agents, new MCP servers, and a few additive extension points.

| Seam (today, verified) | What it gives a new capability |
|---|---|
| **`BaseAgent`** (`core/base_agent.py`) — agentic loop, streaming, prompt-cache (volatile KB in the *first user message*, never the cached system prefix), per-call `telemetry.record`, guardrail pre-flight on every tool input, `USE_MCP` merges bridge tools | Subclass it for `webapp_agent`, `validation_agent`, `llm_redteam_agent`, `cloud_agent`. Override `MODEL`/`EFFORT` for tiering. Get safety + cost tracking for free. |
| **Specialist + `PhaseAgent`** (`agents/`) — native tools via `_tool_map()`, register in `Orchestrator._get_agent` + `_ALL_AGENTS` + the planner roster prompt | The template for every new agent. `credential_access` / `lateral_movement` PhaseAgents already exist → C5 just gives them AD tools, no new agent. |
| **MCP layer** — inbound `MCPBridge` (`mcp_layer/mcp_bridge.py`: stdio+sse, `tool_allowlist`, namespaced `mcp_<prefix>_<tool>`, `_CONNECT_TIMEOUT`, graceful skip) + registry `MCP_SERVERS` (`mcp_config.py`) + outbound FastMCP server (`redteam_mcp_server.py`) | Each new tool surface (ZAP, Nuclei, BloodHound CE, GoPhish, garak/PyRIT, Prowler/Trivy) is a `MCP_SERVERS` entry and/or a small FastMCP server under `mcp_layer/servers/`. Unreachable ⇒ warn + native fallback. |
| **`EngagementScope`** (`config/authorization.py`) — `scope.authorize(target, OperationType)` at the start of every target-touching tool; IP/CIDR/hostname-suffix matching; expiry check | Every new action routes through this. Non-IP targets (email domains, cloud accounts, LLM endpoints) need an additive extension — see §6.1. |
| **`EvidenceStore`** (`core/evidence_store.py`) — append-only SHA-256 chain in SQLite; `evidence.log(agent, op, action, target, result, severity)`; `verify_chain()` | Every new finding/action is logged here, chained and tamper-evident. Unchanged. |
| **`KnowledgeBase`** (`core/knowledge_base.py`) — thread-safe JSON store + `attach_sink` (mirrors writes into the attack graph) | New findings land via `kb.add_vulnerability` / `add_note`. The attack-graph sink (2A) means C5's AD paths and C1's web findings auto-populate the graph. |
| **`Guardrails`** (`core/guardrails.py`) — destructive-command/payload block (base64-aware), secret redaction, `check_tool_input` | Every new command/payload passes `check_command`/`check_payload`; reports get `sanitize()`. Unchanged and authoritative. |
| **`Telemetry` + budget governor + `ModelRouter`** (`core/telemetry.py`, `model_router.py`) — per-agent token/USD, `over_budget()`, `router.pick(task_class)` reading model names from `settings` | Cost governance + model tiering for high-volume specialist work (alert/scan-result triage → fast model). No hardcoded models. |
| **Degradation template** — `MCPBridge._mcp_available()` / `redteam_mcp_server._mcp_available()`: optional dep missing ⇒ log warning, no-op, continue | Copy this exactly for `zaproxy`, `nuclei`, `bloodhound`, `gophish`, `garak`, `pyrit`, `prowler`, `trivy`. A missing external tool never crashes an engagement. |
| **FastAPI app** (`api/server.py`) — REST + SSE `/events` (already streams phase, telemetry, findings, graph) + zero-build `/dashboard` | C4 extends this with CRUD + approval-queue + WebSocket; the existing static dashboard keeps working. |

## 6.1 New cross-cutting extension points (built once in early capabilities, reused by many)

These are the only genuinely *new* primitives; everything else is an agent or an MCP
server. All are additive and opt-in.

1. **Scope gate for non-IP targets** (additive to `config/authorization.py`). The current
   gate models targets as IP/CIDR/hostname. Three capabilities act on other identifiers:
   - C6 phishing → **email addresses / domains** (must be inside the client's authorized domain)
   - C9 cloud posture → **cloud accounts / subscriptions / projects** (not network hosts)
   - C8 LLM red-team → **LLM API endpoints / URLs**

   Plan: add new `OperationType` members (`WEB_ACTIVE_SCAN`, `PHISHING`, `CLOUD_POSTURE`,
   `LLM_REDTEAM`, `AD_STATE_CHANGE`) and new settings
   (`authorized_email_domains`, `authorized_cloud_accounts`, `authorized_llm_endpoints`)
   with `scope.authorize_email(addr)`, `scope.authorize_cloud(account)`,
   `scope.authorize_endpoint(url)` helpers that mirror `authorize()` (raise
   `AuthorizationError` out of scope, log on success). The existing `authorize()` path is
   untouched. *(Needs your sign-off — see Open Decisions.)*

2. **Explicit-authorization + human-approval gate** for any intrusive/outbound action
   (web active scan, AD state change, phishing send, exploit). New
   `core/approval.py`: a tiny gate `require_authorization(action, settings_flag)` that
   (a) checks a per-capability written-authorization flag tied to the engagement
   (`WEBAPP_ACTIVE_SCAN_AUTHORIZED`, `PHISHING_AUTHORIZED`, `AD_STATE_CHANGE_AUTHORIZED`,
   default **false**), and (b) requires a human-approval record before the action runs.
   Reuses the EvidenceStore for the approval audit trail. This is the single choke-point
   the prompt's "explicit authorization flag AND a human-approval step" maps onto.

3. **Finding lifecycle `candidate → confirmed → approved`** (C2; `core/finding_state.py`).
   A separate signature-keyed store (like `findings_ledger.json`), **not** a mutation of
   the KB vuln dicts, so the KB JSON schema is untouched. AI agents only ever write
   `candidate`; the deterministic `validation_agent` promotes to `confirmed`; a human
   promotes to `approved` via API/CLI. Nothing is reported or sent until `approved`.
   Builds directly on the existing `FindingValidator` + `finding_signature`.

4. **Compliance-mapping expansion** (C3; extends `core/compliance.py`). Add
   `ATTACK_TO_ISO27001`, `ATTACK_TO_CBK` (Central Bank of Kenya Guidance Note on
   Cybersecurity), `ATTACK_TO_KDPA` (Kenya Data Protection Act 2019) tables alongside the
   existing NIST/PCI/SOC2 maps; report structure anchored on **PTES**, severity on **CVSS**.

5. **Pre-run cost estimator** (`core/cost_estimator.py`). Estimate tokens from scope size
   × per-phase priors → USD; hard-stop before the run if estimate > `engagement_budget_usd`
   (the live governor in `telemetry.over_budget()` already enforces the ceiling mid-run).

## 6.2 The nine capabilities

For each: **what's new**, **where it plugs in**, **safety routing**, **degradation**,
**tests** (offline, mock the external tool), **Kali install**, **model tier**.

### C1 — Web application testing (`webapp_agent` + `webapp` MCP server: OWASP ZAP + Nuclei)
- **New:** `agents/webapp_agent.py` (deep agent, mirrors `VulnAgent`); `mcp_layer/servers/zap_server.py`
  (FastMCP, mirrors `redteam_mcp_server.py`) exposing `zap_context_setup`, `zap_spider`,
  `zap_ajax_spider`, `zap_active_scan`, `zap_alerts` (via the `zaproxy` Python client to a
  ZAP daemon) and `nuclei_scan` (subprocess, `-json-export`, `-update-templates`); registry
  entries in `MCP_SERVERS`; `core/owasp_map.py` (ATT&CK/CWE → OWASP Top 10 + WSTG).
- **Plug-in:** register `webapp` in `Orchestrator._get_agent`, `_ALL_AGENTS`, planner roster.
- **Safety:** spider/passive ⇒ `scope.authorize(host, VULNERABILITY_SCAN)`. **Active scan is
  intrusive** ⇒ `OperationType.WEB_ACTIVE_SCAN` + `approval.require_authorization(...)`
  (flag + human step). ZAP attack payloads pass `guardrails.check_command/payload`. Alerts →
  `kb.add_vulnerability` + `evidence.log`, created as **candidate** findings (feeds C2).
- **Degradation:** ZAP daemon down / `zaproxy`/`nuclei` absent ⇒ warn + no-op; agent
  continues on native HTTP checks.
- **Tests:** mock the ZAP client + nuclei subprocess; assert out-of-scope URL blocked,
  active scan refused without the auth flag + approval, alerts become candidate findings,
  OWASP mapping correct.
- **Kali:** `sudo apt install -y zaproxy nuclei && nuclei -update-templates` (or
  `pip install zaproxy`); run ZAP daemon: `zaproxy -daemon -port 8090 -config api.key=…`.
- **Model tier:** alert triage/classification → `router.pick("classify")` (fast model).

### C2 — Finding-validation engine (`candidate → confirmed → approved` + approval queue)
- **New:** `core/finding_state.py` (state machine + signature-keyed `ApprovalQueue` store);
  `agents/validation_agent.py` (deterministic re-test: re-issue the exact HTTP request,
  re-run the specific Nuclei template, replay client-side issues in a headless browser).
- **Plug-in:** all agent finding-writes (`record_finding`, `save_vulnerability`, C1 alerts)
  default to `state=candidate`. `validation_agent` promotes candidate→confirmed **only** with
  bound re-test evidence + CVSS. Human promotes confirmed→approved via a new API endpoint /
  CLI command. Reporting/sending (C3/C4/C6) refuse anything not `approved`.
- **Safety:** re-tests go through the same scope gate + guardrails; confirmation evidence is
  chained. Hard invariant (tested): **no path lets an AI agent produce `confirmed` or
  `approved`.**
- **Tests:** candidate cannot auto-approve; validator promotes only on matching evidence;
  approval requires explicit human action; report/send blocked for non-approved.
- **Model tier:** none (deterministic, no model call) — this is the anti-hallucination spine.

### C3 — Compliance-mapped reporting (ISO 27001 Annex A · PCI DSS · CBK · Kenya DPA 2019)
- **New:** mapping tables in `core/compliance.py` (see §6.1.4); `ReportingAgent` gains a
  `compliance_appendix` tool and three-tier rendering (executive / technical / compliance
  appendix) reusing `core/report_export.py`.
- **Plug-in:** consumes **approved** findings (C2) + C9 cloud checks; one engagement → three
  documents. Structure anchored on PTES, severity on CVSS (existing `_calculate_risk_score`).
- **Tests:** each technique maps to all four frameworks; three tiers render; only approved
  findings appear.
- **Decision:** CBK + KDPA control maps are curated subsets seeded from the public source
  texts — I'll cite sources in-doc; confirm you want the full mapping vs a representative subset first.

### C4 — Client dashboard (full API + React frontend, live cost over WebSocket/SSE)
- **New:** extend `api/server.py` with CRUD (engagements, findings w/ candidate/confirmed/
  approved + the approval action, evidence, reports, agent start/stop/observe) and a
  WebSocket endpoint that bridges `core/message_bus.py` for live agent activity; `frontend/`
  React (Vite) app: KPI overview, engagements list, findings table (states), approval queue,
  live activity + live token/USD (the SSE `/events` payload already carries telemetry).
- **Plug-in:** purely additive endpoints; the existing zero-build `/dashboard` stays.
- **Tests:** FastAPI `TestClient` (offline) for CRUD + approval transitions + SSE/WS payload
  shape. Frontend kept out of the pytest gate (separate `npm test`/excluded).
- **Decision:** React (Vite) vs Next.js; `frontend/` in-repo (adds Node to CI) vs separate.

### C5 — Active Directory / Windows testing (`ad` MCP server for the existing phase agents)
- **New:** `mcp_layer/servers/ad_server.py` wrapping **BloodHound CE** (REST API + collector),
  **bloodhound-python** (ce branch), **NetExec (nxc)**, **Impacket**, **Certipy**. Tools:
  `bh_collect`, `bh_load`, `bh_shortest_path`, `nxc_enum`, `impacket_query`, `certipy_find`
  (+ gated state-changing variants). Replaces/extends the existing read-only `bloodhound`
  SSE stub in `MCP_SERVERS`.
- **Plug-in:** **no new agent** — the existing `credential_access` + `lateral_movement`
  `PhaseAgent`s gain these via `USE_MCP`. Collected attack paths are recorded as evidence
  **and** mirrored into the 2A attack graph (KB sink), enriching `next_best_action`.
- **Safety:** enumeration/read-first by default. State-changing actions (nxc exec, Certipy
  request/auth) ⇒ `OperationType.AD_STATE_CHANGE` + `approval.require_authorization` + scope.
- **Degradation:** BHCE/nxc/impacket/certipy absent ⇒ warn + no-op.
- **Tests:** mock BHCE REST + nxc/impacket/certipy subprocess; assert read-only default,
  state-change refused without auth, paths recorded + graph updated.
- **Kali:** `pipx install bloodhound netexec impacket certipy-ad`; BloodHound CE via
  `docker compose` (BHCE compose file) — I'll add a `bloodhound-ce` service to `docker-compose.yml`.

### C6 — Phishing / social engineering (`social_eng` MCP server: GoPhish REST)
- **New:** `mcp_layer/servers/gophish_server.py` wrapping the GoPhish REST API (templates,
  landing pages, sending profiles, target groups, multi-wave campaigns, click/submit metrics).
- **Safety (strongest gates in the build):** every campaign ⇒ `OperationType.PHISHING` +
  `approval.require_authorization("phishing", PHISHING_AUTHORIZED)` (written-authorization
  flag tied to the engagement) **+ human approval**. Target lists validated with
  `scope.authorize_email(addr)` — **every** recipient must be inside the authorized client
  domain or the campaign is refused. All actions + metrics → evidence/KB.
- **Degradation:** GoPhish API unreachable ⇒ warn + no-op.
- **Tests:** campaign blocked without the flag; blocked without human approval; any
  out-of-domain recipient rejects the whole send; mock the GoPhish API.
- **Kali:** download the GoPhish release binary, run it, set `GOPHISH_API_URL` +
  `GOPHISH_API_KEY` in `.env`.
- **Decision:** how "written authorization" is represented (flag + reference to a signed
  authorization file vs a stronger token) — see Open Decisions.

### C7 — Multi-tenant SaaS backend (PostgreSQL + RLS · Celery + Redis · OAuth2/JWT + RBAC · Vault/KMS · append-only audit)
- **New:** a `saas/` package — SQLAlchemy models (`tenants`, `users`, `engagements`,
  `findings`, `evidence_index`, `audit_log`) with `tenant_id` on every row + **Postgres
  row-level security**; **Celery + Redis** tasks wrapping `Orchestrator.run_mission/
  run_autonomous` (persistence, retries, status, resume — builds on `core/checkpoint.py`);
  **OAuth2/JWT + RBAC** (operator / analyst / client-viewer) layered on the FastAPI app;
  a secrets provider abstraction (**Vault / cloud KMS**, degrading to `.env` in dev);
  append-only `audit_log` mirroring the evidence-chain pattern.
- **How it reconciles with the singletons (key design point):** the core engine stays a
  per-process singleton (`kb`/`evidence`/`scope`/`telemetry`). **One Celery worker runs one
  engagement**; the Postgres layer is the multi-tenant system-of-record that indexes/mirrors
  each job's findings + evidence and enforces tenant isolation + RBAC at the API edge. Core
  modules are **not** refactored — C7 wraps them. This keeps "additive & non-breaking" true.
- **Delivers the product non-negotiables:** reliability (Celery crash-survival/resume/partial
  progress), self-security (RLS tenant isolation, at-rest evidence encryption via the existing
  `cryptography` dep, secret rotation via Vault, access logging via `audit_log`), per-tenant
  cost budgets (Postgres-tracked, on top of the per-engagement governor).
- **Tests (offline):** RLS denies cross-tenant reads (SQLite-compat shim or a marked
  pg-only subset), RBAC matrix, Celery task status transitions (eager mode / mock broker),
  JWT issue/verify. No live Postgres/Redis required for the suite.
- **This is the one capability that strains the additive constraint — see Open Decisions
  for scope, RLS-vs-schema-per-tenant, secret backend, and whether it should precede C4's auth.**

### C8 — AI / LLM red teaming (`llm_redteam_agent` + `llm_redteam` MCP server: garak + PyRIT)
- **New:** `agents/llm_redteam_agent.py`; `mcp_layer/servers/llm_redteam_server.py` running
  **garak** (baseline scan) and **PyRIT** (multi-turn / indirect prompt-injection scenarios)
  against a client-authorized LLM endpoint; `core/owasp_llm_map.py` (OWASP Top 10 for LLM
  Apps; prompt injection = **LLM01**).
- **Safety:** assessment/discovery **only**, scoped to the client's own app via
  `scope.authorize_endpoint(url)` + `OperationType.LLM_REDTEAM` + an explicit
  `LLM_REDTEAM_AUTHORIZED` flag. Findings written as candidates (C2) mapped to LLM01–LLM10.
- **Degradation:** garak/PyRIT absent ⇒ warn + no-op (heavy optional deps).
- **Tests:** mock the garak/PyRIT runners; scope gate on endpoint; results map to LLM01–10.
- **Kali/host:** `pip install garak pyrit` (verify exact PyRIT package name during C8).
- **Model tier:** result parsing/classification → fast model.

### C9 — Cloud & container posture (`cloud_agent` + `cloud` MCP server: Prowler + Trivy)
- **New:** `agents/cloud_agent.py`; `mcp_layer/servers/cloud_server.py` running **Prowler**
  (AWS/Azure/GCP/K8s CSPM, compliance-framework-aware, `-M json`) and **Trivy**
  (container/image/IaC/cloud misconfig, `--format json`) with **read-only** client creds.
- **Safety:** `scope.authorize_cloud(account)` + `OperationType.CLOUD_POSTURE`; read-only
  credentials enforced. Each failed check → severity + a compliance control (feeds C3) →
  candidate finding (C2) + evidence.
- **Degradation:** prowler/trivy absent ⇒ warn + no-op.
- **Tests:** mock prowler/trivy JSON; scope gate on account; checks map to severity + control
  as candidates.
- **Kali:** `pip install prowler` ; `sudo apt install -y trivy` (or the Aqua install script).
- **Model tier:** check summarisation/mapping → fast model.

## 6.3 Product-grade non-negotiables (built in, mapped to mechanisms)

- **Cost governance** — per-engagement budget + live hard-stop already exist
  (`engagement_budget_usd`, `telemetry.over_budget()`); add the **pre-run estimator**
  (§6.1.5) and **per-tenant budgets** in C7. Model tiering via `model_router` keeps
  high-volume specialist work on the fast model. No model names hardcoded.
- **Reliability** — Celery (C7) gives crash-survival, retries, and resume; `core/checkpoint.py`
  already rehydrates an interrupted autonomous run; the orchestrator already returns partial
  findings on halt/iteration-limit. Scans report partial progress through the job-status row.
- **Self-security** — encrypt evidence at rest (C7, `cryptography` already a dep — also
  mitigates the known OneDrive-sync leak), tenant isolation (RLS), secret rotation (Vault/KMS),
  append-only access/audit logging. The SHA-256 evidence chain stays the integrity anchor.

## 6.4 Sequencing & branches (prompt-fixed order C1 → C9)

| # | Branch | New agent / server | Key new files | Depends on |
|---|---|---|---|---|
| C1 | `feat/C1-webapp-testing` | `webapp_agent` + `zap`/`nuclei` MCP | `agents/webapp_agent.py`, `mcp_layer/servers/zap_server.py`, `core/owasp_map.py` | scope-gate (active-scan op) |
| C2 | `feat/C2-finding-validation` | `validation_agent` | `core/finding_state.py`, `core/approval.py`, `agents/validation_agent.py` | C1 (candidate findings) |
| C3 | `feat/C3-compliance-reporting` | (extends reporting) | `core/compliance.py` (+ISO/CBK/KDPA) | C2 (approved findings) |
| C4 | `feat/C4-client-dashboard` | (extends API) | `api/` routes + `frontend/` | C2 (states), C3 (reports) |
| C5 | `feat/C5-ad-windows` | `ad` MCP (existing phase agents) | `mcp_layer/servers/ad_server.py` | scope/approval, 2A graph |
| C6 | `feat/C6-phishing` | `social_eng` MCP | `mcp_layer/servers/gophish_server.py` | scope-email, approval |
| C7 | `feat/C7-saas-backend` | `saas/` (Postgres/Celery/JWT) | `saas/**` | C4 (API), checkpoint |
| C8 | `feat/C8-llm-redteam` | `llm_redteam_agent` + MCP | `agents/llm_redteam_agent.py`, `mcp_layer/servers/llm_redteam_server.py`, `core/owasp_llm_map.py` | scope-endpoint, C2 |
| C9 | `feat/C9-cloud-posture` | `cloud_agent` + MCP | `agents/cloud_agent.py`, `mcp_layer/servers/cloud_server.py` | scope-cloud, C2, C3 |

Each branch stacks on the previous, ships its own offline tests green
(`& "C:\Users\james\venvs\redteam-ai-agents\Scripts\python.exe" -m pytest -q`, currently
**179 passing**), and updates `CHANGELOG.md`, `.env.example`, `requirements.txt`, and
`README.md` only as it needs.

## 6.5 Open decisions — I need your input before implementing

1. **C7 scope & timing (biggest).** Confirm the additive `saas/` wrapper approach (core
   singletons untouched, one engagement per Celery worker, Postgres as multi-tenant
   system-of-record). And pick: **(a)** Postgres **RLS** vs **schema-per-tenant**;
   **(b)** secret backend = HashiCorp **Vault** / **cloud KMS** / dev-only `.env`;
   **(c)** should C7 land **before C4** so the dashboard ships with real RBAC, or do C4
   open-on-localhost first and bolt auth on in C7 (matches the prompt's order)?
2. **Scope-gate extension for non-IP targets.** OK to add `OperationType` members + the
   `authorized_email_domains` / `authorized_cloud_accounts` / `authorized_llm_endpoints`
   settings + `scope.authorize_email/cloud/endpoint` helpers (all additive, existing
   `authorize()` untouched)? This is the cleanest way to keep C6/C8/C9 "physically unable
   to act outside scope."
3. **Finding-state storage.** Confirm a **separate signature-keyed store** (recommended —
   zero change to the KB JSON schema) over adding a `state` field to KB vuln dicts.
4. **"Written authorization" representation** for phishing / active scan / AD state-change /
   exploit: minimum I'll implement is a per-capability settings flag **plus** a recorded
   human-approval entry referencing a signed-authorization filename. Want anything stronger
   (e.g. a signed token, or a second-operator countersign)?
5. **C4 frontend.** React (**Vite**) vs **Next.js**, and `frontend/` **in-repo** (adds a Node
   build to CI) vs a **separate** repo/dir excluded from the Python gate.
6. **C3 compliance depth.** Full ISO 27001 Annex A / PCI / CBK / KDPA control maps, or a
   curated representative subset first (seeded from the public source texts, expanded later)?
7. **Run host.** These tools (ZAP, Nuclei, BloodHound CE, NetExec, Impacket, Certipy,
   GoPhish, garak, PyRIT, Prowler, Trivy) are Linux/Kali and won't run on this Windows +
   OneDrive dev box — confirm the live run host is **Kali** so I size the install docs +
   degradation right, and that it's expected the dev box only runs the **mocked offline tests**.
