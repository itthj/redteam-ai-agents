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
