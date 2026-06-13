"""
core/orchestrator.py
─────────────────────
Mission control. Two ways to run an engagement:

  1. DETERMINISTIC  — run_mission(targets, phases)
     Runs the specialist agents in a fixed kill-chain order. Predictable,
     auditable, good for repeatable assessments.

  2. AUTONOMOUS     — run_autonomous(objective, targets)
     The OrchestratorAgent (Claude Opus 4.8, xhigh effort) plans the
     engagement itself: it treats each specialist agent as a TOOL, reasons
     about findings between delegations, and decides what to do next.
     This is the "agents-as-tools" multi-agent pattern.

Both paths connect the MCP layer first and print a telemetry summary at the end.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import asdict
from typing import Optional

from agents.phase_agents import KALI_PHASES, PhaseAgent
from config.settings import settings
from core.attack_graph import graph
from core.base_agent import BaseAgent
from core.checkpoint import checkpoint
from core.evidence_store import evidence
from core.knowledge_base import kb
from core.memory import memory
from core.telemetry import telemetry
from core.tracing import span
from mcp_layer.mcp_bridge import bridge

log = logging.getLogger(__name__)

_AGENT_PHASES = {
    "recon": "recon",
    "scan": "scanner",
    "vuln_assessment": "vuln",
    "exploitation": "exploit",
    "post_exploitation": "post_exploit",
    "forensics": "forensics",
    "reporting": "reporting",
}

# Deep bespoke agents + the 11 Kali-aligned phase agents = full roster
_DEEP_AGENTS = ["recon", "scanner", "vuln", "webapp", "exploit", "post_exploit",
                "validation", "llm_redteam", "cloud", "forensics", "reporting"]
_ALL_AGENTS = _DEEP_AGENTS + sorted(KALI_PHASES)


def _last_host_on_path(path) -> Optional[str]:
    """Extract the target host ip from a graph path (the host whose creds reach the goal)."""
    for node in reversed(path or []):
        if node.startswith("cred:") and "@" in node:
            return node.split("@", 1)[1]
        if node.startswith("host:"):
            return node.split("host:", 1)[1]
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  OrchestratorAgent — the autonomous planner (agents-as-tools)
# ══════════════════════════════════════════════════════════════════════════════
class OrchestratorAgent(BaseAgent):
    NAME = "orchestrator"
    DESCRIPTION = "Master planner — delegates to specialist red-team agents"
    EFFORT = settings.orchestrator_effort        # xhigh — best for agentic planning
    USE_MCP = False                              # sub-agents carry MCP; planner delegates
    MAX_ITERATIONS = 40

    SYSTEM_PROMPT = """You are the Orchestrator of an authorized red-team operation.

You do not run tools against targets yourself. Instead you PLAN the engagement
and DELEGATE to specialist agents, reasoning about their findings between steps.

SPECIALIST AGENTS — delegate to them via the `delegate` tool.

Deep agents:
  recon         — DNS, OSINT, Shodan, subdomain enumeration
  scanner       — nmap port scanning and service fingerprinting
  vuln          — CVE correlation, CVSS scoring, NSE vuln scripts
  webapp        — web app testing (OWASP ZAP + Nuclei), mapped to OWASP Top 10 / WSTG
  exploit       — controlled exploitation (authorization-gated)
  post_exploit  — enumeration, privesc analysis, lateral-movement mapping
  validation    — deterministically re-tests candidate findings → confirms reproduced ones
  llm_redteam   — LLM app red teaming (garak + PyRIT), mapped to the OWASP LLM Top 10
  cloud         — cloud & container posture (Prowler + Trivy), compliance-mapped (read-only)
  forensics     — timeline, MITRE ATT&CK mapping, artifact collection
  reporting     — executive + technical report generation

Kill-chain phase agents (one per Kali category 01–15):
  resource_development  — payload / infrastructure prep for the engagement
  execution             — code execution on accessible in-scope hosts
  persistence           — reversible, documented footholds
  privilege_escalation  — escalate privileges on compromised hosts
  defense_evasion       — test blue-team detection coverage
  credential_access     — dump and crack credentials
  lateral_movement      — pivot to other in-scope hosts
  collection            — inventory data of interest (locations only)
  command_and_control   — manage C2 channels
  exfiltration          — test DLP / egress with benign marker data
  impact                — assess and document impact (non-destructive)

METHODOLOGY (adapt as findings dictate — you are not bound to a fixed order):
  Consult the attack graph between steps — next_best_action returns a ranked
  list of moves and query_attack_graph answers path questions — then choose.
  1. Recon the authorized scope to map the attack surface.
  2. Scan discovered hosts for open ports and services.
  3. Assess vulnerabilities on the services that matter.
  4. Where the engagement scope permits, attempt controlled exploitation of
     the highest-value, most-exploitable findings.
  5. Run post-exploitation enumeration on anything compromised.
  6. Collect forensic artifacts and map activity to MITRE ATT&CK.
  7. Generate the final report.

RULES:
- Give each agent a SPECIFIC, detailed task — not a vague one-liner.
- Read each agent's findings before deciding the next delegation.
- Call get_engagement_status whenever you need the current knowledge base.
- Before each delegation, call next_best_action and justify your choice against
  the returned ranking (advisory — you still decide).
- Stay strictly within the authorized scope. Never request destructive actions.
- Before reporting, delegate to the validation agent to re-test candidate findings;
  only reproduced findings become "confirmed", and a human approves before anything ships.
- Finish by delegating to the reporting agent, then summarise the engagement.
"""

    TOOLS = [
        {
            "name": "delegate",
            "description": "Delegate a detailed task to a specialist agent and "
                           "receive its findings. The agent runs its own tools "
                           "and updates the shared knowledge base.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "agent": {
                        "type": "string",
                        "enum": _ALL_AGENTS,
                        "description": "Which specialist agent to delegate to",
                    },
                    "task": {
                        "type": "string",
                        "description": "Detailed, specific instructions for the agent",
                    },
                },
                "required": ["agent", "task"],
            },
        },
        {
            "name": "get_engagement_status",
            "description": "Get the current knowledge base, mission phase, and "
                           "telemetry (token usage and cost so far).",
            "input_schema": {"type": "object", "properties": {}},
        },
        {
            "name": "set_mission_phase",
            "description": "Record the current mission phase for the audit trail.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "phase": {"type": "string", "description": "e.g. recon, scanning, exploitation"},
                },
                "required": ["phase"],
            },
        },
        {
            "name": "query_attack_graph",
            "description": "Ask the attack graph a path/relationship question "
                           "(e.g. 'shortest path to domain admin', 'which hosts are "
                           "reachable but unowned'). Returns paths and node sets.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "question": {"type": "string",
                                 "description": "The graph question in plain English"},
                },
                "required": ["question"],
            },
        },
        {
            "name": "next_best_action",
            "description": "Score the attack graph and return a RANKED list of next "
                           "moves ({agent, target, rationale, score}) — crown-jewel "
                           "exploits, credential paths, pivot frontiers. Advisory: "
                           "you still choose.",
            "input_schema": {"type": "object", "properties": {}},
        },
        {
            "name": "recall_tradecraft",
            "description": "Recall lessons from past similar engagements (what worked "
                           "against comparable services/targets). Returns distilled "
                           "{situation, action, technique_id, outcome} tips. Advisory.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "situation": {"type": "string",
                                  "description": "Current situation / target profile to match"},
                },
                "required": ["situation"],
            },
        },
    ]

    def __init__(self, get_agent: Callable[[str], BaseAgent]) -> None:
        self._get_agent = get_agent
        super().__init__()

    def _tool_map(self):
        return {
            "delegate": self._delegate,
            "get_engagement_status": self._get_status,
            "set_mission_phase": self._set_phase,
            "query_attack_graph": self._query_attack_graph,
            "next_best_action": self._next_best_action,
            "recall_tradecraft": self._recall_tradecraft,
        }

    async def _delegate(self, agent: str, task: str) -> dict:
        log.info("[ORCHESTRATOR] → delegating to '%s'", agent)
        evidence.log("orchestrator", "delegate", f"Delegated to {agent}: {task[:80]}",
                     severity="info")
        with span("orchestrator.delegate", agent=agent):
            try:
                sub_agent = self._get_agent(agent)
                result = await sub_agent.run(task)
                return {"agent": agent, "findings": result}
            except Exception as e:
                log.error("[ORCHESTRATOR] delegation to '%s' failed: %s", agent, e)
                return {"agent": agent, "error": str(e)}

    def _get_status(self) -> dict:
        return {
            "mission_phase": kb.get_state(),
            "knowledge_base": kb.snapshot(),
            "telemetry": telemetry.summary(),
            "budget": {
                "limit_usd": settings.engagement_budget_usd,
                "spent_usd": round(telemetry.total_cost(), 4),
                "remaining_usd": telemetry.budget_remaining(),
                "over_budget": telemetry.over_budget(),
            },
        }

    def _set_phase(self, phase: str) -> dict:
        kb.set_state(phase)
        return {"mission_phase": phase}

    # ── Graph-driven planning (2B) ──────────────────────────────────────────────

    def _query_attack_graph(self, question: str = "") -> dict:
        """Answer a path/relationship question from the attack graph (2A)."""
        q = (question or "").lower()
        if any(w in q for w in ("path", "domain", "admin", "crown", "goal")):
            return {
                "question": question,
                "shortest_path_to_domain_admin": graph.shortest_path_to("domain_admin"),
                "high_value_unexploited": graph.high_value_unexploited(),
            }
        if any(w in q for w in ("reach", "unowned", "pivot", "host")):
            return {
                "question": question,
                "reachable_unowned_hosts": graph.reachable_unowned_hosts(),
            }
        return {
            "question": question,
            "high_value_unexploited": graph.high_value_unexploited(),
            "reachable_unowned_hosts": graph.reachable_unowned_hosts(),
            "shortest_path_to_domain_admin": graph.shortest_path_to("domain_admin"),
            "graph": graph.stats(),
        }

    def _next_best_action(self) -> dict:
        """Rank the next moves from the attack graph — advisory input to the planner."""
        suggestions: list[dict] = []
        high_value = graph.high_value_unexploited()
        hv_ips = {hv["ip"] for hv in high_value}

        # 1. Crown-jewel unexploited services → exploit (CVSS-weighted, capped < cred path).
        for hv in high_value:
            suggestions.append({
                "agent": "exploit",
                "target": hv["ip"],
                "rationale": f"{hv['service'] or 'service'} on {hv['ip']}:{hv['port']} has "
                             f"{hv['vuln_count']} vuln(s), max CVSS {hv['max_cvss']} — unexploited",
                "score": round(min(hv["max_cvss"], 10.0) / 10.0 * 0.8, 3),
            })

        # 2. An existing credential path to domain admin → walk it (lateral movement).
        path = graph.shortest_path_to("domain_admin")
        if path:
            suggestions.append({
                "agent": "lateral_movement",
                "target": _last_host_on_path(path),
                "rationale": "a credential path to domain_admin already exists in the graph",
                "score": 0.9,
            })

        # 3. Pivot frontier — hosts we can reach but haven't characterised → scan.
        for ip in graph.reachable_unowned_hosts():
            if ip in hv_ips:
                continue
            suggestions.append({
                "agent": "scanner",
                "target": ip,
                "rationale": f"{ip} is reachable but not yet exploited — scan and assess it",
                "score": 0.3,
            })

        suggestions.sort(key=lambda s: s["score"], reverse=True)
        return {"suggestions": suggestions, "count": len(suggestions)}

    def _recall_tradecraft(self, situation: str) -> dict:
        """Recall lessons from past engagements matching the current situation (2C)."""
        if not settings.enable_tradecraft_memory:
            return {"enabled": False, "lessons": []}
        lessons = memory.recall(situation, k=5)
        return {"enabled": True, "lessons": [asdict(lesson) for lesson in lessons]}


# ══════════════════════════════════════════════════════════════════════════════
#  Orchestrator — coordinator with both run modes
# ══════════════════════════════════════════════════════════════════════════════
class Orchestrator:
    """Top-level mission coordinator."""

    PHASES = ["recon", "scan", "vuln_assessment", "exploitation",
              "post_exploitation", "forensics", "reporting"]

    def __init__(self) -> None:
        self._agents: dict[str, BaseAgent] = {}

    # ── Agent registry (lazy import to avoid circular deps) ───────────────────

    def _get_agent(self, name: str) -> BaseAgent:
        if name not in self._agents:
            if name == "recon":
                from agents.recon_agent import ReconAgent
                self._agents[name] = ReconAgent()
            elif name == "scanner":
                from agents.scanner_agent import ScannerAgent
                self._agents[name] = ScannerAgent()
            elif name == "vuln":
                from agents.vuln_agent import VulnAgent
                self._agents[name] = VulnAgent()
            elif name == "webapp":
                from agents.webapp_agent import WebAppAgent
                self._agents[name] = WebAppAgent()
            elif name == "exploit":
                from agents.exploit_agent import ExploitAgent
                self._agents[name] = ExploitAgent()
            elif name == "post_exploit":
                from agents.post_exploit_agent import PostExploitAgent
                self._agents[name] = PostExploitAgent()
            elif name == "validation":
                from agents.validation_agent import ValidationAgent
                self._agents[name] = ValidationAgent()
            elif name == "llm_redteam":
                from agents.llm_redteam_agent import LLMRedTeamAgent
                self._agents[name] = LLMRedTeamAgent()
            elif name == "cloud":
                from agents.cloud_agent import CloudAgent
                self._agents[name] = CloudAgent()
            elif name == "forensics":
                from agents.forensics_agent import ForensicsAgent
                self._agents[name] = ForensicsAgent()
            elif name == "reporting":
                from agents.reporting_agent import ReportingAgent
                self._agents[name] = ReportingAgent()
            elif name in KALI_PHASES:
                # Kali-aligned kill-chain phase agent (02,04-08,10-14)
                self._agents[name] = PhaseAgent(name)
            else:
                raise ValueError(f"Unknown agent: {name}")
        return self._agents[name]

    # ── Mode 1: deterministic kill-chain ──────────────────────────────────────

    async def run_mission(
        self,
        targets: list[str],
        phases: Optional[list[str]] = None,
        mission_note: str = "",
    ) -> dict:
        """Run the specialist agents in a fixed phase order."""
        phases = phases or ["recon", "scan", "vuln_assessment", "forensics", "reporting"]
        await self._startup(targets, phases, mode="deterministic")

        results: dict = {"mode": "deterministic", "phases": {}}
        for phase in phases:
            log.info("[ORCH] ── PHASE: %s ──", phase.upper())
            kb.set_state(phase)
            try:
                summary = await self._run_phase(phase, targets, mission_note)
                results["phases"][phase] = {"status": "complete", "summary": summary[:600]}
            except Exception as e:
                log.error("[ORCH] phase %s failed: %s", phase, e)
                results["phases"][phase] = {"status": "error", "error": str(e)}

        return self._finish(results)

    async def _run_phase(self, phase: str, targets: list[str], note: str) -> str:
        target_str = ", ".join(targets)
        prompts = {
            "recon": f"Perform comprehensive reconnaissance on: {target_str}. "
                     f"Use DNS, Shodan, and subdomain enumeration. Save all findings. Note: {note}",
            "scan": f"Port-scan and fingerprint services on all targets: {target_str}. "
                    f"Top-1000 TCP ports, then version detection and NSE default scripts.",
            "vuln_assessment": f"Assess vulnerabilities on every discovered service for: {target_str}. "
                               f"Query NVD, run NSE vuln scripts, rank by CVSS and exploitability.",
            "exploitation": f"Attempt controlled, authorization-checked exploitation of the "
                            f"highest-priority vulnerabilities on: {target_str}. Log every attempt.",
            "post_exploitation": f"Run post-exploitation enumeration on compromised hosts in "
                                 f"{target_str}: users, network, privesc vectors, lateral paths.",
            "forensics": f"Collect forensic artifacts, build the operation timeline for "
                         f"{target_str}, and map all activity to MITRE ATT&CK.",
            "reporting": f"Generate the complete penetration-test report for engagement "
                         f"{settings.engagement_id} (targets: {target_str}): executive summary, "
                         f"findings, ATT&CK coverage, remediation roadmap. Save it to disk.",
        }
        agent = self._get_agent(_AGENT_PHASES[phase])
        return await agent.run(prompts.get(phase, f"Run {phase} on {target_str}"))

    # ── Mode 2: autonomous planning ───────────────────────────────────────────

    async def run_autonomous(self, objective: str, targets: list[str],
                             resume_engagement: Optional[str] = None) -> dict:
        """Let the OrchestratorAgent plan and delegate the engagement itself.

        resume_engagement (5B): rehydrate that engagement's latest checkpoint and
        continue the planner's conversation from there.
        """
        await self._startup(targets, ["autonomous"], mode="autonomous")
        kb.set_state("autonomous")

        planner = OrchestratorAgent(get_agent=self._get_agent)
        base_task = (
            f"Objective: {objective}\n"
            f"Authorized targets: {', '.join(targets)}\n\n"
            f"Plan and execute the engagement. Delegate to specialist agents, "
            f"review their findings, and produce a final report."
        )
        # 2C: prepend recalled tradecraft to the FIRST user message (cache-safe).
        task = self._tradecraft_preamble(objective, targets) + base_task

        # 5B: rehydrate a prior planner conversation, and checkpoint each round.
        resume_messages = None
        if resume_engagement:
            snap = checkpoint.load(resume_engagement)
            if snap:
                resume_messages = snap.get("orchestrator_messages")
                log.info("[ORCH] resuming %s from checkpoint seq %s",
                         resume_engagement, snap.get("seq"))

        def _save(messages: list) -> None:
            checkpoint.save(
                settings.engagement_id,
                kb_snapshot=kb.snapshot(),
                mission_state=kb.get_state(),
                orchestrator_messages=messages,
                telemetry=telemetry.summary(),
                graph_export=graph.export(),
                objective=objective,
                targets=targets,
            )

        try:
            final = await planner.run(task, resume_messages=resume_messages,
                                      checkpoint_cb=_save)
        except KeyboardInterrupt:
            log.warning("[ORCH] interrupted — resume with: python main.py resume %s",
                        settings.engagement_id)
            raise
        return self._finish({"mode": "autonomous", "objective": objective,
                             "orchestrator_summary": final})

    # ── Single-agent dispatch ─────────────────────────────────────────────────

    async def dispatch(self, agent_name: str, task: str,
                       context: Optional[dict] = None) -> str:
        """Run one ad-hoc task on a named agent."""
        await bridge.connect()
        return await self._get_agent(agent_name).run(task, context)

    # ── Lifecycle helpers ─────────────────────────────────────────────────────

    async def _startup(self, targets: list[str], phases: list[str], mode: str) -> None:
        log.info("=" * 64)
        log.info("MISSION START — %s [%s]", settings.engagement_id, mode)
        log.info("Targets : %s", targets)
        log.info("Phases  : %s", phases)
        mcp = await bridge.connect()
        if mcp["tool_count"]:
            log.info("MCP     : %d tools from %s", mcp["tool_count"], mcp["connected_servers"])
        log.info("=" * 64)
        evidence.log("orchestrator", "mission_start",
                     f"Mission started [{mode}] targets={targets}", severity="info")

    def _finish(self, results: dict) -> dict:
        kb.set_state("complete")
        results["status"] = "complete"
        results["telemetry"] = telemetry.summary()
        results["evidence_chain_valid"] = evidence.verify_chain()
        log.info("[ORCH] Mission complete — cost so far: $%.4f",
                 results["telemetry"]["total"]["cost_usd"])
        evidence.log("orchestrator", "mission_complete", "Mission complete",
                     result=results.get("telemetry"), severity="info")
        self._distill_memory()
        return results

    # ── Tradecraft memory (2C) ──────────────────────────────────────────────────

    def _tradecraft_preamble(self, objective: str, targets: list[str]) -> str:
        """Recalled lessons for the FIRST user message (cache-safe). Empty when
        memory is disabled or nothing matches."""
        if not settings.enable_tradecraft_memory:
            return ""
        ctx = (f"{objective} " + " ".join(str(t) for t in targets) + " "
               + json.dumps(kb.snapshot().get("targets", {}), default=str)[:2000])
        lessons = memory.recall(ctx, k=3)
        if not lessons:
            return ""
        lines = [f"- {lesson.situation} → {lesson.action} ({lesson.technique_id}) [{lesson.outcome}]"
                 for lesson in lessons]
        return ("# Recalled tradecraft (from past similar engagements — advisory)\n"
                + "\n".join(lines) + "\n\n")

    def _distill_memory(self) -> None:
        """Distil + store lessons at engagement end (best-effort, gated)."""
        if not settings.enable_tradecraft_memory:
            return
        try:
            lessons = memory.distill(settings.engagement_id, kb.snapshot())
            if lessons:
                memory.store(lessons)
                log.info("[ORCH] distilled %d tradecraft lesson(s)", len(lessons))
        except Exception as e:  # noqa: BLE001
            log.warning("[ORCH] memory distill skipped: %s", e)
