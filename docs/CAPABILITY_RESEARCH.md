# Capability Research & Roadmap — `redteam-ai-agents`

**Date:** 2026-06-11 · **Method:** web survey of SOTA offensive-AI agents, Anthropic
agent-engineering guidance, prompt-injection research, adversary-emulation
frameworks, and evaluation benchmarks, mapped against this platform's architecture.

This note exists so the research is durable and the roadmap is actionable. It cites
primary sources (see **References**) and marks each capability **[DONE]**, **[NEXT]**
(offline / no new deps), or **[LATER]** (needs the full `requirements.txt` / a 3.12
host / external infra).

---

## 1. Where the field is (2025–2026)

| System / work | Takeaway for us |
|---|---|
| **CAI** (aliasrobotics) — 8 pillars: Agents, Tools, Handoffs, Patterns, Turns, Tracing, Guardrails, HITL; ReAct loop; #1 at CTFs | Validates our orchestrator + specialist-agent + tracing design. Their **guardrails do input (injection) *and* output (dangerous-command, base64-aware) validation** and they keep **human-in-the-loop** authority — both directly relevant. |
| **HPTSA** (UIUC) — hierarchical planner + team-manager + vuln-class expert subagents; 53% on real-world vulns, 4.5× a single agent | Our orchestrator delegates, but our specialists are *phase*-shaped, not *vuln-class* experts. Sub-agent **context isolation** (each returns a 1–2k-token distilled summary) is a concrete refinement. |
| **XBOW / Google Big Sleep** — autonomous discovery, but pair LLM agents with **deterministic validators** and human verification | The #1 complaint about AI security tools is **hallucinated findings**. A validation/evidence-grounding layer is high-value. |
| **Anthropic** — *Building Effective Agents*, *Effective Context Engineering*, *Effective Harnesses for Long-Running Agents* | **Compaction** (summarize near the context limit, preserving decisions/findings, dropping redundant tool dumps) and **tool-result clearing** map straight onto long engagements. We have tool-output compression (5A) + checkpoints (5B) but no in-loop compaction. |
| **MITRE Caldera** — planners are decision logics ("if a DA credential is found, schedule lateral movement"); RAG over CTI (STIX) | Mirrors our attack-graph `next_best_action`. **CTI/technique enrichment** (Atomic Red Team / ATT&CK STIX) would deepen planning. |
| **Prompt injection** — Simon Willison's *lethal trifecta*; Meta's *Agents Rule of Two*; *The Attacker Moves Second* (12 defenses bypassed >90%); Microsoft **spotlighting** | We hold the lethal trifecta (untrusted input + sensitive KB/creds + external tools). Defenses are **defense-in-depth, never a fix** — keep scope gate + guardrails + operator authoritative. |
| **Benchmarks** — Cybench, NYU CTF Bench, CAIBench, CyberSecEval; "LLM-as-judge + lightweight CTF benchmark" | An **offline eval harness** + LLM-as-judge would let us measure agent quality and regressions, not just unit-test plumbing. |
| **OWASP** — LLM Top 10 (2025, prompt injection #1) + Agentic AI Top 10 (Dec 2025): cross-agent injection, excessive agency | Our shared KB/MessageBus is a **cross-agent injection** path; our guardrails/authorization already address excessive agency. |

## 2. Gap analysis vs. this platform

Already strong: orchestrator-workers, MITRE ATT&CK mapping, attack graph + planner
tools, evidence chain, scope gate, destructive-action guardrails, secret redaction,
tracing, checkpoints, budget governor, cross-engagement memory, MCP in/out.

Gaps the research surfaces, by value:

1. **Untrusted-content / prompt-injection defense** — we ingest target-controlled
   text but had no inbound-injection handling. *(highest value; pure safety+capability)*
2. **Finding validation (anti-hallucination)** — nothing grounds a reported finding
   against the evidence before it ships.
3. **Conversation compaction** — long autonomous runs can exhaust context; we trim
   single tool results but never compact the running history.
4. **Vuln-class expert sub-agents + context isolation** — refine delegation.
5. **CTI/technique knowledge** — richer, threat-informed planning.
6. **Semantic tradecraft memory** — recall is keyword-only today.
7. **Offline eval harness / LLM-as-judge** — measure capability and guard regressions.

## 3. Roadmap

- **[DONE 2026-06-11] Untrusted-content defense** — `core/content_safety.py`:
  heuristic injection **detection** (records a finding — a target attacking your
  tooling is reportable) + **spotlighting** (Microsoft delimiting) of tool output
  before it re-enters context. Opt-in: `ENABLE_UNTRUSTED_CONTENT_DEFENSE` (default
  off). Wired into `BaseAgent._run_tool_calls`; 13 offline tests. Defense-in-depth
  only — scope gate / guardrails / operator remain authoritative.
- **[DONE 2026-06-11] Finding validator** — `core/finding_validator.py` grades each
  finding against EvidenceStore/KB facts (port scanned? CVE well-formed and present
  in evidence?) → confidence + verdict; exposed as the reporting agent's
  `validate_findings` tool, with a prompt rule to label weak findings unverified.
  +10 tests.
- **[DONE 2026-06-11] Context compaction** — `BaseAgent._maybe_compact_history`
  clears old, large tool_result content once history grows past a threshold
  (structure-preserving tool-result clearing; opt-in `COMPACT_HISTORY`). +4 tests.
- **[DONE 2026-06-11] HTML report export** — `core/report_export.py` renders the
  report to a self-contained, print-friendly HTML doc (untrusted text escaped,
  link schemes allow-listed). `save_report` format enum gains `html`. +11 tests.
- **[DONE 2026-06-11] Output guardrail hardening** — `guardrails.check_command` now
  base64-decodes command segments and re-scans them, catching destructive payloads
  smuggled past the matcher by encoding (CAI-style). +5 tests.
- **[LATER] Semantic memory** — embeddings backend behind the existing
  `TradecraftMemory` interface (needs `sentence-transformers`/`chromadb`; 3.12).
- **[LATER] CTI enrichment** — ingest ATT&CK STIX / Atomic Red Team to enrich the
  attack graph + `next_best_action`.
- **[LATER] Eval harness** — offline scenario suite + LLM-as-judge scoring
  (Cybench/CAIBench-style) to track agent quality over time.

## References

- Anthropic — [Building Effective Agents](https://www.anthropic.com/research/building-effective-agents),
  [Effective Context Engineering](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents),
  [Harnesses for Long-Running Agents](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents),
  [Multi-agent Research System](https://www.anthropic.com/engineering/multi-agent-research-system)
- CAI — [aliasrobotics/CAI](https://github.com/aliasrobotics/CAI) · HPTSA — [uiuc-kang-lab/HPTSA](https://github.com/uiuc-kang-lab/HPTSA), [arXiv:2406.01637](https://arxiv.org/abs/2406.01637)
- XBOW — [xbow.com/platform](https://xbow.com/platform) · Big Sleep — [Google security blog](https://blog.google/innovation-and-ai/technology/safety-security/cybersecurity-updates-summer-2025/)
- Prompt injection — [Lethal trifecta (Willison)](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/), [Spotlighting (arXiv:2403.14720)](https://arxiv.org/abs/2403.14720)
- [MITRE Caldera](https://github.com/mitre/caldera) · [MITRE MCP plugin](https://github.com/mitre/MCP)
- Benchmarks — [Cybench](https://github.com/andyzorigin/cybench), [NYU CTF Bench](https://nyu-llm-ctf.github.io/), [CAIBench (arXiv:2510.24317)](https://arxiv.org/html/2510.24317v1)
- [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/) · [OWASP Agentic AI Top 10 (Dec 2025)](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
