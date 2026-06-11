# Changelog

All notable changes to `redteam-ai-agents` are recorded here. This file tracks the
**Epic 6 — Client-grade engagement delivery** capability expansion (C1–C9); see
`IMPLEMENTATION_PLAN.md` (§ EPIC 6) for the design. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project versions by capability.

## [Unreleased]

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
