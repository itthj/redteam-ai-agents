# QUICKSTART — run & demonstrate the platform

> There is **no hosted link** — this is a local CLI + API tool, not a website. The
> only URL involved is the local dashboard in §3. Repo:
> <https://github.com/itthj/redteam-ai-agents>

All commands assume you're in the repo root. On this machine the Python 3.12 venv is
at `C:\Users\james\venvs\redteam-ai-agents-py312`; substitute `python` with
`C:\Users\james\venvs\redteam-ai-agents-py312\Scripts\python.exe` (or activate it).

---

## 1. See it work in 10 seconds — offline demo (NO API key, NO target)

```powershell
python scripts/demo.py
start demo_report.html      # opens the generated HTML report (macOS/Linux: open / xdg-open)
```

This seeds a synthetic engagement and shows, with no network and no real host:
- **untrusted-content defense** detecting a prompt-injection payload hidden in a banner,
- a **guardrail** blocking a base64-encoded `rm -rf /`,
- the **finding validator** catching a fabricated vulnerability (wrong port, malformed
  CVE, no evidence), and
- a real **HTML report** (`demo_report.html`) you can open or hand to someone.

This is the safest way to demonstrate the system — it can run anywhere.

## 2. No-key CLI commands (read-only)

```powershell
python main.py scope        # engagement authorization + scope
python main.py actors       # built-in adversary profiles (APT29/28/FIN7/Lazarus)
python main.py agents       # the 18 agents and what they do
```

## 3. Live dashboard (no key needed to view)

Easiest — double-click **`run_dashboard.bat`**, or run:

```powershell
python scripts/dashboard.py
```
This starts the server *and* opens <http://localhost:8000/dashboard> for you — a live
view of phase, telemetry, findings, and the attack graph (Server-Sent Events).

**Leave the window open** (it's a live server, not a file). Open it with **`localhost`**,
never `0.0.0.0` (that address is not browsable). Manual form:
`python -m uvicorn api.server:app --host 127.0.0.1 --port 8000`.

## 4. The real thing — a live engagement (needs an API key + an authorized target)

1. Create `.env` from the template and fill in two values:
   ```powershell
   copy .env.example .env
   ```
   - `ANTHROPIC_API_KEY=sk-ant-...` (a real key)
   - `AUTHORIZED_TARGETS=192.168.56.0/24` (only hosts you own or are authorized to test —
     e.g. a local **Metasploitable 2/3** VM, an HTB/TryHackMe box, or a Docker target)
2. Run a deterministic kill-chain, or let the orchestrator drive autonomously:
   ```powershell
   python main.py mission 192.168.56.101 --phases recon,scan
   python main.py autonomous 192.168.56.101 -o "Find and validate the highest-impact vuln"
   python main.py mission 192.168.56.101 --actor APT29      # emulate a named adversary
   ```
3. Reports land in `data/reports/`. Ask the reporting agent for HTML
   (`save_report` supports `markdown` | `json` | `html`).

> ⚠️ Live runs execute real tools (nmap, etc.) against the target and make real API
> calls. Only ever point them at systems you are authorized to test. `nmap` /
> Metasploit RPC must be installed on the host (all present on Kali Linux).

## 5. Optional capabilities (set in `.env`)

| Flag | Effect |
|------|--------|
| `ENABLE_UNTRUSTED_CONTENT_DEFENSE=true` | detect + spotlight prompt-injection in tool output |
| `COMPACT_HISTORY=true` | clear old tool output on long runs to save context |
| `MEMORY_SEMANTIC_RECALL=true` | embedding-based tradecraft recall (needs `sentence-transformers`) |
| `COMPRESS_TOOL_OUTPUT=true` | summarize huge tool dumps with the fast model |
| `ENGAGEMENT_ACTOR=APT29` | bias technique selection toward a named adversary |
| `ENGAGEMENT_BUDGET_USD=25` | halt/downgrade when the spend cap is hit |

## 6. Run the tests (offline, no key)

```powershell
python -m pytest -q        # 179 tests, fully offline
```
