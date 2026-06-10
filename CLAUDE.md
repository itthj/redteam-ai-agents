# CLAUDE.md — standing build protocol for `redteam-ai-agents`

This file is auto-loaded every session. It encodes the workflow so you don't have
to re-paste the kickoff prompt. To advance the build, the operator just says
**"continue"** (next workstream in sequence) or **names a workstream** (e.g. "do 2E").
The full original kickoff prompt lives at `outputs/CLAUDE_CODE_PROMPT.md`; the full
design lives at `IMPLEMENTATION_PLAN.md` (read the relevant workstream section before coding).

## What this project is
A multi-agent, authorized red-team platform on the Anthropic SDK. We are executing
a two-epic, 11-workstream build-out **one workstream = one PR = one session** —
deliberately, because long single-shot runs drift.

## Build sequence (do them in this order; honor stated deps)
`5A → 2A → 2B → 5C → 2E → 5B → 2C → 2D → 5D → 5E → 5F`

**Find current progress before starting:** `git branch` (each workstream is a
`feat/<id>-...` branch, stacked on the previous), the `.dev/PLAN_<id>.md` scratch
files, and `git log --oneline`. Implement the lowest un-built workstream next.

## Per-workstream workflow (every time)
1. **EXPLORE** (read-only): the workstream's section in `IMPLEMENTATION_PLAN.md` +
   the actual files it touches + existing tests.
2. **PLAN**: write `.dev/PLAN_<id>.md` (files to create/modify, exact signatures,
   new settings + safe defaults, test cases per acceptance criterion). Track steps
   with the task tools. Pause for the operator ONLY on a genuine conflict; else proceed.
3. **IMPLEMENT**: smallest change per step; run the relevant tests after each.
4. **VERIFY**: full suite green, fully offline (command below).
5. **COMMIT**: branch `feat/<id>-...` (stacked on the prior workstream's branch),
   logical chunks, clear messages. Update `README.md`, `.env.example`, and
   `requirements.txt` only as the workstream needs. Then STOP and give the report
   (files changed; pytest line; open decisions; out-of-scope notes; the command to
   see it working) and await the next "continue".

## Hard constraints (violating one means the work is wrong even if it runs)
- **Additive & non-breaking.** No changes to existing public signatures, CLI output,
  or the KB JSON schema. New behavior is opt-in via settings with safe defaults.
- **Stay minimal.** Build only what the workstream specifies. No speculative
  abstractions/config/files. Note resisted generalizations in `.dev/PLAN_<id>.md`.
- **Graceful degradation.** Every new optional dependency degrades like `MCPBridge`:
  missing/misconfigured → log a warning, no-op, continue. Never hard-depend an
  existing path on a new optional package.
- **Preserve the cache strategy.** Volatile data (KB, recalled memory) goes in the
  FIRST USER MESSAGE, never the cached system prompt; don't reorder the system/tools prefix.
- **Preserve the offline test guarantee.** New tests run with NO network and NO API
  key — mock the Anthropic client; degrade optional backends behind availability flags.
- **Don't weaken auth / guardrails / evidence.** New capability routes *through* them.
- **Ask, don't guess** on irreversible or genuinely ambiguous choices; otherwise follow the plan.

## Test command (venv lives OUTSIDE OneDrive)
```
& "C:\Users\james\venvs\redteam-ai-agents\Scripts\python.exe" -m pytest -q
```
Only the deps needed so far are installed in that venv; add a workstream's deps to
both the venv and `requirements.txt` when it genuinely needs them.

## Environment note
The repo lives in a OneDrive-synced folder, so `.env` and `data/` (evidence,
checkpoints, tradecraft memory) sync to the cloud despite `.gitignore`. Keep real
secrets/engagement data out until that's resolved (see memory `repo-in-onedrive`).
