---
description: Implement the next workstream PR in the redteam-ai-agents build sequence
argument-hint: "[workstream id, e.g. 5C — optional; defaults to next in sequence]"
---

Continue the `redteam-ai-agents` build-out following the standing protocol in
`CLAUDE.md` (workflow, hard constraints, sequence, test command).

Workstream to implement this session: **$ARGUMENTS**

If the argument is empty, determine the next un-built workstream from the sequence
`5A → 2A → 2B → 5C → 2E → 5B → 2C → 2D → 5D → 5E → 5F` by inspecting `git branch`
and `git log` (each workstream is a stacked `feat/<id>-...` branch).

Do EXACTLY ONE workstream: EXPLORE → PLAN (`.dev/PLAN_<id>.md`) → IMPLEMENT → VERIFY
(full suite green, offline) → COMMIT (stacked `feat/<id>-...` branch, logical chunks,
update README/.env.example/requirements only as needed). Read that workstream's
section in `IMPLEMENTATION_PLAN.md` first. Then STOP and report, and await the next "continue".
