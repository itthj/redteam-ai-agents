"""
agents/validation_agent.py
───────────────────────────
Validation Agent (capability C2) — the deterministic gate between an AI-produced
*candidate* finding and a *confirmed* one.

It does NOT decide truth with the model. For each candidate it runs `core.retest`
(re-run the exact Nuclei template / re-issue the request / grade against evidence),
and promotes to *confirmed* ONLY when the re-test reproduced the issue — binding the
re-test evidence + a CVSS score. It can never approve: approval is a human action
(CLI / API). Findings it cannot reproduce stay candidates, flagged for manual review.
"""

from __future__ import annotations

import logging

from core.base_agent import BaseAgent
from core.evidence_store import evidence
from core.finding_state import finding_state, severity_to_cvss
from core.retest import retest

log = logging.getLogger(__name__)


class ValidationAgent(BaseAgent):
    NAME = "validation"
    DESCRIPTION = "Deterministically re-tests candidate findings and confirms only reproduced ones"

    USE_MCP = False   # validation works from the finding store + re-test, not external MCP tools

    SYSTEM_PROMPT = """You are the Validation Agent in an authorized red-team operation.

Your sole job is to separate REAL findings from hallucinated ones. AI agents produce
CANDIDATE findings; you deterministically re-test each one and CONFIRM only those that
are actually reproduced. You do NOT approve anything — approval is a human decision.

RULES:
- Call list_candidates to see what needs validation.
- Call revalidate(signature) on each candidate. Promotion to "confirmed" is decided by
  the deterministic re-test, not by your opinion — never claim a finding is confirmed
  unless revalidate reports promoted=true.
- For candidates that could not be reproduced, say so plainly and recommend manual
  verification. Do not overstate.
- Finish with validation_summary and a short report of confirmed vs unconfirmed.
"""

    TOOLS = [
        {
            "name": "list_candidates",
            "description": "List all candidate findings awaiting validation.",
            "input_schema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "revalidate",
            "description": "Deterministically re-test one candidate finding by signature and, "
                           "if reproduced, promote it to 'confirmed' with bound evidence + CVSS. "
                           "Returns the re-test result and whether it was promoted.",
            "input_schema": {
                "type": "object",
                "properties": {"signature": {"type": "string"}},
                "required": ["signature"],
            },
        },
        {
            "name": "validation_summary",
            "description": "Counts of findings by lifecycle state (candidate/confirmed/approved/rejected).",
            "input_schema": {"type": "object", "properties": {}, "required": []},
        },
    ]

    def _tool_map(self):
        return {
            "list_candidates": self._list_candidates,
            "revalidate": self._revalidate,
            "validation_summary": self._validation_summary,
        }

    # ── Tool implementations ──────────────────────────────────────────────────

    def _list_candidates(self) -> dict:
        candidates = finding_state.list("candidate")
        return {"count": len(candidates), "candidates": candidates}

    async def _revalidate(self, signature: str) -> dict:
        entry = finding_state.get(signature)
        if entry is None:
            return {"error": f"unknown finding signature: {signature}"}

        result = await retest(entry)
        cvss = entry.get("cvss") or severity_to_cvss(entry.get("severity", "info"))
        outcome = finding_state.confirm(signature, validation=result, cvss=cvss,
                                        by=self.NAME)

        evidence.log(
            self.NAME, "revalidate",
            f"Re-tested {signature} via {result['method']} → "
            f"{'CONFIRMED' if outcome.get('promoted') else 'not confirmed'}",
            target=entry.get("target"),
            result={"reproduced": result["reproduced"], "verdict": result["verdict"],
                    "promoted": outcome.get("promoted")},
            severity="info",
        )
        return {
            "signature": signature,
            "method": result["method"],
            "reproduced": result["reproduced"],
            "verdict": result["verdict"],
            "confidence": result["confidence"],
            "promoted": outcome.get("promoted", False),
            "state": outcome.get("state", entry["state"]),
            "note": result["evidence"],
        }

    def _validation_summary(self) -> dict:
        return finding_state.summary()
