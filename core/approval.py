"""
core/approval.py
─────────────────
Explicit-authorization gate for INTRUSIVE / OUTBOUND actions — web active scan,
AD state-change, phishing send, exploitation. Defense-in-depth ON TOP of the
EngagementScope gate, not a replacement:

    EngagementScope  → WHICH targets may be touched (in scope + not expired).
    ApprovalGate     → an intrusive action additionally needs a WRITTEN
                       AUTHORIZATION for THIS engagement before it may run.

The written-authorization is a per-capability settings flag that defaults to
False, so an agent is *physically unable* to launch an intrusive action unless a
human has deliberately enabled it for the engagement. Every decision — allowed or
blocked — is logged to the tamper-evident evidence chain, so the audit trail shows
the authorization basis (and, when present, the human approver).

This is the seam the richer per-finding human-approval QUEUE (capability C2/C4)
plugs into later: `require()` already records an `approver`, and a queue simply
becomes another caller that supplies one. C1 enforces the written-auth flag.
"""

from __future__ import annotations

import logging
from typing import Optional

from core.evidence_store import evidence

log = logging.getLogger(__name__)


class AuthorizationRequired(Exception):
    """Raised when an intrusive action lacks the required written authorization."""


class ApprovalGate:
    """Stateless gate. Blocks intrusive actions that lack written authorization."""

    def require(
        self,
        action: str,
        *,
        authorized: bool,
        target: Optional[str] = None,
        approver: Optional[str] = None,
        agent: str = "unknown",
    ) -> None:
        """
        Raise ``AuthorizationRequired`` unless ``authorized`` is True.

        ``authorized`` is the per-capability written-authorization flag for this
        engagement (e.g. ``settings.webapp_active_scan_authorized``). ``approver``
        is an optional human approver recorded for the audit trail. Both the
        allow and the block are written to the evidence chain.
        """
        if not authorized:
            evidence.log(
                agent, "approval_block",
                f"BLOCKED intrusive action '{action}' — no written authorization "
                f"for this engagement",
                target=target, severity="high",
            )
            raise AuthorizationRequired(
                f"Intrusive action '{action}' is not authorized for this engagement. "
                f"It requires explicit written authorization (a deliberate operator "
                f"opt-in) before it can run. Set the corresponding *_AUTHORIZED flag "
                f"in the engagement config only once you hold signed client sign-off."
            )
        evidence.log(
            agent, "approval_grant",
            f"Authorized intrusive action '{action}'"
            + (f" (approved by {approver})" if approver else ""),
            target=target, severity="info",
        )

    def is_authorized(self, *, authorized: bool) -> bool:
        """Non-throwing check — True if the written-authorization flag is set."""
        return bool(authorized)


# Module-level singleton — mirrors guardrails / scope / evidence.
approval = ApprovalGate()
