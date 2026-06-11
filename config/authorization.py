"""
config/authorization.py
────────────────────────
CRITICAL: Every agent operation MUST pass through this gate.
No network touch, no exploitation, no file access without an authorization check.

Enforces:
  1. Target is in the authorized scope (IP / CIDR / hostname match)
  2. Engagement has not expired
  3. The requested operation type is permitted for this engagement
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import UTC, datetime
from enum import Enum
from typing import Optional

from config.settings import settings

log = logging.getLogger(__name__)


class OperationType(str, Enum):
    PASSIVE_RECON = "passive_recon"       # OSINT, DNS lookups, Shodan — no packets sent
    ACTIVE_SCAN = "active_scan"           # Nmap, banner grabbing — packets to target
    VULNERABILITY_SCAN = "vuln_scan"      # Authenticated / unauthenticated vuln scanning
    WEB_ACTIVE_SCAN = "web_active_scan"   # Intrusive web-app scanning (ZAP active scan, nuclei DAST)
    AD_STATE_CHANGE = "ad_state_change"   # State-changing AD action (NetExec exec, Certipy request)
    EXPLOITATION = "exploitation"         # Active exploitation attempts
    POST_EXPLOITATION = "post_exploit"    # Lateral movement, persistence, data access
    FORENSICS = "forensics"              # Evidence collection, log analysis
    REPORTING = "reporting"              # Report generation — always safe


class AuthorizationError(Exception):
    """Raised when an operation is not authorized."""


class EngagementScope:
    """
    Parses and validates the engagement authorization from settings.
    Thread-safe singleton used by all agents.
    """

    def __init__(self) -> None:
        self._targets: list[str] = settings.authorized_target_list
        self._expiry: Optional[datetime] = None
        if settings.engagement_expiry:
            try:
                self._expiry = datetime.fromisoformat(settings.engagement_expiry).replace(
                    tzinfo=UTC
                )
            except ValueError:
                log.warning("Could not parse ENGAGEMENT_EXPIRY: %s", settings.engagement_expiry)

    # ── Core gate ─────────────────────────────────────────────────────────────

    def authorize(
        self,
        target: str,
        operation: OperationType,
        agent_name: str = "unknown",
    ) -> None:
        """
        Raise AuthorizationError if the operation should not proceed.
        Call this at the START of every tool that touches a target.
        """
        self._check_expiry()
        self._check_target(target)
        log.info(
            "[AUTH OK] agent=%s operation=%s target=%s engagement=%s",
            agent_name,
            operation.value,
            target,
            settings.engagement_id,
        )

    def is_authorized(self, target: str, operation: OperationType) -> bool:
        """Non-throwing version — returns True/False."""
        try:
            self._check_expiry()
            self._check_target(target)
            return True
        except AuthorizationError:
            return False

    # ── Internal checks ───────────────────────────────────────────────────────

    def _check_expiry(self) -> None:
        if self._expiry and datetime.now(UTC) > self._expiry:
            raise AuthorizationError(
                f"Engagement {settings.engagement_id} expired at {self._expiry.isoformat()}. "
                "Update ENGAGEMENT_EXPIRY in .env to continue."
            )

    def _check_target(self, target: str) -> None:
        if not self._targets:
            raise AuthorizationError(
                "No authorized targets defined. "
                "Set AUTHORIZED_TARGETS in .env before running any operations."
            )
        if self._is_target_authorized(target):
            return
        raise AuthorizationError(
            f"Target '{target}' is NOT in the authorized scope for "
            f"engagement {settings.engagement_id}. "
            f"Authorized: {', '.join(self._targets)}"
        )

    def _is_target_authorized(self, target: str) -> bool:
        """Check if target matches any authorized entry (IP, CIDR, hostname)."""
        for authorized in self._targets:
            if authorized == target:
                return True
            # Try CIDR match
            try:
                network = ipaddress.ip_network(authorized, strict=False)
                target_ip = ipaddress.ip_address(target)
                if target_ip in network:
                    return True
            except ValueError:
                pass
            # Hostname suffix match (e.g. "*.lab.internal")
            if authorized.startswith("*.") and target.endswith(authorized[1:]):
                return True
        return False

    # ── Info ──────────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        return {
            "engagement_id": settings.engagement_id,
            "engagement_name": settings.engagement_name,
            "operator": settings.operator_name,
            "authorized_targets": self._targets,
            "expiry": self._expiry.isoformat() if self._expiry else "none",
            "expired": (
                self._expiry is not None
                and datetime.now(UTC) > self._expiry
            ),
        }


# Module-level singleton
scope = EngagementScope()
