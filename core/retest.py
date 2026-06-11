"""
core/retest.py
───────────────
Deterministic re-test of a candidate finding (capability C2). No model call — this
is the anti-hallucination check that gates candidate → confirmed.

Two signals are combined:
  1. a CONSISTENCY grade from the existing `finding_validator` (is the finding
     coherent with the scanned ports + evidence already on record?), and
  2. a live REPRODUCTION attempt — re-run the specific Nuclei template, or re-issue
     the request and look for the recorded reproduction signal.

`reproduced` is True only when a live re-test actually confirms the issue. If the
re-test cannot run (tool absent, not authorized, no reproducible artifact), the
finding is NOT confirmed — it stays a candidate flagged for manual review. That
conservative default is the whole point: if we can't reproduce it, we don't claim it.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import requests

from config.authorization import AuthorizationError, OperationType, scope
from core.evidence_store import evidence
from core.finding_validator import finding_validator
from core.knowledge_base import kb

log = logging.getLogger(__name__)

_HTTP_TIMEOUT = 15


def _host(url: str) -> str | None:
    if not url:
        return None
    parsed = urlparse(url if "//" in url else f"//{url}")
    return parsed.hostname or None


async def _reproduce(finding: dict) -> tuple[str, bool, str]:
    """Attempt a live reproduction. Returns (method, reproduced, evidence_str)."""
    url = finding.get("url")
    template = finding.get("template") or finding.get("template_id")

    # 1. Nuclei finding → re-run the exact template (intrusive; gated inside nuclei_scan).
    if template and url:
        from mcp_layer.servers.zap_server import nuclei_scan
        res = await nuclei_scan(url, templates=str(template))
        if res.get("blocked") or res.get("degraded"):
            return ("nuclei", False, res.get("error", "nuclei re-test unavailable"))
        hit = any(f.get("template") == template for f in res.get("findings", []))
        return ("nuclei", hit,
                f"nuclei re-run of {template}: {'reproduced' if hit else 'no hit'}")

    # 2. Web finding with a recorded reproduction signal → re-issue and look for it.
    if url:
        host = _host(url)
        if host:
            try:
                scope.authorize(host, OperationType.VULNERABILITY_SCAN, agent_name="validation")
            except AuthorizationError as e:
                return ("http", False, str(e))
        signal = finding.get("repro_signal") or finding.get("evidence") or finding.get("proof")
        if not signal:
            return ("http", False, "no reproduction signal recorded to confirm against")
        try:
            r = requests.get(url, timeout=_HTTP_TIMEOUT, verify=False)  # noqa: S501 — pentest re-test
        except Exception as e:  # noqa: BLE001 — graceful degradation
            return ("http", False, f"request failed: {e}")
        reproduced = str(signal) in (r.text or "")
        return ("http", reproduced,
                f"reproduction signal {'present' if reproduced else 'absent'} "
                f"(HTTP {r.status_code})")

    return ("none", False, "no reproducible artifact on the finding")


async def retest(finding: dict) -> dict:
    """Deterministically re-test a candidate finding.

    Returns ``{reproduced, method, evidence, grade, verdict, confidence}``.
    `reproduced` gates confirmation; `grade` is the consistency check used to
    prioritise manual review of the ones that could not be reproduced.
    """
    target = finding.get("target")
    kb_target = kb.get_target(target) if target else None
    open_ports = (kb_target or {}).get("open_ports", [])
    target_ev = evidence.get_all(target=target) if target else []

    grade = finding_validator.validate(
        finding, open_ports=open_ports, target_evidence=target_ev,
    )
    method, reproduced, ev = await _reproduce(finding)
    return {
        "reproduced": reproduced,
        "method": method,
        "evidence": ev,
        "grade": grade,
        "verdict": grade["verdict"],
        "confidence": grade["confidence"],
    }
