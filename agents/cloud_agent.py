"""
agents/cloud_agent.py
───────────────────────
Cloud & Container Posture Agent (capability C9).

Assesses authorized cloud accounts and container/IaC artifacts with Prowler (CSPM) and
Trivy, using READ-ONLY credentials. Each failed check becomes a candidate finding with a
normalized severity and the compliance controls the tool tagged it with — feeding the
compliance reporting (C3). Uses the same gated handlers as the `cloud` MCP server, so
scope authorization and evidence logging apply either way.
"""

from __future__ import annotations

import logging

from core.base_agent import BaseAgent
from mcp_layer.servers import cloud_server as cloud

log = logging.getLogger(__name__)


class CloudAgent(BaseAgent):
    NAME = "cloud"
    DESCRIPTION = "Cloud & container posture — Prowler (CSPM) + Trivy, compliance-mapped"

    SYSTEM_PROMPT = """You are the Cloud & Container Posture Agent in an authorized engagement.

You assess AUTHORIZED cloud accounts and container/IaC artifacts with Prowler (CSPM) and
Trivy, using READ-ONLY credentials. This is posture assessment — no changes are made.

RULES:
- Only scan authorized accounts/images. Every tool authorizes the resource; if blocked,
  report that it needs the authorized-accounts list — do not attempt to bypass the gate.
- Use prowler_scan for cloud CSPM (aws/azure/gcp/kubernetes) and trivy_scan for
  container images, filesystems, and IaC.
- Findings are CANDIDATES carrying a severity and the compliance controls the tool tagged
  (CIS / NIST / PCI …). Summarise by severity and by the most-affected services.

WORKFLOW:
1. prowler_scan the authorized cloud account(s).
2. trivy_scan authorized images / IaC paths.
3. Summarise the posture: top failed checks by severity and the compliance impact.
"""

    TOOLS = [
        {
            "name": "prowler_scan",
            "description": "Run Prowler CSPM against an authorized cloud account "
                           "(provider: aws/azure/gcp/kubernetes). Read-only, scope-gated.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "provider": {"type": "string", "description": "aws | azure | gcp | kubernetes"},
                    "account": {"type": "string", "description": "Authorized account/subscription/project id"},
                },
                "required": ["provider", "account"],
            },
        },
        {
            "name": "trivy_scan",
            "description": "Run Trivy against an authorized target (scan_type: config/image/fs/repo). "
                           "Read-only, scope-gated.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Authorized image / path / repo"},
                    "scan_type": {"type": "string", "description": "config | image | fs | repo"},
                },
                "required": ["target"],
            },
        },
    ]

    def _tool_map(self):
        return {
            "prowler_scan": cloud.prowler_scan,
            "trivy_scan": cloud.trivy_scan,
        }
