"""
agents/phase_agents.py
───────────────────────
Kill-chain phase agents — one per Kali Linux operational category.

The Kali Applications menu organises tooling into categories that mirror the
MITRE ATT&CK tactics. The project already ships deep, bespoke agents for
several phases; this module fills in the rest with a data-driven PhaseAgent
so the platform covers the FULL Kali kill chain (categories 01–15).

ONE PhaseAgent class + a declarative registry = consistent, maintainable
coverage of every phase, instead of a dozen near-duplicate files.

Full roster (matches the Kali menu):
  01 Reconnaissance        → ReconAgent          (recon_agent.py)
  02 Resource Development  → PhaseAgent  ← here   resource_development
  03 Initial Access        → ExploitAgent        (exploit_agent.py)
  04 Execution             → PhaseAgent  ← here   execution
  05 Persistence           → PhaseAgent  ← here   persistence
  06 Privilege Escalation  → PhaseAgent  ← here   privilege_escalation
  07 Defense Evasion       → PhaseAgent  ← here   defense_evasion
  08 Credential Access     → PhaseAgent  ← here   credential_access
  09 Discovery             → ScannerAgent        (scanner_agent.py)
  10 Lateral Movement      → PhaseAgent  ← here   lateral_movement
  11 Collection            → PhaseAgent  ← here   collection
  12 Command and Control   → PhaseAgent  ← here   command_and_control
  13 Exfiltration          → PhaseAgent  ← here   exfiltration
  14 Impact                → PhaseAgent  ← here   impact   (assessment only)
  15 Forensics             → ForensicsAgent      (forensics_agent.py)
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass

from config.authorization import AuthorizationError, OperationType, scope
from config.settings import settings
from core.adversary_profiles import get_profile
from core.attack_framework import attack
from core.base_agent import BaseAgent
from core.evidence_store import evidence
from core.finding_state import finding_state
from core.guardrails import GuardrailViolation, guardrails
from core.knowledge_base import kb

log = logging.getLogger(__name__)


# ── Phase specification ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PhaseSpec:
    kali_no: int
    name: str
    tactic: str                  # MITRE ATT&CK tactic
    operation: OperationType     # for the authorization gate
    kali_tools: tuple[str, ...]  # Kali tools relevant to this phase
    mission: str                 # phase-specific system-prompt body


# ── The Kali-aligned phase registry ───────────────────────────────────────────
KALI_PHASES: dict[str, PhaseSpec] = {

    "resource_development": PhaseSpec(
        2, "Resource Development", "Resource Development",
        OperationType.PASSIVE_RECON,
        ("msfvenom", "setoolkit", "gophish", "veil", "shellter", "cewl", "crunch"),
        "Prepare the tooling and infrastructure for the engagement: generate "
        "payloads, stage listeners, build phishing infrastructure for authorized "
        "social-engineering tests, and build target-specific wordlists. Every "
        "artefact is for THIS authorized engagement only and stays within the "
        "test infrastructure.",
    ),

    "execution": PhaseSpec(
        4, "Execution", "Execution",
        OperationType.EXPLOITATION,
        ("metasploit", "crackmapexec", "impacket-wmiexec", "impacket-psexec",
         "powershell-empire", "sliver"),
        "Achieve code execution on authorized hosts to which access has already "
        "been obtained. Pick the right technique for the platform (command "
        "interpreters, scheduled jobs, service execution, WMI/PsExec) and confirm "
        "execution with a benign proof (whoami / id) before anything further.",
    ),

    "persistence": PhaseSpec(
        5, "Persistence", "Persistence",
        OperationType.POST_EXPLOITATION,
        ("metasploit", "crontab", "systemctl", "ssh-keygen", "schtasks"),
        "Establish and DOCUMENT persistence on compromised in-scope hosts so "
        "access survives reboots — for the engagement duration only. Use "
        "reversible, clearly-tagged mechanisms (a marked cron entry, a named "
        "service, a labelled SSH key) and record every change so it can be "
        "cleanly removed during cleanup.",
    ),

    "privilege_escalation": PhaseSpec(
        6, "Privilege Escalation", "Privilege Escalation",
        OperationType.POST_EXPLOITATION,
        ("linpeas", "winpeas", "linux-exploit-suggester", "BeRoot", "pspy",
         "GTFOBins"),
        "Escalate from the current privilege level to higher privileges on "
        "compromised in-scope hosts. Enumerate escalation vectors first (SUID, "
        "sudo rules, kernel version, service misconfigurations, unquoted paths), "
        "validate the most promising, and record the exact path taken.",
    ),

    "defense_evasion": PhaseSpec(
        7, "Defense Evasion", "Defense Evasion",
        OperationType.POST_EXPLOITATION,
        ("veil", "shellter", "msfvenom", "chameleon", "timestomp"),
        "Exercise defence-evasion techniques against authorized targets to test "
        "the blue team's detection coverage, and document which techniques were "
        "detected versus missed. Do NOT permanently or destructively disable "
        "security controls — the goal is to measure detection, not to cripple it.",
    ),

    "credential_access": PhaseSpec(
        8, "Credential Access", "Credential Access",
        OperationType.POST_EXPLOITATION,
        ("mimikatz", "hashcat", "john", "hydra", "impacket-secretsdump",
         "responder", "lazagne"),
        "Obtain credentials from compromised in-scope hosts — dump hashes, "
        "harvest stored secrets, and crack offline. Treat every recovered "
        "credential as highly sensitive: record its location and type, and never "
        "expose plaintext credentials in any report.",
    ),

    "lateral_movement": PhaseSpec(
        10, "Lateral Movement", "Lateral Movement",
        OperationType.POST_EXPLOITATION,
        ("crackmapexec", "impacket-psexec", "evil-winrm", "ssh", "proxychains"),
        "Move from a compromised in-scope host to OTHER in-scope hosts using "
        "harvested credentials and remote services (SMB/PsExec, WinRM, SSH). "
        "Verify each new host is inside the authorized scope BEFORE connecting — "
        "the authorization gate will reject out-of-scope targets.",
    ),

    "collection": PhaseSpec(
        11, "Collection", "Collection",
        OperationType.POST_EXPLOITATION,
        ("bloodhound", "powerview", "find", "grep"),
        "Locate and inventory data of interest on compromised in-scope hosts "
        "(documents, databases, credential stores, source code, key material). "
        "Record LOCATIONS and data types only — do not bulk-copy real sensitive "
        "data. This is an assessment of exposure, not data theft.",
    ),

    "command_and_control": PhaseSpec(
        12, "Command and Control", "Command and Control",
        OperationType.POST_EXPLOITATION,
        ("metasploit", "sliver", "empire", "ligolo-ng", "chisel"),
        "Establish and manage C2 channels to compromised in-scope hosts for the "
        "engagement. Choose channels that meaningfully test the blue team's "
        "egress monitoring, and document every channel so it can be torn down "
        "completely at cleanup.",
    ),

    "exfiltration": PhaseSpec(
        13, "Exfiltration", "Exfiltration",
        OperationType.POST_EXPLOITATION,
        ("dnscat2", "exfiltration over HTTP/HTTPS", "rclone"),
        "Demonstrate data-exfiltration paths from in-scope hosts to test DLP and "
        "egress controls. Exfiltrate ONLY benign marker data (a canary file you "
        "create for the test) — never real sensitive data. Record which channels "
        "succeeded and which were blocked.",
    ),

    "impact": PhaseSpec(
        14, "Impact", "Impact",
        OperationType.POST_EXPLOITATION,
        ("(assessment only — no destructive tooling)",),
        "ASSESS and DOCUMENT the business impact an attacker could achieve from "
        "the access obtained — what could be encrypted, destroyed, or disrupted — "
        "WITHOUT executing any destructive action. Demonstrate capability with a "
        "harmless proof only (e.g. writing a single marker file). Destructive "
        "commands are blocked by the guardrails layer and must never be attempted.",
    ),
}


def list_phases() -> list[dict]:
    """Return the phase roster, ordered by Kali category number."""
    return [
        {"key": k, "kali_no": s.kali_no, "name": s.name, "tactic": s.tactic}
        for k, s in sorted(KALI_PHASES.items(), key=lambda kv: kv[1].kali_no)
    ]


# ── The phase agent ────────────────────────────────────────────────────────────

class PhaseAgent(BaseAgent):
    """
    A kill-chain phase agent. One class, configured per-phase from KALI_PHASES.
    Specialised by its system prompt; powered by a shared, gated toolkit.
    """

    USE_MCP = True

    TOOLS = [
        {
            "name": "get_playbook",
            "description": "Get this phase's ATT&CK techniques and the recommended "
                           "Kali tools. Call this FIRST to ground your approach.",
            "input_schema": {"type": "object", "properties": {}},
        },
        {
            "name": "run_command",
            "description": "Execute an authorized command-line tool. Every command "
                           "is guardrail-checked (destructive actions blocked) and, "
                           "when a target is given, scope-authorized. Output is "
                           "logged to the evidence chain.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The shell command to run"},
                    "rationale": {"type": "string", "description": "Why this command, in one line"},
                    "target": {"type": "string", "description": "Target IP/host this acts on (required unless this is a prep-only phase)"},
                },
                "required": ["command", "rationale"],
            },
        },
        {
            "name": "record_finding",
            "description": "Record a phase finding to the knowledge base and the "
                           "tamper-evident evidence chain.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "finding": {"type": "string", "description": "What was found / achieved"},
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                    },
                    "technique": {"type": "string", "description": "MITRE ATT&CK technique ID, e.g. T1078"},
                },
                "required": ["target", "finding"],
            },
        },
    ]

    def __init__(self, phase_key: str) -> None:
        if phase_key not in KALI_PHASES:
            raise ValueError(
                f"Unknown phase '{phase_key}'. Valid: {sorted(KALI_PHASES)}"
            )
        spec = KALI_PHASES[phase_key]
        # Per-instance configuration — set BEFORE BaseAgent.__init__ reads them
        self.NAME = phase_key
        self.DESCRIPTION = f"Kali {spec.kali_no:02d} — {spec.name}"
        self.SYSTEM_PROMPT = _compose_prompt(spec)
        self._phase = spec
        super().__init__()

    def _tool_map(self):
        return {
            "get_playbook": self._get_playbook,
            "run_command": self._run_command,
            "record_finding": self._record_finding,
        }

    # ── Tool implementations ──────────────────────────────────────────────────

    def _get_playbook(self) -> dict:
        p = self._phase
        seed = f"{p.name} {p.tactic} " + " ".join(p.kali_tools)
        profile = get_profile(settings.engagement_actor)
        playbook = {
            "phase": p.name,
            "kali_category": f"{p.kali_no:02d} - {p.name}",
            "attack_tactic": p.tactic,
            "recommended_kali_tools": list(p.kali_tools),
            "relevant_attack_techniques": attack.map_action(seed, active_profile=profile),
        }
        if profile:
            playbook["emulating_actor"] = profile.name
            playbook["actor_preferred_tools"] = list(profile.preferred_tools)
        return playbook

    def _run_command(self, command: str, rationale: str, target: str | None = None) -> dict:
        op = self._phase.operation

        # 1. Authorization — required for any phase that touches a target
        if target:
            try:
                scope.authorize(target, op, agent_name=self.NAME)
            except AuthorizationError as e:
                return {"error": str(e), "blocked": True}
        elif op != OperationType.PASSIVE_RECON:
            return {"error": "This phase acts on a target — provide the 'target' parameter."}

        # 2. Guardrail — block destructive actions
        try:
            guardrails.check_command(command, context=self.NAME)
        except GuardrailViolation as e:
            evidence.log(self.NAME, "guardrail_block", str(e), target=target, severity="high")
            return {"error": f"GUARDRAIL BLOCK: {e}", "blocked": True}

        # 3. Execute
        log.info("[%s] run: %s", self.NAME.upper(), command[:100])
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=180
            )
        except subprocess.TimeoutExpired:
            return {"error": "command timed out after 180s"}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

        output = (result.stdout + result.stderr)[-4000:]
        evidence.log(
            self.NAME, "run_command", f"{rationale}: {command[:80]}",
            target=target, result={"exit_code": result.returncode}, severity="info",
        )
        return {"command": command, "exit_code": result.returncode, "output": output}

    def _record_finding(
        self,
        target: str,
        finding: str,
        severity: str = "medium",
        technique: str | None = None,
    ) -> dict:
        kb.ensure_target(target)
        tag = f" (ATT&CK {technique})" if technique else ""
        kb.add_note(target, f"[{self._phase.name}] {finding}{tag}")
        evidence.log(
            self.NAME, "finding", finding, target=target,
            result={"technique": technique, "phase": self._phase.name},
            severity=severity,
        )
        # C2: register as a CANDIDATE finding (AI agents only ever produce candidates).
        finding_state.register_candidate({
            "target": target, "title": finding, "severity": severity,
            "technique": technique, "source": self.NAME,
        })
        # 2D soft constraint — flag (don't block) off-profile technique choices.
        profile = get_profile(settings.engagement_actor)
        if profile and technique and technique not in profile.techniques \
                and technique.split(".")[0] not in profile.techniques:
            evidence.log(self.NAME, "off_profile_technique",
                         f"Off-profile technique {technique} chosen "
                         f"(emulating {profile.name})", target=target, severity="info")
        return {"recorded": True, "target": target, "phase": self._phase.name}


def _compose_prompt(spec: PhaseSpec) -> str:
    return (
        f"You are the {spec.name} Agent — Kali category {spec.kali_no:02d}, "
        f"MITRE ATT&CK tactic '{spec.tactic}' — in an authorized red-team operation.\n\n"
        f"{spec.mission}\n\n"
        "WORKFLOW:\n"
        "1. Call get_playbook first — it returns the ATT&CK techniques and Kali "
        "tools relevant to this phase.\n"
        "2. Review the knowledge base (provided below) for findings from earlier "
        "phases and build on them.\n"
        "3. Use run_command to execute authorized Kali tooling. Every command is "
        "guardrail-checked and scope-authorized — destructive actions are blocked.\n"
        "4. Call record_finding for everything significant, mapping it to an "
        "ATT&CK technique ID.\n"
        "5. Summarise what you achieved and what the next phase should pick up.\n\n"
        "RULES: operate strictly within the authorized scope; keep every change "
        "reversible and documented for cleanup; never attempt destructive actions."
    )
