"""
core/guardrails.py
───────────────────
Safety layer enforced on every tool call and every agent output.

Three jobs:
  1. BLOCK destructive actions — ransomware, disk wipers, mass deletion,
     DoS, exfiltration of real bulk data. These are never part of an
     authorized red-team engagement.
  2. SANITIZE outputs — strip real credentials/secrets before anything
     is written to a report or shown to a non-operator.
  3. PRE-FLIGHT checks — catch obviously dangerous commands before they run.

This is defense-in-depth: the EngagementScope authorizes WHICH targets,
guardrails govern WHAT may be done to them.
"""

from __future__ import annotations

import logging
import re

log = logging.getLogger(__name__)


class GuardrailViolation(Exception):
    """Raised when an action is blocked by a guardrail."""


# ── Destructive command / payload signatures ──────────────────────────────────
# Matched case-insensitively against tool inputs and generated commands.
_DESTRUCTIVE_PATTERNS: list[tuple[str, str]] = [
    (r"\brm\s+-rf\s+/(?:\s|$)", "Recursive deletion of filesystem root"),
    (r"\bmkfs\.", "Filesystem format"),
    (r"\bdd\s+if=.*of=/dev/[sh]d", "Raw disk overwrite"),
    (r":\(\)\s*\{\s*:\|:&\s*\}", "Fork bomb"),
    (r"\b(shutdown|halt|poweroff|reboot)\b", "Host shutdown/reboot"),
    (r">\s*/dev/[sh]d[a-z]", "Direct write to block device"),
    (r"\bwall\b.*|\bshred\s+", "Disk shredding"),
    (r"ransom|encryptor|wiper|killdisk", "Ransomware / wiper tooling"),
    (r"\bhalt\b|\binit\s+0\b", "Host halt"),
    (r"chmod\s+-R\s+000\s+/", "Mass permission destruction"),
    (r"\b(deltree|format)\s+[a-z]:", "Windows drive format"),
]

# Metasploit / payload signatures that are out of scope for a controlled test
_BANNED_PAYLOADS: list[tuple[str, str]] = [
    (r"windows/.*/vncinject.*persist", "Persistent VNC injection without approval"),
    (r"\bchmod\s+\+s\b.*passwd", "SUID backdoor on passwd"),
    (r"\bnc\b.*-e\s+/bin/(?:ba)?sh.*&\s*$", "Unmanaged backdoor listener"),
]

# Secret patterns to redact from any text written to reports / shown externally
_SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"), "password=[REDACTED]"),
    (re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*\S+"), "secret=[REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
     "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b"), "[REDACTED NTLM HASH]"),
    (re.compile(r"\baws_secret_access_key\s*=\s*\S+"), "aws_secret_access_key=[REDACTED]"),
]


class Guardrails:
    """Static safety checks. Stateless — safe to call from anywhere."""

    # ── Destructive-action gate ───────────────────────────────────────────────

    @staticmethod
    def check_command(command: str, *, context: str = "") -> None:
        """
        Raise GuardrailViolation if `command` matches a destructive signature.
        Call this before executing ANY shell command or exploit module.
        """
        text = command.lower()
        for pattern, reason in _DESTRUCTIVE_PATTERNS:
            if re.search(pattern, text):
                log.error("[GUARDRAIL] BLOCKED destructive command: %s", reason)
                raise GuardrailViolation(
                    f"Blocked destructive action: {reason}. "
                    f"This is out of scope for an authorized engagement. "
                    f"Command: {command[:120]}"
                    + (f" (context: {context})" if context else "")
                )

    @staticmethod
    def check_payload(payload: str) -> None:
        """Raise GuardrailViolation for banned exploitation payloads."""
        text = payload.lower()
        for pattern, reason in _BANNED_PAYLOADS:
            if re.search(pattern, text):
                log.error("[GUARDRAIL] BLOCKED payload: %s", reason)
                raise GuardrailViolation(
                    f"Blocked payload: {reason}. Use a managed reverse shell "
                    f"(meterpreter/reverse_tcp) and obtain client sign-off for persistence."
                )

    @staticmethod
    def check_tool_input(tool_name: str, tool_input: dict) -> None:
        """
        Pre-flight check on a tool's input dict before execution.
        Scans common string fields for destructive content.
        """
        for key in ("command", "extra_args", "payload", "module", "scripts", "rc", "content"):
            value = tool_input.get(key)
            if isinstance(value, str) and value:
                Guardrails.check_command(value, context=f"{tool_name}.{key}")
                if key in ("payload", "module"):
                    Guardrails.check_payload(value)

    # ── Output sanitization ───────────────────────────────────────────────────

    @staticmethod
    def sanitize(text: str) -> str:
        """
        Redact secrets (passwords, keys, hashes) from text destined for a
        report or any non-operator surface. The raw values stay in the
        EvidenceStore for the operator; reports get the redacted form.
        """
        if not text:
            return text
        cleaned = text
        for pattern, replacement in _SECRET_PATTERNS:
            cleaned = pattern.sub(replacement, cleaned)
        return cleaned

    @staticmethod
    def contains_secrets(text: str) -> bool:
        """True if the text appears to contain a credential or key."""
        return any(p.search(text or "") for p, _ in _SECRET_PATTERNS)


# Module-level singleton-style access
guardrails = Guardrails()
