"""Tests for the guardrails safety layer."""

import pytest

from core.guardrails import GuardrailViolation, guardrails


# ── Destructive-command blocking ──────────────────────────────────────────────

@pytest.mark.parametrize("command", [
    "rm -rf /",
    "dd if=/dev/zero of=/dev/sda",
    "mkfs.ext4 /dev/sdb1",
    "shutdown -h now",
    ":(){ :|:& };:",
])
def test_destructive_commands_blocked(command):
    with pytest.raises(GuardrailViolation):
        guardrails.check_command(command)


@pytest.mark.parametrize("command", [
    "nmap -sS 192.168.56.10",
    "ls -la /tmp",
    "cat /etc/passwd",
    "whoami",
])
def test_safe_commands_allowed(command):
    # Should not raise
    guardrails.check_command(command)


def test_tool_input_screened():
    with pytest.raises(GuardrailViolation):
        guardrails.check_tool_input("nmap_scan", {"extra_args": "; rm -rf /"})


def test_clean_tool_input_passes():
    guardrails.check_tool_input("nmap_scan", {"target": "10.0.0.5", "ports": "1-1024"})


# ── Output sanitization ───────────────────────────────────────────────────────

def test_password_redacted():
    out = guardrails.sanitize("Found creds: password=SuperSecret123")
    assert "SuperSecret123" not in out
    assert "REDACTED" in out


def test_api_key_redacted():
    out = guardrails.sanitize("api_key=sk-abc123xyz token=ghp_zzz")
    assert "sk-abc123xyz" not in out


def test_contains_secrets_detection():
    assert guardrails.contains_secrets("password: hunter2")
    assert not guardrails.contains_secrets("the scan found 3 open ports")


def test_clean_text_unchanged():
    text = "Host 10.0.0.5 has SSH open on port 22."
    assert guardrails.sanitize(text) == text
