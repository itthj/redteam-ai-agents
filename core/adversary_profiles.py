"""
core/adversary_profiles.py
───────────────────────────
Named-adversary emulation (workstream 2D).

Constrain an operation to a real threat group's known TTPs for emulation
exercises. Set `engagement_actor` (CLI `--actor APT29`) and the technique mapper
+ phase playbooks re-rank toward the actor's repertoire, and the actor's
tradecraft notes are injected into every agent's first message.

Soft constraint, not a block: off-profile technique choices are logged as
evidence, not prevented — emulation fidelity is a goal, not a guardrail.
(Destructive actions stay hard-blocked by guardrails.)

Technique sets are a **curated subset** of each group's MITRE ATT&CK mappings,
chosen to overlap this project's technique registry. Regenerate from the official
ATT&CK Groups data (attack.mitre.org/groups) for fuller coverage.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AdversaryProfile:
    group_id: str            # MITRE ATT&CK group id, e.g. "G0016"
    name: str                # e.g. "APT29"
    techniques: frozenset    # ATT&CK technique ids the group is known to use
    preferred_tools: tuple
    tradecraft_notes: str    # injected into agent prompts when this actor is active


PROFILES: dict[str, AdversaryProfile] = {
    "APT29": AdversaryProfile(
        "G0016", "APT29",
        frozenset({"T1078", "T1059", "T1003", "T1021.001", "T1021.002", "T1071",
                   "T1027", "T1070", "T1547", "T1053.005", "T1552", "T1190"}),
        ("cobalt strike", "powershell", "wmi", "mimikatz"),
        "Quiet, patient, living-off-the-land. Prefer valid accounts and built-in "
        "tooling (PowerShell/WMI) over noisy exploits; clean up indicators; favour "
        "stealth and long-dwell persistence over speed.",
    ),
    "APT28": AdversaryProfile(
        "G0007", "APT28",
        frozenset({"T1190", "T1059", "T1110", "T1078", "T1003", "T1071", "T1572",
                   "T1046", "T1021.001"}),
        ("x-agent", "responder", "mimikatz", "hydra"),
        "Aggressive credential access and remote services. Comfortable with "
        "brute force/password spray, public-facing exploitation, and protocol "
        "tunnelling for C2.",
    ),
    "FIN7": AdversaryProfile(
        "G0046", "FIN7",
        frozenset({"T1190", "T1059", "T1203", "T1547", "T1053.005", "T1071",
                   "T1005", "T1041", "T1078"}),
        ("carbanak", "powershell", "cobalt strike"),
        "Financially motivated. Social-engineering-led initial access, scheduled "
        "tasks / autostart persistence, and staged collection + exfiltration of "
        "payment data over the C2 channel.",
    ),
    "LAZARUS": AdversaryProfile(
        "G0032", "Lazarus Group",
        frozenset({"T1190", "T1059", "T1486", "T1071", "T1003", "T1078", "T1572",
                   "T1547"}),
        ("manuscrypt", "powershell", "custom rats"),
        "Capable and destructive. Public-facing exploitation, custom RATs over "
        "application-layer C2, and willingness to deploy data-encryption impact "
        "(assess only — never execute destructive actions here).",
    ),
}


def get_profile(name_or_id: str):
    """Resolve a profile by name (APT29) or group id (G0016). None if unset/unknown."""
    if not name_or_id:
        return None
    key = name_or_id.strip().upper()
    if key in PROFILES:
        return PROFILES[key]
    for profile in PROFILES.values():
        if profile.group_id.upper() == key or profile.name.upper() == key:
            return profile
    return None


def list_profiles() -> list[dict]:
    return [
        {"name": p.name, "group_id": p.group_id,
         "techniques": len(p.techniques), "preferred_tools": list(p.preferred_tools)}
        for p in PROFILES.values()
    ]
