"""
core/attack_framework.py
─────────────────────────
MITRE ATT&CK (Enterprise) knowledge module.

Provides:
  • A registry of common red-team techniques keyed by ATT&CK ID
  • Tactic definitions (the 14 Enterprise tactics)
  • A keyword mapper: free-text action → matching technique(s)
  • Coverage reporting: which tactics an engagement exercised

This replaces the small inline map that previously lived in the
forensics agent, and is used by both the forensics and reporting agents.

Reference: https://attack.mitre.org/  (Enterprise matrix)
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id: str           # e.g. "T1046"
    name: str         # e.g. "Network Service Discovery"
    tactic: str       # primary tactic name
    keywords: tuple   # lowercase keywords that map free text → this technique


# ── The 14 Enterprise tactics (ordered by typical kill-chain position) ────────
TACTICS: dict[str, str] = {
    "Reconnaissance": "TA0043",
    "Resource Development": "TA0042",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040",
}

# ── Technique registry (common red-team techniques) ───────────────────────────
TECHNIQUES: list[Technique] = [
    # Reconnaissance
    Technique("T1595", "Active Scanning", "Reconnaissance",
              ("nmap", "port scan", "masscan", "active scan", "scanning")),
    Technique("T1592", "Gather Victim Host Information", "Reconnaissance",
              ("banner grab", "fingerprint", "host info", "service detection")),
    Technique("T1590", "Gather Victim Network Information", "Reconnaissance",
              ("dns", "whois", "network info", "subdomain")),
    Technique("T1596", "Search Open Technical Databases", "Reconnaissance",
              ("shodan", "censys", "osint", "open database")),
    Technique("T1589", "Gather Victim Identity Information", "Reconnaissance",
              ("email harvest", "username", "identity")),

    # Initial Access
    Technique("T1190", "Exploit Public-Facing Application", "Initial Access",
              ("exploit", "web exploit", "public-facing", "rce", "remote code")),
    Technique("T1133", "External Remote Services", "Initial Access",
              ("vpn", "rdp access", "external remote", "exposed service")),
    Technique("T1078", "Valid Accounts", "Initial Access",
              ("valid account", "default credential", "stolen credential", "login")),

    # Execution
    Technique("T1059", "Command and Scripting Interpreter", "Execution",
              ("reverse shell", "bash", "powershell", "cmd", "script", "interpreter")),
    Technique("T1203", "Exploitation for Client Execution", "Execution",
              ("client exploit", "browser exploit", "document exploit")),

    # Persistence
    Technique("T1053.003", "Scheduled Task/Job: Cron", "Persistence",
              ("crontab", "cron job", "scheduled cron")),
    Technique("T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence",
              ("schtasks", "scheduled task", "windows task")),
    Technique("T1098.004", "Account Manipulation: SSH Authorized Keys", "Persistence",
              ("ssh key", "authorized_keys", "ssh authorized")),
    Technique("T1547", "Boot or Logon Autostart Execution", "Persistence",
              ("autorun", "registry run", "startup", "logon script")),

    # Privilege Escalation
    Technique("T1548.001", "Abuse Elevation Control: Setuid/Setgid", "Privilege Escalation",
              ("suid", "setuid", "setgid", "sgid")),
    Technique("T1548.003", "Abuse Elevation Control: Sudo and Sudo Caching", "Privilege Escalation",
              ("sudo", "sudoers", "sudo -l")),
    Technique("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation",
              ("kernel exploit", "privesc exploit", "local exploit", "privilege escalation")),
    Technique("T1574", "Hijack Execution Flow", "Privilege Escalation",
              ("dll hijack", "unquoted service path", "path hijack", "library hijack")),

    # Defense Evasion
    Technique("T1070", "Indicator Removal", "Defense Evasion",
              ("clear log", "log deletion", "indicator removal", "timestomp")),
    Technique("T1027", "Obfuscated Files or Information", "Defense Evasion",
              ("obfuscate", "encode payload", "base64 payload", "packed")),
    Technique("T1562", "Impair Defenses", "Defense Evasion",
              ("disable firewall", "disable av", "impair defense", "stop service")),

    # Credential Access
    Technique("T1110", "Brute Force", "Credential Access",
              ("brute force", "password spray", "hydra", "bruteforce", "spray")),
    Technique("T1003", "OS Credential Dumping", "Credential Access",
              ("mimikatz", "credential dump", "lsass", "sam dump", "hashdump", "shadow file")),
    Technique("T1555", "Credentials from Password Stores", "Credential Access",
              ("password store", "keychain", "credential manager", "browser password")),
    Technique("T1552", "Unsecured Credentials", "Credential Access",
              ("hardcoded credential", "config password", "credential in file", "plaintext credential")),

    # Discovery
    Technique("T1046", "Network Service Discovery", "Discovery",
              ("service discovery", "open ports", "service enum", "port enumeration")),
    Technique("T1018", "Remote System Discovery", "Discovery",
              ("remote system", "host discovery", "ping sweep", "arp scan")),
    Technique("T1087", "Account Discovery", "Discovery",
              ("account discovery", "user enum", "/etc/passwd", "net user", "enumerate users")),
    Technique("T1083", "File and Directory Discovery", "Discovery",
              ("file discovery", "directory listing", "find files", "sensitive file")),
    Technique("T1082", "System Information Discovery", "Discovery",
              ("systeminfo", "uname", "os version", "system information")),

    # Lateral Movement
    Technique("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement",
              ("rdp", "remote desktop", "mstsc")),
    Technique("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement",
              ("smb", "psexec", "admin share", "windows admin share")),
    Technique("T1021.004", "Remote Services: SSH", "Lateral Movement",
              ("ssh lateral", "ssh pivot", "ssh into")),
    Technique("T1570", "Lateral Tool Transfer", "Lateral Movement",
              ("tool transfer", "upload tool", "pivot tool")),

    # Collection
    Technique("T1005", "Data from Local System", "Collection",
              ("local data", "collect file", "data collection", "stage data")),
    Technique("T1119", "Automated Collection", "Collection",
              ("automated collection", "bulk collect")),

    # Command and Control
    Technique("T1071", "Application Layer Protocol", "Command and Control",
              ("c2", "command and control", "beacon", "http c2", "meterpreter")),
    Technique("T1572", "Protocol Tunneling", "Command and Control",
              ("tunnel", "ssh tunnel", "port forward", "socks proxy", "pivot")),

    # Exfiltration
    Technique("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
              ("exfiltration", "exfil", "data exfil")),

    # Impact (documented for reporting — never executed destructively)
    Technique("T1486", "Data Encrypted for Impact", "Impact",
              ("ransomware", "data encrypted", "encryption impact")),
]

# Fast lookup index
_BY_ID = {t.id: t for t in TECHNIQUES}


class AttackFramework:
    """Query interface over the ATT&CK technique registry."""

    @staticmethod
    def get(technique_id: str) -> Technique | None:
        return _BY_ID.get(technique_id)

    @staticmethod
    def map_action(description: str, active_profile=None) -> list[dict]:
        """
        Map a free-text action description to matching ATT&CK techniques.
        Returns a list of {technique_id, name, tactic} dicts (most relevant first).

        When `active_profile` is given (2D), the actor's techniques are ranked
        ahead of the rest and each result is flagged with "in_profile".
        """
        text = description.lower()
        prof = None
        if active_profile is not None:
            prof = (active_profile.techniques if hasattr(active_profile, "techniques")
                    else set(active_profile))
        scored: list[tuple[bool, int, Technique]] = []
        for tech in TECHNIQUES:
            hits = sum(1 for kw in tech.keywords if kw in text)
            if hits:
                in_prof = prof is not None and (
                    tech.id in prof or tech.id.split(".")[0] in prof)
                scored.append((in_prof, hits, tech))
        scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
        out = []
        for in_prof, _, t in scored:
            row = {
                "technique_id": t.id,
                "name": t.name,
                "tactic": t.tactic,
                "tactic_id": TACTICS.get(t.tactic, ""),
            }
            if prof is not None:
                row["in_profile"] = in_prof
            out.append(row)
        return out

    @staticmethod
    def coverage(actions: list[str]) -> dict:
        """
        Given a list of action descriptions from an engagement, report which
        ATT&CK tactics and techniques were exercised.
        """
        techniques_hit: dict[str, dict] = {}
        tactics_hit: set[str] = set()
        for action in actions:
            for match in AttackFramework.map_action(action):
                techniques_hit[match["technique_id"]] = match
                tactics_hit.add(match["tactic"])
        return {
            "tactics_covered": sorted(tactics_hit),
            "tactics_total": len(TACTICS),
            "techniques_observed": sorted(techniques_hit.values(), key=lambda x: x["technique_id"]),
            "technique_count": len(techniques_hit),
        }

    @staticmethod
    def navigator_layer(actions: list[str], name: str = "Engagement") -> dict:
        """
        Produce a MITRE ATT&CK Navigator-compatible layer JSON so findings
        can be visualised on the official ATT&CK matrix.
        """
        cov = AttackFramework.coverage(actions)
        return {
            "name": name,
            "versions": {"layer": "4.5", "navigator": "4.9.1"},
            "domain": "enterprise-attack",
            "description": "Techniques exercised during the authorized engagement",
            "techniques": [
                {
                    "techniqueID": t["technique_id"].split(".")[0],
                    "score": 1,
                    "color": "#fd8d3c",
                    "comment": f"{t['name']} ({t['tactic']})",
                }
                for t in cov["techniques_observed"]
            ],
            "gradient": {"colors": ["#ffffff", "#fd8d3c"], "minValue": 0, "maxValue": 1},
        }


# Module-level singleton
attack = AttackFramework()
