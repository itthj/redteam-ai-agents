"""
core/owasp_map.py
──────────────────
Map web-app findings to the OWASP Top 10 (2021) and the OWASP Web Security Testing
Guide (WSTG), so ZAP alerts and Nuclei hits land in the categories a client report
is structured around.

A finding can be classified from any of three signals (most-specific first):
  • a CWE id (the most reliable — ZAP and Nuclei both emit CWEs),
  • a nuclei tag / template id,
  • the ZAP alert name (substring match).

Curated subset keyed to the alerts this platform produces most. Unknown findings
fall back to A04 (Insecure Design) with an "unmapped" WSTG marker rather than being
dropped — every finding stays reportable.
"""

from __future__ import annotations

# OWASP Top 10 2021 category id → human name
OWASP_2021: dict[str, str] = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A06": "A06:2021 Vulnerable and Outdated Components",
    "A07": "A07:2021 Identification and Authentication Failures",
    "A08": "A08:2021 Software and Data Integrity Failures",
    "A09": "A09:2021 Security Logging and Monitoring Failures",
    "A10": "A10:2021 Server-Side Request Forgery (SSRF)",
}

# CWE id (int) → (OWASP id, WSTG id). The strongest signal.
_CWE_TO_OWASP: dict[int, tuple[str, str]] = {
    89: ("A03", "WSTG-INPV-05"),    # SQL Injection
    79: ("A03", "WSTG-INPV-01"),    # Cross-Site Scripting (reflected)
    78: ("A03", "WSTG-INPV-12"),    # OS Command Injection
    94: ("A03", "WSTG-INPV-11"),    # Code Injection
    90: ("A03", "WSTG-INPV-07"),    # LDAP Injection
    91: ("A03", "WSTG-INPV-08"),    # XML/XPath Injection
    22: ("A01", "WSTG-ATHZ-01"),    # Path Traversal
    639: ("A01", "WSTG-ATHZ-04"),   # IDOR / insecure direct object reference
    284: ("A01", "WSTG-ATHZ-02"),   # Improper Access Control
    352: ("A01", "WSTG-SESS-05"),   # CSRF
    200: ("A01", "WSTG-ATHZ-04"),   # Information Exposure
    327: ("A02", "WSTG-CRYP-04"),   # Broken/weak crypto
    319: ("A02", "WSTG-CRYP-03"),   # Cleartext transmission
    311: ("A02", "WSTG-CRYP-03"),   # Missing encryption of sensitive data
    20: ("A04", "WSTG-INPV-01"),    # Improper Input Validation
    16: ("A05", "WSTG-CONF-02"),    # Configuration
    693: ("A05", "WSTG-CONF-07"),   # Protection mechanism failure (missing headers)
    1021: ("A05", "WSTG-CLNT-09"),  # Clickjacking / improper UI layering
    548: ("A05", "WSTG-CONF-04"),   # Directory listing exposure
    1035: ("A06", "WSTG-CONF-01"),  # Outdated third-party component
    1104: ("A06", "WSTG-CONF-01"),  # Unmaintained third-party component
    287: ("A07", "WSTG-ATHN-01"),   # Improper Authentication
    307: ("A07", "WSTG-ATHN-03"),   # Improper restriction of auth attempts
    384: ("A07", "WSTG-SESS-01"),   # Session fixation
    345: ("A08", "WSTG-BUSL-09"),   # Insufficient verification of data authenticity
    778: ("A09", "WSTG-CONF-02"),   # Insufficient logging
    918: ("A10", "WSTG-INPV-19"),   # SSRF
}

# Lower-cased substring in a ZAP alert name / nuclei tag → (OWASP id, WSTG id).
_NAME_TO_OWASP: list[tuple[str, str, str]] = [
    ("sql injection", "A03", "WSTG-INPV-05"),
    ("sqli", "A03", "WSTG-INPV-05"),
    ("cross site scripting", "A03", "WSTG-INPV-01"),
    ("cross-site scripting", "A03", "WSTG-INPV-01"),
    ("xss", "A03", "WSTG-INPV-01"),
    ("command injection", "A03", "WSTG-INPV-12"),
    ("remote code execution", "A03", "WSTG-INPV-11"),
    ("rce", "A03", "WSTG-INPV-11"),
    ("path traversal", "A01", "WSTG-ATHZ-01"),
    ("directory traversal", "A01", "WSTG-ATHZ-01"),
    ("lfi", "A01", "WSTG-ATHZ-01"),
    ("idor", "A01", "WSTG-ATHZ-04"),
    ("access control", "A01", "WSTG-ATHZ-02"),
    ("csrf", "A01", "WSTG-SESS-05"),
    ("information disclosure", "A01", "WSTG-ATHZ-04"),
    ("cleartext", "A02", "WSTG-CRYP-03"),
    ("weak cipher", "A02", "WSTG-CRYP-04"),
    ("tls", "A02", "WSTG-CRYP-01"),
    ("ssl", "A02", "WSTG-CRYP-01"),
    ("security header", "A05", "WSTG-CONF-07"),
    ("missing header", "A05", "WSTG-CONF-07"),
    ("content security policy", "A05", "WSTG-CONF-07"),
    ("x-frame-options", "A05", "WSTG-CLNT-09"),
    ("clickjack", "A05", "WSTG-CLNT-09"),
    ("directory listing", "A05", "WSTG-CONF-04"),
    ("misconfig", "A05", "WSTG-CONF-02"),
    ("default credential", "A07", "WSTG-ATHN-01"),
    ("outdated", "A06", "WSTG-CONF-01"),
    ("vulnerable component", "A06", "WSTG-CONF-01"),
    ("cve-", "A06", "WSTG-CONF-01"),
    ("authentication", "A07", "WSTG-ATHN-01"),
    ("session", "A07", "WSTG-SESS-01"),
    ("ssrf", "A10", "WSTG-INPV-19"),
    ("server-side request forgery", "A10", "WSTG-INPV-19"),
]

_FALLBACK = ("A04", "unmapped")


def _to_int(value: object) -> int | None:
    try:
        return int(str(value).strip().upper().replace("CWE-", ""))
    except (TypeError, ValueError):
        return None


def classify(alert_name: str | None = None, cwe: object = None,
             tags: object = None) -> dict:
    """
    Classify a web finding into an OWASP Top 10 (2021) category + a WSTG id.

    Resolution order: CWE id → alert-name/tag substring → fallback (A04, unmapped).
    Returns ``{owasp_id, owasp, wstg}`` — never raises, never drops a finding.
    """
    cwe_num = _to_int(cwe)
    if cwe_num is not None and cwe_num in _CWE_TO_OWASP:
        owasp_id, wstg = _CWE_TO_OWASP[cwe_num]
        return {"owasp_id": owasp_id, "owasp": OWASP_2021[owasp_id], "wstg": wstg}

    haystacks: list[str] = []
    if alert_name:
        haystacks.append(str(alert_name).lower())
    if tags:
        if isinstance(tags, (list, tuple, set)):
            haystacks.append(" ".join(str(t) for t in tags).lower())
        else:
            haystacks.append(str(tags).lower())
    blob = " ".join(haystacks)
    if blob:
        for needle, owasp_id, wstg in _NAME_TO_OWASP:
            if needle in blob:
                return {"owasp_id": owasp_id, "owasp": OWASP_2021[owasp_id], "wstg": wstg}

    owasp_id, wstg = _FALLBACK
    return {"owasp_id": owasp_id, "owasp": OWASP_2021[owasp_id], "wstg": wstg}
