"""
config/settings.py
──────────────────
Centralised configuration loaded from environment / .env file.
All other modules import from here — never read os.environ directly.

Uses Pydantic v2 + pydantic-settings: each field maps automatically to the
upper-case environment variable of the same name (e.g. `claude_model`
← `CLAUDE_MODEL`).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from dotenv import dotenv_values
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_ROOT = Path(__file__).resolve().parent.parent


def _load_env_file() -> None:
    """
    Load the engagement .env. The .env is authoritative: it fills any variable
    that is missing OR set to an empty string in the ambient environment — an
    empty ambient ANTHROPIC_API_KEY must not shadow the real key in .env.
    Genuinely-set ambient vars are left untouched (important for tests / CI).
    """
    env_path = _ROOT / ".env"
    if not env_path.exists():
        return
    for key, value in dotenv_values(env_path).items():
        if value is not None and not os.environ.get(key):
            os.environ[key] = value


_load_env_file()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Anthropic ─────────────────────────────────────────────────────────────
    anthropic_api_key: str = Field(...)
    claude_model: str = "claude-opus-4-8"
    claude_fast_model: str = "claude-haiku-4-5"
    orchestrator_effort: str = "xhigh"
    agent_effort: str = "high"

    # ── Cost / budget governor (5A) ───────────────────────────────────────────
    # All optional with safe defaults so an existing .env keeps working unchanged.
    engagement_budget_usd: float = 0.0     # USD ceiling for the engagement; 0 = no ceiling
    on_budget_exceeded: str = "downgrade"  # when the ceiling is hit: "downgrade" | "halt"
    compress_tool_output: bool = False     # opt-in: summarise oversized tool output via the fast model
    # opt-in: detect + spotlight prompt-injection in untrusted tool output before it
    # re-enters the model context (defense-in-depth; see core/content_safety.py)
    enable_untrusted_content_defense: bool = False
    # opt-in: clear old tool output from the running history once it grows past
    # compact_after_chars, so long autonomous runs don't exhaust context
    compact_history: bool = False
    compact_after_chars: int = 60000

    # ── Finding lifecycle (C2) ────────────────────────────────────────────────
    # When True, only HUMAN-APPROVED findings may be reported or sent (the strict
    # candidate→confirmed→approved workflow). Default False keeps existing behavior
    # (report everything) — non-breaking; opt in for the gated workflow.
    require_finding_approval: bool = False

    # ── Phishing / social engineering (C6) ────────────────────────────────────
    # GoPhish REST + the authorized client email domain(s). Campaigns are blocked
    # unless phishing_authorized is set AND a human approver is named at launch, and
    # every target must be inside an authorized domain.
    gophish_api_url: str = ""               # e.g. https://127.0.0.1:3333
    gophish_api_key: str = ""
    authorized_email_domains: str = ""      # comma-separated, e.g. "acme.co.ke,*.acme.com"
    phishing_authorized: bool = False       # written-authorization flag for THIS engagement

    # ── Engagement Authorization ──────────────────────────────────────────────
    authorized_targets: str = ""
    engagement_id: str = "ENG-UNKNOWN"
    engagement_name: str = "Unnamed Engagement"
    operator_name: str = "unknown"
    engagement_expiry: Optional[str] = None

    # ── External Recon APIs ───────────────────────────────────────────────────
    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    nvd_api_key: str = ""
    greynoise_api_key: str = ""    # 5D — threat-intel MCP
    virustotal_api_key: str = ""   # 5D — threat-intel MCP
    siem_token: str = ""           # 5D — SIEM MCP (read-only)

    # ── Web application testing (C1) ──────────────────────────────────────────
    # OWASP ZAP daemon + Nuclei. All optional/safe-default — the webapp agent
    # degrades to native checks if ZAP/nuclei are unreachable (graceful degradation).
    zap_api_url: str = "http://127.0.0.1:8090"   # ZAP daemon address
    zap_api_key: str = ""                          # ZAP API key ("" = ZAP's disabled-key mode)
    nuclei_path: str = "nuclei"                    # nuclei binary (on PATH by default)
    # Intrusive web scanning (ZAP active scan / nuclei DAST) sends attack traffic to
    # the target, so it needs explicit WRITTEN authorization for THIS engagement.
    # Default off → the agent cannot actively scan without a deliberate operator opt-in.
    webapp_active_scan_authorized: bool = False

    # ── Active Directory / Windows testing (C5) ───────────────────────────────
    # BloodHound CE REST + NetExec/Impacket/Certipy (subprocess). All optional; the
    # ad MCP server degrades gracefully if a tool or BHCE is unreachable.
    bloodhound_ce_url: str = "http://127.0.0.1:8080"   # BloodHound CE API base
    bloodhound_ce_token: str = ""                       # BHCE bearer token
    netexec_path: str = "nxc"                           # NetExec binary
    # State-changing AD actions (nxc command exec, Certipy cert request) are intrusive
    # → need explicit written authorization. Read/enumeration is allowed in scope.
    ad_state_change_authorized: bool = False

    # ── Metasploit RPC ────────────────────────────────────────────────────────
    msfrpc_host: str = "127.0.0.1"
    msfrpc_port: int = 55553
    msfrpc_user: str = "msf"
    msfrpc_pass: str = ""

    # ── MCP ───────────────────────────────────────────────────────────────────
    mcp_enabled_servers: str = ""

    # ── Attack graph (2A) ─────────────────────────────────────────────────────
    # Optional Neo4j mirror for a live BloodHound-style browser. Empty uri =
    # in-process networkx only (the default; no infrastructure required).
    neo4j_uri: str = ""
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""

    # ── Tracing (5C) ──────────────────────────────────────────────────────────
    # OTLP endpoint for OpenTelemetry spans (e.g. http://localhost:4318/v1/traces).
    # Empty = tracing off (no-op). Needs `opentelemetry-exporter-otlp-proto-http`.
    otel_exporter_otlp_endpoint: str = ""

    # ── Tradecraft memory (2C) ────────────────────────────────────────────────
    # Opt-in: distil lessons at engagement end and recall them on similar future
    # targets. Off by default (no post-run model calls, existing behavior).
    enable_tradecraft_memory: bool = False
    # opt-in: rank tradecraft recall by embedding similarity (needs sentence-transformers;
    # degrades to keyword overlap when the dep is absent — see core/embeddings.py)
    memory_semantic_recall: bool = False
    embedding_model: str = "all-MiniLM-L6-v2"

    # ── Adversary emulation (2D) ──────────────────────────────────────────────
    engagement_actor: str = ""    # e.g. "APT29" — empty = no actor constraint

    # ── Storage ───────────────────────────────────────────────────────────────
    evidence_dir: Path = Path("./data/evidence")
    reports_dir: Path = Path("./data/reports")
    knowledge_dir: Path = Path("./data/knowledge")

    # ── API Server ────────────────────────────────────────────────────────────
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_secret_key: str = "change_me"
    # CORS allow-list (comma-separated origins). "*" = open (default, keeps the
    # original localhost-friendly behavior); set explicit origins — e.g.
    # "https://ops.example.com" — to lock down a networked deployment.
    api_cors_origins: str = "*"

    # ── Logging ───────────────────────────────────────────────────────────────
    log_level: str = "INFO"

    # ── Derived helpers ───────────────────────────────────────────────────────

    @property
    def authorized_target_list(self) -> list[str]:
        """Parsed list of authorized targets."""
        return [t.strip() for t in self.authorized_targets.split(",") if t.strip()]

    @property
    def mcp_server_list(self) -> list[str]:
        """Parsed list of enabled MCP server names."""
        return [s.strip() for s in self.mcp_enabled_servers.split(",") if s.strip()]

    @property
    def authorized_email_domains_list(self) -> list[str]:
        """Parsed list of authorized client email domains (C6 phishing)."""
        return [d.strip() for d in self.authorized_email_domains.split(",") if d.strip()]

    def ensure_dirs(self) -> None:
        """Create data directories if they don't exist."""
        for d in (self.evidence_dir, self.reports_dir, self.knowledge_dir):
            Path(d).mkdir(parents=True, exist_ok=True)


# Singleton — import this everywhere
settings = Settings()
settings.ensure_dirs()
