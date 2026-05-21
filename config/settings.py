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
    claude_model: str = "claude-opus-4-7"
    claude_fast_model: str = "claude-haiku-4-5"
    orchestrator_effort: str = "xhigh"
    agent_effort: str = "high"

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

    # ── Metasploit RPC ────────────────────────────────────────────────────────
    msfrpc_host: str = "127.0.0.1"
    msfrpc_port: int = 55553
    msfrpc_user: str = "msf"
    msfrpc_pass: str = ""

    # ── MCP ───────────────────────────────────────────────────────────────────
    mcp_enabled_servers: str = ""

    # ── Storage ───────────────────────────────────────────────────────────────
    evidence_dir: Path = Path("./data/evidence")
    reports_dir: Path = Path("./data/reports")
    knowledge_dir: Path = Path("./data/knowledge")

    # ── API Server ────────────────────────────────────────────────────────────
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_secret_key: str = "change_me"

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

    def ensure_dirs(self) -> None:
        """Create data directories if they don't exist."""
        for d in (self.evidence_dir, self.reports_dir, self.knowledge_dir):
            Path(d).mkdir(parents=True, exist_ok=True)


# Singleton — import this everywhere
settings = Settings()
settings.ensure_dirs()
