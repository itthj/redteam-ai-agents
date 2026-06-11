"""
saas/secrets.py
────────────────
Secret provider abstraction. In production, secrets (JWT signing key, DB creds, the
at-rest encryption key) come from HashiCorp Vault or a cloud KMS — never plaintext
`.env`. In development the provider degrades to the environment / settings, exactly
like the MCP layer degrades when an optional backend is absent.
"""

from __future__ import annotations

import logging
import os

from config.settings import settings

log = logging.getLogger(__name__)


def _hvac_available() -> bool:
    try:
        import hvac  # noqa: F401
        return True
    except ImportError:
        return False


def _from_vault(name: str) -> str | None:
    """Read secret/data/redteam/<name> from Vault KV v2. Returns None on any failure."""
    try:
        import hvac
        client = hvac.Client(url=settings.vault_addr, token=settings.vault_token)
        resp = client.secrets.kv.v2.read_secret_version(path="redteam")
        return resp["data"]["data"].get(name)
    except Exception as e:  # noqa: BLE001 — graceful degradation
        log.warning("[SECRETS] Vault read failed for %s (%s) — falling back to env", name, e)
        return None


def get_secret(name: str, default: str = "") -> str:
    """Resolve a secret: Vault (if configured) → env var → settings attr → default."""
    if settings.vault_addr and _hvac_available():
        val = _from_vault(name)
        if val:
            return val
    env = os.environ.get(name) or os.environ.get(name.upper())
    if env:
        return env
    attr = getattr(settings, name.lower(), "")
    return attr or default


def jwt_secret() -> str:
    """The JWT signing key — from the secret provider, else the API secret key."""
    return get_secret("jwt_secret") or settings.api_secret_key
