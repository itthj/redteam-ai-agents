"""
saas/crypto.py
───────────────
At-rest encryption for sensitive stored values (e.g. tenant secrets, stored creds).
Uses Fernet (AES-128-CBC + HMAC) from the `cryptography` package when available and a
key is configured. If either is missing it degrades to a clear no-op + warning rather
than silently pretending to encrypt — the caller can require `available()` in prod.

This is the application-level half of "encrypt evidence at rest"; the database itself
should additionally use SQLCipher (sqlite) or PostgreSQL TDE in production.
"""

from __future__ import annotations

import logging

from saas.secrets import get_secret

log = logging.getLogger(__name__)


def _fernet():
    """Return a Fernet instance, or None if cryptography/key are unavailable."""
    key = get_secret("saas_encryption_key")
    if not key:
        return None
    try:
        from cryptography.fernet import Fernet
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception as e:  # noqa: BLE001 — graceful degradation
        log.warning("[CRYPTO] Fernet unavailable (%s) — at-rest encryption disabled", e)
        return None


def available() -> bool:
    return _fernet() is not None


def encrypt(plaintext: str) -> str:
    f = _fernet()
    if f is None:
        return plaintext
    return f.encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    f = _fernet()
    if f is None:
        return token
    try:
        return f.decrypt(token.encode()).decode()
    except Exception as e:  # noqa: BLE001
        log.warning("[CRYPTO] decrypt failed (%s)", e)
        return token


def generate_key() -> str:
    """Generate a fresh Fernet key (for `SAAS_ENCRYPTION_KEY`). Requires cryptography."""
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode()
