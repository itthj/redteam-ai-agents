"""
saas/auth.py
─────────────
Authentication + RBAC for the SaaS backend.

  • Passwords  — PBKDF2-HMAC-SHA256 (stdlib; no native dependency).
  • Tokens     — JWT (HS256, PyJWT) carrying {sub, tenant_id, role}.
  • RBAC       — three roles (operator / analyst / client_viewer) and a permission
                 matrix; the API guards each route with a required permission.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from enum import Enum

import jwt

from saas.secrets import jwt_secret

_PBKDF2_ITERS = 200_000


# ── Passwords ────────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS)
    return f"pbkdf2_sha256${_PBKDF2_ITERS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _algo, iters, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt_hex), int(iters))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk.hex(), hash_hex)


# ── Roles + permissions ──────────────────────────────────────────────────────────

class Role(str, Enum):
    OPERATOR = "operator"
    ANALYST = "analyst"
    CLIENT_VIEWER = "client_viewer"


PERMISSIONS: dict[Role, set[str]] = {
    Role.OPERATOR: {
        "engagement:create", "engagement:read", "engagement:run",
        "finding:read", "finding:approve", "audit:read", "tenant:admin",
    },
    Role.ANALYST: {
        "engagement:read", "engagement:run", "finding:read", "finding:approve",
    },
    Role.CLIENT_VIEWER: {
        "engagement:read", "finding:read",
    },
}


def has_permission(role: str, permission: str) -> bool:
    try:
        return permission in PERMISSIONS[Role(role)]
    except ValueError:
        return False


# ── Tokens ───────────────────────────────────────────────────────────────────────

def create_token(*, user_id: str, tenant_id: str, role: str,
                 ttl: int | None = None, secret: str | None = None) -> str:
    from config.settings import settings
    now = int(time.time())
    payload = {
        "sub": user_id, "tenant_id": tenant_id, "role": role,
        "iat": now, "exp": now + (ttl if ttl is not None else settings.jwt_ttl_seconds),
    }
    return jwt.encode(payload, secret or jwt_secret(), algorithm="HS256")


def decode_token(token: str, secret: str | None = None) -> dict:
    """Decode + verify a JWT. Raises jwt.PyJWTError on tamper/expiry."""
    return jwt.decode(token, secret or jwt_secret(), algorithms=["HS256"])
