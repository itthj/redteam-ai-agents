"""Tests for SaaS auth — passwords, JWT, RBAC (C7) — offline."""

import jwt
import pytest

from saas import auth

_K = "test-signing-key-at-least-32-bytes-long!!"
_OTHER = "a-different-signing-key-also-32-bytes-x!!"


def test_password_hash_roundtrip():
    h = auth.hash_password("s3cr3t!")
    assert h.startswith("pbkdf2_sha256$")
    assert auth.verify_password("s3cr3t!", h) is True
    assert auth.verify_password("wrong", h) is False


def test_jwt_roundtrip():
    tok = auth.create_token(user_id="u1", tenant_id="t1", role="operator", secret=_K)
    claims = auth.decode_token(tok, secret=_K)
    assert claims["sub"] == "u1" and claims["tenant_id"] == "t1" and claims["role"] == "operator"


def test_jwt_rejects_wrong_secret():
    tok = auth.create_token(user_id="u1", tenant_id="t1", role="operator", secret=_K)
    with pytest.raises(jwt.PyJWTError):
        auth.decode_token(tok, secret=_OTHER)


def test_jwt_rejects_expired():
    tok = auth.create_token(user_id="u1", tenant_id="t1", role="operator", ttl=-1, secret=_K)
    with pytest.raises(jwt.PyJWTError):
        auth.decode_token(tok, secret=_K)


def test_rbac_matrix():
    assert auth.has_permission("operator", "engagement:create") is True
    assert auth.has_permission("analyst", "engagement:run") is True
    assert auth.has_permission("analyst", "engagement:create") is False
    assert auth.has_permission("client_viewer", "engagement:read") is True
    assert auth.has_permission("client_viewer", "engagement:create") is False
    assert auth.has_permission("bogus_role", "engagement:read") is False
