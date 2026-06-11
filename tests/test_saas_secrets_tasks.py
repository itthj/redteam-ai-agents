"""Tests for the SaaS secret provider + job runner (C7) — offline."""

import core.orchestrator as orch_mod
import saas.tasks as tasks
from config.settings import settings
from saas import secrets
from saas.store import store

# ── Secret provider ──────────────────────────────────────────────────────────────

def test_env_fallback(monkeypatch):
    monkeypatch.setenv("MY_SAAS_SECRET", "abc123")
    assert secrets.get_secret("MY_SAAS_SECRET") == "abc123"


def test_default_when_absent():
    assert secrets.get_secret("DEFINITELY_NOT_SET_XYZ", "fallback") == "fallback"


def test_vault_skipped_when_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "vault_addr", "")
    assert secrets.get_secret("WHATEVER", "d") == "d"


def test_jwt_secret_falls_back_to_api_key(monkeypatch):
    monkeypatch.setattr(settings, "jwt_secret", "")
    monkeypatch.delenv("JWT_SECRET", raising=False)
    assert secrets.jwt_secret() == settings.api_secret_key


# ── Job runner (sync fallback) ───────────────────────────────────────────────────

class _FakeOrch:
    async def run_autonomous(self, objective, targets):
        return {}

    async def run_mission(self, targets):
        return {}


class _BoomOrch:
    async def run_autonomous(self, objective, targets):
        raise RuntimeError("boom")


def test_sync_run_marks_complete(monkeypatch):
    monkeypatch.setattr(orch_mod, "Orchestrator", _FakeOrch)
    t = store.create_tenant("Acme")
    e = store.create_engagement(t, "eng")
    out = tasks.run_engagement(t, e, "obj", ["10.0.0.5"])
    assert out["status"] == "complete"
    assert store.get_engagement(t, e)["status"] == "complete"


def test_run_error_marks_error(monkeypatch):
    monkeypatch.setattr(orch_mod, "Orchestrator", _BoomOrch)
    t = store.create_tenant("Acme")
    e = store.create_engagement(t, "eng")
    out = tasks.run_engagement(t, e, "obj", [])
    assert out["status"] == "error"
    assert store.get_engagement(t, e)["status"] == "error"


def test_enqueue_uses_sync_without_broker(monkeypatch):
    monkeypatch.setattr(settings, "redis_url", "")
    monkeypatch.setattr(orch_mod, "Orchestrator", _FakeOrch)
    t = store.create_tenant("Acme")
    e = store.create_engagement(t, "eng")
    out = tasks.enqueue_engagement(t, e, "obj", [])
    assert out["backend"] == "sync" and out["status"] == "complete"
