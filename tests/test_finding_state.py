"""Tests for the finding lifecycle store (C2) — fully offline."""

import pytest

from config.settings import settings
from core.finding_state import FindingState, FindingStateStore, severity_to_cvss, signature


@pytest.fixture
def store(tmp_path):
    return FindingStateStore(path=str(tmp_path / "fs.json"))


_F = {"target": "10.0.0.5", "title": "Reflected XSS", "severity": "high",
      "cwe": "79", "url": "https://10.0.0.5/q"}


def test_register_creates_candidate(store):
    sig = store.register_candidate(_F)
    entry = store.get(sig)
    assert entry["state"] == FindingState.CANDIDATE.value
    assert entry["severity"] == "high"


def test_register_is_idempotent(store):
    a = store.register_candidate(_F)
    b = store.register_candidate(_F)
    assert a == b
    assert len(store.list()) == 1


def test_confirm_requires_reproduction(store):
    sig = store.register_candidate(_F)
    res = store.confirm(sig, validation={"reproduced": False})
    assert res["promoted"] is False
    assert store.get(sig)["state"] == FindingState.CANDIDATE.value


def test_confirm_promotes_when_reproduced(store):
    sig = store.register_candidate(_F)
    res = store.confirm(sig, validation={"reproduced": True, "method": "nuclei"}, cvss=7.5)
    assert res["promoted"] is True
    assert store.get(sig)["state"] == FindingState.CONFIRMED.value
    assert store.get(sig)["cvss"] == 7.5


def test_candidate_cannot_be_approved_directly(store):
    sig = store.register_candidate(_F)
    res = store.approve(sig, approver="alice")
    assert res["approved"] is False
    assert store.get(sig)["state"] == FindingState.CANDIDATE.value


def test_approve_only_from_confirmed(store):
    sig = store.register_candidate(_F)
    store.confirm(sig, validation={"reproduced": True})
    res = store.approve(sig, approver="alice")
    assert res["approved"] is True
    assert store.get(sig)["state"] == FindingState.APPROVED.value
    assert store.get(sig)["approved_by"] == "alice"


def test_cannot_reject_after_approved(store):
    sig = store.register_candidate(_F)
    store.confirm(sig, validation={"reproduced": True})
    store.approve(sig, approver="alice")
    res = store.reject(sig, by="bob")
    assert res["rejected"] is False


def test_queue_is_confirmed_only(store):
    s1 = store.register_candidate(_F)
    store.register_candidate({**_F, "title": "SQLi", "url": "https://10.0.0.5/s"})
    store.confirm(s1, validation={"reproduced": True})
    queue = store.queue()
    assert len(queue) == 1 and queue[0]["signature"] == s1


def test_can_report_gate(store, monkeypatch):
    sig = store.register_candidate(_F)
    monkeypatch.setattr(settings, "require_finding_approval", False)
    assert store.can_report(sig) is True            # gate off → everything passes
    monkeypatch.setattr(settings, "require_finding_approval", True)
    assert store.can_report(sig) is False           # gate on → candidate blocked
    store.confirm(sig, validation={"reproduced": True})
    store.approve(sig, approver="alice")
    assert store.can_report(sig) is True            # approved passes


def test_signature_stable_and_distinct():
    assert signature(_F) == signature(dict(_F))
    assert signature(_F) != signature({**_F, "title": "different"})


def test_severity_to_cvss():
    assert severity_to_cvss("critical") > severity_to_cvss("high") > severity_to_cvss("low")
    assert severity_to_cvss("nonsense") == 0.0
