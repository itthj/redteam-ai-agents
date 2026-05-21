"""Tests for the tamper-evident evidence store."""

from core.evidence_store import evidence


def test_log_returns_id():
    rec_id = evidence.log("test", "unit", "test action", target="10.0.0.5")
    assert isinstance(rec_id, str) and len(rec_id) > 10


def test_chain_valid_after_writes():
    for i in range(5):
        evidence.log("test", "unit", f"action {i}", severity="info")
    assert evidence.verify_chain() is True


def test_records_are_retrievable():
    evidence.log("recon", "dns", "DNS lookup", target="192.168.56.10")
    records = evidence.get_all(target="192.168.56.10")
    assert any(r["agent"] == "recon" for r in records)


def test_severity_filtering():
    evidence.log("vuln", "scan", "critical finding", severity="critical")
    findings = evidence.get_findings(min_severity="high")
    assert all(
        r["severity"] in ("high", "critical") for r in findings
    )


def test_tamper_detection():
    """Corrupting a record must break chain verification."""
    from core.evidence_store import _conn

    evidence.log("test", "unit", "original action", severity="info")
    assert evidence.verify_chain() is True

    # Tamper: rewrite an action without recomputing the chain hash
    row = _conn.execute(
        "SELECT id FROM evidence ORDER BY timestamp LIMIT 1"
    ).fetchone()
    _conn.execute(
        "UPDATE evidence SET action=? WHERE id=?",
        ("TAMPERED ACTION", row["id"]),
    )
    _conn.commit()

    assert evidence.verify_chain() is False
