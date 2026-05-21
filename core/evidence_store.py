"""
core/evidence_store.py
───────────────────────
Tamper-evident, append-only evidence log.
Every agent action is written here with a SHA-256 chain hash —
suitable for inclusion in a final pentest report or legal proceeding.

Storage: SQLite (single file, zero-dependency, portable to Kali).
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from config.settings import settings

log = logging.getLogger(__name__)

DB_PATH = Path(settings.evidence_dir) / "evidence.db"


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS evidence (
            id          TEXT PRIMARY KEY,
            timestamp   REAL NOT NULL,
            engagement  TEXT NOT NULL,
            operator    TEXT NOT NULL,
            agent       TEXT NOT NULL,
            operation   TEXT NOT NULL,
            target      TEXT,
            action      TEXT NOT NULL,
            result      TEXT,
            severity    TEXT DEFAULT 'info',
            chain_hash  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_evidence_ts ON evidence(timestamp);
        CREATE INDEX IF NOT EXISTS idx_evidence_target ON evidence(target);
        """
    )
    conn.commit()


# ── Init on import ─────────────────────────────────────────────────────────────
Path(settings.evidence_dir).mkdir(parents=True, exist_ok=True)
_conn = _get_conn()
_init_db(_conn)
_last_hash = "GENESIS"  # chain anchor


class EvidenceStore:
    """Append-only, chain-hashed evidence log."""

    def __init__(self) -> None:
        global _last_hash
        # Recover last hash on restart so the chain is continuous
        row = _conn.execute(
            "SELECT chain_hash FROM evidence ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
        if row:
            _last_hash = row["chain_hash"]

    # ── Write ──────────────────────────────────────────────────────────────────

    def log(
        self,
        agent: str,
        operation: str,
        action: str,
        target: Optional[str] = None,
        result: Optional[Any] = None,
        severity: str = "info",
    ) -> str:
        """
        Append one evidence record. Returns the record ID.
        severity: info | low | medium | high | critical
        """
        global _last_hash

        record_id = str(uuid.uuid4())
        ts = time.time()
        result_str = json.dumps(result, default=str) if result is not None else None

        # Hash = SHA256(prev_hash + id + timestamp + action + result)
        chain_input = f"{_last_hash}|{record_id}|{ts}|{action}|{result_str or ''}"
        chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()
        _last_hash = chain_hash

        _conn.execute(
            """
            INSERT INTO evidence
              (id, timestamp, engagement, operator, agent, operation, target,
               action, result, severity, chain_hash)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                record_id, ts,
                settings.engagement_id,
                settings.operator_name,
                agent, operation,
                target, action, result_str, severity, chain_hash,
            ),
        )
        _conn.commit()
        log.debug("[EVIDENCE] %s | %s | %s → %s", agent, operation, target or "-", action)
        return record_id

    # ── Read ───────────────────────────────────────────────────────────────────

    def get_all(self, target: Optional[str] = None) -> list[dict]:
        if target:
            rows = _conn.execute(
                "SELECT * FROM evidence WHERE target=? ORDER BY timestamp",
                (target,),
            ).fetchall()
        else:
            rows = _conn.execute(
                "SELECT * FROM evidence ORDER BY timestamp"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_findings(self, min_severity: str = "low") -> list[dict]:
        """Return findings at or above a given severity level."""
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = order.get(min_severity, 0)
        rows = _conn.execute(
            "SELECT * FROM evidence ORDER BY timestamp"
        ).fetchall()
        return [
            dict(r)
            for r in rows
            if order.get(r["severity"], 0) >= threshold
        ]

    def verify_chain(self) -> bool:
        """
        Walk the entire chain and verify each record's hash.
        Returns True if the chain is intact; False if tampering detected.
        """
        rows = _conn.execute(
            "SELECT * FROM evidence ORDER BY timestamp"
        ).fetchall()
        prev = "GENESIS"
        for row in rows:
            chain_input = (
                f"{prev}|{row['id']}|{row['timestamp']}|"
                f"{row['action']}|{row['result'] or ''}"
            )
            expected = hashlib.sha256(chain_input.encode()).hexdigest()
            if expected != row["chain_hash"]:
                log.error("Chain integrity FAILED at record %s", row["id"])
                return False
            prev = row["chain_hash"]
        return True

    def export_json(self, path: Optional[Path] = None) -> Path:
        """Export all evidence to a JSON file."""
        out = path or Path(settings.evidence_dir) / f"evidence_export_{int(time.time())}.json"
        records = self.get_all()
        with open(out, "w") as f:
            json.dump(
                {
                    "engagement": settings.engagement_id,
                    "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "chain_valid": self.verify_chain(),
                    "records": records,
                },
                f,
                indent=2,
                default=str,
            )
        return out


# Module-level singleton
evidence = EvidenceStore()
