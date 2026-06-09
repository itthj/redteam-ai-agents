"""
core/knowledge_base.py
───────────────────────
Shared, in-memory + JSON-persisted intelligence store.
Agents read and write here so findings from Recon feed into the Scanner,
Scanner feeds into VulnAssessment, and so on.

Structure:
    {
      "targets": {
        "192.168.1.5": {
          "hostnames": [...],
          "open_ports": [...],
          "services": {...},
          "vulnerabilities": [...],
          "exploits_attempted": [...],
          "credentials": [...],
          "notes": [...]
        }
      },
      "domain_info": {...},
      "credentials": [...],
      "pivot_hosts": [...],
      "mission_state": "recon|scanning|exploitation|..."
    }
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Optional

from config.settings import settings

log = logging.getLogger(__name__)

_KB_FILE = Path(settings.knowledge_dir) / "knowledge_base.json"


class KnowledgeBase:
    """Thread-safe shared intelligence store."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._data: dict = self._load()
        self._sinks: list = []          # 2A: mirror writes into the attack graph, etc.

    # ── Sinks (2A) ────────────────────────────────────────────────────────────

    def attach_sink(self, sink) -> None:
        """Register a callable sink(event, payload) that mirrors every intel write
        elsewhere (e.g. the attack graph). Best-effort — a failing sink never
        breaks a KB write."""
        self._sinks.append(sink)

    def _emit(self, event: str, **payload) -> None:
        for sink in self._sinks:
            try:
                sink(event, payload)
            except Exception as e:  # noqa: BLE001 — a sink must never break a write
                log.warning("KB sink failed on '%s': %s", event, e)

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> dict:
        if _KB_FILE.exists():
            try:
                with open(_KB_FILE) as f:
                    return json.load(f)
            except Exception as e:
                log.warning("Could not load knowledge base: %s — starting fresh", e)
        return {
            "targets": {},
            "domain_info": {},
            "credentials": [],
            "pivot_hosts": [],
            "mission_state": "idle",
            "last_updated": None,
        }

    def save(self) -> None:
        with self._lock:
            self._data["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            _KB_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(_KB_FILE, "w") as f:
                json.dump(self._data, f, indent=2, default=str)

    # ── Target management ─────────────────────────────────────────────────────

    def ensure_target(self, ip: str) -> dict:
        """Get or create a target entry."""
        with self._lock:
            if ip not in self._data["targets"]:
                self._data["targets"][ip] = {
                    "ip": ip,
                    "hostnames": [],
                    "os_guess": None,
                    "open_ports": [],
                    "services": {},
                    "vulnerabilities": [],
                    "exploits_attempted": [],
                    "credentials": [],
                    "shells": [],
                    "notes": [],
                    "first_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            return self._data["targets"][ip]

    def add_hostname(self, ip: str, hostname: str) -> None:
        with self._lock:
            t = self.ensure_target(ip)
            if hostname not in t["hostnames"]:
                t["hostnames"].append(hostname)
            self.save()
            self._emit("hostname_added", ip=ip, hostname=hostname)

    def add_port(self, ip: str, port: int, protocol: str = "tcp", state: str = "open") -> None:
        with self._lock:
            t = self.ensure_target(ip)
            entry = {"port": port, "protocol": protocol, "state": state}
            if entry not in t["open_ports"]:
                t["open_ports"].append(entry)
            self.save()
            self._emit("port_added", ip=ip, port=port, protocol=protocol, state=state)

    def add_service(self, ip: str, port: int, service_info: dict) -> None:
        with self._lock:
            t = self.ensure_target(ip)
            t["services"][str(port)] = service_info
            self.save()
            self._emit("service_added", ip=ip, port=port, info=service_info)

    def add_vulnerability(self, ip: str, vuln: dict) -> None:
        """
        vuln should contain: cve, cvss, severity, description, port (optional)
        """
        with self._lock:
            t = self.ensure_target(ip)
            t["vulnerabilities"].append({**vuln, "found_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
            self.save()
            self._emit("vuln_added", ip=ip, vuln=vuln)

    def add_credential(self, ip: str, cred: dict) -> None:
        """cred: {username, password/hash, service, port}"""
        with self._lock:
            t = self.ensure_target(ip)
            t["credentials"].append(cred)
            # Also in global creds list for cross-target reuse
            self._data["credentials"].append({**cred, "source_ip": ip})
            self.save()
            self._emit("credential_added", ip=ip, cred=cred)

    def add_shell(self, ip: str, shell_info: dict) -> None:
        with self._lock:
            t = self.ensure_target(ip)
            t["shells"].append(shell_info)
            if ip not in self._data["pivot_hosts"]:
                self._data["pivot_hosts"].append(ip)
            self.save()
            self._emit("shell_added", ip=ip, info=shell_info)

    def add_exploit_attempt(self, ip: str, attempt: dict) -> None:
        with self._lock:
            t = self.ensure_target(ip)
            t["exploits_attempted"].append(attempt)
            self.save()

    def add_note(self, ip: str, note: str) -> None:
        with self._lock:
            t = self.ensure_target(ip)
            t["notes"].append({"text": note, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
            self.save()

    # ── Mission state ─────────────────────────────────────────────────────────

    def set_state(self, state: str) -> None:
        with self._lock:
            self._data["mission_state"] = state
            self.save()

    def get_state(self) -> str:
        return self._data.get("mission_state", "idle")

    # ── Generic read/write ────────────────────────────────────────────────────

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value
            self.save()

    def get_target(self, ip: str) -> Optional[dict]:
        with self._lock:
            return self._data["targets"].get(ip)

    def get_all_targets(self) -> dict:
        with self._lock:
            return dict(self._data["targets"])

    def snapshot(self) -> dict:
        with self._lock:
            return json.loads(json.dumps(self._data, default=str))


# Module-level singleton
kb = KnowledgeBase()
