"""
core/message_bus.py
────────────────────
In-process pub/sub message bus for agent-to-agent communication.
Agents publish events; other agents subscribe to topics they care about.

Topics (by convention):
  recon.complete        – Recon agent finished; payload = {targets: [...]}
  scan.complete         – Scanner finished; payload = {ip, open_ports, services}
  vuln.found            – Vulnerability discovered; payload = {ip, cve, severity}
  exploit.success       – Exploitation succeeded; payload = {ip, shell_id}
  exploit.failed        – Exploitation failed; payload = {ip, module, reason}
  post_exploit.finding  – Post-exploit finding; payload = {ip, type, data}
  forensics.artifact    – Forensic artifact collected; payload = {ip, artifact}
  mission.phase_change  – Orchestrator changed the mission phase
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import defaultdict
from typing import Any, Callable, Coroutine

log = logging.getLogger(__name__)

# Type alias for async handlers
Handler = Callable[[dict], Coroutine[Any, Any, None]]


class MessageBus:
    """Lightweight asyncio-based pub/sub bus."""

    def __init__(self) -> None:
        # topic → list of handlers
        self._subscribers: dict[str, list[Handler]] = defaultdict(list)
        # Full message history (for replay / forensics)
        self._history: list[dict] = []

    # ── Subscribe ─────────────────────────────────────────────────────────────

    def subscribe(self, topic: str, handler: Handler) -> None:
        """Register an async handler for a topic."""
        self._subscribers[topic].append(handler)
        log.debug("[BUS] subscribed to '%s'", topic)

    def unsubscribe(self, topic: str, handler: Handler) -> None:
        try:
            self._subscribers[topic].remove(handler)
        except ValueError:
            pass

    # ── Publish ───────────────────────────────────────────────────────────────

    async def publish(self, topic: str, payload: Any = None, source: str = "unknown") -> str:
        """
        Publish a message to all subscribers of *topic*.
        Returns the message ID.
        """
        msg_id = str(uuid.uuid4())
        message = {
            "id": msg_id,
            "topic": topic,
            "source": source,
            "payload": payload,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self._history.append(message)
        log.info("[BUS] %s → '%s' (from %s)", msg_id[:8], topic, source)

        handlers = self._subscribers.get(topic, [])
        if handlers:
            await asyncio.gather(*[h(message) for h in handlers], return_exceptions=True)

        return msg_id

    def publish_sync(self, topic: str, payload: Any = None, source: str = "unknown") -> str:
        """Synchronous wrapper — creates an event loop if needed."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Schedule as a coroutine and return immediately (fire-and-forget)
                asyncio.ensure_future(self.publish(topic, payload, source))
                return "scheduled"
            else:
                return loop.run_until_complete(self.publish(topic, payload, source))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            return loop.run_until_complete(self.publish(topic, payload, source))

    # ── History ───────────────────────────────────────────────────────────────

    def get_history(self, topic: str | None = None) -> list[dict]:
        if topic:
            return [m for m in self._history if m["topic"] == topic]
        return list(self._history)

    def clear_history(self) -> None:
        self._history.clear()


# Module-level singleton
bus = MessageBus()
