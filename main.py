"""
main.py
────────
Entry point for the Red Team AI Agent System.

Usage:
    python main.py                         # launches the CLI
    python main.py mission 192.168.56.10   # CLI subcommand passthrough

Programmatic use:
    import asyncio
    from main import run_autonomous
    asyncio.run(run_autonomous("full pentest of the lab", ["192.168.56.0/24"]))

⚠️  Authorized security testing only. Configure .env (AUTHORIZED_TARGETS,
    ENGAGEMENT_ID, ANTHROPIC_API_KEY) before running anything.
"""

from __future__ import annotations

import logging
import sys


def setup_logging() -> None:
    """Configure root logging from the LOG_LEVEL setting."""
    from config.settings import settings
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    # Quiet noisy third-party loggers
    for noisy in ("httpx", "anthropic", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# ── Programmatic API ───────────────────────────────────────────────────────────

async def run_mission(targets: list[str], phases: list[str] | None = None,
                       note: str = "") -> dict:
    """Run a deterministic kill-chain mission."""
    from core.orchestrator import Orchestrator
    return await Orchestrator().run_mission(targets, phases, note)


async def run_autonomous(objective: str, targets: list[str]) -> dict:
    """Let the OrchestratorAgent plan and execute the engagement."""
    from core.orchestrator import Orchestrator
    return await Orchestrator().run_autonomous(objective, targets)


async def dispatch(agent: str, task: str) -> str:
    """Run one ad-hoc task on a single specialist agent."""
    from core.orchestrator import Orchestrator
    return await Orchestrator().dispatch(agent, task)


# ── Launcher ───────────────────────────────────────────────────────────────────

def _preflight() -> bool:
    """Verify the engagement is configured before doing anything."""
    try:
        from config.settings import settings
        from config.authorization import scope
    except Exception as e:  # noqa: BLE001
        print(f"[FATAL] Configuration error: {e}", file=sys.stderr)
        print("        Copy .env.example to .env and fill it in.", file=sys.stderr)
        return False

    if not settings.authorized_target_list:
        print("[FATAL] No AUTHORIZED_TARGETS set in .env — refusing to run.",
              file=sys.stderr)
        return False

    s = scope.summary()
    if s["expired"]:
        print(f"[FATAL] Engagement {s['engagement_id']} has expired ({s['expiry']}).",
              file=sys.stderr)
        return False
    return True


def main() -> None:
    setup_logging()
    if not _preflight():
        sys.exit(1)
    # Mirror knowledge-base writes into the attack graph (2A)
    from core.attack_graph import graph
    from core.knowledge_base import kb
    kb.attach_sink(graph.on_kb_event)
    # Initialise tracing — no-op unless OTel + OTEL_EXPORTER_OTLP_ENDPOINT are set (5C)
    from core.tracing import init_tracing
    init_tracing()
    # Hand off to the rich CLI
    from cli.main import cli
    cli()


if __name__ == "__main__":
    main()
