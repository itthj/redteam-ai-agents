"""
cli/main.py
────────────
Rich CLI for the red-team agent system.
Lets you drive any agent or a full mission from the terminal.

Usage:
  python -m cli.main scope             # show current engagement scope
  python -m cli.main mission --help    # full mission options
  python -m cli.main agent recon "scan example.com"
  python -m cli.main kb               # dump knowledge base
  python -m cli.main evidence          # show evidence log
  python -m cli.main report            # show latest report
"""

from __future__ import annotations

import asyncio
import json
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

from config.authorization import scope
from config.settings import settings
from core.evidence_store import evidence
from core.knowledge_base import kb
from core.orchestrator import Orchestrator

console = Console()


def _banner():
    console.print(Panel.fit(
        "[bold red]RED TEAM AI AGENT SYSTEM[/bold red]\n"
        f"[dim]Engagement: {settings.engagement_id} | Operator: {settings.operator_name}[/dim]\n"
        "[yellow]AUTHORIZED USE ONLY — All activity is logged[/yellow]",
        border_style="red",
    ))


# ── CLI root ──────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """Multi-agent cybersecurity operations platform."""
    _banner()


# ── scope ─────────────────────────────────────────────────────────────────────

@cli.command()
def scope_cmd():
    """Show current engagement scope and authorization status."""
    info = scope.summary()
    table = Table(title="Engagement Scope", border_style="cyan")
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")
    for k, v in info.items():
        val = str(v) if not isinstance(v, list) else "\n".join(v)
        style = "red" if k == "expired" and v else "green" if k == "expired" else ""
        table.add_row(k, val, style=style)
    console.print(table)


cli.add_command(scope_cmd, name="scope")


# ── mission ───────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("--phases", "-p", default=None, help="Comma-separated phases: recon,scan,vuln_assessment,exploitation,post_exploitation,forensics,reporting")
@click.option("--note", "-n", default="", help="Mission note / objective")
def mission(targets, phases, note):
    """Run a red team mission against TARGETS.

    \b
    Example:
      python -m cli.main mission 192.168.1.0/24 --phases recon,scan
    """
    phase_list = [p.strip() for p in phases.split(",")] if phases else None
    console.print(f"\n[bold]Targets:[/bold] {list(targets)}")
    console.print(f"[bold]Phases:[/bold]  {phase_list or 'full lifecycle'}\n")

    orch = Orchestrator()
    result = asyncio.run(orch.run_mission(list(targets), phase_list, note))
    console.print_json(json.dumps(result, indent=2, default=str))


# ── agent ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("agent_name")
@click.argument("task")
@click.option("--context", "-c", default=None, help="JSON context string")
def agent(agent_name, task, context):
    """Dispatch TASK directly to a specific AGENT.

    \b
    Agents: recon, scanner, vuln, exploit, post_exploit, forensics, reporting

    Example:
      python -m cli.main agent recon "enumerate subdomains of example.com"
    """
    ctx = json.loads(context) if context else None
    orch = Orchestrator()
    result = asyncio.run(orch.dispatch(agent_name, task, ctx))
    console.print(Panel(result, title=f"[bold]{agent_name.upper()} Agent Response[/bold]", border_style="green"))


# ── autonomous ────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("--objective", "-o", required=True,
              help="What the orchestrator should achieve")
def autonomous(targets, objective):
    """Run an AUTONOMOUS mission — the orchestrator agent plans and delegates.

    \b
    Example:
      python -m cli.main autonomous 192.168.56.0/24 \\
        -o "full pentest, prioritise web and SMB services"
    """
    console.print(f"\n[bold]Objective:[/bold] {objective}")
    console.print(f"[bold]Targets:[/bold]   {list(targets)}\n")
    console.print("[dim]The orchestrator (Opus 4.7, xhigh effort) is planning…[/dim]\n")

    orch = Orchestrator()
    result = asyncio.run(orch.run_autonomous(objective, list(targets)))
    console.print(Panel(
        result.get("orchestrator_summary", ""),
        title="[bold]Orchestrator Summary[/bold]", border_style="green",
    ))
    tel = result.get("telemetry", {}).get("total", {})
    console.print(f"\n[dim]Cost: ${tel.get('cost_usd', 0):.4f} | "
                  f"API calls: {tel.get('api_calls', 0)} | "
                  f"Cache hit: {tel.get('cache_hit_rate', 0) * 100:.0f}%[/dim]")


# ── mcp ───────────────────────────────────────────────────────────────────────

@cli.command()
def mcp_cmd():
    """Show MCP server connection status and discovered tools."""
    from mcp_layer.mcp_bridge import bridge
    summary = asyncio.run(bridge.connect())
    if not summary["mcp_available"]:
        console.print("[yellow]MCP SDK not installed — run: pip install mcp[/yellow]")
        return
    if not summary["connected_servers"]:
        console.print("[yellow]No MCP servers connected. "
                      "Set MCP_ENABLED_SERVERS in .env.[/yellow]")
        return
    table = Table(title="MCP Integration", border_style="blue")
    table.add_column("Server", style="bold cyan")
    console.print(f"[green]{summary['tool_count']} tools[/green] from "
                  f"{len(summary['connected_servers'])} server(s)")
    for srv in summary["connected_servers"]:
        table.add_row(srv)
    console.print(table)
    for tool in summary["tools"]:
        console.print(f"  [dim]•[/dim] {tool}")


cli.add_command(mcp_cmd, name="mcp")


# ── kb ────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target", required=False)
def knowledge(target):
    """Dump the knowledge base. Optionally filter to a specific TARGET IP."""
    if target:
        data = kb.get_target(target)
        if not data:
            console.print(f"[red]Target {target} not found in knowledge base[/red]")
            sys.exit(1)
        console.print_json(json.dumps(data, indent=2, default=str))
    else:
        console.print_json(json.dumps(kb.snapshot(), indent=2, default=str))


# ── evidence ──────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--min-severity", default="info", help="Minimum severity: info/low/medium/high/critical")
@click.option("--verify", is_flag=True, help="Verify chain integrity")
def evidence_cmd(min_severity, verify):
    """Show evidence log."""
    if verify:
        valid = evidence.verify_chain()
        status = "[green]INTACT[/green]" if valid else "[red]TAMPERED![/red]"
        console.print(f"Chain integrity: {status}")
        return

    records = evidence.get_findings(min_severity=min_severity)
    table = Table(title=f"Evidence Log (≥{min_severity})", border_style="yellow")
    table.add_column("Time", style="dim")
    table.add_column("Agent")
    table.add_column("Target")
    table.add_column("Action")
    table.add_column("Severity")

    sev_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }
    import time
    for r in records:
        ts = time.strftime("%H:%M:%S", time.gmtime(r.get("timestamp", 0)))
        sev = r.get("severity", "info")
        table.add_row(
            ts,
            r.get("agent", ""),
            r.get("target") or "-",
            r.get("action", "")[:60],
            f"[{sev_colors.get(sev, '')}]{sev}[/]",
        )
    console.print(table)
    console.print(f"\n[dim]Total: {len(records)} records[/dim]")


cli.add_command(evidence_cmd, name="evidence")


# ── report ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--generate", "-g", is_flag=True, help="Generate a new report now")
def report(generate):
    """View or generate the latest pentest report."""
    from pathlib import Path
    if generate:
        orch = Orchestrator()
        result = asyncio.run(orch.dispatch(
            "reporting",
            f"Generate a complete pentest report for engagement {settings.engagement_id}",
        ))
        console.print(Markdown(result))
        return

    reports_dir = Path(settings.reports_dir)
    reports = sorted(reports_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        console.print("[yellow]No reports found. Run with --generate to create one.[/yellow]")
        return
    console.print(Markdown(reports[0].read_text()))


if __name__ == "__main__":
    cli()
