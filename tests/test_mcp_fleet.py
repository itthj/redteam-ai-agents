"""Tests for the expanded MCP fleet (5D) — offline (registry config only)."""

from config.settings import settings
from mcp_layer.mcp_config import MCP_SERVERS, get_enabled_servers

_FLEET = ("nuclei", "theharvester", "bloodhound", "threatintel", "siem")


def test_fleet_entries_present():
    for name in _FLEET:
        assert name in MCP_SERVERS


def test_fleet_entries_well_formed():
    for name in _FLEET:
        cfg = MCP_SERVERS[name]
        assert cfg.get("tool_allowlist"), f"{name} must keep a tight allowlist"
        assert cfg.get("tool_prefix")
        assert cfg.get("description")
        transport = cfg.get("transport")
        assert transport in ("stdio", "sse")
        if transport == "stdio":
            assert cfg.get("command")
        else:
            assert cfg.get("url")


def test_get_enabled_servers_selects_fleet(monkeypatch):
    monkeypatch.setattr(settings, "mcp_enabled_servers", "web,nuclei,siem")
    enabled = get_enabled_servers()
    assert {"web", "nuclei", "siem"} <= set(enabled)
    assert "shodan" not in enabled       # only the named servers are enabled
