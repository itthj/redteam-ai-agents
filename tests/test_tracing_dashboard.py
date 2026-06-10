"""
Tests for OpenTelemetry tracing + the live dashboard (5C) — fully offline.

Tracing is exercised against an in-memory SDK exporter (no collector, no network);
the dashboard helpers and the /dashboard route are tested in-process via the
starlette TestClient. No API key required.
"""

import asyncio
import json


# ── tracing ──────────────────────────────────────────────────────────────────────

def test_span_noop_by_default():
    import core.tracing as tracing
    # Inactive by default (no OTEL_EXPORTER_OTLP_ENDPOINT) → span yields None.
    with tracing.span("x", foo="bar") as s:
        assert s is None


def test_init_tracing_off_without_endpoint(monkeypatch):
    from config.settings import settings
    import core.tracing as tracing
    monkeypatch.setattr(settings, "otel_exporter_otlp_endpoint", "")
    monkeypatch.setattr(tracing, "_enabled", False)
    assert tracing.init_tracing() is False


def test_span_records_with_inmemory_exporter(monkeypatch):
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    import core.tracing as tracing

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(tracing, "_tracer", provider.get_tracer("test"))
    monkeypatch.setattr(tracing, "_enabled", True)

    with tracing.span("agent.turn", agent="recon", model="claude-opus-4-7") as s:
        assert s is not None

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "agent.turn"
    assert spans[0].attributes["agent"] == "recon"
    assert spans[0].attributes["model"] == "claude-opus-4-7"


# ── dashboard ─────────────────────────────────────────────────────────────────────

def test_event_payload_has_keys():
    from api.server import _event_payload
    p = _event_payload()
    assert set(p) >= {"phase", "telemetry", "findings", "graph", "ts"}


def test_event_stream_emits_one_sse_frame():
    from api.server import _event_stream

    async def collect():
        out = []
        async for chunk in _event_stream(max_iterations=1):
            out.append(chunk)
        return out

    chunks = asyncio.run(collect())
    assert len(chunks) == 1
    assert chunks[0].startswith("data: ")
    assert chunks[0].endswith("\n\n")
    payload = json.loads(chunks[0][len("data: "):].strip())
    assert "telemetry" in payload and "phase" in payload


def test_dashboard_html_wires_eventsource():
    from api.server import _dashboard_html
    html = _dashboard_html()
    assert "EventSource('/events')" in html
    assert "<table" in html


def test_dashboard_route_returns_html():
    from fastapi.testclient import TestClient
    import api.server as server

    client = TestClient(server.app)
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "EventSource" in resp.text
