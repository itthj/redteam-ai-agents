"""
core/tracing.py
────────────────
OpenTelemetry tracing for the agent loop (workstream 5C).

Graceful degradation (MCPBridge-style): tracing is **active only** when the
`opentelemetry` SDK is installed AND `settings.otel_exporter_otlp_endpoint` is
set. Otherwise every `span(...)` is a zero-overhead no-op and the engagement is
unaffected. Spans export over OTLP/HTTP to Jaeger/Tempo/Grafana (or any hosted
OTLP sink — Honeycomb, Datadog, …).

Usage:
    from core.tracing import span
    with span("agent.turn", agent="recon", model="claude-opus-4-8"):
        ...
"""

from __future__ import annotations

import logging
from contextlib import contextmanager

from config.settings import settings

log = logging.getLogger(__name__)

try:
    from opentelemetry import trace as _trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    _OTEL_AVAILABLE = True
except ImportError:  # opentelemetry not installed → tracing disabled
    _OTEL_AVAILABLE = False

_enabled = False
_tracer = None


def init_tracing() -> bool:
    """
    Initialise tracing once. Active only when the OTel SDK is installed AND an
    OTLP endpoint is configured. Returns True if tracing is active.

    Safe to call from multiple entry points (idempotent).
    """
    global _enabled, _tracer
    if _enabled:
        return True
    if not _OTEL_AVAILABLE or not settings.otel_exporter_otlp_endpoint:
        return False
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        provider = TracerProvider(
            resource=Resource.create({"service.name": "redteam-agents"})
        )
        provider.add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint)
            )
        )
        _trace.set_tracer_provider(provider)
        _tracer = _trace.get_tracer("redteam")
        _enabled = True
        log.info("[OTEL] tracing active → %s", settings.otel_exporter_otlp_endpoint)
    except Exception as e:  # noqa: BLE001 — missing exporter pkg, bad endpoint, etc.
        log.warning("[OTEL] tracing init failed (%s) — continuing without traces", e)
    return _enabled


@contextmanager
def span(name: str, **attrs):
    """
    Start a span named `name` with the given attributes. A zero-overhead no-op
    when tracing is inactive (yields None so callers can guard attribute sets).
    """
    if not _enabled or _tracer is None:
        yield None
        return
    with _tracer.start_as_current_span(name) as current:
        try:
            for key, value in attrs.items():
                if value is not None:
                    current.set_attribute(key, value)
        except Exception:  # noqa: BLE001 — instrumentation must never break the loop
            pass
        yield current
