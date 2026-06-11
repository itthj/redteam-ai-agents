"""
Tests for tool-output compression (5A).

Two layers, both fully offline (the model client is never really called):
  • the compression seam in BaseAgent._run_tool_calls — on / off / under-threshold
    / error-skip;
  • _compress_tool_output itself — success, and graceful fallback to raw output
    on API error or empty summary.
"""

import asyncio
from types import SimpleNamespace

from config.settings import settings
from core.base_agent import _COMPRESS_THRESHOLD, BaseAgent


def _tool_use(name="scan", inputs=None, block_id="t1"):
    return SimpleNamespace(type="tool_use", name=name, input=inputs or {}, id=block_id)


def _run(agent, content):
    results = asyncio.run(agent._run_tool_calls(content))
    return results[0]["content"], results[0]["is_error"]


def _usage(inp=10, out=5):
    return SimpleNamespace(
        input_tokens=inp, output_tokens=out,
        cache_creation_input_tokens=0, cache_read_input_tokens=0,
    )


# ── the compression seam in _run_tool_calls ─────────────────────────────────────

def test_large_output_compressed_when_enabled(monkeypatch):
    monkeypatch.setattr(settings, "compress_tool_output", True)
    agent = BaseAgent()
    big = "x" * (_COMPRESS_THRESHOLD + 1)

    async def _exec(name, inputs):
        return big, False
    monkeypatch.setattr(agent, "_execute_tool", _exec)

    async def _compress(text):
        return "COMPRESSED"
    monkeypatch.setattr(agent, "_compress_tool_output", _compress)

    text, is_error = _run(agent, [_tool_use()])
    assert text == "COMPRESSED"
    assert is_error is False


def test_output_not_compressed_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "compress_tool_output", False)
    agent = BaseAgent()
    big = "x" * (_COMPRESS_THRESHOLD + 1)

    async def _exec(name, inputs):
        return big, False
    monkeypatch.setattr(agent, "_execute_tool", _exec)

    called = {"n": 0}

    async def _compress(text):
        called["n"] += 1
        return "COMPRESSED"
    monkeypatch.setattr(agent, "_compress_tool_output", _compress)

    text, _ = _run(agent, [_tool_use()])
    assert text == big            # passed through untouched
    assert called["n"] == 0       # compression never invoked


def test_small_output_not_compressed(monkeypatch):
    monkeypatch.setattr(settings, "compress_tool_output", True)
    agent = BaseAgent()
    small = "x" * 10

    async def _exec(name, inputs):
        return small, False
    monkeypatch.setattr(agent, "_execute_tool", _exec)

    called = {"n": 0}

    async def _compress(text):
        called["n"] += 1
        return "COMPRESSED"
    monkeypatch.setattr(agent, "_compress_tool_output", _compress)

    text, _ = _run(agent, [_tool_use()])
    assert text == small
    assert called["n"] == 0


def test_errored_output_not_compressed(monkeypatch):
    monkeypatch.setattr(settings, "compress_tool_output", True)
    agent = BaseAgent()
    big = "x" * (_COMPRESS_THRESHOLD + 1)

    async def _exec(name, inputs):
        return big, True          # is_error → never compressed
    monkeypatch.setattr(agent, "_execute_tool", _exec)

    called = {"n": 0}

    async def _compress(text):
        called["n"] += 1
        return "COMPRESSED"
    monkeypatch.setattr(agent, "_compress_tool_output", _compress)

    text, is_error = _run(agent, [_tool_use()])
    assert text == big
    assert is_error is True
    assert called["n"] == 0


# ── _compress_tool_output itself ────────────────────────────────────────────────

def test_compress_returns_summary_on_success():
    agent = BaseAgent()
    big = "x" * (_COMPRESS_THRESHOLD + 1)

    async def _create(**kwargs):
        return SimpleNamespace(
            usage=_usage(),
            content=[SimpleNamespace(type="text", text="port 22 open: OpenSSH 8.2")],
        )
    agent._client = SimpleNamespace(messages=SimpleNamespace(create=_create))

    out = asyncio.run(agent._compress_tool_output(big))
    assert "port 22 open: OpenSSH 8.2" in out
    assert "compressed" in out.lower()
    assert len(out) < len(big)


def test_compress_falls_back_to_raw_on_error():
    agent = BaseAgent()
    raw = "raw tool output that must survive a failure"

    async def _boom(**kwargs):
        raise RuntimeError("api unavailable")
    agent._client = SimpleNamespace(messages=SimpleNamespace(create=_boom))

    out = asyncio.run(agent._compress_tool_output(raw))
    assert out == raw             # graceful degradation — never lose the output


def test_compress_falls_back_when_summary_empty():
    agent = BaseAgent()
    raw = "raw tool output"

    async def _empty(**kwargs):
        return SimpleNamespace(usage=_usage(out=0), content=[])
    agent._client = SimpleNamespace(messages=SimpleNamespace(create=_empty))

    out = asyncio.run(agent._compress_tool_output(raw))
    assert out == raw
