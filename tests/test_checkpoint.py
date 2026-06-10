"""
Tests for resumable checkpoints (5B) — fully offline.

Checkpoint save/load round-trip, plus the BaseAgent.run resume + per-round
checkpoint hooks (model client mocked, no network).
"""

import asyncio
from types import SimpleNamespace

from core.checkpoint import Checkpoint


def _usage(inp=1, out=1):
    return SimpleNamespace(input_tokens=inp, output_tokens=out,
                           cache_creation_input_tokens=0, cache_read_input_tokens=0)


# ── checkpoint store ─────────────────────────────────────────────────────────────

def test_save_load_roundtrip(tmp_path):
    ck = Checkpoint(base_dir=str(tmp_path))
    msgs = [{"role": "user", "content": "hi"},
            {"role": "assistant", "content": [{"type": "text", "text": "yo"}]}]
    path = ck.save("ENG-1", kb_snapshot={"targets": {}}, mission_state="autonomous",
                   orchestrator_messages=msgs, telemetry={"total": {}},
                   graph_export={"nodes": [], "edges": []},
                   objective="full pentest", targets=["10.0.0.0/24"])
    assert path.exists()
    loaded = ck.load("ENG-1")
    assert loaded["orchestrator_messages"] == msgs
    assert loaded["objective"] == "full pentest"
    assert loaded["targets"] == ["10.0.0.0/24"]
    assert loaded["seq"] == 1


def test_seq_increments_and_loads_latest(tmp_path):
    ck = Checkpoint(base_dir=str(tmp_path))
    for i in range(3):
        ck.save("ENG-2", kb_snapshot={}, mission_state=f"s{i}", orchestrator_messages=[],
                telemetry={}, graph_export={})
    loaded = ck.load("ENG-2")
    assert loaded["seq"] == 3
    assert loaded["mission_state"] == "s2"


def test_list_and_missing(tmp_path):
    ck = Checkpoint(base_dir=str(tmp_path))
    assert ck.load("never-saved") is None
    ck.save("ENG-3", kb_snapshot={}, mission_state="x", orchestrator_messages=[],
            telemetry={}, graph_export={})
    rows = ck.list()
    assert any(r["engagement_id"] == "ENG-3" and r["checkpoints"] == 1 for r in rows)


# ── BaseAgent.run resume + checkpoint hook ───────────────────────────────────────

def test_run_starts_from_resume_messages(monkeypatch):
    from core.base_agent import BaseAgent
    agent = BaseAgent()
    seen = {}

    async def _stream(system, tools, messages):
        seen.setdefault("first", list(messages))
        return SimpleNamespace(usage=_usage(),
                               content=[SimpleNamespace(type="text", text="ok")],
                               stop_reason="end_turn")
    monkeypatch.setattr(agent, "_stream_turn", _stream)

    resume = [
        {"role": "user", "content": "prior task"},
        {"role": "assistant", "content": [{"type": "text", "text": "prior reply"}]},
        {"role": "user", "content": [{"type": "text", "text": "continue"}]},
    ]
    asyncio.run(agent.run("ignored-task", resume_messages=resume))
    assert seen["first"][0]["content"] == "prior task"   # not a fresh first message
    assert len(seen["first"]) == 3


def test_checkpoint_cb_called_each_tool_round(monkeypatch):
    from core.base_agent import BaseAgent
    agent = BaseAgent()
    responses = iter([
        SimpleNamespace(usage=_usage(),
                        content=[SimpleNamespace(type="tool_use", name="x", id="1", input={})],
                        stop_reason="tool_use"),
        SimpleNamespace(usage=_usage(),
                        content=[SimpleNamespace(type="text", text="done")],
                        stop_reason="end_turn"),
    ])

    async def _stream(system, tools, messages):
        return next(responses)

    async def _run_tools(content):
        return [{"type": "tool_result", "tool_use_id": "1", "content": "ok", "is_error": False}]

    monkeypatch.setattr(agent, "_stream_turn", _stream)
    monkeypatch.setattr(agent, "_run_tool_calls", _run_tools)

    saved = []
    out = asyncio.run(agent.run("t", checkpoint_cb=lambda m: saved.append(len(m))))
    assert "done" in out
    assert len(saved) == 1            # exactly one checkpoint per tool round
