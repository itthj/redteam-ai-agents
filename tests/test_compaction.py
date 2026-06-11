"""
Tests for opt-in context compaction (tool-result clearing) in BaseAgent.
Fully offline — operates on a crafted message list, no model call. Verifies that
old, large tool output is cleared while recent turns, the first message (task/KB),
and all message structure (tool_use/tool_result pairing) are preserved.
"""

from types import SimpleNamespace

from config.settings import settings
from core.base_agent import _CLEARED_PREFIX, BaseAgent, _history_chars


def _tool_result(text, tid="t"):
    return {"role": "user",
            "content": [{"type": "tool_result", "tool_use_id": tid, "content": text, "is_error": False}]}


def _assistant(text):
    return {"role": "assistant", "content": [SimpleNamespace(type="text", text=text)]}


def _build():
    msgs = [{"role": "user", "content": "FIRST MESSAGE: task + volatile KB"}]   # idx 0
    msgs.append(_tool_result("OLD" + "A" * 5000, "old"))                        # idx 1 (old)
    msgs += [_assistant(f"turn {i}") for i in range(6)]                         # idx 2..7
    msgs.append(_tool_result("RECENT" + "B" * 5000, "recent"))                 # idx 8 (recent)
    return msgs


def test_history_chars_counts_content():
    msgs = [{"role": "user", "content": "hello"}, _tool_result("x" * 100)]
    assert _history_chars(msgs) >= 105


def test_compaction_clears_old_keeps_recent(monkeypatch):
    monkeypatch.setattr(settings, "compact_after_chars", 1000)
    agent = BaseAgent()
    msgs = _build()

    saved = agent._maybe_compact_history(msgs)

    assert saved > 0
    old_block = msgs[1]["content"][0]
    recent_block = msgs[8]["content"][0]
    assert old_block["content"].startswith(_CLEARED_PREFIX)        # old cleared
    assert old_block["type"] == "tool_result"                     # structure intact
    assert recent_block["content"] == "RECENT" + "B" * 5000        # recent untouched
    assert msgs[0]["content"] == "FIRST MESSAGE: task + volatile KB"  # first msg preserved


def test_no_compaction_under_threshold(monkeypatch):
    monkeypatch.setattr(settings, "compact_after_chars", 10_000_000)
    agent = BaseAgent()
    msgs = _build()

    assert agent._maybe_compact_history(msgs) == 0
    assert msgs[1]["content"][0]["content"].startswith("OLD")     # unchanged


def test_compaction_is_idempotent(monkeypatch):
    monkeypatch.setattr(settings, "compact_after_chars", 1000)
    agent = BaseAgent()
    msgs = _build()

    agent._maybe_compact_history(msgs)
    assert agent._maybe_compact_history(msgs) == 0                 # nothing left to clear
