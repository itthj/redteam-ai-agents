"""
Tests for cross-engagement tradecraft memory (2C) — fully offline.

Store/recall on the JSONL backend, redaction, distillation (fast model mocked),
the recall_tradecraft planner tool, and first-message injection.
"""

import asyncio

from config.settings import settings
from core.memory import Lesson, TradecraftMemory

# ── store / recall ───────────────────────────────────────────────────────────────

def test_store_recall_roundtrip(tmp_path):
    mem = TradecraftMemory(store_path=str(tmp_path / "t.jsonl"))
    mem.store([Lesson("vsftpd 2.3.4 ftp", "cve-2011-2523 backdoor", "T1190", "root", "ftp")])
    hits = mem.recall("we found vsftpd on the ftp port", k=3)
    assert hits and "vsftpd" in hits[0].situation


def test_recall_ranks_relevant_first(tmp_path):
    mem = TradecraftMemory(store_path=str(tmp_path / "t.jsonl"))
    mem.store([
        Lesson("apache tomcat manager", "deploy war", "T1190", "rce", "http tomcat"),
        Lesson("smb eternalblue", "ms17 010", "T1210", "system", "windows smb"),
    ])
    hits = mem.recall("target runs smb and looks like windows", k=2)
    assert hits[0].technique_id == "T1210"


def test_recall_empty_when_no_match(tmp_path):
    mem = TradecraftMemory(store_path=str(tmp_path / "t.jsonl"))
    mem.store([Lesson("smb eternalblue", "ms17 010", "T1210", "system", "windows smb")])
    assert mem.recall("zzzzz qqqqq wwwww", k=3) == []


def test_store_redacts_secrets_and_ips(tmp_path):
    mem = TradecraftMemory(store_path=str(tmp_path / "t.jsonl"))
    mem.store([Lesson("host 10.0.0.5 had password=Secret123", "logged in",
                      "T1078", "access", "ssh")])
    raw = (tmp_path / "t.jsonl").read_text(encoding="utf-8")
    assert "10.0.0.5" not in raw
    assert "Secret123" not in raw
    assert "redacted" in raw.lower()


# ── distillation (fast model mocked) ─────────────────────────────────────────────

def test_distill_parses_lessons(monkeypatch, tmp_path):
    import core.memory as mem_mod
    monkeypatch.setattr(
        mem_mod, "_summarize",
        lambda prompt, model: 'noise [{"situation":"smb 445","action":"eternalblue",'
                              '"technique_id":"T1210","outcome":"shell",'
                              '"target_profile":"windows smb"}] trailing',
    )
    mem = TradecraftMemory(store_path=str(tmp_path / "t.jsonl"))
    lessons = mem.distill("ENG", {"targets": {}})
    assert len(lessons) == 1
    assert lessons[0].technique_id == "T1210"


# ── planner tool + first-message injection ───────────────────────────────────────

def test_recall_tradecraft_tool(monkeypatch, tmp_path):
    import core.orchestrator as orch_mod
    from core.orchestrator import OrchestratorAgent

    mem = TradecraftMemory(store_path=str(tmp_path / "t.jsonl"))
    mem.store([Lesson("vsftpd 2.3.4 on ftp", "CVE-2011-2523 backdoor via exploit",
                      "T1190", "root shell", "ftp")])
    monkeypatch.setattr(orch_mod, "memory", mem)
    monkeypatch.setattr(settings, "enable_tradecraft_memory", True)

    result = OrchestratorAgent(get_agent=lambda n: None)._recall_tradecraft("found vsftpd ftp")
    assert result["enabled"] is True
    assert any("vsftpd" in lesson["situation"] for lesson in result["lessons"])


def test_recall_tradecraft_tool_off_by_default(monkeypatch):
    from core.orchestrator import OrchestratorAgent
    monkeypatch.setattr(settings, "enable_tradecraft_memory", False)
    result = OrchestratorAgent(get_agent=lambda n: None)._recall_tradecraft("anything")
    assert result == {"enabled": False, "lessons": []}


def test_preamble_injected_into_autonomous_first_message(monkeypatch):
    from core.orchestrator import Orchestrator, OrchestratorAgent
    from core.telemetry import telemetry

    telemetry.reset()
    captured = {}

    async def fake_run(self, task, context=None, resume_messages=None, checkpoint_cb=None):
        captured["task"] = task
        return "done"

    monkeypatch.setattr(OrchestratorAgent, "run", fake_run)
    monkeypatch.setattr(Orchestrator, "_tradecraft_preamble",
                        lambda self, objective, targets: "LESSON-PREAMBLE-XYZ\n\n")

    orch = Orchestrator()
    asyncio.run(orch.run_autonomous("pentest the lab", ["10.0.0.0/24"]))
    assert captured["task"].startswith("LESSON-PREAMBLE-XYZ")
    assert "Objective: pentest the lab" in captured["task"]
