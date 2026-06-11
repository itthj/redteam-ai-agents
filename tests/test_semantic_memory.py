"""
Tests for opt-in semantic tradecraft recall. Fully offline — the embedding backend
is monkeypatched, so these pass whether or not sentence-transformers is installed
(and the offline CI venv deliberately does not install it).
"""

import core.embeddings as emb
from config.settings import settings
from core.memory import Lesson, TradecraftMemory


def _mem(tmp_path):
    return TradecraftMemory(store_path=str(tmp_path / "tc.jsonl"))


def test_embeddings_available_returns_bool():
    assert isinstance(emb.available(), bool)


def test_embeddings_rank_empty_inputs():
    assert emb.rank("q", []) == []
    assert emb.rank("", ["a"]) == []


def test_keyword_recall_when_semantic_off(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "memory_semantic_recall", False)
    m = _mem(tmp_path)
    m.store([Lesson("vsftpd 2.3.4 ftp", "exploit backdoor", "T1190", "root", "linux ftp")])
    out = m.recall("vsftpd ftp service", k=3)
    assert len(out) == 1 and out[0].technique_id == "T1190"


def test_semantic_recall_orders_by_embedding(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "memory_semantic_recall", True)
    m = _mem(tmp_path)
    m.store([
        Lesson("apache struts rce", "exploit", "T1190", "shell", "web"),
        Lesson("smb eternalblue", "exploit", "T1210", "system", "windows"),
    ])
    # backend "available": rank prefers index 1 (the smb lesson) regardless of keywords
    monkeypatch.setattr(emb, "rank", lambda q, cands: [(1, 0.91), (0, 0.10)])
    out = m.recall("anything at all", k=1)
    assert out[0].technique_id == "T1210"


def test_semantic_falls_back_to_keyword_when_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "memory_semantic_recall", True)
    m = _mem(tmp_path)
    m.store([Lesson("vsftpd ftp", "exploit", "T1190", "root", "ftp")])
    monkeypatch.setattr(emb, "rank", lambda q, cands: [])    # backend unavailable
    out = m.recall("vsftpd ftp", k=3)
    assert len(out) == 1 and out[0].technique_id == "T1190"
