"""
core/embeddings.py
───────────────────
Optional semantic-similarity provider for tradecraft recall.

Wraps `sentence-transformers` *if it is installed*; otherwise reports itself
unavailable so callers fall back to keyword matching — the same graceful-
degradation pattern as MCPBridge. Pure in-process cosine similarity: no vector
database, and the only network is the one-time model download that
sentence-transformers performs on first use.

`available()` is cheap (an import check, no model load). The model is loaded
lazily on the first `rank()` call, so importing this module — or merely checking
availability — never triggers a download. The offline test suite therefore runs
untouched on a venv that doesn't have the dependency.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

_DEFAULT_MODEL = "all-MiniLM-L6-v2"
_model = None
_load_failed = False


def available() -> bool:
    """True if the embedding backend can be used (the library is importable)."""
    try:
        import sentence_transformers  # noqa: F401
        return True
    except ImportError:
        return False


def _get_model():
    """Lazily load (and cache) the embedding model. Returns None if unavailable."""
    global _model, _load_failed
    if _model is not None or _load_failed:
        return _model
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        _load_failed = True
        return None
    try:
        from config.settings import settings
        name = getattr(settings, "embedding_model", "") or _DEFAULT_MODEL
        _model = SentenceTransformer(name)
    except Exception as e:  # noqa: BLE001 — model download/load is best-effort
        log.warning("[EMBEDDINGS] could not load model (%s) — keyword fallback", e)
        _load_failed = True
        return None
    return _model


def rank(query: str, candidates: list[str]) -> list[tuple[int, float]]:
    """
    Rank `candidates` by cosine similarity to `query`. Returns [(index, score)]
    sorted high→low, or [] when the backend is unavailable / inputs are empty
    (so the caller falls back to keyword recall).
    """
    if not query or not candidates:
        return []
    model = _get_model()
    if model is None:
        return []
    try:
        import numpy as np
        vectors = model.encode([query, *candidates], normalize_embeddings=True)
        qv, cvs = vectors[0], vectors[1:]
        sims = cvs @ qv
        return [(int(i), float(sims[i])) for i in np.argsort(-sims)]
    except Exception as e:  # noqa: BLE001 — never break recall on an embedding error
        log.warning("[EMBEDDINGS] rank failed (%s) — keyword fallback", e)
        return []
