"""Retrieval over the knowledge base.

BM25 over a tokenised index built in-process. Deliberately dependency-free
(numpy only) so the product runs fully offline with no model download.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from functools import lru_cache

import numpy as np

from .kb_data import all_documents

_TOKEN = re.compile(r"[a-z0-9]+(?:[.\-_/][a-z0-9]+)*")

# Domain vocabulary that must be preserved as single tokens so that
# "T1059.001", "lsass.exe" and "kerberoasting" survive tokenisation.
_KEEP = re.compile(r"(t\d{4}(?:\.\d{3})?|[a-z0-9-]+\.(?:exe|dll|ps1|bat|py|log|json|com|net|io)|cve-\d{4}-\d+)")


def _tokenize(text: str) -> list[str]:
    text = (text or "").lower()
    kept = _KEEP.findall(text)
    rest = _TOKEN.findall(_KEEP.sub(" ", text))
    return kept + rest


def _doc_text(doc: dict) -> str:
    parts = [
        doc.get("id", ""),
        doc.get("title", ""),
        doc.get("tactic", ""),
        doc.get("keywords", ""),
        doc.get("body", ""),
        " ".join(doc.get("triage", []) or []),
        " ".join(doc.get("queries", []) or []),
        " ".join(doc.get("remediation", []) or []),
    ]
    return "\n".join(p for p in parts if p)


class _Index:
    def __init__(self, docs: list[dict], k1: float = 1.5, b: float = 0.75):
        self.docs = docs
        self.k1, self.b = k1, b
        self.terms: list[list[str]] = [_tokenize(_doc_text(d)) for d in docs]
        self.len = np.array([len(t) for t in self.terms], dtype=np.float32)
        self.avg_len = float(self.len.mean()) if len(self.len) else 1.0
        self.tf: list[Counter] = [Counter(t) for t in self.terms]

        df: Counter = Counter()
        for tf in self.tf:
            df.update(tf.keys())
        n = max(len(docs), 1)
        self.idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}
        self.postings: dict[str, list[int]] = {}
        for i, tf in enumerate(self.tf):
            for t in tf:
                self.postings.setdefault(t, []).append(i)

    def search(self, query: str, limit: int, kinds: list[str] | None) -> list[dict]:
        q = _tokenize(query)
        if not q:
            return []
        scores = np.zeros(len(self.docs), dtype=np.float32)
        for term in q:
            post = self.postings.get(term)
            if not post:
                continue
            idf = self.idf.get(term, 0.0)
            for i in post:
                f = self.tf[i][term]
                denom = f + self.k1 * (1 - self.b + self.b * self.len[i] / self.avg_len)
                scores[i] += idf * (f * (self.k1 + 1)) / denom
        if kinds:
            allowed = {k.lower() for k in kinds}
            mask = np.array([d.get("kind", "").lower() in allowed for d in self.docs])
            scores *= mask
        order = np.argsort(-scores)
        out = []
        for i in order[: limit * 4]:
            if scores[i] <= 0:
                break
            d = self.docs[i]
            out.append(
                {
                    "id": d["id"],
                    "kind": d["kind"],
                    "title": d["title"],
                    "score": round(float(scores[i]), 3),
                    "tactic": d.get("tactic", ""),
                    "excerpt": _excerpt(d),
                    "doc": d,
                }
            )
            if len(out) >= limit:
                break
        return out


def _excerpt(doc: dict, width: int = 320) -> str:
    body = re.sub(r"\s+", " ", doc.get("body", "")).strip()
    return body[:width] + ("…" if len(body) > width else "")


@lru_cache(maxsize=1)
def _get_index() -> _Index:
    return _Index(all_documents())


def retrieve(query: str, limit: int = 6, kinds: list[str] | None = None) -> list[dict]:
    """Retrieve knowledge-base documents relevant to a free-text query."""
    return _get_index().search(query, limit, kinds)


def retrieve_for_alert(alert: dict, extracted: dict | None, limit: int = 6) -> list[dict]:
    """Build a query from alert structure plus observed indicators."""
    bits: list[str] = []
    for key in (
        "title",
        "description",
        "rule_name",
        "process_name",
        "command_line",
        "mitre_tactic",
        "mitre_technique",
        "raw_log",
    ):
        v = alert.get(key)
        if v:
            bits.append(str(v))

    # Explicit technique ids are a strong prior — retrieve those directly first.
    tid = alert.get("mitre_technique")
    docs: list[dict] = []
    seen: set[str] = set()
    if tid:
        for d in retrieve(str(tid), limit=2, kinds=["technique"]):
            if d["id"].lower() == str(tid).lower() and d["id"] not in seen:
                docs.append(d)
                seen.add(d["id"])

    for d in retrieve(" ".join(bits), limit=limit * 2):
        if d["id"] not in seen:
            docs.append(d)
            seen.add(d["id"])
        if len(docs) >= limit:
            break

    # Guarantee policy documents are always in context for decision-making.
    for d in retrieve("escalation containment authority handoff", limit=4, kinds=["policy"]):
        if d["id"] not in seen:
            docs.append(d)
            seen.add(d["id"])

    return docs[: limit + 2]


def index_stats() -> dict:
    idx = _get_index()
    by_kind: Counter = Counter(d["kind"] for d in idx.docs)
    return {
        "documents": len(idx.docs),
        "unique_terms": len(idx.idf),
        "by_kind": dict(by_kind),
        "avg_doc_tokens": round(float(idx.avg_len), 1),
    }
