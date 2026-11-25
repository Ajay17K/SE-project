from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, List, Set, Tuple

from backend.app.models import CitationRecord, KnowledgeItem


STOPWORDS: Set[str] = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "he",
    "in", "is", "it", "its", "of", "on", "or", "that", "the", "to", "was", "were",
    "will", "with", "shall", "must", "should", "may", "system", "requirements",
}

SYNONYM_EXPANSIONS: Dict[str, List[str]] = {
    "mfa": ["afa", "authentication", "step-up", "otp", "biometric"],
    "afa": ["mfa", "authentication", "step-up"],
    "upi": ["npci", "vpa", "rrn", "udir", "cooling", "p2p", "p2m"],
    "card": ["pci", "coft", "tokenization", "pan", "cvv", "hsm"],
    "fraud": ["ews", "scbmf", "fmr", "mule", "velocity", "scoring", "anomaly"],
    "mule": ["fan-in", "fan-out", "ews", "str", "pmla"],
    "privacy": ["dpdp", "consent", "erasure", "fiduciary", "breach"],
    "retention": ["pmla", "cert-in", "180", "5", "years", "localization", "india"],
    "incident": ["cert-in", "6", "hours", "breach", "siem", "ntp"],
    "latency": ["ms", "sla", "timeout", "tps", "p99", "idempotent"],
    "dispute": ["udir", "chargeback", "reconciliation", "settlement"],
    "sdlc": ["waterfall", "agile", "devsecops", "v-model", "spiral", "hybrid"],
}


def tokenize(text: str) -> List[str]:
    raw = re.findall(r"[a-z0-9\-]+", text.lower())
    tokens: List[str] = []
    for tok in raw:
        if len(tok) > 1 and tok not in STOPWORDS:
            tokens.append(tok)
    return tokens


def expand_query_tokens(tokens: List[str]) -> List[str]:
    expanded = list(tokens)
    for tok in tokens:
        if tok in SYNONYM_EXPANSIONS:
            expanded.extend(SYNONYM_EXPANSIONS[tok])
    return expanded


class HybridKBRetriever:
    """
    Hybrid BM25 + TF-IDF cosine vector retriever strictly enforcing allowlisted KB items.
    Zero external vector server required; deterministic and auditable.
    """

    def __init__(self, items: List[KnowledgeItem]):
        # Enforce allowlist: only approved=True items can enter the retrieval index
        self.items: List[KnowledgeItem] = [item for item in items if item.approved]
        self.item_map: Dict[str, KnowledgeItem] = {item.kb_id: item for item in self.items}
        self._doc_tokens: List[List[str]] = []
        self._doc_tf: List[Counter[str]] = []
        self._df: Counter[str] = Counter()
        self._idf: Dict[str, float] = {}
        self._doc_vecs: List[Dict[str, float]] = []
        self._doc_norms: List[float] = []
        self._avg_dl: float = 1.0
        self._build_index()

    def _build_index(self) -> None:
        if not self.items:
            return
        total_len = 0
        for item in self.items:
            full_text = " ".join(
                [
                    item.kb_id,
                    item.title,
                    item.category,
                    item.source,
                    " ".join(item.applicability),
                    " ".join(item.mandatory_controls),
                    item.content,
                ]
            )
            toks = tokenize(full_text)
            self._doc_tokens.append(toks)
            tf = Counter(toks)
            self._doc_tf.append(tf)
            total_len += len(toks)
            for term in tf:
                self._df[term] += 1

        n_docs = len(self.items)
        self._avg_dl = max(1.0, total_len / n_docs)
        for term, df in self._df.items():
            self._idf[term] = math.log((n_docs + 1.0) / (df + 0.5)) + 1.0

        for tf in self._doc_tf:
            vec: Dict[str, float] = {}
            norm_sq = 0.0
            for term, count in tf.items():
                w = (1.0 + math.log(count)) * self._idf.get(term, 1.0)
                vec[term] = w
                norm_sq += w * w
            self._doc_vecs.append(vec)
            self._doc_norms.append(math.sqrt(norm_sq) or 1.0)

    def retrieve(self, query: str, top_k: int = 4, min_score: float = 0.08) -> List[CitationRecord]:
        if not self.items:
            return []
        q_tokens = expand_query_tokens(tokenize(query))
        if not q_tokens:
            return []

        q_tf = Counter(q_tokens)
        q_vec: Dict[str, float] = {}
        q_norm_sq = 0.0
        for term, count in q_tf.items():
            if term in self._idf:
                w = (1.0 + math.log(count)) * self._idf[term]
                q_vec[term] = w
                q_norm_sq += w * w
        q_norm = math.sqrt(q_norm_sq) or 1.0

        scored: List[Tuple[int, float]] = []
        k1 = 1.5
        b = 0.75
        n_docs = len(self.items)

        for idx, item in enumerate(self.items):
            # Cosine TF-IDF similarity
            d_vec = self._doc_vecs[idx]
            dot = sum(q_w * d_vec.get(term, 0.0) for term, q_w in q_vec.items())
            cos_sim = dot / (q_norm * self._doc_norms[idx])

            # BM25 normalized score
            dl = max(1, len(self._doc_tokens[idx]))
            bm25 = 0.0
            d_tf = self._doc_tf[idx]
            for term in set(q_tokens):
                f = d_tf.get(term, 0)
                if f > 0:
                    idf = math.log(1.0 + (n_docs - self._df[term] + 0.5) / (self._df[term] + 0.5))
                    bm25 += idf * ((f * (k1 + 1.0)) / (f + k1 * (1.0 - b + b * (dl / self._avg_dl))))
            bm25_norm = min(1.0, bm25 / 12.0)

            hybrid = round(0.55 * cos_sim + 0.45 * bm25_norm, 4)
            if hybrid >= min_score:
                scored.append((idx, hybrid))

        scored.sort(key=lambda pair: pair[1], reverse=True)
        results: List[CitationRecord] = []
        for idx, score in scored[:top_k]:
            item = self.items[idx]
            results.append(
                CitationRecord(
                    kb_id=item.kb_id,
                    title=item.title,
                    source=item.source,
                    jurisdiction=item.jurisdiction,
                    version=item.version,
                    effective_date=item.effective_date,
                    similarity_score=min(0.99, round(score, 3)),
                    verified=True,
                    excerpt=item.content[:220] + ("..." if len(item.content) > 220 else ""),
                )
            )
        return results

    def verify_citations(self, kb_ids: List[str]) -> Tuple[List[str], List[str]]:
        """Separates allowlisted verified KB IDs from unverified/hallucinated IDs."""
        valid: List[str] = []
        hallucinated: List[str] = []
        for kid in kb_ids:
            if kid in self.item_map:
                valid.append(kid)
            else:
                hallucinated.append(kid)
        return valid, hallucinated
