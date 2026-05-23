from __future__ import annotations


def keyword_score(query: str, text: str) -> float:
    query_terms = {term for term in query.lower().split() if term}
    text_terms = set(text.lower().split())
    if not query_terms:
        return 0.0
    overlap = query_terms.intersection(text_terms)
    return len(overlap) / len(query_terms)
