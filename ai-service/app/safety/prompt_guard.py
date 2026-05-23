from __future__ import annotations


def trim_text(text: str, limit: int = 4000) -> str:
    return text[:limit]
