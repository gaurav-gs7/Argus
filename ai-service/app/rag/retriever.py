from __future__ import annotations

from .store import Store


class Retriever:
    def __init__(self, store: Store) -> None:
        self.store = store

    def runbooks(self, query: str, limit: int = 5) -> list[dict]:
        return self.store.search_runbooks(query, limit=limit)

    def similar_incidents(self, query: str, limit: int = 3) -> list[dict]:
        return self.store.similar_incidents(query, limit=limit)
