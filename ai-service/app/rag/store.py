from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import json
from typing import Any

from .chunker import chunk_text
from .embeddings import keyword_score


@dataclass
class DocumentChunk:
    source: str
    title: str
    chunk_index: int
    content: str
    metadata: dict[str, Any]


class Store:
    def __init__(self) -> None:
        self.runbook_chunks: list[DocumentChunk] = []
        self.past_incidents: list[dict[str, Any]] = []

    def index_runbooks(self, base_path: str) -> int:
        self.runbook_chunks = []
        runbook_root = Path(base_path)
        if not runbook_root.exists():
            return 0
        for path in sorted(runbook_root.glob("*.md")):
            content = path.read_text(encoding="utf-8")
            for idx, chunk in enumerate(chunk_text(content)):
                self.runbook_chunks.append(
                    DocumentChunk(
                        source="runbook",
                        title=path.stem,
                        chunk_index=idx,
                        content=chunk,
                        metadata={"path": str(path)},
                    )
                )
        return len(self.runbook_chunks)

    def load_past_incidents(self, file_path: str) -> int:
        path = Path(file_path)
        if not path.exists():
            self.past_incidents = []
            return 0
        self.past_incidents = json.loads(path.read_text(encoding="utf-8"))
        return len(self.past_incidents)

    def search_runbooks(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        scored = sorted(
            (
                (keyword_score(query, chunk.title + " " + chunk.content), chunk)
                for chunk in self.runbook_chunks
            ),
            key=lambda item: item[0],
            reverse=True,
        )
        results = [asdict(chunk) | {"score": score} for score, chunk in scored if score > 0]
        return results[:limit]

    def similar_incidents(self, query: str, limit: int = 3) -> list[dict[str, Any]]:
        scored = sorted(
            (
                (
                    keyword_score(query, json.dumps(item)),
                    item,
                )
                for item in self.past_incidents
            ),
            key=lambda item: item[0],
            reverse=True,
        )
        return [item | {"score": score} for score, item in scored if score > 0][:limit]
