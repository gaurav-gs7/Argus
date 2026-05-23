from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class LLMClient(Protocol):
    async def generate(self, prompt: str, temperature: float = 0.1, max_tokens: int = 512) -> str:
        ...


@dataclass
class MockLLMClient:
    async def generate(self, prompt: str, temperature: float = 0.1, max_tokens: int = 512) -> str:
        del temperature, max_tokens
        return (
            "Confirmed facts were prioritized from structured evidence. "
            "The most likely cause appears consistent with the deterministic hypothesis. "
            "Treat this summary as advisory and verify with the linked runbook."
        )
