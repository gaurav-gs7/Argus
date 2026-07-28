from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class GenerationResult:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0


class LLMClient(Protocol):
    async def generate(
        self,
        prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 512,
    ) -> GenerationResult:
        ...


@dataclass
class MockLLMClient:
    async def generate(
        self,
        prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 512,
    ) -> GenerationResult:
        del temperature, max_tokens
        marker = "DETERMINISTIC_CANDIDATES_JSON="
        if marker in prompt:
            encoded = prompt.split(marker, 1)[1].splitlines()[0]
            candidates = json.loads(encoded)
            proposals = [
                {
                    "action_type": candidate["action_type"],
                    "target": candidate["target"],
                    "rationale": "Matches the deterministic RCA evidence and still requires operator review.",
                    "confidence": 0.8,
                }
                for candidate in candidates[:2]
            ]
            text = json.dumps({"proposals": proposals})
        else:
            text = (
                "Confirmed facts were prioritized from structured evidence. "
                "The most likely cause appears consistent with the deterministic hypothesis. "
                "Treat this summary as advisory and verify with the linked runbook."
            )
        return GenerationResult(
            text=text,
            input_tokens=estimate_tokens(prompt),
            output_tokens=estimate_tokens(text),
        )


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)
