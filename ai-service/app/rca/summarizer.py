from __future__ import annotations

from app.observability.metrics import ObservedGeneration, ObservedLLM
from app.rca.prompts import summarize_rca_prompt


class RCASummarizer:
    def __init__(self, client: ObservedLLM) -> None:
        self.client = client

    async def summarize(self, payload: dict, confidence_score: float) -> ObservedGeneration:
        prompt = summarize_rca_prompt(payload)
        return await self.client.generate(
            "rca_summary",
            prompt,
            temperature=0.1,
            max_tokens=300,
            confidence_score=confidence_score,
        )
