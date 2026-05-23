from __future__ import annotations

from app.rca.prompts import summarize_rca_prompt


class RCASummarizer:
    def __init__(self, client) -> None:
        self.client = client

    async def summarize(self, payload: dict) -> str:
        prompt = summarize_rca_prompt(payload)
        return await self.client.generate(prompt, temperature=0.1, max_tokens=300)
