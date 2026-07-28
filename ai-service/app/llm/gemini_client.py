from __future__ import annotations

import httpx

from app.llm.base import GenerationResult


class GeminiClient:
    def __init__(self, api_key: str, model: str) -> None:
        self.api_key = api_key
        self.model = model

    async def generate(
        self,
        prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 512,
    ) -> GenerationResult:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}",
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": temperature,
                        "maxOutputTokens": max_tokens,
                    },
                },
            )
            response.raise_for_status()
            payload = response.json()
            candidates = payload.get("candidates", [])
            parts = candidates[0].get("content", {}).get("parts", []) if candidates else []
            usage = payload.get("usageMetadata", {})
            return GenerationResult(
                text="".join(part.get("text", "") for part in parts),
                input_tokens=int(usage.get("promptTokenCount", 0) or 0),
                output_tokens=int(usage.get("candidatesTokenCount", 0) or 0),
            )
