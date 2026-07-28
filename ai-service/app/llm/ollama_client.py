from __future__ import annotations

import httpx

from app.llm.base import GenerationResult


class OllamaClient:
    def __init__(self, base_url: str, model: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model

    async def generate(
        self,
        prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 512,
    ) -> GenerationResult:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": temperature, "num_predict": max_tokens},
                },
            )
            response.raise_for_status()
            payload = response.json()
            return GenerationResult(
                text=payload.get("response", ""),
                input_tokens=int(payload.get("prompt_eval_count", 0) or 0),
                output_tokens=int(payload.get("eval_count", 0) or 0),
            )
