from __future__ import annotations

import os

from pydantic import BaseModel


class Settings(BaseModel):
    listen_addr: str = os.getenv("ARGUS_AI_ADDR", ":8090")
    llm_backend: str = os.getenv("ARGUS_LLM_BACKEND", "mock")
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash-lite")
    runbook_path: str = os.getenv("ARGUS_RUNBOOK_PATH", "/data/runbooks")
    incidents_path: str = os.getenv(
        "ARGUS_PAST_INCIDENTS_PATH", "/data/incidents/sample-past-incidents.json"
    )
    ai_service_token: str = os.getenv("ARGUS_AI_SERVICE_TOKEN", "argus-ai-local")
    verdikt_url: str = os.getenv("ARGUS_VERDIKT_URL", "http://verdikt:8080")
    verdikt_api_token: str = os.getenv("ARGUS_VERDIKT_API_TOKEN", "argus-verdikt-local")
    verdikt_timeout_seconds: float = float(os.getenv("ARGUS_VERDIKT_TIMEOUT_SECONDS", "3"))
    llm_input_cost_per_million_usd: float = float(
        os.getenv("ARGUS_LLM_INPUT_COST_PER_MILLION_USD", "0")
    )
    llm_output_cost_per_million_usd: float = float(
        os.getenv("ARGUS_LLM_OUTPUT_COST_PER_MILLION_USD", "0")
    )


settings = Settings()
