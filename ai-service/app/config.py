from pydantic import BaseModel
import os


class Settings(BaseModel):
    listen_addr: str = os.getenv("ARGUS_AI_ADDR", ":8090")
    llm_backend: str = os.getenv("ARGUS_LLM_BACKEND", "mock")
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash-lite")
    runbook_path: str = os.getenv("ARGUS_RUNBOOK_PATH", "/data/runbooks")
    incidents_path: str = os.getenv("ARGUS_PAST_INCIDENTS_PATH", "/data/incidents/sample-past-incidents.json")


settings = Settings()
