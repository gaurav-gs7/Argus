from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, Field

from app.config import settings
from app.llm.base import MockLLMClient
from app.llm.gemini_client import GeminiClient
from app.llm.ollama_client import OllamaClient
from app.rag.retriever import Retriever
from app.rag.store import Store
from app.rca.prompts import remediation_explain_prompt
from app.rca.summarizer import RCASummarizer
from app.safety.prompt_guard import trim_text


app = FastAPI(title="Argus AI Service", version="0.1.0")
store = Store()
retriever = Retriever(store)


def build_client():
    if settings.llm_backend == "ollama":
        return OllamaClient(settings.ollama_base_url, settings.ollama_model), "ollama", settings.ollama_model
    if settings.llm_backend == "gemini" and settings.gemini_api_key:
        return GeminiClient(settings.gemini_api_key, settings.gemini_model), "gemini", settings.gemini_model
    return MockLLMClient(), "mock", "mock-advisory"


client, backend_name, model_name = build_client()
summarizer = RCASummarizer(client)


class RCASummarizeRequest(BaseModel):
    incident: dict
    primary_hypothesis: str = ""
    evidence: list[str] = Field(default_factory=list)


class RemediationExplainRequest(BaseModel):
    remediation: dict
    incident: dict = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)


class SearchRequest(BaseModel):
    query: str
    limit: int = 5


class ReportRequest(BaseModel):
    incident: dict
    timeline: list[dict] = Field(default_factory=list)
    rca: dict = Field(default_factory=dict)
    remediations: list[dict] = Field(default_factory=list)


@app.on_event("startup")
async def startup() -> None:
    store.index_runbooks(settings.runbook_path)
    store.load_past_incidents(settings.incidents_path)


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "backend": backend_name, "model": model_name}


@app.post("/v1/rca/summarize")
async def summarize_rca(request: RCASummarizeRequest) -> dict:
    runbooks = retriever.runbooks(
        f"{request.incident.get('title', '')} {request.primary_hypothesis}",
        limit=3,
    )
    similar = retriever.similar_incidents(
        f"{request.incident.get('service', '')} {request.primary_hypothesis}",
        limit=2,
    )
    payload = {
        "incident": request.incident,
        "primary_hypothesis": request.primary_hypothesis,
        "evidence": request.evidence,
        "runbook_chunks": runbooks,
        "similar_incidents": similar,
    }
    summary = trim_text(await summarizer.summarize(payload), limit=1500)
    return {
        "summary": summary,
        "backend": backend_name,
        "model": model_name,
        "runbook_matches": runbooks,
        "similar_incidents": similar,
    }


@app.post("/v1/remediation/explain")
async def explain_remediation(request: RemediationExplainRequest) -> dict:
    prompt = remediation_explain_prompt(request.model_dump())
    summary = trim_text(await client.generate(prompt, temperature=0.1, max_tokens=250), limit=1200)
    return {
        "summary": summary,
        "backend": backend_name,
        "model": model_name,
    }


@app.post("/v1/runbooks/index")
async def runbooks_index() -> dict:
    count = store.index_runbooks(settings.runbook_path)
    return {"status": "ok", "indexed_chunks": count}


@app.post("/v1/runbooks/search")
async def runbooks_search(request: SearchRequest) -> dict:
    return {"results": retriever.runbooks(request.query, request.limit)}


@app.post("/v1/incidents/similar")
async def incidents_similar(request: SearchRequest) -> dict:
    return {"results": retriever.similar_incidents(request.query, request.limit)}


@app.post("/v1/report/generate")
async def report_generate(request: ReportRequest) -> dict:
    narrative = (
        f"Incident {request.incident.get('title', 'unknown')} affected "
        f"{request.incident.get('service', 'unknown service')}. "
        f"RCA hypothesis: {request.rca.get('primary_hypothesis', 'insufficient evidence')}."
    )
    return {
        "summary": narrative,
        "incident": request.incident,
        "timeline": request.timeline,
        "rca": request.rca,
        "remediations": request.remediations,
        "backend": backend_name,
        "model": model_name,
    }
