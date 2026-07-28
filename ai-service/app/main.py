from __future__ import annotations

import secrets

from fastapi import FastAPI, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field
from prometheus_client import CONTENT_TYPE_LATEST

from app.config import settings
from app.governance.verdikt import GovernanceUnavailable, VerdiktClient
from app.llm.base import MockLLMClient
from app.llm.gemini_client import GeminiClient
from app.llm.ollama_client import OllamaClient
from app.observability.metrics import AIMetrics, ObservedLLM
from app.rag.retriever import Retriever
from app.rag.store import Store
from app.rca.prompts import remediation_explain_prompt
from app.rca.summarizer import RCASummarizer
from app.remediation.advisor import DeterministicCandidate, RemediationAdvisor
from app.safety.prompt_guard import sanitize_untrusted, trim_text


app = FastAPI(title="Argus AI Service", version="0.2.0")
store = Store()
retriever = Retriever(store)
metrics = AIMetrics()


def build_client():
    if settings.llm_backend == "ollama":
        return OllamaClient(settings.ollama_base_url, settings.ollama_model), "ollama", settings.ollama_model
    if settings.llm_backend == "gemini" and settings.gemini_api_key:
        return GeminiClient(settings.gemini_api_key, settings.gemini_model), "gemini", settings.gemini_model
    return MockLLMClient(), "mock", "mock-advisory"


raw_client, backend_name, model_name = build_client()
client = ObservedLLM(
    raw_client,
    metrics,
    backend_name,
    model_name,
    settings.llm_input_cost_per_million_usd,
    settings.llm_output_cost_per_million_usd,
)
summarizer = RCASummarizer(client)
governance = VerdiktClient(
    settings.verdikt_url,
    settings.verdikt_api_token,
    settings.verdikt_timeout_seconds,
)
remediation_advisor = RemediationAdvisor(client, governance, metrics)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RCASummarizeRequest(StrictModel):
    incident: dict
    primary_hypothesis: str = ""
    evidence: list[str] = Field(default_factory=list, max_length=200)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class RemediationExplainRequest(StrictModel):
    remediation: dict
    incident: dict = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list, max_length=200)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class RemediationSuggestRequest(StrictModel):
    incident: dict
    evidence: list[str] = Field(default_factory=list, max_length=200)
    deterministic_candidates: list[DeterministicCandidate] = Field(max_length=8)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class SearchRequest(StrictModel):
    query: str
    limit: int = Field(default=5, ge=1, le=20)


class ReportRequest(StrictModel):
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
    return {
        "status": "ok",
        "backend": backend_name,
        "model": model_name,
        "governance": "verdikt",
    }


@app.get("/metrics")
async def prometheus_metrics() -> Response:
    return Response(content=metrics.render(), media_type=CONTENT_TYPE_LATEST)


def require_internal_token(authorization: str | None) -> None:
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(
        supplied, settings.ai_service_token
    ):
        raise HTTPException(status_code=401, detail="valid Argus service token required")


def guard(value, surface: str):
    guarded = sanitize_untrusted(value)
    for finding in guarded.findings:
        metrics.injection_blocks.labels(surface, finding.rule).inc()
    return guarded.value


@app.post("/v1/rca/summarize")
async def summarize_rca(request: RCASummarizeRequest) -> dict:
    incident = guard(request.incident, "rca")
    evidence = guard(request.evidence, "rca")
    hypothesis = guard(request.primary_hypothesis, "rca")
    runbooks = retriever.runbooks(
        f"{incident.get('title', '')} {hypothesis}",
        limit=3,
    )
    similar = retriever.similar_incidents(
        f"{incident.get('service', '')} {hypothesis}",
        limit=2,
    )
    payload = {
        "incident": incident,
        "primary_hypothesis": hypothesis,
        "evidence": evidence,
        "runbook_chunks": runbooks,
        "similar_incidents": similar,
    }
    result = await summarizer.summarize(payload, request.confidence)
    return {
        "summary": trim_text(result.text, limit=1500),
        "backend": backend_name,
        "model": model_name,
        "confidence_score": result.confidence_score,
        "usage": {
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "estimated_cost_usd": result.estimated_cost_usd,
            "latency_seconds": result.latency_seconds,
        },
        "runbook_matches": runbooks,
        "similar_incidents": similar,
    }


@app.post("/v1/remediation/explain")
async def explain_remediation(request: RemediationExplainRequest) -> dict:
    payload = guard(request.model_dump(), "remediation_explanation")
    result = await client.generate(
        "remediation_explanation",
        remediation_explain_prompt(payload),
        temperature=0.1,
        max_tokens=250,
        confidence_score=request.confidence,
    )
    return {
        "summary": trim_text(result.text, limit=1200),
        "backend": backend_name,
        "model": model_name,
        "confidence_score": result.confidence_score,
        "usage": {
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "estimated_cost_usd": result.estimated_cost_usd,
            "latency_seconds": result.latency_seconds,
        },
    }


@app.post("/v1/remediation/suggest")
async def suggest_remediation(
    request: RemediationSuggestRequest,
    authorization: str | None = Header(default=None),
) -> dict:
    require_internal_token(authorization)
    incident = guard(request.incident, "remediation_suggestion")
    evidence = guard(request.evidence, "remediation_suggestion")
    try:
        return await remediation_advisor.suggest(
            incident,
            evidence,
            request.deterministic_candidates,
            request.confidence,
        )
    except GovernanceUnavailable as exc:
        metrics.governance.labels("unavailable", "fail_closed").inc()
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/v1/runbooks/index")
async def runbooks_index() -> dict:
    count = store.index_runbooks(settings.runbook_path)
    return {"status": "ok", "indexed_chunks": count}


@app.post("/v1/runbooks/search")
async def runbooks_search(request: SearchRequest) -> dict:
    query = guard(request.query, "runbook_search")
    return {"results": retriever.runbooks(query, request.limit)}


@app.post("/v1/incidents/similar")
async def incidents_similar(request: SearchRequest) -> dict:
    query = guard(request.query, "incident_search")
    return {"results": retriever.similar_incidents(query, request.limit)}


@app.post("/v1/report/generate")
async def report_generate(request: ReportRequest) -> dict:
    incident = guard(request.incident, "report")
    narrative = (
        f"Incident {incident.get('title', 'unknown')} affected "
        f"{incident.get('service', 'unknown service')}. "
        f"RCA hypothesis: {request.rca.get('primary_hypothesis', 'insufficient evidence')}."
    )
    return {
        "summary": narrative,
        "incident": incident,
        "timeline": guard(request.timeline, "report"),
        "rca": guard(request.rca, "report"),
        "remediations": guard(request.remediations, "report"),
        "backend": backend_name,
        "model": model_name,
    }
