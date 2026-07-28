from __future__ import annotations

import json
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.governance.verdikt import GovernanceDecision
from app.observability.metrics import AIMetrics, ObservedGeneration, ObservedLLM
from app.rca.prompts import remediation_suggest_prompt
from app.safety.prompt_guard import trim_text


ActionType = Literal[
    "collect_diagnostics",
    "restart_service",
    "rollback_config",
    "reload_nginx",
    "clear_redis_keyspace",
    "drain_postgres_connections",
    "revert_feature_flag",
]


class DeterministicCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: ActionType
    target: str = Field(min_length=1, max_length=160)
    risk: Literal["low", "medium"]
    requires_approval: bool


class ModelProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: ActionType
    target: str = Field(min_length=1, max_length=160)
    rationale: str = Field(min_length=1, max_length=800)
    confidence: float = Field(ge=0.0, le=1.0)


class ModelEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposals: list[ModelProposal] = Field(max_length=3)


class GovernanceClient(Protocol):
    async def evaluate_proposal(self, arguments: dict[str, Any]) -> GovernanceDecision:
        ...


class RemediationAdvisor:
    def __init__(
        self,
        llm: ObservedLLM,
        governance: GovernanceClient,
        metrics: AIMetrics,
    ) -> None:
        self.llm = llm
        self.governance = governance
        self.metrics = metrics

    async def suggest(
        self,
        incident: dict[str, Any],
        evidence: list[str],
        candidates: list[DeterministicCandidate],
        confidence_score: float,
    ) -> dict[str, Any]:
        candidate_payload = [candidate.model_dump() for candidate in candidates]
        generation = await self.llm.generate(
            "remediation_suggestion",
            remediation_suggest_prompt(
                {"incident": incident, "evidence": evidence}, candidate_payload
            ),
            temperature=0.0,
            max_tokens=400,
            confidence_score=confidence_score,
        )
        try:
            envelope = ModelEnvelope.model_validate(json.loads(generation.text))
        except (json.JSONDecodeError, ValidationError):
            return self._response(generation, [], [], "invalid_model_output")

        authoritative = {
            (candidate.action_type, candidate.target): candidate for candidate in candidates
        }
        allowed: list[dict[str, Any]] = []
        denied: list[dict[str, Any]] = []
        for proposal in envelope.proposals:
            candidate = authoritative.get((proposal.action_type, proposal.target))
            if candidate is None:
                denied.append(
                    {
                        "action_type": proposal.action_type,
                        "target": proposal.target,
                        "rule": "not_deterministic_candidate",
                        "reason": "Model output did not match the deterministic RCA candidate set",
                    }
                )
                self.metrics.governance.labels("denied", "not_deterministic_candidate").inc()
                continue
            decision = await self.governance.evaluate_proposal(
                {
                    "actor": "argus-ai-service",
                    "incident_id": str(incident.get("id", "unknown")),
                    "environment": str(incident.get("environment", "local")),
                    "action_type": candidate.action_type,
                    "target": candidate.target,
                    "risk": candidate.risk,
                    "dry_run": True,
                    "advisory_only": True,
                }
            )
            outcome = "allowed" if decision.allowed else "denied"
            self.metrics.governance.labels(outcome, decision.rule).inc()
            item = {
                "action_type": candidate.action_type,
                "target": candidate.target,
                "risk": candidate.risk,
                "requires_approval": candidate.requires_approval,
                "rationale": trim_text(proposal.rationale, 800),
                "confidence": proposal.confidence,
                "verdikt": {
                    "allowed": decision.allowed,
                    "rule": decision.rule,
                    "reason": decision.reason,
                    "action": decision.action,
                    "correlation_id": decision.correlation_id,
                    "executed": decision.executed,
                },
            }
            (allowed if decision.allowed else denied).append(item)
        return self._response(generation, allowed, denied, "governed")

    @staticmethod
    def _response(
        generation: ObservedGeneration,
        suggestions: list[dict[str, Any]],
        denied: list[dict[str, Any]],
        status: str,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "advisory_only": True,
            "executed": False,
            "suggestions": suggestions,
            "denied": denied,
            "usage": {
                "input_tokens": generation.input_tokens,
                "output_tokens": generation.output_tokens,
                "estimated_cost_usd": generation.estimated_cost_usd,
                "latency_seconds": generation.latency_seconds,
                "confidence_score": generation.confidence_score,
            },
        }
