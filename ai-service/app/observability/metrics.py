from __future__ import annotations

import time
from dataclasses import dataclass

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest

from app.llm.base import GenerationResult, LLMClient, estimate_tokens


class AIMetrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        labels = ["operation", "backend", "model"]
        self.calls = Counter(
            "argus_ai_advisory_calls_total",
            "Advisory LLM calls by operation and outcome.",
            labels + ["outcome"],
            registry=self.registry,
        )
        self.latency = Histogram(
            "argus_ai_advisory_latency_seconds",
            "Advisory LLM latency.",
            labels,
            registry=self.registry,
        )
        self.tokens = Counter(
            "argus_ai_tokens_total",
            "Tokens consumed by advisory LLM calls.",
            labels + ["direction"],
            registry=self.registry,
        )
        self.estimated_cost = Counter(
            "argus_ai_estimated_cost_usd_total",
            "Configured estimated cost of advisory LLM calls in USD.",
            labels,
            registry=self.registry,
        )
        self.confidence = Histogram(
            "argus_ai_advisory_confidence_score",
            "Deterministic confidence supplied to each advisory call.",
            labels,
            buckets=(0.0, 0.25, 0.5, 0.7, 0.8, 0.9, 0.95, 1.0),
            registry=self.registry,
        )
        self.governance = Counter(
            "argus_ai_governance_decisions_total",
            "Verdikt decisions for AI remediation proposals.",
            ["decision", "rule"],
            registry=self.registry,
        )
        self.injection_blocks = Counter(
            "argus_ai_prompt_injection_blocks_total",
            "Untrusted prompt-injection payloads removed before advisory calls.",
            ["surface", "rule"],
            registry=self.registry,
        )

    def render(self) -> bytes:
        return generate_latest(self.registry)


@dataclass(frozen=True)
class ObservedGeneration:
    text: str
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: float
    latency_seconds: float
    confidence_score: float


class ObservedLLM:
    def __init__(
        self,
        client: LLMClient,
        metrics: AIMetrics,
        backend: str,
        model: str,
        input_cost_per_million_usd: float = 0.0,
        output_cost_per_million_usd: float = 0.0,
    ) -> None:
        self.client = client
        self.metrics = metrics
        self.backend = backend
        self.model = model
        self.input_cost = max(0.0, input_cost_per_million_usd)
        self.output_cost = max(0.0, output_cost_per_million_usd)

    async def generate(
        self,
        operation: str,
        prompt: str,
        *,
        temperature: float,
        max_tokens: int,
        confidence_score: float,
    ) -> ObservedGeneration:
        labels = (operation, self.backend, self.model)
        confidence = min(1.0, max(0.0, confidence_score))
        started = time.perf_counter()
        try:
            result: GenerationResult = await self.client.generate(prompt, temperature, max_tokens)
        except Exception:
            elapsed = time.perf_counter() - started
            self.metrics.calls.labels(*labels, "failed").inc()
            self.metrics.latency.labels(*labels).observe(elapsed)
            self.metrics.confidence.labels(*labels).observe(confidence)
            raise

        elapsed = time.perf_counter() - started
        input_tokens = result.input_tokens or estimate_tokens(prompt)
        output_tokens = result.output_tokens or estimate_tokens(result.text)
        estimated_cost = (
            input_tokens * self.input_cost + output_tokens * self.output_cost
        ) / 1_000_000
        self.metrics.calls.labels(*labels, "succeeded").inc()
        self.metrics.latency.labels(*labels).observe(elapsed)
        self.metrics.tokens.labels(*labels, "input").inc(input_tokens)
        self.metrics.tokens.labels(*labels, "output").inc(output_tokens)
        self.metrics.estimated_cost.labels(*labels).inc(estimated_cost)
        self.metrics.confidence.labels(*labels).observe(confidence)
        return ObservedGeneration(
            text=result.text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost_usd=estimated_cost,
            latency_seconds=elapsed,
            confidence_score=confidence,
        )
