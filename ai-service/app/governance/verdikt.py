from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


class GovernanceUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class GovernanceDecision:
    allowed: bool
    rule: str
    reason: str
    action: str
    correlation_id: str
    executed: bool


class VerdiktClient:
    def __init__(
        self,
        base_url: str,
        api_token: str,
        timeout_seconds: float = 3.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout_seconds = timeout_seconds
        self.transport = transport

    async def evaluate_proposal(self, arguments: dict[str, Any]) -> GovernanceDecision:
        headers = {"Authorization": f"Bearer {self.api_token}"}
        body = {
            "server": "argus-ai",
            "tool": "argus.propose_remediation",
            "arguments": arguments,
        }
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                transport=self.transport,
            ) as client:
                response = await client.post(
                    f"{self.base_url}/api/evaluate",
                    json=body,
                    headers=headers,
                )
        except httpx.HTTPError as exc:
            raise GovernanceUnavailable("Verdikt is unavailable; proposal denied") from exc
        if response.status_code not in {200, 403}:
            raise GovernanceUnavailable(
                f"Verdikt returned unexpected status {response.status_code}; proposal denied"
            )
        try:
            payload = response.json()
            executed = bool(payload.get("result", {}).get("executed", True))
            decision = GovernanceDecision(
                allowed=bool(payload["allowed"]),
                rule=str(payload.get("rule", "unknown")),
                reason=str(payload.get("reason", "policy decision")),
                action=str(payload.get("action", "DENY")),
                correlation_id=str(payload.get("correlation_id", "")),
                executed=executed,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GovernanceUnavailable("Verdikt returned an invalid decision; proposal denied") from exc
        if executed or (decision.allowed and decision.action != "PROPOSE_ONLY"):
            raise GovernanceUnavailable(
                "Verdikt violated the proposal-only contract; proposal denied"
            )
        return decision
