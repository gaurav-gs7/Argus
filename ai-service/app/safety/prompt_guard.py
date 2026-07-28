from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any


INJECTION_RULES = {
    "instruction_override": re.compile(
        r"\b(ignore|disregard|forget)\b.{0,80}\b(previous|prior|system|developer|safety)\b.{0,40}\b(instruction|message|rule|policy)s?\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "tool_coercion": re.compile(
        r"\b(you\s+must|must|immediately|without\s+asking)\b.{0,60}\b(call|invoke|execute|run|use)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "secret_exfiltration": re.compile(
        r"\b(exfiltrat|upload|send|transmit)\w*\b.{0,100}\b(secret|credential|token|api[_ -]?key)s?\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "role_reassignment": re.compile(
        r"\byou are now\b|\bact as\b.{0,50}\b(system|administrator|root|developer)\b",
        re.IGNORECASE | re.DOTALL,
    ),
}
INVISIBLE_CONTROL_PATTERN = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")


@dataclass(frozen=True)
class GuardFinding:
    path: str
    rule: str
    evidence_hash: str


@dataclass(frozen=True)
class GuardedPayload:
    value: Any
    findings: list[GuardFinding]


def sanitize_untrusted(value: Any, path: str = "$") -> GuardedPayload:
    findings: list[GuardFinding] = []

    def walk(item: Any, current_path: str) -> Any:
        if isinstance(item, dict):
            return {str(key): walk(child, f"{current_path}.{key}") for key, child in item.items()}
        if isinstance(item, list):
            return [walk(child, f"{current_path}[{index}]") for index, child in enumerate(item)]
        if not isinstance(item, str):
            return item

        text = item[:4000]
        rule = _matching_rule(text)
        if rule is None and not INVISIBLE_CONTROL_PATTERN.search(text):
            return text
        rule = rule or "invisible_unicode_control"
        digest = hashlib.sha256(text.encode(errors="replace")).hexdigest()
        findings.append(GuardFinding(current_path, rule, digest))
        return f"[BLOCKED_UNTRUSTED_CONTENT sha256={digest}]"

    return GuardedPayload(walk(value, path), findings)


def trim_text(text: str, limit: int = 4000) -> str:
    return text[:limit]


def _matching_rule(text: str) -> str | None:
    for name, pattern in INJECTION_RULES.items():
        if pattern.search(text):
            return name
    return None
