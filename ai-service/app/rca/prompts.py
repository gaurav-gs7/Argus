from __future__ import annotations

import json


def summarize_rca_prompt(payload: dict) -> str:
    return (
        "You are assisting an incident response system.\n"
        "Use only the structured evidence below.\n"
        "Do not invent evidence.\n"
        "Separate confirmed facts from hypotheses.\n"
        "Keep the answer compact and operational.\n\n"
        f"{json.dumps(payload, indent=2)}"
    )


def remediation_explain_prompt(payload: dict) -> str:
    return (
        "Explain the remediation risk using only the structured context below.\n"
        "Do not suggest unsafe commands.\n\n"
        f"{json.dumps(payload, indent=2)}"
    )
