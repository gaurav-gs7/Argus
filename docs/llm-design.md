# LLM Design

The LLM is explicitly advisory only.

## Inputs

- incident metadata
- deterministic timeline
- evidence list
- matched runbook chunks
- similar incident summaries

## Outputs

- RCA narrative
- missing evidence suggestions
- remediation explanation
- incident report draft

## Constraints

- no raw unbounded log dumps
- JSON-oriented prompts
- instruct model to separate facts from hypotheses
- deterministic engine remains the source of truth
