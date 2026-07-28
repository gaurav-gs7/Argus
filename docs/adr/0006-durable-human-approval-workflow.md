# ADR 0006: Durable Human Approval Workflow

## Status

Accepted.

## Context

A policy result such as `requires_approval=true` is not evidence that a human reviewed an action. Regulated production environments need a durable record of what was reviewed, who decided, why they decided, and whether the request expired or escalated.

## Decision

Argus stores approval requests in PostgreSQL and binds each request to one immutable remediation ID, incident, typed action, target, risk, and deadline. Generic webhook decisions require an Argus operator/admin identity. Slack decisions require a verified Slack signature and timestamp, an allow-listed Slack-to-Argus identity mapping, and a reason submitted through a modal.

Approval decisions update the request, transition the remediation, and append approval and remediation audit entries in one database transaction. Four-eyes approval is the default. A lightweight background controller escalates unanswered requests once and expires them after the configured timeout.

## Consequences

- LLM output and webhook possession cannot authorize execution.
- API restarts preserve pending requests and decisions.
- Replayed, late, self-approved, and conflicting decisions fail closed.
- Notification outages leave a visible pending request and emit failure metrics.
- Slack incoming webhooks plus free Slack app interactivity provide in-Slack decisions without adding a paid dependency.
