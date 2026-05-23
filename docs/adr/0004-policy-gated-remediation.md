# ADR 0004: Policy-Gated Remediation

Remediation is valuable only if it is safe. Argus requires typed handlers, approval gates, idempotency, and audit logs before executing any non-trivial action.
