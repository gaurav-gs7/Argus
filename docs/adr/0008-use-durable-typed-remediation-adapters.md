# ADR 0008: Use Durable Typed Remediation Adapters

## Status

Accepted.

## Context

A handler name that only returns a success message does not prove safe execution. Argus needs enough remediation variety to demonstrate target validation, bounded parameters, dry-run behavior, approval binding, and at-least-once replay safety without adding Kubernetes or a paid control service to the default laptop profile.

## Decision

Argus models remediation as typed desired state. Pod restart, connection-pool resize, feature-flag toggle, and cache purge each have a concrete handler and fail-closed input contract. Deterministic RCA owns the parameters; the LLM may rank a candidate but cannot replace its target or parameters.

The local adapter stores target state and execution receipts in PostgreSQL. A transaction takes advisory locks for the idempotency key and target, applies the desired state, and writes one receipt. Dry-run performs no writes. Policy and the worker both validate the action.

## Consequences

JetStream replay and concurrent duplicate delivery do not repeat a side effect. Approval notifications and audit records identify the exact parameters being approved. The local implementation remains small enough for an 8 GB MacBook. A production Kubernetes, dynamic-config, or cache adapter can replace the local state backend behind the same handler contract, but external side effects require an equivalent provider-side idempotency token.
