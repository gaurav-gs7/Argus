# ADR 0011: Dispatch remediation jobs through a PostgreSQL outbox

## Status

Accepted

## Decision

The remediation job is a row in `remediation_dispatches`, written in the same transaction that moves the remediation to `queued` and appends its audit entry. A dispatcher in every API process publishes pending rows to JetStream (claimed with `FOR UPDATE SKIP LOCKED`, row id as `Nats-Msg-Id`) and retries with backoff while JetStream is unavailable. The same dispatcher reconciles: a remediation still `queued` well after its job was published is re-sent a bounded number of times and then marked `timed_out`. Dead letters can be replayed only through this outbox.

## Consequences

A crash or JetStream outage between reservation and publish can no longer strand a remediation, and a job lost after publication is recovered without an operator. Execute succeeds while JetStream is down, so execution latency, not the API response, absorbs the outage. Workers may see a job more than once (a publish repeated after the duplicate window, a redispatch while an old copy is still queued), so the compare-and-swap claim and execution receipts remain the guarantee against double execution. Remediations that reach `running` and are then abandoned are outside the reconciler's scope.
