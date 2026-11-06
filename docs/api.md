# API

Core endpoints:

- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `GET /v1/auth/me` (verified OIDC principal and mapped Argus role)
- `POST /v1/alerts/alertmanager`
- `GET /v1/incidents`
- `POST /v1/incidents`
- `GET /v1/incidents/{incident_id}`
- `GET /v1/incidents/{incident_id}/timeline`
- `GET /v1/incidents/{incident_id}/signals`
- `GET /v1/incidents/{incident_id}/topology`
- `GET /v1/incidents/{incident_id}/rca`
- `POST /v1/incidents/{incident_id}/rca/generate`
- `POST /v1/incidents/{incident_id}/remediations/suggest` (read-only, Verdikt-governed AI advice)
- `POST /v1/incidents/{incident_id}/remediations/propose` (deterministic durable proposal)
- `GET /v1/incidents/{incident_id}/remediations`
- `POST /v1/remediations/{remediation_id}/approve`
- `POST /v1/remediations/{remediation_id}/reject`
- `POST /v1/remediations/{remediation_id}/execute`
- `POST /v1/remediations/{remediation_id}/cancel`
- `GET /v1/approval-requests?status=pending`
- `GET /v1/approval-requests/{approval_request_id}`
- `POST /v1/approval-requests/{approval_request_id}/decision`
- `POST /v1/approval-callbacks/slack` (public transport endpoint; Slack HMAC verification is mandatory)
- `GET /v1/audit`
- `GET /v1/audit/verify` (admin-only full hash-chain verification)
- `GET /v1/dead-letters` (admin)
- `POST /v1/dead-letters/{sequence}/replay` (admin)
- `POST /v1/dead-letters/{sequence}/discard` (admin)
- `GET /v1/services`
- `POST /v1/services`
- `GET /v1/topology`
- `POST /v1/topology/dependencies` (admin)
- `GET /v1/runbooks`
- `POST /v1/runbooks/reindex` (forwards to the AI service; `503` when no AI service is configured, `502` when it fails)

## Request Limits

Request bodies are capped at 1 MiB, and at 8 MiB for `POST /v1/alerts/alertmanager` because a large alert group is legitimate. A larger body returns `413` before any of it is processed. The server closes connections whose headers take longer than `ARGUS_HTTP_READ_HEADER_TIMEOUT` (default 5s) or whose full request takes longer than `ARGUS_HTTP_READ_TIMEOUT` (15s), bounds response writes with `ARGUS_HTTP_WRITE_TIMEOUT` (30s), and drops idle keep-alive connections after `ARGUS_HTTP_IDLE_TIMEOUT` (120s).

## RCA

`POST /v1/incidents/{incident_id}/rca/generate` runs the deterministic RCA (probes, scoring, candidates) and returns `201` once the report is stored:

```json
{
  "rca_report_id": "rca_...",
  "status": "completed",
  "llm_status": "pending",
  "report": {"primary_hypothesis": "...", "confidence": 0.8, "candidates": [...]}
}
```

The report and its probe timeline events commit in one transaction. It does not wait for the LLM. When an AI service is configured, the optional narrative summary is generated in the background (at most four at a time, 30s each) and written to the same report; `GET /v1/incidents/{incident_id}/rca` shows `llm_status` moving from `pending` to `completed` or `failed`. Without an AI service it is `disabled`. A failed summary never changes the deterministic result.

`POST /v1/incidents/{incident_id}/remediations/propose` reuses the latest report and its stored candidates. It regenerates RCA only when there is no report yet or the incident received new signals after the report was created. The response includes `rca_report_id` and `rca_reused`, and repeated proposals do not add duplicate timeline events.

## Judikt Finding Contract

Judikt's finding outbox uses `POST /v1/alerts/alertmanager`. It does not call `POST /v1/incidents`; using the normal alert ingress ensures security findings receive the same normalization, grouping, topology, signal, timeline, audit, and deterministic RCA treatment as operational alerts.

The request requires `Authorization: Bearer <OIDC access token>`. The token's mapped Argus role must include `ingest_signal`: `ingester` (signals only, used by Alertmanager and Judikt), `operator`, or `admin`. The reader accepts Alertmanager's v4 webhook payload, ignores unknown fields, and caps the body at 8 MiB. Resolved alerts update the open incident they belong to and never create one; the response's `correlation` block reports `resolved_alerts`, `unmatched_resolved_alerts`, and `truncated_alerts`. Judikt places its dedupe key in `alerts[0].fingerprint`, maps risk to Argus severity, labels the source as `judikt`, and forwards hashes instead of caller arguments, model/tool results, tokens, or raw injected text. See the committed [producer-shaped payload](../demo/alerts/judikt_security_finding.json).

Argus responds with `202 Accepted` and the normal ingestion envelope:

```json
{
  "incidents": [
    {
      "id": "inc_example",
      "service": "mcp-platform-ops",
      "severity": "sev2",
      "status": "detected"
    }
  ],
  "correlation": {
    "alert_count": 1,
    "incident_groups": 1,
    "affected_service_count": 1,
    "observed_roots": 1,
    "inferred_roots": 0,
    "suppressed_alert_count": 0
  }
}
```

An outbox retry with the same fingerprint, while that alert is still firing or within the grouping window, returns the existing incident ID while appending another signal and timeline event. RCA generation is explicit: call `POST /v1/incidents/{incident_id}/rca/generate` using an identity with `generate_rca`. See [Judikt Finding Ingestion](integrations/judikt.md) for setup, field mapping, security boundaries, and integration evidence.

Approval decision body:

```json
{
  "decision": "approve",
  "reason": "Reviewed deterministic evidence; rollback is available"
}
```

The actor is derived from the verified OIDC token's issuer and subject. Signature, issuer, audience, expiry, signing algorithm, and role mapping are validated before authorization. `reason` is required, a proposer cannot decide their own request by default, and replayed or expired decisions fail closed.

Remediation execution returns `202 {"status":"queued"}` for a newly accepted execution: the remediation is reserved as `queued` and its job written to the outbox in one transaction, then published to JetStream, and a worker runs it asynchronously. If JetStream is unavailable the request still returns `202`; the job stays in the outbox and is published when JetStream recovers.

## Dead Letters

Jobs a worker gives up on, and JetStream's max-deliveries advisories for jobs that were never acknowledged, are kept in `ARGUS_DEAD_LETTER` for 30 days. These routes need the `manage_dead_letters` permission, which only `admin` holds.

`GET /v1/dead-letters?limit=50` lists them oldest first with `sequence`, `kind` (`job` or `max_deliveries_advisory`), `reason`, `deliveries`, `remediation_id`, the remediation's current `remediation_status`, and `replayable`.

`POST /v1/dead-letters/{sequence}/replay` with `{"reason": "..."}` re-sends the job of a remediation that is still `queued` or `running` through the outbox (audited as `remediation.redispatched`), deletes the dead letter, and returns `202` with the `dispatch_id`. It returns `409` with the remediation status when the remediation has moved on, and `422` when the dead letter names no remediation.

`POST /v1/dead-letters/{sequence}/discard` with `{"reason": "..."}` records `remediation.dead_letter_discarded` and then deletes the dead letter.

The CLI equivalents are `argus deadletter list`, `argus deadletter replay <sequence> --reason ...`, and `argus deadletter discard <sequence> --reason ...`. Repeating the request for a queued, running, or succeeded remediation returns `200 {"status":"reused"}`; Argus does not enqueue the typed action again and records the idempotent reuse in the audit trail.

Parameterized actions carry immutable desired state through proposal, policy, approval notification, audit, worker execution, and optional Helios delegation:

```json
{
  "action_type": "resize_connection_pool",
  "target": "payments-api",
  "parameters": {"size": 20},
  "risk": "medium",
  "status": "awaiting_approval"
}
```

Parameters are selected by deterministic RCA, not by the LLM. The custom Go policy and worker both validate them. The parameter object is included in proposal matching and the idempotency-key digest.

Audit list responses include `chain_position`, `previous_hash`, `entry_hash`, and `hash_version`. Verification returns `200` with `valid: true` when every entry and the persisted chain head agree. It returns `409` with the first invalid position and a bounded reason when tampering, deletion, reordering, or a head mismatch is detected.

The Slack endpoint accepts Slack's form-encoded interactivity payload. A signed button callback opens a reason modal; only the signed modal submission decides the request. Slack user IDs must map to Argus identities using `ARGUS_SLACK_APPROVERS`.

Create or update a directed dependency:

```json
{
  "service": "payments-api",
  "depends_on": "postgres",
  "dependency_type": "datastore",
  "criticality": "critical"
}
```

Alert ingestion returns both root incidents and batch-local correlation statistics:

```json
{
  "incidents": [{"id": "inc_example", "service": "postgres"}],
  "correlation": {
    "alert_count": 20,
    "incident_groups": 1,
    "affected_service_count": 4,
    "observed_roots": 1,
    "inferred_roots": 0,
    "suppressed_alert_count": 18
  }
}
```

## Conflicts

`POST /v1/incidents/{id}/ack` and `/resolve` return `409` when the incident lifecycle does not allow the transition from its current status, and `404` for an unknown incident. `POST /v1/remediations/{id}/execute` returns `409` for a resolved or cancelled incident, and `/cancel` returns `409` when the remediation changed state (for example a worker claimed it) before the cancel applied.
