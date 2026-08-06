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
- `GET /v1/services`
- `POST /v1/services`
- `GET /v1/topology`
- `POST /v1/topology/dependencies` (admin)
- `GET /v1/runbooks`
- `POST /v1/runbooks/reindex`

## Judikt Finding Contract

Judikt's finding outbox uses `POST /v1/alerts/alertmanager`. It does not call `POST /v1/incidents`; using the normal alert ingress ensures security findings receive the same normalization, grouping, topology, signal, timeline, audit, and deterministic RCA treatment as operational alerts.

The request requires `Authorization: Bearer <OIDC access token>`. The token's mapped Argus role must include `ingest_signal` (`operator` or `admin` in v1). Judikt places its dedupe key in `alerts[0].fingerprint`, maps risk to Argus severity, labels the source as `judikt`, and forwards hashes instead of caller arguments, model/tool results, tokens, or raw injected text. See the committed [producer-shaped payload](../demo/alerts/judikt_security_finding.json).

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

An outbox retry with the same fingerprint and within the grouping window returns the existing incident ID while appending another signal and timeline event. RCA generation is explicit: call `POST /v1/incidents/{incident_id}/rca/generate` using an identity with `generate_rca`. See [Judikt Finding Ingestion](integrations/judikt.md) for setup, field mapping, security boundaries, and integration evidence.

Approval decision body:

```json
{
  "decision": "approve",
  "reason": "Reviewed deterministic evidence; rollback is available"
}
```

The actor is derived from the verified OIDC token's issuer and subject. Signature, issuer, audience, expiry, signing algorithm, and role mapping are validated before authorization. `reason` is required, a proposer cannot decide their own request by default, and replayed or expired decisions fail closed.

Remediation execution returns `202 {"status":"queued"}` for a newly accepted execution. Repeating the request for a queued, running, or succeeded remediation returns `200 {"status":"reused"}`; Argus does not enqueue the typed action again and records the idempotent reuse in the audit trail.

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
