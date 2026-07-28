# API

Core endpoints:

- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `POST /v1/alerts/alertmanager`
- `GET /v1/incidents`
- `POST /v1/incidents`
- `GET /v1/incidents/{incident_id}`
- `GET /v1/incidents/{incident_id}/timeline`
- `GET /v1/incidents/{incident_id}/signals`
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
- `GET /v1/services`
- `POST /v1/services`
- `GET /v1/runbooks`
- `POST /v1/runbooks/reindex`

Approval decision body:

```json
{
  "decision": "approve",
  "reason": "Reviewed deterministic evidence; rollback is available"
}
```

The actor is derived from the operator/admin bearer token. `reason` is required, a proposer cannot decide their own request by default, and replayed or expired decisions fail closed.

The Slack endpoint accepts Slack's form-encoded interactivity payload. A signed button callback opens a reason modal; only the signed modal submission decides the request. Slack user IDs must map to Argus identities using `ARGUS_SLACK_APPROVERS`.
