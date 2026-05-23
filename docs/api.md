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
- `POST /v1/incidents/{incident_id}/remediations/propose`
- `GET /v1/incidents/{incident_id}/remediations`
- `POST /v1/remediations/{remediation_id}/approve`
- `POST /v1/remediations/{remediation_id}/reject`
- `POST /v1/remediations/{remediation_id}/execute`
- `POST /v1/remediations/{remediation_id}/cancel`
- `GET /v1/audit`
- `GET /v1/services`
- `POST /v1/services`
- `GET /v1/runbooks`
- `POST /v1/runbooks/reindex`
