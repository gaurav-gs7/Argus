# Judikt Finding Ingestion

## Purpose

Judikt converts selected blocked or high-risk MCP operations into bounded security findings. Its durable SQLite outbox exports those findings to Argus so the same incident correlation, evidence retention, RCA, policy, approval, and audit surfaces can handle security and reliability signals.

Judikt and Verdikt have different roles:

| Integration | Direction | Responsibility |
| --- | --- | --- |
| Judikt | Judikt finding outbox -> Argus alert ingress | Create a deduplicated security incident from a governed MCP finding |
| Verdikt | Argus AI service -> Verdikt policy-only endpoint | Validate an AI recommendation as `PROPOSE_ONLY`; never execute it |

## HTTP Contract

| Property | Value |
| --- | --- |
| Method | `POST` |
| Argus path | `/v1/alerts/alertmanager` |
| Authentication | OIDC/JWT bearer access token |
| Required Argus permission | `ingest_signal` |
| Accepted v1 roles | `operator`, `admin` |
| Content type | `application/json` |
| Success status | `202 Accepted` |
| Producer implementation | [`ArgusAlertmanagerSink`](https://github.com/gaurav-gs7/Judikt/blob/main/src/judikt/findings.py) |
| Consumer implementation | [`handleAlertmanager`](../../internal/api/server.go) |

Argus intentionally reuses its Alertmanager ingress rather than adding a privileged source-specific incident endpoint. This ensures a Judikt finding cannot skip OIDC authorization, signal normalization, exact deduplication, topology grouping, evidence persistence, timeline generation, or incident audit creation.

## Judikt Configuration

Configure Judikt with the Argus base URL and an operator-managed OIDC access token:

```bash
export JUDIKT_ARGUS_URL="https://argus.example.com"
export JUDIKT_ARGUS_API_TOKEN="<OIDC access token mapped to Argus operator>"
```

For a local loopback demo, `http://127.0.0.1:8080` is accepted by Judikt. Non-loopback production traffic should use HTTPS. The token must be issued by the provider configured through Argus's `ARGUS_OIDC_*` settings, have the configured audience, and contain a role claim mapped to `operator` or `admin`.

Judikt can also send `X-Judikt-Event-ID` and `X-Judikt-Signature-256`. Argus v1 uses the verified OIDC identity as its authentication boundary and does not consume those headers. Deployments that require independent body-signature verification must enforce the HMAC at a trusted ingress proxy before forwarding to Argus; claiming native dual verification would be inaccurate.

From an Argus clone, the consumer contract can be exercised directly with the committed producer-shaped fixture:

```bash
export ARGUS_API_TOKEN="<OIDC access token mapped to Argus operator>"

curl -fsS -X POST http://127.0.0.1:8080/v1/alerts/alertmanager \
  -H "Authorization: Bearer ${ARGUS_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @demo/alerts/judikt_security_finding.json
```

The response contains the incident ID required by the RCA endpoint. Repeating the request within the grouping window returns the same incident ID.

## Field Mapping

| Judikt finding | Alertmanager envelope | Argus behavior |
| --- | --- | --- |
| `server` | `labels.service = mcp-<server>` | Service catalog identity and incident scope |
| fixed finding type | `labels.alertname = JudiktMCPSecurityFinding` | Stable alert class |
| `risk_level` | `labels.severity = sev1..sev4` | Incident severity |
| configured environment | `labels.environment` | Environment-isolated grouping |
| `rule` | `labels.rule` | Persisted security-control evidence |
| `dedupe_key` | `fingerprint` | Exact Argus dedupe component |
| `correlation_id`, tool, risk, action | annotations | Bounded timeline and RCA context |
| argument, result, and reason hashes | annotations | Correlation without raw private payloads |

The complete envelope is committed as [`demo/alerts/judikt_security_finding.json`](../../demo/alerts/judikt_security_finding.json). Argus derives this incident key:

```text
mcp-platform-ops:JudiktMCPSecurityFinding:production:<judikt-dedupe-key>
```

## End-To-End Flow

```text
blocked MCP call
  -> Judikt signed audit record
  -> durable Judikt finding outbox
  -> POST /v1/alerts/alertmanager with OIDC bearer token
  -> Argus ingest_signal authorization
  -> normalized alert + exact fingerprint dedupe
  -> incident + signal + timeline + incident.detected audit event
  -> 202 response containing created/reused incident ID
  -> POST /v1/incidents/{id}/rca/generate
  -> deterministic evidence scoring; optional advisory summary
```

Finding ingestion does not automatically invoke RCA or remediation. An operator or controller explicitly requests RCA using `POST /v1/incidents/{incident_id}/rca/generate`. Remediation remains a separate deterministic proposal, policy, approval, idempotency, and typed-worker workflow.

## Retry And Privacy Semantics

Judikt retries failed delivery from its durable outbox. Within Argus's grouping window, the same fingerprint reuses the open incident. Argus still appends each accepted delivery to `signals` and `incident_timeline_events`, preserving retry-visible evidence without creating duplicate incidents.

Judikt does not forward raw caller tokens, OAuth credentials, tool arguments, tool results, denial reasons, or injected text. It forwards SHA-256 hashes and bounded metadata. Argus persists those labels and annotations as alert evidence. Neither hash values nor labels should be treated as proof of source truth; they remain producer-supplied evidence under the trust boundary described in [Threat Model And Explicit Limitations](../threat-model.md).

## Integration Proof

[`TestJudiktFindingOutboxCreatesDeduplicatedIncident`](../../internal/incidents/service_integration_test.go) runs against disposable PostgreSQL in `make integration-test` and CI. It proves that the committed Judikt envelope:

- creates one `mcp-platform-ops` severity `sev2` incident
- maps the Judikt fingerprint into the expected Argus dedupe key
- converges two identical outbox deliveries onto the same incident ID
- retains both deliveries as signals and timeline evidence
- persists the rule, correlation ID, and evidence hashes without raw private content
- writes exactly one `incident.detected` audit event bound to the OIDC service identity

Judikt separately tests payload construction, bearer delivery, HMAC generation, retry after `503`, dedupe, and private-data exclusion in its own repository. Together, those producer tests and this consumer test close the integration claim from both sides without requiring both projects in one CI workspace.
