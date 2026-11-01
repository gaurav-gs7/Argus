# Incident Lifecycle

States:

- detected
- triaged
- investigating
- rca_generated
- remediation_proposed
- awaiting_approval
- remediating
- mitigated
- resolved
- failed
- cancelled

Allowed transitions are enforced in one conditional SQL statement (`TransitionIncident`):

| From | To |
| --- | --- |
| detected | triaged, investigating, rca_generated, resolved, cancelled |
| triaged | investigating, rca_generated, resolved, cancelled |
| investigating | rca_generated, resolved, failed |
| rca_generated | remediation_proposed, awaiting_approval, resolved |
| remediation_proposed | awaiting_approval, remediating, resolved |
| awaiting_approval | remediating, resolved, cancelled |
| remediating | mitigated, resolved, failed |
| mitigated | resolved |
| failed | investigating, resolved |

`resolved` and `cancelled` are terminal. RCA generation and remediation proposals only move an incident forward: regenerating RCA on an incident that has moved on, or is resolved, records the report without rewinding it. Operator `ack` and `resolve` return `409` for a transition the table does not allow. Remediation cannot be dispatched for a resolved or cancelled incident.

Exact duplicate detection uses:

`service + alert_name + environment + fingerprint`

An open incident accepts alerts while any of its alerts is still firing, or within the grouping window (`ARGUS_INCIDENT_GROUPING_WINDOW`, default `5m`) of its last activity. A firing alert that Alertmanager has not re-sent for `ARGUS_ALERT_STALE_AFTER` (default `6h`, above Alertmanager's 4h `repeat_interval`) no longer holds the incident open.

Resolved notifications never open incidents. They mark the alert resolved on the open incident where it is firing (`alert_resolved`); when the last alert resolves, `alerts_cleared_at` is set and the timeline records `alerts_cleared`. The incident stays open until an operator resolves it. If an alert fires again within the grouping window the same incident is reused (`alerts_refired`); after the window a new incident opens.

Each Alertmanager delivery is applied in one transaction, including its audit entries.

Before opening incidents, Argus correlates all services in an Alertmanager batch against the durable service graph. Alerts that share a reachable upstream dependency become one topology group. If the upstream service also alerted it is an observed root; otherwise it is clearly marked as inferred. Independent graph components remain independent incidents.

If a downstream symptom arrives first, Argus opens the best incident available. A later upstream alert inside the grouping window promotes that same incident to the stronger root instead of opening another. Every alert delivery remains a signal and timeline event, including downstream alerts suppressed from incident creation.
