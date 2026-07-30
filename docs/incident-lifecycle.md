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

Exact duplicate detection uses:

`service + alert_name + environment + fingerprint`

Grouping window default:

`5m`

Before opening incidents, Argus correlates all services in an Alertmanager batch against the durable service graph. Alerts that share a reachable upstream dependency become one topology group. If the upstream service also alerted it is an observed root; otherwise it is clearly marked as inferred. Independent graph components remain independent incidents.

If a downstream symptom arrives first, Argus opens the best incident available. A later upstream alert inside the grouping window promotes that same incident to the stronger root instead of opening another. Every alert delivery remains a signal and timeline event, including downstream alerts suppressed from incident creation.
