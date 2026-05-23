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

The incident manager deduplicates alerts using:

`service + alert_name + environment + fingerprint`

Grouping window default:

`5m`
