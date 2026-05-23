package incidents

import "time"

const (
	StatusDetected            = "detected"
	StatusTriaged             = "triaged"
	StatusInvestigating       = "investigating"
	StatusRCAGenerated        = "rca_generated"
	StatusRemediationProposed = "remediation_proposed"
	StatusAwaitingApproval    = "awaiting_approval"
	StatusRemediating         = "remediating"
	StatusMitigated           = "mitigated"
	StatusResolved            = "resolved"
	StatusFailed              = "failed"
	StatusCancelled           = "cancelled"
)

type Service struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Owner           string    `json:"owner,omitempty"`
	Tier            string    `json:"tier"`
	Environment     string    `json:"environment"`
	SLOAvailability *float64  `json:"slo_availability,omitempty"`
	SLOLatencyP95MS *int      `json:"slo_latency_p95_ms,omitempty"`
	RunbookID       *string   `json:"runbook_id,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type Incident struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	ServiceID   string     `json:"service_id,omitempty"`
	Service     string     `json:"service,omitempty"`
	Severity    string     `json:"severity"`
	Status      string     `json:"status"`
	DedupeKey   string     `json:"dedupe_key"`
	Fingerprint string     `json:"fingerprint"`
	StartedAt   time.Time  `json:"started_at"`
	DetectedAt  time.Time  `json:"detected_at"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
	Summary     string     `json:"summary,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type Signal struct {
	ID         string         `json:"id"`
	IncidentID string         `json:"incident_id,omitempty"`
	ServiceID  string         `json:"service_id,omitempty"`
	Source     string         `json:"source"`
	SignalType string         `json:"signal_type"`
	Severity   string         `json:"severity,omitempty"`
	Name       string         `json:"name"`
	Body       map[string]any `json:"body"`
	ObservedAt time.Time      `json:"observed_at"`
	CreatedAt  time.Time      `json:"created_at"`
}

type TimelineEvent struct {
	ID         string         `json:"id"`
	IncidentID string         `json:"incident_id"`
	EventType  string         `json:"event_type"`
	Source     string         `json:"source"`
	Summary    string         `json:"summary"`
	Evidence   map[string]any `json:"evidence"`
	Confidence float64        `json:"confidence"`
	OccurredAt time.Time      `json:"occurred_at"`
	CreatedAt  time.Time      `json:"created_at"`
}

type RCAReport struct {
	ID                   string    `json:"id"`
	IncidentID           string    `json:"incident_id"`
	DeterministicSummary string    `json:"deterministic_summary"`
	LLMSummary           string    `json:"llm_summary,omitempty"`
	PrimaryHypothesis    string    `json:"primary_hypothesis"`
	ContributingFactors  []string  `json:"contributing_factors,omitempty"`
	Evidence             []string  `json:"evidence"`
	Confidence           float64   `json:"confidence"`
	ModelBackend         string    `json:"model_backend,omitempty"`
	ModelName            string    `json:"model_name,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
}

type RemediationAction struct {
	ID             string         `json:"id"`
	IncidentID     string         `json:"incident_id"`
	ActionType     string         `json:"action_type"`
	Target         string         `json:"target"`
	Status         string         `json:"status"`
	Risk           string         `json:"risk"`
	IdempotencyKey string         `json:"idempotency_key"`
	ProposedBy     string         `json:"proposed_by"`
	ApprovedBy     string         `json:"approved_by,omitempty"`
	PolicyDecision map[string]any `json:"policy_decision"`
	DryRun         bool           `json:"dry_run"`
	Attempt        int            `json:"attempt"`
	MaxAttempts    int            `json:"max_attempts"`
	QueuedAt       *time.Time     `json:"queued_at,omitempty"`
	StartedAt      *time.Time     `json:"started_at,omitempty"`
	CompletedAt    *time.Time     `json:"completed_at,omitempty"`
	Result         map[string]any `json:"result,omitempty"`
	Error          string         `json:"error,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}

type AlertmanagerWebhook struct {
	Status            string              `json:"status"`
	Receiver          string              `json:"receiver"`
	ExternalURL       string              `json:"externalURL"`
	GroupLabels       map[string]string   `json:"groupLabels"`
	CommonLabels      map[string]string   `json:"commonLabels"`
	CommonAnnotations map[string]string   `json:"commonAnnotations"`
	Alerts            []AlertmanagerAlert `json:"alerts"`
}

type AlertmanagerAlert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	Fingerprint  string            `json:"fingerprint"`
	GeneratorURL string            `json:"generatorURL"`
}

type ManualIncidentRequest struct {
	Title    string `json:"title"`
	Service  string `json:"service"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
}
