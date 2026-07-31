package approvals

import (
	"context"
	"time"

	"github.com/gauravgs7/argus/internal/incidents"
)

const (
	StatusPending   = "pending"
	StatusApproved  = "approved"
	StatusDenied    = "denied"
	StatusExpired   = "expired"
	StatusCancelled = "cancelled"

	DecisionApprove = "approve"
	DecisionDeny    = "deny"
)

type Request struct {
	ID                    string         `json:"id"`
	RemediationID         string         `json:"remediation_id"`
	IncidentID            string         `json:"incident_id"`
	ActionType            string         `json:"action_type"`
	Target                string         `json:"target"`
	Parameters            map[string]any `json:"parameters"`
	Risk                  string         `json:"risk"`
	Status                string         `json:"status"`
	RequestedBy           string         `json:"requested_by"`
	RequestedAt           time.Time      `json:"requested_at"`
	EscalatesAt           time.Time      `json:"escalates_at"`
	ExpiresAt             time.Time      `json:"expires_at"`
	EscalatedAt           *time.Time     `json:"escalated_at,omitempty"`
	DecidedAt             *time.Time     `json:"decided_at,omitempty"`
	DecidedBy             string         `json:"decided_by,omitempty"`
	DecisionReason        string         `json:"decision_reason,omitempty"`
	DecisionSource        string         `json:"decision_source,omitempty"`
	NotificationStatus    string         `json:"notification_status"`
	NotificationAttempts  int            `json:"notification_attempts"`
	LastNotificationError string         `json:"last_notification_error,omitempty"`
	CreatedAt             time.Time      `json:"created_at"`
	UpdatedAt             time.Time      `json:"updated_at"`
}

type Decision struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

type Workflow interface {
	RequestApproval(context.Context, incidents.Incident, incidents.RemediationAction) (Request, error)
	DecideByRemediation(context.Context, string, string, string, string, string) (Request, error)
	CancelByRemediation(context.Context, string, string, string) (Request, error)
}

type Notifier interface {
	Notify(context.Context, Request, bool) error
	Name() string
}
