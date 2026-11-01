package policy

import (
	"fmt"
	"strings"

	"github.com/gauravgs7/argus/internal/actions"
)

type Input struct {
	Actor struct {
		ID   string `json:"id"`
		Role string `json:"role"`
	} `json:"actor"`
	Incident struct {
		ID          string `json:"id"`
		Severity    string `json:"severity"`
		Service     string `json:"service"`
		Environment string `json:"environment"`
	} `json:"incident"`
	Remediation struct {
		Type       string         `json:"type"`
		Target     string         `json:"target"`
		Risk       string         `json:"risk"`
		DryRun     bool           `json:"dry_run"`
		Parameters map[string]any `json:"parameters"`
	} `json:"remediation"`
	History struct {
		SameActionLast10m int `json:"same_action_last_10m"`
		FailedAttempts    int `json:"failed_attempts"`
	} `json:"history"`
}

type Decision struct {
	Allow            bool   `json:"allow"`
	RequiresApproval bool   `json:"requires_approval"`
	Reason           string `json:"reason"`
	MaxAttempts      int    `json:"max_attempts"`
	// Risk is the effective risk the decision was made on: the stricter of
	// the action catalog's class and the proposal's.
	Risk string `json:"risk"`
}

type Engine struct {
	environments map[string]struct{}
}

// NewEngine permits remediation only in the "local" environment.
func NewEngine() *Engine {
	return NewEngineForEnvironments([]string{"local"})
}

// NewEngineForEnvironments permits remediation in the listed environments.
func NewEngineForEnvironments(environments []string) *Engine {
	allowed := map[string]struct{}{}
	for _, environment := range environments {
		if environment = strings.TrimSpace(environment); environment != "" {
			allowed[environment] = struct{}{}
		}
	}
	return &Engine{environments: allowed}
}

func (e *Engine) Evaluate(input Input) Decision {
	decision := Decision{Allow: false, RequiresApproval: true, Reason: "Blocked by default until explicitly allowed", MaxAttempts: 1}

	if input.Actor.Role == "viewer" {
		decision.Reason = "Viewer role cannot propose or execute remediation"
		return decision
	}
	if input.Actor.Role == "" {
		decision.Reason = "Actor role is missing"
		return decision
	}
	if _, ok := e.environments[input.Incident.Environment]; !ok {
		decision.Reason = fmt.Sprintf("Remediation is not enabled for environment %q", input.Incident.Environment)
		return decision
	}
	input.Remediation.Risk = actions.EffectiveRisk(input.Remediation.Type, input.Remediation.Risk)
	decision.Risk = input.Remediation.Risk
	if input.Remediation.Risk == "high" {
		decision.Reason = "High-risk actions are blocked"
		return decision
	}
	if !actions.IsRegistered(input.Remediation.Type) {
		decision.Reason = "Remediation type is not registered"
		return decision
	}
	if input.History.SameActionLast10m >= 2 {
		decision.Reason = "Too many repeated remediation attempts"
		return decision
	}
	if input.History.FailedAttempts >= 2 {
		decision.Reason = "Circuit breaker: repeated remediation failures"
		return decision
	}
	if err := actions.Validate(input.Remediation.Type, input.Remediation.Target, input.Remediation.Parameters); err != nil {
		decision.Reason = err.Error()
		return decision
	}

	decision.Allow = true
	switch input.Remediation.Risk {
	case "low":
		decision.RequiresApproval = false
		decision.Reason = "Low-risk remediation is allowed"
		decision.MaxAttempts = 2
	case "medium":
		decision.RequiresApproval = true
		decision.Reason = "Medium risk remediation requires approval"
		decision.MaxAttempts = 1
	default:
		decision.Allow = false
		decision.Reason = "Unknown remediation risk level"
	}
	return decision
}
