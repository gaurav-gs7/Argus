package policy

import "strings"

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
		Type   string `json:"type"`
		Target string `json:"target"`
		Risk   string `json:"risk"`
		DryRun bool   `json:"dry_run"`
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
}

type Engine struct {
	registered map[string]struct{}
}

func NewEngine() *Engine {
	registered := map[string]struct{}{}
	for _, action := range []string{
		"collect_diagnostics",
		"restart_service",
		"rollback_config",
		"reload_nginx",
		"clear_redis_keyspace",
		"drain_postgres_connections",
		"scale_worker_simulation",
		"revert_feature_flag",
		"disable_bad_route",
	} {
		registered[action] = struct{}{}
	}
	return &Engine{registered: registered}
}

func (e *Engine) Evaluate(input Input) Decision {
	decision := Decision{Allow: false, RequiresApproval: true, Reason: "Blocked by default until explicitly allowed", MaxAttempts: 1}

	if input.Actor.Role == "viewer" {
		decision.Reason = "Viewer role cannot propose or execute remediation"
		return decision
	}
	if input.Actor.Role == "" {
		input.Actor.Role = "operator"
	}
	if input.Incident.Environment != "local" {
		decision.Reason = "Only local environment is enabled in v1"
		return decision
	}
	if input.Remediation.Risk == "high" {
		decision.Reason = "High-risk actions are blocked"
		return decision
	}
	if _, ok := e.registered[input.Remediation.Type]; !ok {
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
	if input.Remediation.Type == "clear_redis_keyspace" && !strings.HasPrefix(input.Remediation.Target, "demo:pressure:") {
		decision.Reason = "Redis remediation is restricted to demo:pressure:* keys"
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
