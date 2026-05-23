package policy

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

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Evaluate(input Input) Decision {
	decision := Decision{
		Allow:            false,
		RequiresApproval: true,
		Reason:           "Blocked by default until explicitly allowed",
		MaxAttempts:      1,
	}

	if input.Remediation.Risk == "high" {
		decision.Reason = "High-risk actions are blocked"
		return decision
	}

	if input.History.SameActionLast10m >= 2 {
		decision.Reason = "Too many repeated remediation attempts"
		return decision
	}

	switch input.Remediation.Type {
	case "restart_service", "rollback_config", "reload_nginx", "clear_redis_keyspace", "drain_postgres_connections", "revert_feature_flag", "disable_bad_route":
		decision.Allow = true
	default:
		decision.Reason = "Remediation type is not registered"
		return decision
	}

	if input.Incident.Environment != "local" {
		decision.Allow = false
		decision.Reason = "Only local environment is enabled in v1"
		return decision
	}

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
