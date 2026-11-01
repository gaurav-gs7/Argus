package correlation

import (
	"fmt"
	"strings"

	"github.com/gauravgs7/argus/internal/actions"
	"github.com/gauravgs7/argus/internal/evidence"
)

type RuleID string

const (
	RulePostgresConnectionExhaustion RuleID = "postgres_connection_exhaustion"
	RuleRedisMemoryPressure          RuleID = "redis_memory_pressure"
	RuleNginxUpstreamConfig          RuleID = "nginx_upstream_config"
	RuleDependencyLatency            RuleID = "dependency_latency"
	RuleBadConfigRollout             RuleID = "bad_config_rollout"
)

// FailureModeLabel lets an alert rule name its failure mode explicitly instead
// of relying on the alertname table.
const FailureModeLabel = "argus_failure_mode"

// Rule is one failure mode Argus can diagnose. A rule is selected only by
// structured alert identity (alertname or the explicit failure-mode label);
// free-text annotations never select a rule. Probes then corroborate or refute
// the hypothesis against real backends.
type Rule struct {
	ID           RuleID
	Hypothesis   string
	AlertNames   []string
	Probes       []evidence.Probe
	Remediations []CandidateTemplate
}

// CandidateTemplate describes a remediation whose target comes from the alert
// that matched the rule, never from a constant. TargetLabel names the alert
// label holding the target; empty means the alert's service. TargetFormat is a
// printf pattern with one %s. A candidate whose target is missing or fails the
// action catalog's validation is dropped, not guessed.
type CandidateTemplate struct {
	ActionType        string
	TargetLabel       string
	FallbackToService bool
	TargetFormat      string
	Parameters        map[string]any
	Risk              string
}

const (
	errorRatioQuery = `sum(rate(http_requests_total{service="{{service}}",status=~"5.."}[5m])) / sum(rate(http_requests_total{service="{{service}}"}[5m]))`
	p95LatencyQuery = `histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket{service="{{service}}"}[5m])))`
)

func errorRatioProbe(id string, weight float64) evidence.Probe {
	return evidence.Probe{
		ID: id, Backend: evidence.Prometheus, Query: errorRatioQuery,
		Comparator: evidence.AtLeast, Threshold: 0.05, Weight: weight,
		Claim: "5xx response ratio is at or above 5%", Symptom: true,
	}
}

func logProbe(id, filter, claim string, weight float64) evidence.Probe {
	return evidence.Probe{
		ID: id, Backend: evidence.Loki,
		Query:      `sum(count_over_time({service="{{service}}"} ` + filter + ` [10m]))`,
		Comparator: evidence.AtLeast, Threshold: 1, Weight: weight, Claim: claim,
	}
}

// DefaultRules is the compiled, CI-reviewed rule table.
func DefaultRules() []Rule {
	return []Rule{
		{
			ID:         RulePostgresConnectionExhaustion,
			Hypothesis: "PostgreSQL connection pool exhaustion",
			AlertNames: []string{"PaymentsAPIPostgresConnectionExhaustion", "PaymentsAPIPostgresPoolSaturation", "PostgresConnectionPoolExhausted"},
			Probes: []evidence.Probe{
				{
					ID: "postgres_pool_utilisation", Backend: evidence.Prometheus,
					Query:      `max(db_connection_pool_in_use{service="{{service}}"} / db_connection_pool_max{service="{{service}}"})`,
					Comparator: evidence.AtLeast, Threshold: 0.9, Weight: 0.20,
					Claim: "connection pool utilisation is at or above 90%",
				},
				errorRatioProbe("postgres_service_error_ratio", 0.10),
				logProbe("postgres_acquisition_timeout_logs", `|= "connection acquisition timeout"`, "logs contain postgres connection acquisition timeouts", 0.20),
			},
			Remediations: []CandidateTemplate{
				{ActionType: actions.DrainPostgresConnections, Risk: "medium"},
				{ActionType: actions.ResizeConnectionPool, Parameters: map[string]any{"size": 20}, Risk: "medium"},
				{ActionType: actions.RestartPod, TargetLabel: "pod", FallbackToService: true, TargetFormat: "local/%s", Risk: "medium"},
			},
		},
		{
			ID:         RuleRedisMemoryPressure,
			Hypothesis: "Redis memory pressure causing cache degradation",
			AlertNames: []string{"PaymentsAPIRedisMemoryPressure", "RedisMemoryPressure", "RedisMemoryHigh"},
			Probes: []evidence.Probe{
				{
					ID: "redis_memory_utilisation", Backend: evidence.Prometheus,
					Query:      `max(redis_memory_used_bytes{service="{{service}}"} / redis_memory_max_bytes{service="{{service}}"})`,
					Comparator: evidence.AtLeast, Threshold: 0.9, Weight: 0.20,
					Claim: "redis memory usage is at or above 90% of maxmemory",
				},
				{
					ID: "redis_operation_errors", Backend: evidence.Prometheus,
					Query:      `sum(increase(redis_operation_errors_total{service="{{service}}"}[10m]))`,
					Comparator: evidence.AtLeast, Threshold: 1, Weight: 0.15,
					Claim: "redis operation errors increased in the last 10 minutes",
				},
				logProbe("redis_memory_pressure_logs", `|= "redis memory pressure"`, "logs report redis memory pressure", 0.15),
			},
			Remediations: []CandidateTemplate{
				{ActionType: actions.PurgeCache, TargetLabel: "cache_key_pattern", Parameters: map[string]any{"max_keys": 500}, Risk: "medium"},
			},
		},
		{
			ID:         RuleNginxUpstreamConfig,
			Hypothesis: "Nginx upstream misconfiguration or bad route rollout",
			AlertNames: []string{"Nginx5xxSpike", "NginxUpstreamErrors"},
			Probes: []evidence.Probe{
				{
					ID: "nginx_5xx_ratio", Backend: evidence.Prometheus,
					Query:      `sum(rate(nginx_http_requests_total{service="{{service}}",status=~"5.."}[5m])) / sum(rate(nginx_http_requests_total{service="{{service}}"}[5m]))`,
					Comparator: evidence.AtLeast, Threshold: 0.05, Weight: 0.20,
					Claim: "edge 5xx response ratio is at or above 5%", Symptom: true,
				},
				logProbe("nginx_upstream_error_logs", `|= "upstream"`, "edge logs report upstream errors", 0.15),
			},
			Remediations: []CandidateTemplate{
				{ActionType: actions.RollbackConfig, Risk: "medium"},
				{ActionType: actions.ReloadNginx, Risk: "medium"},
			},
		},
		{
			ID:         RuleDependencyLatency,
			Hypothesis: "Downstream dependency latency dominates the request path",
			AlertNames: []string{"PaymentsAPIDependencyLatency", "DownstreamDependencyLatency"},
			Probes: []evidence.Probe{
				{
					ID: "service_p95_latency", Backend: evidence.Prometheus, Query: p95LatencyQuery,
					Comparator: evidence.AtLeast, Threshold: 0.8, Weight: 0.20,
					Claim: "p95 request latency is at or above 800ms", Symptom: true,
				},
				logProbe("dependency_latency_logs", `|= "latency dominated"`, "logs attribute request latency to a downstream dependency", 0.15),
			},
			Remediations: []CandidateTemplate{
				{ActionType: actions.ToggleFeatureFlag, TargetLabel: "degradable_feature_flag", Parameters: map[string]any{"enabled": false}, Risk: "medium"},
			},
		},
		{
			ID:         RuleBadConfigRollout,
			Hypothesis: "Bad config rollout introduced an invalid runtime configuration",
			AlertNames: []string{"PaymentsAPIBadConfigRollout", "ConfigRolloutFailed"},
			Probes: []evidence.Probe{
				logProbe("config_parse_error_logs", `|~ "config parse|invalid config"`, "logs contain configuration parse errors", 0.25),
				errorRatioProbe("config_service_error_ratio", 0.10),
			},
			Remediations: []CandidateTemplate{
				{ActionType: actions.RollbackConfig, Risk: "medium"},
				{ActionType: actions.RestartPod, TargetLabel: "pod", FallbackToService: true, TargetFormat: "local/%s", Risk: "medium"},
			},
		},
	}
}

// ValidateRules enforces the invariants the scorer depends on.
func ValidateRules(rules []Rule) error {
	ids := map[RuleID]struct{}{}
	alertNames := map[string]RuleID{}
	for _, rule := range rules {
		if rule.ID == "" || rule.Hypothesis == "" {
			return fmt.Errorf("rule id and hypothesis are required")
		}
		if _, ok := ids[rule.ID]; ok {
			return fmt.Errorf("duplicate rule id %s", rule.ID)
		}
		ids[rule.ID] = struct{}{}
		if len(rule.AlertNames) == 0 {
			return fmt.Errorf("rule %s has no alert names", rule.ID)
		}
		for _, name := range rule.AlertNames {
			if owner, ok := alertNames[name]; ok {
				return fmt.Errorf("alert %s is claimed by both %s and %s", name, owner, rule.ID)
			}
			alertNames[name] = rule.ID
		}
		if len(rule.Probes) == 0 {
			return fmt.Errorf("rule %s has no corroboration probes", rule.ID)
		}
		probeIDs := map[string]struct{}{}
		total := 0.0
		hasCause := false
		for _, probe := range rule.Probes {
			if err := evidence.ValidateProbe(probe); err != nil {
				return fmt.Errorf("rule %s: %w", rule.ID, err)
			}
			if _, ok := probeIDs[probe.ID]; ok {
				return fmt.Errorf("rule %s: duplicate probe %s", rule.ID, probe.ID)
			}
			probeIDs[probe.ID] = struct{}{}
			total += probe.Weight
			hasCause = hasCause || !probe.Symptom
		}
		if !hasCause {
			return fmt.Errorf("rule %s has only symptom probes; it can never be independently corroborated", rule.ID)
		}
		if total > 0.5+1e-9 {
			return fmt.Errorf("rule %s: probe weights sum to %.2f, above 0.50", rule.ID, total)
		}
		for _, template := range rule.Remediations {
			if err := validateTemplate(template); err != nil {
				return fmt.Errorf("rule %s: %w", rule.ID, err)
			}
		}
	}
	return nil
}

func validateTemplate(template CandidateTemplate) error {
	if !actions.IsRegistered(template.ActionType) {
		return fmt.Errorf("remediation %q is not a registered action", template.ActionType)
	}
	switch template.Risk {
	case "low", "medium", "high":
	default:
		return fmt.Errorf("remediation %s has unknown risk %q", template.ActionType, template.Risk)
	}
	if template.TargetFormat != "" && strings.Count(template.TargetFormat, "%s") != 1 {
		return fmt.Errorf("remediation %s target format must contain exactly one %%s", template.ActionType)
	}
	if template.TargetLabel == "" && template.FallbackToService {
		return fmt.Errorf("remediation %s: fallback without a target label is redundant", template.ActionType)
	}
	return nil
}

// Render resolves a template against the alert that matched the rule. It
// returns an empty target and a reason when no safe target can be derived.
func (template CandidateTemplate) Render(service string, labels map[string]string) (string, map[string]any, string) {
	value := service
	source := "alert service"
	if template.TargetLabel != "" {
		value = labels[template.TargetLabel]
		source = "label " + template.TargetLabel
		if value == "" && template.FallbackToService {
			value, source = service, "alert service"
		}
	}
	if value == "" {
		return "", nil, fmt.Sprintf("alert has no %s", source)
	}
	target := value
	if template.TargetFormat != "" {
		target = fmt.Sprintf(template.TargetFormat, value)
	}
	parameters := make(map[string]any, len(template.Parameters))
	for key, val := range template.Parameters {
		parameters[key] = val
	}
	if err := actions.Validate(template.ActionType, target, parameters); err != nil {
		return "", nil, fmt.Sprintf("target %q from %s rejected by action catalog: %v", target, source, err)
	}
	return target, parameters, ""
}
