package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: failure-injector <scenario>")
		os.Exit(1)
	}

	scenario := os.Args[1]
	paymentsURL := getenv("PAYMENTS_API_BASE_URL", "http://localhost:9001")
	argusURL := getenv("ARGUS_API_BASE_URL", "http://localhost:8080")

	activateScenario(paymentsURL, scenario)
	postAlert(argusURL, scenario)
}

func activateScenario(baseURL, scenario string) {
	body, _ := json.Marshal(map[string]string{"scenario": scenario})
	_, _ = http.Post(baseURL+"/admin/scenarios/activate", "application/json", bytes.NewReader(body))
}

func postAlert(baseURL, scenario string) {
	labels := map[string]string{
		"alertname":   scenarioToAlert(scenario),
		"service":     scenarioService(scenario),
		"environment": "local",
		"severity":    "sev2",
	}
	for key, value := range scenarioLabels(scenario) {
		labels[key] = value
	}
	payload := map[string]any{
		"status":   "firing",
		"receiver": "argus",
		"alerts": []map[string]any{
			{
				"status": "firing",
				"labels": labels,
				"annotations": map[string]string{
					"summary": scenarioToSummary(scenario),
				},
				"startsAt":    time.Now().UTC(),
				"fingerprint": "demo-" + scenario,
			},
		},
	}
	body, _ := json.Marshal(payload)
	_, _ = http.Post(baseURL+"/v1/alerts/alertmanager", "application/json", bytes.NewReader(body))
}

// scenarioService and scenarioLabels mirror demo/scenarios/*.yaml. RCA derives
// remediation targets from alert labels, so the demo alerts carry the labels a
// real alert rule would set for these failure modes.
func scenarioService(scenario string) string {
	if scenario == "nginx_5xx_spike" {
		return "nginx"
	}
	return "payments-api"
}

func scenarioLabels(scenario string) map[string]string {
	switch scenario {
	case "redis_memory_pressure":
		return map[string]string{"cache_key_pattern": "demo:pressure:*"}
	case "dependency_latency":
		return map[string]string{"degradable_feature_flag": "payments-api/optional-notifications"}
	default:
		return nil
	}
}

func scenarioToAlert(scenario string) string {
	switch scenario {
	case "postgres_connection_exhaustion":
		return "PaymentsAPIPostgresConnectionExhaustion"
	case "redis_memory_pressure":
		return "PaymentsAPIRedisMemoryPressure"
	case "nginx_5xx_spike":
		return "Nginx5xxSpike"
	case "dependency_latency":
		return "PaymentsAPIDependencyLatency"
	case "bad_config_rollout":
		return "PaymentsAPIBadConfigRollout"
	default:
		return "DemoIncident"
	}
}

func scenarioToSummary(scenario string) string {
	switch scenario {
	case "postgres_connection_exhaustion":
		return "payments-api is showing postgres connection exhaustion signals"
	case "redis_memory_pressure":
		return "payments-api cache performance degraded due to redis memory pressure"
	case "nginx_5xx_spike":
		return "nginx is returning elevated 5xx responses for the payments path"
	case "dependency_latency":
		return "notification-api latency is dominating request time"
	case "bad_config_rollout":
		return "recent config rollout likely broke payments-api connectivity"
	default:
		return "generic demo incident"
	}
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
