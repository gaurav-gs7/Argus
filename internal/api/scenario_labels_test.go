package api

import (
	"testing"

	"github.com/gauravgs7/argus/internal/actions"
)

func TestDemoScenarioLabelsSatisfyRemediationCatalog(t *testing.T) {
	if got := scenarioService("nginx_5xx_spike"); got != "nginx" {
		t.Fatalf("nginx scenario service=%q", got)
	}
	if got := scenarioService("postgres_connection_exhaustion"); got != "payments-api" {
		t.Fatalf("default scenario service=%q", got)
	}
	redis := scenarioLabels("redis_memory_pressure")["cache_key_pattern"]
	if err := actions.Validate(actions.PurgeCache, redis, map[string]any{"max_keys": 500}); err != nil {
		t.Fatalf("redis demo label rejected by catalog: %v", err)
	}
	flag := scenarioLabels("dependency_latency")["degradable_feature_flag"]
	if err := actions.Validate(actions.ToggleFeatureFlag, flag, map[string]any{"enabled": false}); err != nil {
		t.Fatalf("latency demo label rejected by catalog: %v", err)
	}
	if scenarioLabels("postgres_connection_exhaustion") != nil {
		t.Fatal("scenarios without target labels should add none")
	}
}
