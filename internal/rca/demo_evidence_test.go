package rca

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gauravgs7/argus/internal/correlation"
	"github.com/gauravgs7/argus/internal/incidents"
)

var updateDemoEvidence = flag.Bool("update-demo-evidence", false, "rewrite the RCA sections of docs/demo-evidence from recorded probe values")

// demoScenarios pairs each committed demo-evidence snapshot with the probe
// values recorded from a live run of that scenario: the demo payments-api
// scraped by Prometheus 2.53 and pushing logs to Loki 3.0 (see
// TestLiveBackendsScenario). Probes absent from a map returned no data in the
// live run: the demo stack has no nginx telemetry and no redis_exporter.
var demoScenarios = []struct {
	file    string
	alert   string
	service string
	labels  map[string]string
	probes  map[string]answer
}{
	{
		file: "postgres-connection-exhaustion.json", alert: "PaymentsAPIPostgresConnectionExhaustion", service: "payments-api",
		probes: map[string]answer{
			"postgres_pool_utilisation":         {value: 0.95},
			"postgres_service_error_ratio":      {value: 1},
			"postgres_acquisition_timeout_logs": {value: 320},
		},
	},
	{
		file: "redis-memory-pressure.json", alert: "PaymentsAPIRedisMemoryPressure", service: "payments-api",
		labels: map[string]string{"cache_key_pattern": "demo:pressure:*"},
		probes: map[string]answer{
			"redis_operation_errors":     {value: 929.2159},
			"redis_memory_pressure_logs": {value: 920},
		},
	},
	{
		file: "nginx-5xx-spike.json", alert: "Nginx5xxSpike", service: "nginx",
		probes: map[string]answer{},
	},
	{
		file: "dependency-latency.json", alert: "PaymentsAPIDependencyLatency", service: "payments-api",
		labels: map[string]string{"degradable_feature_flag": "payments-api/optional-notifications"},
		probes: map[string]answer{
			"service_p95_latency":     {value: 2.2222},
			"dependency_latency_logs": {value: 368},
		},
	},
	{
		file: "bad-config-rollout.json", alert: "PaymentsAPIBadConfigRollout", service: "payments-api",
		probes: map[string]answer{
			"config_parse_error_logs":    {value: 2960},
			"config_service_error_ratio": {value: 0.9135},
		},
	},
}

func demoRCABlock(t *testing.T, alertName, service string, labels map[string]string, probes map[string]answer) (map[string]any, []map[string]any) {
	t.Helper()
	queriers, _ := backends(service, probes)
	signal := alert(alertName, service, labels)
	signal.ObservedAt = fixedNow
	result := run(newTestService(queriers), incidentFor(service), signal)

	timeline := []map[string]any{{"type": "alert_received", "source": "alertmanager", "summary": fmt.Sprintf("%s fired for %s", alertName, service)}}
	for _, event := range probeTimelineEvents("inc_demo", result.Items) {
		timeline = append(timeline, map[string]any{"type": event.EventType, "source": event.Source, "summary": event.Summary})
	}
	return map[string]any{
		"primary_hypothesis":   result.Hypothesis,
		"confidence":           result.Confidence,
		"summary":              result.Summary,
		"evidence":             result.Evidence,
		"contributing_factors": result.Factors,
		"evidence_items":       result.Items,
		"score_breakdown":      result.Score,
		"candidates":           result.Candidates,
	}, timeline
}

func normalizeJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(generic)
	return string(out)
}

// orderedObject keeps top-level key order so regenerated snapshots diff cleanly.
type orderedObject struct {
	keys   []string
	values map[string]json.RawMessage
}

func readOrdered(t *testing.T, path string) orderedObject {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if _, err := decoder.Token(); err != nil {
		t.Fatal(err)
	}
	object := orderedObject{values: map[string]json.RawMessage{}}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		key := token.(string)
		object.keys = append(object.keys, key)
		object.values[key] = value
	}
	return object
}

func (o orderedObject) set(t *testing.T, key string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	o.values[key] = raw
}

func (o orderedObject) write(t *testing.T, path string) {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString("{")
	for i, key := range o.keys {
		if i > 0 {
			buf.WriteString(",")
		}
		name, _ := json.Marshal(key)
		buf.Write(name)
		buf.WriteString(":")
		buf.Write(o.values[key])
	}
	buf.WriteString("}")
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, buf.Bytes(), "", "  "); err != nil {
		t.Fatal(err)
	}
	pretty.WriteString("\n")
	if err := os.WriteFile(path, pretty.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDemoEvidenceMatchesEngine(t *testing.T) {
	for _, scenario := range demoScenarios {
		t.Run(scenario.file, func(t *testing.T) {
			path := filepath.Join("..", "..", "docs", "demo-evidence", scenario.file)
			block, timeline := demoRCABlock(t, scenario.alert, scenario.service, scenario.labels, scenario.probes)
			doc := readOrdered(t, path)

			if *updateDemoEvidence {
				var incident map[string]any
				if err := json.Unmarshal(doc.values["incident"], &incident); err != nil {
					t.Fatal(err)
				}
				incident["service"] = scenario.service
				incident["dedupe_key"] = incidents.BuildDedupeKey(scenario.service, scenario.alert, "local", "manual-"+trimJSONSuffix(scenario.file))
				doc.set(t, "incident", incident)
				doc.set(t, "timeline", timeline)
				doc.set(t, "rca", block)
				doc.write(t, path)
				return
			}

			var committed any
			if err := json.Unmarshal(doc.values["rca"], &committed); err != nil {
				t.Fatal(err)
			}
			if got, want := normalizeJSON(t, block), normalizeJSON(t, committed); got != want {
				t.Fatalf("%s is stale; run go test ./internal/rca -run TestDemoEvidenceMatchesEngine -update-demo-evidence\nengine:    %s\ncommitted: %s", scenario.file, got, want)
			}
			var committedTimeline any
			_ = json.Unmarshal(doc.values["timeline"], &committedTimeline)
			if normalizeJSON(t, timeline) != normalizeJSON(t, committedTimeline) {
				t.Fatalf("%s timeline is stale", scenario.file)
			}
		})
	}
}

func trimJSONSuffix(file string) string {
	name := file[:len(file)-len(filepath.Ext(file))]
	out := []byte(name)
	for i := range out {
		if out[i] == '-' {
			out[i] = '_'
		}
	}
	return string(out)
}

// The demo scenarios must keep exercising every rule.
func TestDemoScenariosCoverEveryRule(t *testing.T) {
	covered := map[correlation.RuleID]bool{}
	c := correlation.New()
	for _, scenario := range demoScenarios {
		for _, match := range c.Match(incidentFor(scenario.service), []incidents.Signal{alert(scenario.alert, scenario.service, nil)}) {
			covered[match.RuleID] = true
		}
	}
	for _, rule := range correlation.DefaultRules() {
		if !covered[rule.ID] {
			t.Fatalf("no demo scenario exercises rule %s", rule.ID)
		}
	}
}
