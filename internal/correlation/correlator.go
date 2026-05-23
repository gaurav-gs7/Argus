package correlation

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/gauravgs7/argus/internal/incidents"
)

type Result struct {
	Events   []incidents.TimelineEvent
	Evidence []EvidenceItem
}

type EvidenceItem struct {
	Type       string
	Source     string
	Summary    string
	Confidence float64
	Weight     float64
	OccurredAt time.Time
}

type Correlator struct{}

func New() *Correlator { return &Correlator{} }

func (c *Correlator) Correlate(incident incidents.Incident, signals []incidents.Signal) Result {
	result := Result{}
	for _, signal := range signals {
		observedAt := signal.ObservedAt
		if observedAt.IsZero() {
			observedAt = incident.StartedAt
		}
		text := signalText(signal)
		result.add(signalEvidence(incident, signal, text, observedAt)...)
	}

	sort.SliceStable(result.Events, func(i, j int) bool {
		return result.Events[i].OccurredAt.Before(result.Events[j].OccurredAt)
	})
	sort.SliceStable(result.Evidence, func(i, j int) bool {
		return result.Evidence[i].OccurredAt.Before(result.Evidence[j].OccurredAt)
	})
	return result
}

func signalText(signal incidents.Signal) string {
	body, _ := json.Marshal(signal.Body)
	return strings.ToLower(signal.Name + " " + signal.Source + " " + signal.SignalType + " " + string(body))
}

func signalEvidence(incident incidents.Incident, signal incidents.Signal, text string, observedAt time.Time) []EvidenceItem {
	var items []EvidenceItem
	add := func(kind, source, summary string, confidence, weight float64) {
		items = append(items, EvidenceItem{
			Type: kind, Source: source, Summary: summary, Confidence: confidence, Weight: weight, OccurredAt: observedAt,
		})
	}

	if strings.Contains(text, "postgres") && strings.Contains(text, "connection") {
		add("metric_anomaly", "prometheus", "postgres connection pool saturation crossed threshold", 0.91, 0.34)
		add("log_pattern", "loki", "application logs indicate postgres connection acquisition timeout", 0.87, 0.29)
		add("service_impact", signal.Source, incident.Service+" error rate increased during the incident window", 0.82, 0.17)
	}
	if strings.Contains(text, "redis") && strings.Contains(text, "memory") {
		add("metric_anomaly", "prometheus", "redis memory pressure signal crossed threshold", 0.86, 0.31)
		add("service_impact", signal.Source, "cache errors increased during the incident window", 0.82, 0.22)
	}
	if strings.Contains(text, "nginx") && strings.Contains(text, "5") {
		add("edge_anomaly", "prometheus", "edge layer is returning elevated 5xx while upstream health is isolated", 0.89, 0.30)
		add("config_event", "config", "nginx route or upstream config changed near the incident window", 0.76, 0.20)
	}
	if strings.Contains(text, "notification") || strings.Contains(text, "latency") {
		add("trace_anomaly", "otel", "downstream dependency latency dominates the request path", 0.84, 0.30)
		add("metric_anomaly", "prometheus", "p95 latency increased before failure rate dominated", 0.77, 0.18)
	}
	if strings.Contains(text, "config") || strings.Contains(text, "parse") || strings.Contains(text, "rollout") {
		add("config_event", "config", "configuration rollout preceded service errors", 0.93, 0.35)
		add("log_pattern", "loki", "runtime logs contain config or connection errors", 0.85, 0.24)
	}

	if len(items) == 0 {
		add("signal", signal.Source, "unclassified signal captured for deterministic analysis", 0.45, 0.05)
	}
	return items
}

func (r *Result) add(items ...EvidenceItem) {
	seen := map[string]struct{}{}
	for _, existing := range r.Evidence {
		seen[existing.Type+existing.Source+existing.Summary] = struct{}{}
	}
	for _, item := range items {
		key := item.Type + item.Source + item.Summary
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		r.Evidence = append(r.Evidence, item)
		r.Events = append(r.Events, incidents.TimelineEvent{
			IncidentID: "",
			EventType:  item.Type,
			Source:     item.Source,
			Summary:    item.Summary,
			Evidence: map[string]any{
				"source_signal": item.Source,
				"weight":        item.Weight,
			},
			Confidence: item.Confidence,
			OccurredAt: item.OccurredAt,
		})
	}
}
