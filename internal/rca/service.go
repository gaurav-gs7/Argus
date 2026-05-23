package rca

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/telemetry"
)

type Service struct {
	store        *incidents.Store
	aiServiceURL string
	metrics      *telemetry.Metrics
	httpClient   *http.Client
}

type Candidate struct {
	ActionType       string `json:"action_type"`
	Target           string `json:"target"`
	Risk             string `json:"risk"`
	RequiresApproval bool   `json:"requires_approval"`
}

func NewService(store *incidents.Store, aiServiceURL string, metrics *telemetry.Metrics) *Service {
	return &Service{
		store:        store,
		aiServiceURL: strings.TrimRight(aiServiceURL, "/"),
		metrics:      metrics,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *Service) Generate(ctx context.Context, incidentID string) (incidents.RCAReport, []Candidate, error) {
	start := time.Now()
	incident, err := s.store.GetIncident(ctx, incidentID)
	if err != nil {
		s.metrics.RCAJobsTotal.WithLabelValues("failed").Inc()
		return incidents.RCAReport{}, nil, err
	}
	signals, err := s.store.ListSignals(ctx, incidentID)
	if err != nil {
		s.metrics.RCAJobsTotal.WithLabelValues("failed").Inc()
		return incidents.RCAReport{}, nil, err
	}

	summary, hypothesis, confidence, evidence, candidates := buildDeterministicRCA(incident, signals)
	report := incidents.RCAReport{
		IncidentID:           incidentID,
		DeterministicSummary: summary,
		PrimaryHypothesis:    hypothesis,
		Evidence:             evidence,
		Confidence:           confidence,
		ModelBackend:         "deterministic",
	}

	if llmSummary, backend, model, err := s.callAdvisor(ctx, incident, evidence, hypothesis); err == nil {
		report.LLMSummary = llmSummary
		report.ModelBackend = backend
		report.ModelName = model
	}

	if err := s.store.SaveRCAReport(ctx, report); err != nil {
		s.metrics.RCAJobsTotal.WithLabelValues("failed").Inc()
		return incidents.RCAReport{}, nil, err
	}

	_ = s.store.UpdateIncidentStatus(ctx, incidentID, incidents.StatusRCAGenerated)
	s.metrics.RCAJobsTotal.WithLabelValues("succeeded").Inc()
	s.metrics.RCADuration.WithLabelValues(report.ModelBackend).Observe(time.Since(start).Seconds())

	saved, err := s.store.GetLatestRCAReport(ctx, incidentID)
	if err != nil {
		return report, candidates, nil
	}
	return saved, candidates, nil
}

func buildDeterministicRCA(incident incidents.Incident, signals []incidents.Signal) (summary, hypothesis string, confidence float64, evidence []string, candidates []Candidate) {
	confidence = 0.45
	for _, signal := range signals {
		payload, _ := json.Marshal(signal.Body)
		text := strings.ToLower(signal.Name + " " + string(payload) + " " + signal.Source)

		switch {
		case strings.Contains(text, "postgres") && strings.Contains(text, "connection"):
			hypothesis = "PostgreSQL connection pool exhaustion"
			confidence = 0.88
			evidence = appendEvidence(evidence,
				incident.Service+" error rate increased",
				"application logs indicate postgres connection acquisition timeout",
				"signal stream references connection pool saturation",
			)
			candidates = []Candidate{
				{ActionType: "drain_postgres_connections", Target: incident.Service, Risk: "medium", RequiresApproval: true},
				{ActionType: "restart_service", Target: incident.Service, Risk: "medium", RequiresApproval: true},
			}
		case strings.Contains(text, "redis") && strings.Contains(text, "memory"):
			hypothesis = "Redis memory pressure causing cache degradation"
			confidence = 0.83
			evidence = appendEvidence(evidence,
				"redis memory pressure signal crossed threshold",
				"cache errors increased during the incident window",
			)
			candidates = []Candidate{
				{ActionType: "clear_redis_keyspace", Target: "demo:pressure:*", Risk: "medium", RequiresApproval: true},
			}
		case strings.Contains(text, "nginx") && strings.Contains(text, "5"):
			hypothesis = "Nginx upstream misconfiguration or bad route rollout"
			confidence = 0.8
			evidence = appendEvidence(evidence,
				"edge layer is returning 5xx",
				"route-level issue appears isolated from service health",
			)
			candidates = []Candidate{
				{ActionType: "rollback_config", Target: "nginx", Risk: "medium", RequiresApproval: true},
				{ActionType: "reload_nginx", Target: "nginx", Risk: "medium", RequiresApproval: true},
			}
		case strings.Contains(text, "notification") || strings.Contains(text, "latency"):
			hypothesis = "Downstream dependency latency dominates the request path"
			confidence = 0.76
			evidence = appendEvidence(evidence,
				"latency increased before failure rate",
				"downstream dependency signal dominates the incident window",
			)
			candidates = []Candidate{
				{ActionType: "revert_feature_flag", Target: "optional-notifications", Risk: "medium", RequiresApproval: true},
			}
		case strings.Contains(text, "config") || strings.Contains(text, "parse"):
			hypothesis = "Bad config rollout introduced an invalid runtime configuration"
			confidence = 0.85
			evidence = appendEvidence(evidence,
				"config-related errors appeared during the incident window",
				"a deployment or config change likely preceded impact",
			)
			candidates = []Candidate{
				{ActionType: "rollback_config", Target: incident.Service, Risk: "medium", RequiresApproval: true},
				{ActionType: "restart_service", Target: incident.Service, Risk: "medium", RequiresApproval: true},
			}
		}
	}

	if hypothesis == "" {
		hypothesis = "Insufficient evidence for a high-confidence root cause"
		summary = "Signals have been collected, but deterministic correlation did not find a strong hypothesis."
		evidence = appendEvidence(evidence, "No high-confidence rule match found")
		candidates = []Candidate{
			{ActionType: "restart_service", Target: incident.Service, Risk: "medium", RequiresApproval: true},
		}
		return summary, hypothesis, confidence, evidence, candidates
	}

	summary = fmt.Sprintf("%s likely impacted %s. Evidence points to %s.", incident.Title, incident.Service, hypothesis)
	return summary, hypothesis, confidence, evidence, candidates
}

func (s *Service) callAdvisor(ctx context.Context, incident incidents.Incident, evidence []string, hypothesis string) (summary, backend, model string, err error) {
	if s.aiServiceURL == "" {
		return "", "", "", fmt.Errorf("ai service disabled")
	}

	request := map[string]any{
		"incident": map[string]any{
			"id":         incident.ID,
			"title":      incident.Title,
			"service":    incident.Service,
			"severity":   incident.Severity,
			"started_at": incident.StartedAt,
		},
		"primary_hypothesis": hypothesis,
		"evidence":           evidence,
	}

	body, _ := json.Marshal(request)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.aiServiceURL+"/v1/rca/summarize", bytes.NewReader(body))
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.metrics.LLMRequestsTotal.WithLabelValues("unknown", "failed").Inc()
		return "", "", "", err
	}
	defer resp.Body.Close()

	var payload struct {
		Summary string `json:"summary"`
		Backend string `json:"backend"`
		Model   string `json:"model"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		s.metrics.LLMRequestsTotal.WithLabelValues("unknown", "failed").Inc()
		return "", "", "", err
	}
	s.metrics.LLMRequestsTotal.WithLabelValues(payload.Backend, "succeeded").Inc()
	s.metrics.LLMRequestDuration.WithLabelValues(payload.Backend).Observe(time.Since(start).Seconds())
	return payload.Summary, payload.Backend, payload.Model, nil
}

func appendEvidence(items []string, values ...string) []string {
	existing := map[string]struct{}{}
	for _, item := range items {
		existing[item] = struct{}{}
	}
	for _, value := range values {
		if _, ok := existing[value]; ok {
			continue
		}
		items = append(items, value)
		existing[value] = struct{}{}
	}
	return items
}
