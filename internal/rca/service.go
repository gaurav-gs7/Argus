package rca

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gauravgs7/argus/internal/correlation"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/telemetry"
)

type Service struct {
	store          *incidents.Store
	aiServiceURL   string
	aiServiceToken string
	metrics        *telemetry.Metrics
	httpClient     *http.Client
	correlator     *correlation.Correlator
}

type Candidate struct {
	ActionType       string `json:"action_type"`
	Target           string `json:"target"`
	Risk             string `json:"risk"`
	RequiresApproval bool   `json:"requires_approval"`
}

type scoredHypothesis struct {
	Name       string
	Score      float64
	Evidence   []string
	Candidates []Candidate
	Factors    []string
}

func NewService(store *incidents.Store, aiServiceURL, aiServiceToken string, metrics *telemetry.Metrics) *Service {
	return &Service{
		store:          store,
		aiServiceURL:   strings.TrimRight(aiServiceURL, "/"),
		aiServiceToken: aiServiceToken,
		metrics:        metrics,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		correlator:     correlation.New(),
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
	topologyAnalysis, err := s.store.GetIncidentTopology(ctx, incidentID)
	if err != nil {
		s.metrics.RCAJobsTotal.WithLabelValues("failed").Inc()
		return incidents.RCAReport{}, nil, err
	}

	correlated := s.correlator.Correlate(incident, signals)
	for _, event := range correlated.Events {
		event.IncidentID = incidentID
		_ = s.store.AddTimelineEvent(ctx, event)
	}

	summary, hypothesis, confidence, evidence, factors, candidates := buildDeterministicRCA(incident, signals)
	summary, hypothesis, confidence, evidence, factors, candidates = applyTopologyFallback(
		incident, topologyAnalysis, summary, hypothesis, confidence, evidence, factors, candidates,
	)
	summary, confidence, evidence, factors = enrichWithTopology(
		summary, confidence, evidence, factors, topologyAnalysis,
	)
	report := incidents.RCAReport{
		IncidentID:           incidentID,
		DeterministicSummary: summary,
		PrimaryHypothesis:    hypothesis,
		ContributingFactors:  factors,
		Evidence:             evidence,
		Confidence:           confidence,
		ModelBackend:         "deterministic",
		Topology:             topologyAnalysis,
	}

	if llmSummary, backend, model, err := s.callAdvisor(
		ctx, incident, evidence, hypothesis, confidence, topologyAnalysis,
	); err == nil {
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
	s.metrics.RCAConfidence.WithLabelValues(hypothesis).Observe(confidence)

	saved, err := s.store.GetLatestRCAReport(ctx, incidentID)
	if err != nil {
		return report, candidates, nil
	}
	return saved, candidates, nil
}

func applyTopologyFallback(
	incident incidents.Incident,
	analysis incidents.IncidentTopology,
	summary, hypothesis string,
	confidence float64,
	evidence, factors []string,
	candidates []Candidate,
) (string, string, float64, []string, []string, []Candidate) {
	if hypothesis != "Insufficient evidence for a high-confidence root cause" ||
		analysis.SuppressedAlertCount == 0 || analysis.RootService == "" {
		return summary, hypothesis, confidence, evidence, factors, candidates
	}

	rootEvidence := "shared dependency inferred from downstream alert paths"
	confidence = 0.58
	if !analysis.RootInferred {
		rootEvidence = "root service emitted alert evidence in the incident window"
		confidence = 0.72
	}
	hypothesis = fmt.Sprintf("Failure at root dependency %s", analysis.RootService)
	summary = fmt.Sprintf(
		"Topology places the failure domain for incident %q at %s. It establishes the affected dependency but not the component-level failure mode.",
		incident.Title,
		analysis.RootService,
	)
	evidence = []string{
		rootEvidence,
		fmt.Sprintf("%d alerts across %d services share dependency root %s", analysis.AlertCount, len(analysis.AffectedServices), analysis.RootService),
	}
	factors = []string{"specific metric, log, or trace evidence is still required to identify the failure mode"}
	candidates = []Candidate{{
		ActionType: "collect_diagnostics",
		Target:     analysis.RootService,
		Risk:       "low",
	}}
	return summary, hypothesis, confidence, evidence, factors, candidates
}

func enrichWithTopology(
	summary string,
	confidence float64,
	evidence []string,
	factors []string,
	analysis incidents.IncidentTopology,
) (string, float64, []string, []string) {
	if analysis.SuppressedAlertCount == 0 {
		return summary, confidence, evidence, factors
	}
	rootQualifier := "observed"
	if analysis.RootInferred {
		rootQualifier = "inferred"
	} else {
		confidence = clamp(confidence+0.03, 0.35, 0.95)
	}
	summary = fmt.Sprintf(
		"%s Topology correlation identified %s root service %s, grouped %d alerts across %d services, and suppressed %d downstream alerts.",
		summary,
		rootQualifier,
		analysis.RootService,
		analysis.AlertCount,
		len(analysis.AffectedServices),
		analysis.SuppressedAlertCount,
	)
	evidence = appendEvidence(
		evidence,
		fmt.Sprintf("%d downstream alerts were suppressed behind root service %s", analysis.SuppressedAlertCount, analysis.RootService),
		fmt.Sprintf("blast radius includes %s", strings.Join(analysis.AffectedServices, ", ")),
	)
	for _, path := range analysis.Paths {
		factors = appendEvidence(factors, "dependency path: "+strings.Join(path.Services, " -> "))
	}
	return summary, confidence, evidence, factors
}

func buildDeterministicRCA(incident incidents.Incident, signals []incidents.Signal) (summary, hypothesis string, confidence float64, evidence []string, factors []string, candidates []Candidate) {
	correlated := correlation.New().Correlate(incident, signals)
	hypotheses := map[string]*scoredHypothesis{
		"PostgreSQL connection pool exhaustion": {
			Name: "PostgreSQL connection pool exhaustion",
			Candidates: []Candidate{
				{ActionType: "drain_postgres_connections", Target: incident.Service, Risk: "medium", RequiresApproval: true},
				{ActionType: "restart_service", Target: incident.Service, Risk: "medium", RequiresApproval: true},
			},
		},
		"Redis memory pressure causing cache degradation": {
			Name:       "Redis memory pressure causing cache degradation",
			Candidates: []Candidate{{ActionType: "clear_redis_keyspace", Target: "demo:pressure:*", Risk: "medium", RequiresApproval: true}},
		},
		"Nginx upstream misconfiguration or bad route rollout": {
			Name: "Nginx upstream misconfiguration or bad route rollout",
			Candidates: []Candidate{
				{ActionType: "rollback_config", Target: "nginx", Risk: "medium", RequiresApproval: true},
				{ActionType: "reload_nginx", Target: "nginx", Risk: "medium", RequiresApproval: true},
			},
		},
		"Downstream dependency latency dominates the request path": {
			Name:       "Downstream dependency latency dominates the request path",
			Candidates: []Candidate{{ActionType: "revert_feature_flag", Target: "optional-notifications", Risk: "medium", RequiresApproval: true}},
		},
		"Bad config rollout introduced an invalid runtime configuration": {
			Name: "Bad config rollout introduced an invalid runtime configuration",
			Candidates: []Candidate{
				{ActionType: "rollback_config", Target: incident.Service, Risk: "medium", RequiresApproval: true},
				{ActionType: "restart_service", Target: incident.Service, Risk: "medium", RequiresApproval: true},
			},
		},
	}

	for _, item := range correlated.Evidence {
		summaryText := strings.ToLower(item.Summary)
		switch {
		case strings.Contains(summaryText, "postgres") || strings.Contains(summaryText, "connection acquisition"):
			addScore(hypotheses["PostgreSQL connection pool exhaustion"], item)
		case strings.Contains(summaryText, "redis") || strings.Contains(summaryText, "cache"):
			addScore(hypotheses["Redis memory pressure causing cache degradation"], item)
		case strings.Contains(summaryText, "nginx") || strings.Contains(summaryText, "edge layer") || strings.Contains(summaryText, "upstream"):
			addScore(hypotheses["Nginx upstream misconfiguration or bad route rollout"], item)
		case strings.Contains(summaryText, "dependency") || strings.Contains(summaryText, "latency") || strings.Contains(summaryText, "notification"):
			addScore(hypotheses["Downstream dependency latency dominates the request path"], item)
		case strings.Contains(summaryText, "config") || strings.Contains(summaryText, "rollout"):
			addScore(hypotheses["Bad config rollout introduced an invalid runtime configuration"], item)
		}
	}

	best := bestHypothesis(hypotheses)
	if best == nil || best.Score <= 0 {
		return "Signals have been collected, but deterministic correlation did not find a strong hypothesis.",
			"Insufficient evidence for a high-confidence root cause",
			0.35,
			[]string{"No high-confidence rule match found"},
			[]string{"missing correlated metric/log/trace evidence"},
			[]Candidate{{ActionType: "collect_diagnostics", Target: incident.Service, Risk: "low", RequiresApproval: false}}
	}

	confidence = clamp(0.35+best.Score, 0.35, 0.95)
	evidence = appendEvidence(nil, best.Evidence...)
	factors = appendEvidence(nil, best.Factors...)
	hypothesis = best.Name
	candidates = best.Candidates
	summary = fmt.Sprintf("%s likely impacted %s. Deterministic evidence score %.2f points to %s.", incident.Title, incident.Service, confidence, hypothesis)
	return summary, hypothesis, confidence, evidence, factors, candidates
}

func addScore(h *scoredHypothesis, item correlation.EvidenceItem) {
	if h == nil {
		return
	}
	h.Score += item.Weight * item.Confidence
	h.Evidence = appendEvidence(h.Evidence, item.Summary)
	h.Factors = appendEvidence(h.Factors, item.Type+" from "+item.Source)
}

func bestHypothesis(items map[string]*scoredHypothesis) *scoredHypothesis {
	ordered := make([]*scoredHypothesis, 0, len(items))
	for _, item := range items {
		ordered = append(ordered, item)
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Score > ordered[j].Score })
	if len(ordered) == 0 {
		return nil
	}
	return ordered[0]
}

func clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func (s *Service) callAdvisor(
	ctx context.Context,
	incident incidents.Incident,
	evidence []string,
	hypothesis string,
	confidence float64,
	topologyAnalysis incidents.IncidentTopology,
) (summary, backend, model string, err error) {
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
		"confidence":         confidence,
		"topology":           topologyAnalysis,
	}

	body, _ := json.Marshal(request)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.aiServiceURL+"/v1/rca/summarize", bytes.NewReader(body))
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	s.authorizeAIRequest(req)

	start := time.Now()
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.metrics.LLMRequestsTotal.WithLabelValues("unknown", "failed").Inc()
		return "", "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		s.metrics.LLMRequestsTotal.WithLabelValues("unknown", "failed").Inc()
		return "", "", "", fmt.Errorf("ai service returned %s", resp.Status)
	}

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

func (s *Service) SuggestRemediations(ctx context.Context, incidentID string) (map[string]any, error) {
	if s.aiServiceURL == "" {
		return nil, fmt.Errorf("ai service disabled")
	}
	incident, err := s.store.GetIncident(ctx, incidentID)
	if err != nil {
		return nil, err
	}
	signals, err := s.store.ListSignals(ctx, incidentID)
	if err != nil {
		return nil, err
	}
	topologyAnalysis, err := s.store.GetIncidentTopology(ctx, incidentID)
	if err != nil {
		return nil, err
	}
	summary, hypothesis, confidence, evidence, factors, candidates := buildDeterministicRCA(incident, signals)
	_, _, confidence, evidence, _, candidates = applyTopologyFallback(
		incident, topologyAnalysis, summary, hypothesis, confidence, evidence, factors, candidates,
	)
	request := map[string]any{
		"incident": map[string]any{
			"id":          incident.ID,
			"title":       incident.Title,
			"service":     incident.Service,
			"severity":    incident.Severity,
			"environment": "local",
		},
		"evidence":                 evidence,
		"deterministic_candidates": candidates,
		"confidence":               confidence,
		"topology":                 topologyAnalysis,
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.aiServiceURL+"/v1/remediation/suggest", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	s.authorizeAIRequest(req)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("governed AI suggestion returned %s", resp.Status)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if err := validateAdvisoryResponse(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func validateAdvisoryResponse(payload map[string]any) error {
	executed, hasExecuted := payload["executed"].(bool)
	advisoryOnly, hasAdvisoryOnly := payload["advisory_only"].(bool)
	if !hasExecuted || executed || !hasAdvisoryOnly || !advisoryOnly {
		return fmt.Errorf("AI suggestion violated advisory-only contract")
	}
	return nil
}

func (s *Service) authorizeAIRequest(req *http.Request) {
	if s.aiServiceToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.aiServiceToken)
	}
}

func appendEvidence(items []string, values ...string) []string {
	existing := map[string]struct{}{}
	for _, item := range items {
		existing[item] = struct{}{}
	}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if _, ok := existing[value]; ok {
			continue
		}
		items = append(items, value)
		existing[value] = struct{}{}
	}
	return items
}
