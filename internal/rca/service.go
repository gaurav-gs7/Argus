package rca

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gauravgs7/argus/internal/correlation"
	"github.com/gauravgs7/argus/internal/evidence"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/telemetry"
)

const (
	// BaselineConfidence is reported when no failure mode is identified.
	BaselineConfidence = 0.35
	// AlertMatchScore is what one firing alert naming a failure mode is worth
	// on its own. The source cap below keeps it under 0.55 until a backend agrees.
	AlertMatchScore = 0.45
	// RefutationFactor scales the weight of probes whose backend answered and
	// contradicted the hypothesis.
	RefutationFactor = 0.5

	insufficientHypothesis = "Insufficient evidence for a high-confidence root cause"
	alertSource            = "alertmanager"
)

// SourceCap bounds confidence by the number of independent sources that
// support a hypothesis: the alert itself, plus Prometheus and Loki when at
// least one cause-specific (non-symptom) probe on that backend corroborated.
func SourceCap(sources int) float64 {
	switch {
	case sources <= 1:
		return 0.55
	case sources == 2:
		return 0.80
	default:
		return 0.95
	}
}

type Service struct {
	store          *incidents.Store
	aiServiceURL   string
	aiServiceToken string
	metrics        *telemetry.Metrics
	httpClient     *http.Client
	correlator     *correlation.Correlator
	collector      *evidence.Collector
	now            func() time.Time
}

type Candidate struct {
	ActionType       string         `json:"action_type"`
	Target           string         `json:"target"`
	Parameters       map[string]any `json:"parameters,omitempty"`
	Risk             string         `json:"risk"`
	RequiresApproval bool           `json:"requires_approval"`
}

// ruleEvidence is the probe run for one matched rule.
type ruleEvidence struct {
	Service string
	Results []evidence.Result
}

type analysis struct {
	RuleID     correlation.RuleID
	Summary    string
	Hypothesis string
	Confidence float64
	Evidence   []string
	Factors    []string
	Candidates []Candidate
	Items      []incidents.RCAEvidence
	Score      incidents.RCAScore
}

// NewService wires RCA. A nil collector means no backends are configured:
// alerts can still be matched, but nothing is ever reported as corroborated.
func NewService(store *incidents.Store, aiServiceURL, aiServiceToken string, metrics *telemetry.Metrics, collector *evidence.Collector) *Service {
	return &Service{
		store:          store,
		aiServiceURL:   strings.TrimRight(aiServiceURL, "/"),
		aiServiceToken: aiServiceToken,
		metrics:        metrics,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		correlator:     correlation.New(),
		collector:      collector,
		now:            time.Now,
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

	result := s.analyze(ctx, incident, signals, topologyAnalysis)
	for _, event := range probeTimelineEvents(incidentID, result.Items) {
		_ = s.store.AddTimelineEvent(ctx, event)
	}

	report := incidents.RCAReport{
		IncidentID:           incidentID,
		DeterministicSummary: result.Summary,
		PrimaryHypothesis:    result.Hypothesis,
		ContributingFactors:  result.Factors,
		Evidence:             result.Evidence,
		Confidence:           result.Confidence,
		ModelBackend:         "deterministic",
		Topology:             topologyAnalysis,
		EvidenceItems:        result.Items,
		Score:                result.Score,
	}

	if llmSummary, backend, model, err := s.callAdvisor(
		ctx, incident, result.Evidence, result.Hypothesis, result.Confidence, topologyAnalysis,
	); err == nil {
		report.LLMSummary = llmSummary
		report.ModelBackend = backend
		report.ModelName = model
	}

	if err := s.store.SaveRCAReport(ctx, report); err != nil {
		s.metrics.RCAJobsTotal.WithLabelValues("failed").Inc()
		return incidents.RCAReport{}, nil, err
	}

	// Advance only: regenerating RCA on an incident that has moved on (or is
	// resolved) records the report without rewinding the incident.
	_, _, _ = s.store.TransitionIncident(ctx, incidentID, incidents.StatusRCAGenerated)
	s.metrics.RCAJobsTotal.WithLabelValues("succeeded").Inc()
	s.metrics.RCADuration.WithLabelValues(report.ModelBackend).Observe(time.Since(start).Seconds())
	s.metrics.RCAConfidence.WithLabelValues(result.Hypothesis).Observe(result.Confidence)

	saved, err := s.store.GetLatestRCAReport(ctx, incidentID)
	if err != nil {
		return report, result.Candidates, nil
	}
	return saved, result.Candidates, nil
}

// analyze matches signals to rules, queries the configured backends for each
// matched rule, and scores the result. Given the same signals and the same
// probe results the outcome is identical; the probe results are persisted with
// the report so every score can be replayed.
func (s *Service) analyze(ctx context.Context, incident incidents.Incident, signals []incidents.Signal, topologyAnalysis incidents.IncidentTopology) analysis {
	matches := s.correlator.Match(incident, signals)
	runs := s.collectEvidence(ctx, incident, matches)
	result := scoreHypotheses(incident, matches, runs)
	result = applyTopologyFallback(incident, topologyAnalysis, result)
	return enrichWithTopology(result, topologyAnalysis)
}

func (s *Service) collectEvidence(ctx context.Context, incident incidents.Incident, matches []correlation.Match) map[correlation.RuleID]ruleEvidence {
	primary := primaryMatches(incident, matches)
	runs := make(map[correlation.RuleID]ruleEvidence, len(primary))
	at := s.now().UTC()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, match := range primary {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results := s.collector.Run(ctx, match.Rule.Probes, match.Service, at)
			mu.Lock()
			runs[match.RuleID] = ruleEvidence{Service: match.Service, Results: results}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return runs
}

// primaryMatches picks one match per rule to scope probes: the one observed on
// the incident's own service, otherwise the earliest.
func primaryMatches(incident incidents.Incident, matches []correlation.Match) []correlation.Match {
	chosen := map[correlation.RuleID]correlation.Match{}
	var order []correlation.RuleID
	for _, match := range matches {
		existing, ok := chosen[match.RuleID]
		if !ok {
			order = append(order, match.RuleID)
			chosen[match.RuleID] = match
			continue
		}
		if existing.Service != incident.Service && match.Service == incident.Service {
			chosen[match.RuleID] = match
		}
	}
	out := make([]correlation.Match, 0, len(order))
	for _, id := range order {
		out = append(out, chosen[id])
	}
	return out
}

type hypothesisScore struct {
	rule         correlation.Rule
	matches      []correlation.Match
	run          ruleEvidence
	corroborated float64
	refuted      float64
	sources      []string
	raw          float64
	cap          float64
	confidence   float64
	contradicted bool
}

func scoreRule(rule correlation.Rule, matches []correlation.Match, run ruleEvidence) hypothesisScore {
	score := hypothesisScore{rule: rule, matches: matches, run: run}
	backends := map[string]struct{}{}
	for _, result := range run.Results {
		switch result.Status {
		case evidence.StatusCorroborated:
			score.corroborated += result.Weight
			if !result.Symptom {
				backends[string(result.Backend)] = struct{}{}
			}
		case evidence.StatusRefuted:
			score.refuted += result.Weight
		}
	}
	score.sources = []string{alertSource}
	for backend := range backends {
		score.sources = append(score.sources, backend)
	}
	sort.Strings(score.sources[1:])
	score.raw = round4(AlertMatchScore + score.corroborated - RefutationFactor*score.refuted)
	score.cap = SourceCap(len(score.sources))
	score.confidence = clamp(score.raw, BaselineConfidence, score.cap)
	score.contradicted = score.refuted > score.corroborated
	return score
}

func scoreHypotheses(incident incidents.Incident, matches []correlation.Match, runs map[correlation.RuleID]ruleEvidence) analysis {
	byRule := map[correlation.RuleID][]correlation.Match{}
	var order []correlation.RuleID
	for _, match := range matches {
		if _, ok := byRule[match.RuleID]; !ok {
			order = append(order, match.RuleID)
		}
		byRule[match.RuleID] = append(byRule[match.RuleID], match)
	}
	if len(order) == 0 {
		return insufficientEvidence(incident)
	}

	scores := make([]hypothesisScore, 0, len(order))
	var items []incidents.RCAEvidence
	for _, id := range order {
		ruleMatches := byRule[id]
		score := scoreRule(ruleMatches[0].Rule, ruleMatches, runs[id])
		scores = append(scores, score)
		items = append(items, evidenceItems(score)...)
	}
	sort.SliceStable(scores, func(i, j int) bool {
		a, b := scores[i], scores[j]
		if a.contradicted != b.contradicted {
			return !a.contradicted
		}
		if a.confidence != b.confidence {
			return a.confidence > b.confidence
		}
		if len(a.sources) != len(b.sources) {
			return len(a.sources) > len(b.sources)
		}
		return a.rule.Hypothesis < b.rule.Hypothesis
	})

	best := scores[0]
	result := analysis{
		RuleID:     best.rule.ID,
		Hypothesis: best.rule.Hypothesis,
		Confidence: best.confidence,
		Evidence:   supportingEvidence(best),
		Factors:    scoreFactors(best),
		Items:      items,
		Score: incidents.RCAScore{
			RuleID:            string(best.rule.ID),
			Baseline:          BaselineConfidence,
			AlertMatch:        AlertMatchScore,
			Corroborated:      round4(best.corroborated),
			Refuted:           round4(best.refuted),
			RefutationPenalty: round4(RefutationFactor * best.refuted),
			Raw:               best.raw,
			Sources:           best.sources,
			SourceCap:         best.cap,
			Contradicted:      best.contradicted,
			Final:             best.confidence,
		},
	}
	service := best.run.Service
	if service == "" {
		service = best.matches[0].Service
	}
	if best.contradicted {
		result.Summary = fmt.Sprintf(
			"%s matched the %s rule, but backend evidence contradicts it (corroborated %.2f < refuted %.2f). Confidence %.4f; only diagnostics are proposed.",
			best.matches[0].AlertName, best.rule.Hypothesis, best.corroborated, best.refuted, best.confidence,
		)
		result.Candidates = []Candidate{diagnostics(service)}
		return result
	}
	result.Summary = fmt.Sprintf(
		"%s likely impacted %s. Confidence %.4f = min(max(%.2f alert match + %.2f corroborated - %.2f refutation penalty, %.2f), %.2f cap for %d independent source(s): %s).",
		best.rule.Hypothesis, service, best.confidence, AlertMatchScore, best.corroborated,
		RefutationFactor*best.refuted, BaselineConfidence, best.cap, len(best.sources), strings.Join(best.sources, ", "),
	)
	candidates, skipped := renderCandidates(best)
	result.Candidates = candidates
	result.Factors = append(result.Factors, skipped...)
	return result
}

func insufficientEvidence(incident incidents.Incident) analysis {
	return analysis{
		Summary:    "Signals have been collected, but no alert names a known failure mode.",
		Hypothesis: insufficientHypothesis,
		Confidence: BaselineConfidence,
		Evidence:   []string{"no alert matched a failure-mode rule by alertname or " + correlation.FailureModeLabel + " label"},
		Factors:    []string{"no corroboration probes were run"},
		Candidates: []Candidate{diagnostics(incident.Service)},
		Items:      []incidents.RCAEvidence{},
		Score:      incidents.RCAScore{Baseline: BaselineConfidence, Sources: []string{}, Final: BaselineConfidence},
	}
}

func diagnostics(service string) Candidate {
	return Candidate{ActionType: "collect_diagnostics", Target: service, Risk: "low", RequiresApproval: false}
}

func supportingEvidence(score hypothesisScore) []string {
	var out []string
	for _, match := range score.matches {
		out = appendEvidence(out, fmt.Sprintf("%s: alert %s fired for %s", alertSource, match.AlertName, match.Service))
	}
	for _, result := range score.run.Results {
		if result.Status == evidence.StatusCorroborated {
			source := string(result.Backend)
			if result.Symptom {
				source += " (symptom)"
			}
			out = appendEvidence(out, fmt.Sprintf("%s: %s (observed %s %s %s)",
				source, result.Claim, formatValue(*result.Value), result.Comparator, formatValue(result.Threshold)))
		}
	}
	return out
}

func scoreFactors(score hypothesisScore) []string {
	factors := []string{fmt.Sprintf("alert match via %s (+%.2f)", score.matches[0].Reason, AlertMatchScore)}
	for _, result := range score.run.Results {
		label := fmt.Sprintf("%s probe %s", result.Backend, result.ProbeID)
		if result.Symptom {
			label += " (symptom)"
		}
		switch result.Status {
		case evidence.StatusCorroborated:
			factors = append(factors, fmt.Sprintf("%s corroborated: observed %s %s %s (+%.2f)",
				label, formatValue(*result.Value), result.Comparator, formatValue(result.Threshold), result.Weight))
		case evidence.StatusRefuted:
			factors = append(factors, fmt.Sprintf("%s refuted: observed %s, expected %s %s (-%.2f)",
				label, formatValue(*result.Value), result.Comparator, formatValue(result.Threshold), RefutationFactor*result.Weight))
		case evidence.StatusNoData:
			factors = append(factors, label+" returned no matching series (not counted)")
		default:
			factors = append(factors, fmt.Sprintf("%s unavailable: %s (not counted)", label, result.Error))
		}
	}
	factors = append(factors, fmt.Sprintf("independent sources: %s (cap %.2f)", strings.Join(score.sources, ", "), score.cap))
	return factors
}

func evidenceItems(score hypothesisScore) []incidents.RCAEvidence {
	var items []incidents.RCAEvidence
	seen := map[string]struct{}{}
	for _, match := range score.matches {
		key := match.AlertName + "|" + match.Service
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		items = append(items, incidents.RCAEvidence{
			RuleID: string(score.rule.ID), Kind: "alert", Source: alertSource, Reference: match.AlertName,
			Service: match.Service, Status: "matched", Weight: AlertMatchScore,
			Claim: "alert matched by " + match.Reason, ObservedAt: match.ObservedAt.UTC(),
		})
	}
	for _, result := range score.run.Results {
		threshold := result.Threshold
		items = append(items, incidents.RCAEvidence{
			RuleID: string(score.rule.ID), Kind: "probe", Source: string(result.Backend), Reference: result.ProbeID,
			Service: score.run.Service, Query: result.Query, Status: string(result.Status), Value: result.Value,
			Comparator: string(result.Comparator), Threshold: &threshold, Weight: result.Weight,
			Claim: result.Claim, Symptom: result.Symptom, Error: result.Error, ObservedAt: result.EvaluatedAt,
		})
	}
	return items
}

// probeTimelineEvents records backend observations (not alerts, which ingestion
// already put on the timeline).
func probeTimelineEvents(incidentID string, items []incidents.RCAEvidence) []incidents.TimelineEvent {
	var events []incidents.TimelineEvent
	for _, item := range items {
		if item.Kind != "probe" || item.Value == nil {
			continue
		}
		events = append(events, incidents.TimelineEvent{
			IncidentID: incidentID,
			EventType:  "probe_" + item.Status,
			Source:     item.Source,
			Summary:    fmt.Sprintf("%s: %s (observed %s, threshold %s %s)", item.Reference, item.Claim, formatValue(*item.Value), item.Comparator, formatValue(*item.Threshold)),
			Evidence:   map[string]any{"rule_id": item.RuleID, "probe_id": item.Reference, "query": item.Query, "value": *item.Value, "service": item.Service},
			Confidence: 1,
			OccurredAt: item.ObservedAt,
		})
	}
	return events
}

// renderCandidates derives remediation targets from the alert that matched the
// rule. Candidates without a safe target are dropped with a recorded reason;
// if none survive, only diagnostics are proposed.
func renderCandidates(score hypothesisScore) ([]Candidate, []string) {
	match := score.matches[0]
	for _, candidate := range score.matches {
		if candidate.Service == score.run.Service {
			match = candidate
			break
		}
	}
	var candidates []Candidate
	var skipped []string
	for _, template := range score.rule.Remediations {
		target, parameters, reason := template.Render(match.Service, match.Labels)
		if reason != "" {
			skipped = append(skipped, fmt.Sprintf("remediation %s not proposed: %s", template.ActionType, reason))
			continue
		}
		if len(parameters) == 0 {
			parameters = nil
		}
		candidates = append(candidates, Candidate{
			ActionType: template.ActionType, Target: target, Parameters: parameters,
			Risk: template.Risk, RequiresApproval: template.Risk != "low",
		})
	}
	if len(candidates) == 0 {
		candidates = []Candidate{diagnostics(match.Service)}
	}
	return candidates, skipped
}

func applyTopologyFallback(incident incidents.Incident, topologyAnalysis incidents.IncidentTopology, result analysis) analysis {
	if result.Hypothesis != insufficientHypothesis ||
		topologyAnalysis.SuppressedAlertCount == 0 || topologyAnalysis.RootService == "" {
		return result
	}

	rootEvidence := "shared dependency inferred from downstream alert paths"
	result.Confidence = 0.58
	if !topologyAnalysis.RootInferred {
		rootEvidence = "root service emitted alert evidence in the incident window"
		result.Confidence = 0.72
	}
	result.Hypothesis = fmt.Sprintf("Failure at root dependency %s", topologyAnalysis.RootService)
	result.Summary = fmt.Sprintf(
		"Topology places the failure domain for incident %q at %s. It establishes the affected dependency but not the component-level failure mode.",
		incident.Title,
		topologyAnalysis.RootService,
	)
	result.Evidence = []string{
		rootEvidence,
		fmt.Sprintf("%d alerts across %d services share dependency root %s", topologyAnalysis.AlertCount, len(topologyAnalysis.AffectedServices), topologyAnalysis.RootService),
	}
	result.Factors = []string{"specific metric, log, or trace evidence is still required to identify the failure mode"}
	result.Candidates = []Candidate{diagnostics(topologyAnalysis.RootService)}
	result.Score.Sources = []string{alertSource, "topology"}
	result.Score.SourceCap = SourceCap(2)
	result.Score.Final = result.Confidence
	return result
}

func enrichWithTopology(result analysis, topologyAnalysis incidents.IncidentTopology) analysis {
	if topologyAnalysis.SuppressedAlertCount == 0 {
		return result
	}
	rootQualifier := "observed"
	if topologyAnalysis.RootInferred {
		rootQualifier = "inferred"
	} else if result.RuleID != "" && !result.Score.Contradicted {
		// An observed root confirms where the matched failure happened. It is
		// operator-managed graph data, so it nudges confidence but never past
		// the cap set by independent evidence sources.
		adjusted := clamp(result.Confidence+0.03, BaselineConfidence, result.Score.SourceCap)
		result.Score.TopologyAdjustment = round4(adjusted - result.Confidence)
		result.Confidence = adjusted
		result.Score.Final = adjusted
	}
	result.Summary = fmt.Sprintf(
		"%s Topology correlation identified %s root service %s, grouped %d alerts across %d services, and suppressed %d downstream alerts.",
		result.Summary,
		rootQualifier,
		topologyAnalysis.RootService,
		topologyAnalysis.AlertCount,
		len(topologyAnalysis.AffectedServices),
		topologyAnalysis.SuppressedAlertCount,
	)
	result.Evidence = appendEvidence(
		result.Evidence,
		fmt.Sprintf("%d downstream alerts were suppressed behind root service %s", topologyAnalysis.SuppressedAlertCount, topologyAnalysis.RootService),
		fmt.Sprintf("blast radius includes %s", strings.Join(topologyAnalysis.AffectedServices, ", ")),
	)
	for _, path := range topologyAnalysis.Paths {
		result.Factors = appendEvidence(result.Factors, "dependency path: "+strings.Join(path.Services, " -> "))
	}
	return result
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

func round4(value float64) float64 {
	return float64(int64(value*10000+0.5*sign(value))) / 10000
}

func sign(value float64) float64 {
	if value < 0 {
		return -1
	}
	return 1
}

func formatValue(value float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.4f", value), "0"), ".")
}

func (s *Service) callAdvisor(
	ctx context.Context,
	incident incidents.Incident,
	evidenceLines []string,
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
		"evidence":           evidenceLines,
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
	result := s.analyze(ctx, incident, signals, topologyAnalysis)
	request := map[string]any{
		"incident": map[string]any{
			"id":          incident.ID,
			"title":       incident.Title,
			"service":     incident.Service,
			"severity":    incident.Severity,
			"environment": incident.Environment,
		},
		"evidence":                 result.Evidence,
		"deterministic_candidates": result.Candidates,
		"confidence":               result.Confidence,
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
