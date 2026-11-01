// Package evidence runs bounded corroboration probes against observability
// backends. A probe only becomes evidence when a configured backend actually
// answered it; missing, failing, or unconfigured backends are reported as
// unavailable and never contribute to RCA confidence.
package evidence

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Backend string

const (
	Prometheus Backend = "prometheus"
	Loki       Backend = "loki"
)

type Comparator string

const (
	AtLeast  Comparator = ">="
	Above    Comparator = ">"
	AtMost   Comparator = "<="
	Below    Comparator = "<"
	Variable            = "{{service}}"
)

// Probe is one instant query whose result either supports or contradicts a
// hypothesis. Query is a template; the only substitution is {{service}}.
type Probe struct {
	ID         string     `json:"id"`
	Backend    Backend    `json:"backend"`
	Query      string     `json:"query"`
	Comparator Comparator `json:"comparator"`
	Threshold  float64    `json:"threshold"`
	Weight     float64    `json:"weight"`
	Claim      string     `json:"claim"`
}

type Status string

const (
	// StatusCorroborated: the backend returned a sample and the comparison held.
	StatusCorroborated Status = "corroborated"
	// StatusRefuted: the backend returned a sample and the comparison did not hold.
	StatusRefuted Status = "refuted"
	// StatusNoData: the backend answered but no series matched (or the value was NaN).
	StatusNoData Status = "no_data"
	// StatusUnavailable: the backend is not configured, failed, timed out, or the
	// probe could not be rendered safely. Nothing was observed.
	StatusUnavailable Status = "unavailable"
)

type Result struct {
	ProbeID     string     `json:"probe_id"`
	Backend     Backend    `json:"backend"`
	Query       string     `json:"query"`
	Comparator  Comparator `json:"comparator"`
	Threshold   float64    `json:"threshold"`
	Weight      float64    `json:"weight"`
	Claim       string     `json:"claim"`
	Status      Status     `json:"status"`
	Value       *float64   `json:"value,omitempty"`
	Error       string     `json:"error,omitempty"`
	EvaluatedAt time.Time  `json:"evaluated_at"`
}

// Querier evaluates an instant query. ok is false when the backend answered
// with no usable samples.
type Querier interface {
	Instant(ctx context.Context, query string, at time.Time) (value float64, ok bool, err error)
}

type Collector struct {
	backends map[Backend]Querier
	timeout  time.Duration
}

// NewCollector builds a collector. Nil queriers are treated as unconfigured.
func NewCollector(timeout time.Duration, backends map[Backend]Querier) *Collector {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	configured := make(map[Backend]Querier, len(backends))
	for backend, querier := range backends {
		if querier != nil {
			configured[backend] = querier
		}
	}
	return &Collector{backends: configured, timeout: timeout}
}

func (c *Collector) Configured(backend Backend) bool {
	if c == nil {
		return false
	}
	_, ok := c.backends[backend]
	return ok
}

// Run evaluates every probe for one service concurrently and returns results
// in probe order.
func (c *Collector) Run(ctx context.Context, probes []Probe, service string, at time.Time) []Result {
	results := make([]Result, len(probes))
	var wg sync.WaitGroup
	for i, probe := range probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = c.runOne(ctx, probe, service, at)
		}()
	}
	wg.Wait()
	return results
}

func (c *Collector) runOne(ctx context.Context, probe Probe, service string, at time.Time) Result {
	result := Result{
		ProbeID:     probe.ID,
		Backend:     probe.Backend,
		Query:       probe.Query,
		Comparator:  probe.Comparator,
		Threshold:   probe.Threshold,
		Weight:      probe.Weight,
		Claim:       probe.Claim,
		Status:      StatusUnavailable,
		EvaluatedAt: at.UTC(),
	}
	query, err := Render(probe.Query, service)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Query = query

	var querier Querier
	if c != nil {
		querier = c.backends[probe.Backend]
	}
	if querier == nil {
		result.Error = fmt.Sprintf("%s backend not configured", probe.Backend)
		return result
	}

	probeCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	value, ok, err := querier.Instant(probeCtx, query, at)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if !ok || math.IsNaN(value) || math.IsInf(value, 0) {
		result.Status = StatusNoData
		return result
	}
	result.Value = &value
	if Compare(value, probe.Comparator, probe.Threshold) {
		result.Status = StatusCorroborated
	} else {
		result.Status = StatusRefuted
	}
	return result
}

func Compare(value float64, comparator Comparator, threshold float64) bool {
	switch comparator {
	case AtLeast:
		return value >= threshold
	case Above:
		return value > threshold
	case AtMost:
		return value <= threshold
	case Below:
		return value < threshold
	default:
		return false
	}
}

// Label values come from untrusted alert payloads. Only values that cannot
// break out of a quoted PromQL/LogQL matcher are substituted.
var safeLabelValue = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?$`)

// Render substitutes the service into a probe template.
func Render(template, service string) (string, error) {
	if !safeLabelValue.MatchString(service) {
		return "", fmt.Errorf("service %q is not a safe label value; probe not executed", service)
	}
	rendered := strings.ReplaceAll(template, Variable, service)
	if strings.Contains(rendered, "{{") {
		return "", fmt.Errorf("probe template has an unknown placeholder")
	}
	return rendered, nil
}

// ValidateProbe checks a probe definition from the trusted rule table.
func ValidateProbe(probe Probe) error {
	switch {
	case strings.TrimSpace(probe.ID) == "":
		return fmt.Errorf("probe id is required")
	case probe.Backend != Prometheus && probe.Backend != Loki:
		return fmt.Errorf("probe %s: unknown backend %q", probe.ID, probe.Backend)
	case !strings.Contains(probe.Query, Variable):
		return fmt.Errorf("probe %s: query must be scoped with %s", probe.ID, Variable)
	case probe.Weight <= 0 || probe.Weight > 0.5:
		return fmt.Errorf("probe %s: weight must be in (0, 0.5]", probe.ID)
	case strings.TrimSpace(probe.Claim) == "":
		return fmt.Errorf("probe %s: claim is required", probe.ID)
	}
	switch probe.Comparator {
	case AtLeast, Above, AtMost, Below:
	default:
		return fmt.Errorf("probe %s: unknown comparator %q", probe.ID, probe.Comparator)
	}
	if _, err := Render(probe.Query, "probe-check"); err != nil {
		return fmt.Errorf("probe %s: %w", probe.ID, err)
	}
	return nil
}
