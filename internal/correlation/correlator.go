package correlation

import (
	"fmt"
	"sort"
	"time"

	"github.com/gauravgs7/argus/internal/incidents"
)

// Match records that a persisted alert signal names a known failure mode.
type Match struct {
	RuleID     RuleID
	Rule       Rule
	SignalID   string
	AlertName  string
	Service    string
	Labels     map[string]string
	ObservedAt time.Time
	Reason     string
}

type Correlator struct {
	rules       []Rule
	byAlertName map[string]int
	byID        map[RuleID]int
}

// New returns a correlator over the default rule table. It panics if the
// compiled table is invalid; that is caught by unit tests, not production.
func New() *Correlator {
	correlator, err := NewWithRules(DefaultRules())
	if err != nil {
		panic(err)
	}
	return correlator
}

func NewWithRules(rules []Rule) (*Correlator, error) {
	if err := ValidateRules(rules); err != nil {
		return nil, err
	}
	c := &Correlator{rules: rules, byAlertName: map[string]int{}, byID: map[RuleID]int{}}
	for i, rule := range rules {
		c.byID[rule.ID] = i
		for _, name := range rule.AlertNames {
			c.byAlertName[name] = i
		}
	}
	return c, nil
}

func (c *Correlator) Rules() []Rule { return c.rules }

// Match maps each signal to at most one rule using structured identity only:
// an explicit argus_failure_mode label wins, then an exact alertname match.
// Annotation text, summaries, and service names are never used to select a
// rule. Matches are returned in observation order.
func (c *Correlator) Match(incident incidents.Incident, signals []incidents.Signal) []Match {
	var matches []Match
	for _, signal := range signals {
		labels := SignalLabels(signal)
		alertName := signal.Name
		if alertName == "" {
			alertName = labels["alertname"]
		}

		index, reason := -1, ""
		if mode := labels[FailureModeLabel]; mode != "" {
			if i, ok := c.byID[RuleID(mode)]; ok {
				index, reason = i, fmt.Sprintf("label %s=%s", FailureModeLabel, mode)
			}
		}
		if index < 0 {
			if i, ok := c.byAlertName[alertName]; ok {
				index, reason = i, "alertname "+alertName
			}
		}
		if index < 0 {
			continue
		}

		observedAt := signal.ObservedAt
		if observedAt.IsZero() {
			observedAt = incident.StartedAt
		}
		matches = append(matches, Match{
			RuleID:     c.rules[index].ID,
			Rule:       c.rules[index],
			SignalID:   signal.ID,
			AlertName:  alertName,
			Service:    SignalService(incident, signal, labels),
			Labels:     labels,
			ObservedAt: observedAt,
			Reason:     reason,
		})
	}
	sort.SliceStable(matches, func(i, j int) bool {
		return matches[i].ObservedAt.Before(matches[j].ObservedAt)
	})
	return matches
}

// SignalLabels extracts the alert label set from a persisted signal body.
func SignalLabels(signal incidents.Signal) map[string]string {
	labels := map[string]string{}
	switch raw := signal.Body["labels"].(type) {
	case map[string]string:
		for key, value := range raw {
			labels[key] = value
		}
	case map[string]any:
		for key, value := range raw {
			if text, ok := value.(string); ok {
				labels[key] = text
			}
		}
	}
	return labels
}

// SignalService is the service a signal was observed on: the alert's service
// label, then the persisted topology observation, then the incident service.
func SignalService(incident incidents.Incident, signal incidents.Signal, labels map[string]string) string {
	if service := labels["service"]; service != "" {
		return service
	}
	if topology, ok := signal.Body["topology"].(map[string]any); ok {
		if service, ok := topology["observed_service"].(string); ok && service != "" {
			return service
		}
	}
	return incident.Service
}
