package incidents

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
)

type ServiceManager struct {
	store          *Store
	auditor        *audit.Service
	groupingWindow time.Duration
}

func NewServiceManager(store *Store, auditor *audit.Service, groupingWindow time.Duration) *ServiceManager {
	return &ServiceManager{
		store:          store,
		auditor:        auditor,
		groupingWindow: groupingWindow,
	}
}

func BuildDedupeKey(service, alertName, environment, fingerprint string) string {
	return fmt.Sprintf("%s:%s:%s:%s", service, alertName, environment, fingerprint)
}

func CanTransition(from, to string) bool {
	allowed := map[string]map[string]bool{
		StatusDetected: {
			StatusTriaged:       true,
			StatusInvestigating: true,
			StatusResolved:      true,
			StatusCancelled:     true,
		},
		StatusTriaged: {
			StatusInvestigating: true,
			StatusResolved:      true,
			StatusCancelled:     true,
		},
		StatusInvestigating: {
			StatusRCAGenerated: true,
			StatusResolved:     true,
			StatusFailed:       true,
		},
		StatusRCAGenerated: {
			StatusRemediationProposed: true,
			StatusResolved:            true,
		},
		StatusRemediationProposed: {
			StatusAwaitingApproval: true,
			StatusRemediating:      true,
			StatusResolved:         true,
		},
		StatusAwaitingApproval: {
			StatusRemediating: true,
			StatusCancelled:   true,
		},
		StatusRemediating: {
			StatusMitigated: true,
			StatusFailed:    true,
		},
		StatusMitigated: {
			StatusResolved: true,
		},
	}
	return allowed[from][to]
}

func (m *ServiceManager) CreateManual(ctx context.Context, req ManualIncidentRequest, actor string) (Incident, error) {
	incident, err := m.store.CreateManualIncident(ctx, req)
	if err != nil {
		return Incident{}, err
	}

	_ = m.auditor.Write(ctx, audit.Entry{
		ActorID:      actor,
		ActorType:    "user",
		Action:       "incident.created",
		ResourceType: "incident",
		ResourceID:   incident.ID,
		AfterState: map[string]any{
			"status":   incident.Status,
			"severity": incident.Severity,
		},
	})

	return incident, nil
}

func (m *ServiceManager) IngestAlertmanager(ctx context.Context, payload AlertmanagerWebhook, actor string) ([]Incident, error) {
	var incidentsOut []Incident
	for _, alert := range payload.Alerts {
		service := firstNonEmpty(alert.Labels["service"], payload.CommonLabels["service"], "unknown-service")
		alertName := firstNonEmpty(alert.Labels["alertname"], payload.CommonLabels["alertname"], "unknown-alert")
		environment := firstNonEmpty(alert.Labels["environment"], payload.CommonLabels["environment"], "local")
		severity := firstNonEmpty(alert.Labels["severity"], payload.CommonLabels["severity"], "sev3")
		fingerprint := firstNonEmpty(alert.Fingerprint, alertName)
		summary := firstNonEmpty(alert.Annotations["summary"], payload.CommonAnnotations["summary"], alertName)
		dedupeKey := BuildDedupeKey(service, alertName, environment, fingerprint)

		incident, err := m.store.FindOpenByDedupeKey(ctx, dedupeKey, m.groupingWindow)
		if err != nil {
			return nil, err
		}

		if incident == nil {
			created, err := m.store.CreateAlertIncident(ctx, summary, service, severity, dedupeKey, fingerprint, summary, alert.StartsAt)
			if err != nil {
				return nil, err
			}
			incident = &created

			_ = m.auditor.Write(ctx, audit.Entry{
				ActorID:      actor,
				ActorType:    "system",
				Action:       "incident.detected",
				ResourceType: "incident",
				ResourceID:   incident.ID,
				AfterState: map[string]any{
					"status":   incident.Status,
					"severity": incident.Severity,
					"service":  incident.Service,
				},
			})
		}

		serviceRecord, err := m.store.EnsureService(ctx, service)
		if err != nil {
			return nil, err
		}

		if err := m.store.AddSignal(ctx, Signal{
			IncidentID: incident.ID,
			ServiceID:  serviceRecord.ID,
			Source:     "alertmanager",
			SignalType: "alert",
			Severity:   severity,
			Name:       alertName,
			Body: map[string]any{
				"labels":      alert.Labels,
				"annotations": alert.Annotations,
				"generator":   alert.GeneratorURL,
				"status":      alert.Status,
			},
			ObservedAt: alert.StartsAt,
		}); err != nil {
			return nil, err
		}

		if err := m.store.AddTimelineEvent(ctx, TimelineEvent{
			IncidentID: incident.ID,
			EventType:  "alert_received",
			Source:     "alertmanager",
			Summary:    summary,
			Evidence: map[string]any{
				"alert_name":  alertName,
				"service":     service,
				"severity":    severity,
				"environment": environment,
			},
			Confidence: 1.0,
			OccurredAt: alert.StartsAt,
		}); err != nil {
			return nil, err
		}

		incidentsOut = append(incidentsOut, *incident)
	}

	return incidentsOut, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
