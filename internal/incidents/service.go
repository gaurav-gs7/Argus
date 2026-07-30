package incidents

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/topology"
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
	result, err := m.IngestAlertmanagerWithResult(ctx, payload, actor)
	return result.Incidents, err
}

func (m *ServiceManager) IngestAlertmanagerWithResult(ctx context.Context, payload AlertmanagerWebhook, actor string) (IngestionResult, error) {
	unlock, err := m.store.LockIncidentIngestion(ctx)
	if err != nil {
		return IngestionResult{}, err
	}
	defer unlock()

	alerts, err := m.normalizeAlerts(ctx, payload)
	if err != nil {
		return IngestionResult{}, err
	}
	if len(alerts) == 0 {
		return IngestionResult{Incidents: []Incident{}}, nil
	}
	dependencies, err := m.store.ListServiceDependencies(ctx)
	if err != nil {
		return IngestionResult{}, err
	}
	graph := topology.New(dependencies)
	groups := topologyGroupsByEnvironment(graph, alerts)
	openIncidents, err := m.store.ListOpenIncidents(ctx, m.groupingWindow)
	if err != nil {
		return IngestionResult{}, err
	}

	stats := IngestionStats{AlertCount: len(alerts)}
	incidentsOut := make([]Incident, 0, len(groups))
	for _, group := range groups {
		groupAlerts := alertsForGroup(alerts, group)
		if len(groupAlerts) == 0 {
			continue
		}
		rootAlert := rootAlertForGroup(groupAlerts, group.Root)
		incident, created, promoted, err := m.findOrCreateTopologyIncident(ctx, graph, group, rootAlert, openIncidents)
		if err != nil {
			return IngestionResult{}, err
		}
		rootInferred := group.Inferred
		if !created && !promoted {
			analysis, err := m.store.GetIncidentTopology(ctx, incident.ID)
			if err != nil {
				return IngestionResult{}, err
			}
			rootInferred = analysis.RootInferred
		}
		stats.IncidentGroups++
		stats.AffectedServiceCount += len(group.Members)
		if rootInferred {
			stats.InferredRoots++
		} else {
			stats.ObservedRoots++
		}
		if created {
			_ = m.auditor.Write(ctx, audit.Entry{
				ActorID:      actor,
				ActorType:    "system",
				Action:       "incident.detected",
				ResourceType: "incident",
				ResourceID:   incident.ID,
				AfterState: map[string]any{
					"status":            incident.Status,
					"severity":          incident.Severity,
					"service":           incident.Service,
					"topology_root":     incident.Service,
					"root_inferred":     rootInferred,
					"affected_services": group.Members,
				},
			})
		}
		if promoted {
			_ = m.auditor.Write(ctx, audit.Entry{
				ActorID:      actor,
				ActorType:    "system",
				Action:       "incident.root_promoted",
				ResourceType: "incident",
				ResourceID:   incident.ID,
				AfterState: map[string]any{
					"root_service":  incident.Service,
					"root_inferred": rootInferred,
				},
			})
		}

		for _, normalized := range groupAlerts {
			path, ok := graph.Path(normalized.service, incident.Service)
			if !ok {
				path = topology.Path{
					From:     normalized.service,
					To:       incident.Service,
					Services: []string{normalized.service},
				}
			}
			suppressed := normalized.service != incident.Service
			if err := m.attachTopologyAlert(ctx, *incident, normalized, path, rootInferred, suppressed); err != nil {
				return IngestionResult{}, err
			}
			if suppressed {
				stats.SuppressedAlertCount++
				_ = m.auditor.Write(ctx, audit.Entry{
					ActorID:      actor,
					ActorType:    "system",
					Action:       "incident.downstream_alert_suppressed",
					ResourceType: "incident",
					ResourceID:   incident.ID,
					Metadata: map[string]any{
						"alert_name":       normalized.alertName,
						"observed_service": normalized.service,
						"root_service":     incident.Service,
						"dependency_path":  path.Services,
					},
				})
			}
		}
		incidentsOut = append(incidentsOut, *incident)
		openIncidents = appendOrReplaceIncident(openIncidents, *incident)
	}
	return IngestionResult{Incidents: incidentsOut, Stats: stats}, nil
}

type normalizedAlert struct {
	alert         AlertmanagerAlert
	service       string
	serviceRecord Service
	alertName     string
	environment   string
	severity      string
	fingerprint   string
	summary       string
	dedupeKey     string
}

func (m *ServiceManager) normalizeAlerts(ctx context.Context, payload AlertmanagerWebhook) ([]normalizedAlert, error) {
	alerts := make([]normalizedAlert, 0, len(payload.Alerts))
	for _, alert := range payload.Alerts {
		service := firstNonEmpty(alert.Labels["service"], payload.CommonLabels["service"], "unknown-service")
		serviceRecord, err := m.store.EnsureService(ctx, service)
		if err != nil {
			return nil, err
		}
		alertName := firstNonEmpty(alert.Labels["alertname"], payload.CommonLabels["alertname"], "unknown-alert")
		environment := firstNonEmpty(alert.Labels["environment"], payload.CommonLabels["environment"], "local")
		severity := firstNonEmpty(alert.Labels["severity"], payload.CommonLabels["severity"], "sev3")
		fingerprint := firstNonEmpty(alert.Fingerprint, alertName)
		summary := firstNonEmpty(alert.Annotations["summary"], payload.CommonAnnotations["summary"], alertName)
		if alert.StartsAt.IsZero() {
			alert.StartsAt = time.Now().UTC()
		}
		alerts = append(alerts, normalizedAlert{
			alert:         alert,
			service:       service,
			serviceRecord: serviceRecord,
			alertName:     alertName,
			environment:   environment,
			severity:      severity,
			fingerprint:   fingerprint,
			summary:       summary,
			dedupeKey:     BuildDedupeKey(service, alertName, environment, fingerprint),
		})
	}
	sort.SliceStable(alerts, func(i, j int) bool {
		if !alerts[i].alert.StartsAt.Equal(alerts[j].alert.StartsAt) {
			return alerts[i].alert.StartsAt.Before(alerts[j].alert.StartsAt)
		}
		if alerts[i].service != alerts[j].service {
			return alerts[i].service < alerts[j].service
		}
		if alerts[i].alertName != alerts[j].alertName {
			return alerts[i].alertName < alerts[j].alertName
		}
		return alerts[i].fingerprint < alerts[j].fingerprint
	})
	return alerts, nil
}

func (m *ServiceManager) findOrCreateTopologyIncident(
	ctx context.Context,
	graph *topology.Graph,
	group topology.Group,
	root normalizedAlert,
	open []Incident,
) (*Incident, bool, bool, error) {
	if root.service == group.Root {
		exact, err := m.store.FindOpenByDedupeKey(ctx, root.dedupeKey, m.groupingWindow)
		if err != nil {
			return nil, false, false, err
		}
		if exact != nil {
			return exact, false, false, nil
		}
	}

	if existing, promote := relatedOpenIncident(graph, group.Root, group.Environment, open); existing != nil {
		if !promote || existing.Service == group.Root {
			return existing, false, false, nil
		}
		promoted, err := m.store.PromoteIncidentRoot(
			ctx, existing.ID, group.Root, rootTitle(group, root), root.severity,
			rootDedupeKey(group, root), rootFingerprint(group, root), rootSummary(group, root), root.alert.StartsAt,
		)
		if err != nil {
			return nil, false, false, err
		}
		return &promoted, false, true, nil
	}

	created, err := m.store.CreateAlertIncident(
		ctx, rootTitle(group, root), group.Root, root.severity, rootDedupeKey(group, root),
		rootFingerprint(group, root), rootSummary(group, root), root.alert.StartsAt,
	)
	if err != nil {
		return nil, false, false, err
	}
	return &created, true, false, nil
}

func (m *ServiceManager) attachTopologyAlert(
	ctx context.Context,
	incident Incident,
	normalized normalizedAlert,
	path topology.Path,
	rootInferred bool,
	suppressed bool,
) error {
	if err := m.store.AddSignal(ctx, Signal{
		IncidentID: incident.ID,
		ServiceID:  normalized.serviceRecord.ID,
		Source:     "alertmanager",
		SignalType: "alert",
		Severity:   normalized.severity,
		Name:       normalized.alertName,
		Body: map[string]any{
			"labels":      normalized.alert.Labels,
			"annotations": normalized.alert.Annotations,
			"generator":   normalized.alert.GeneratorURL,
			"status":      normalized.alert.Status,
			"topology": map[string]any{
				"root_service":     incident.Service,
				"observed_service": normalized.service,
				"root_inferred":    rootInferred,
				"suppressed":       suppressed,
				"dependency_path":  path.Services,
			},
		},
		ObservedAt: normalized.alert.StartsAt,
	}); err != nil {
		return err
	}

	eventType := "alert_received"
	summary := normalized.summary
	if suppressed {
		eventType = "downstream_alert_suppressed"
		summary = fmt.Sprintf(
			"Suppressed downstream alert %s on %s; correlated root is %s",
			normalized.alertName, normalized.service, incident.Service,
		)
	}
	return m.store.AddTimelineEvent(ctx, TimelineEvent{
		IncidentID: incident.ID,
		EventType:  eventType,
		Source:     "alertmanager",
		Summary:    summary,
		Evidence: map[string]any{
			"alert_name":      normalized.alertName,
			"service":         normalized.service,
			"severity":        normalized.severity,
			"environment":     normalized.environment,
			"root_service":    incident.Service,
			"root_inferred":   rootInferred,
			"suppressed":      suppressed,
			"dependency_path": path.Services,
		},
		Confidence: topologyConfidence(rootInferred, suppressed),
		OccurredAt: normalized.alert.StartsAt,
	})
}

func alertsForGroup(alerts []normalizedAlert, group topology.Group) []normalizedAlert {
	members := make(map[string]struct{}, len(group.Members))
	for _, member := range group.Members {
		members[member] = struct{}{}
	}
	var items []normalizedAlert
	for _, alert := range alerts {
		if alert.environment != group.Environment {
			continue
		}
		if _, ok := members[alert.service]; ok {
			items = append(items, alert)
		}
	}
	return items
}

func topologyGroupsByEnvironment(graph *topology.Graph, alerts []normalizedAlert) []topology.Group {
	servicesByEnvironment := make(map[string][]string)
	for _, alert := range alerts {
		servicesByEnvironment[alert.environment] = append(servicesByEnvironment[alert.environment], alert.service)
	}
	environments := make([]string, 0, len(servicesByEnvironment))
	for environment := range servicesByEnvironment {
		environments = append(environments, environment)
	}
	sort.Strings(environments)

	var result []topology.Group
	for _, environment := range environments {
		groups := graph.Groups(servicesByEnvironment[environment])
		for i := range groups {
			groups[i].Environment = environment
		}
		result = append(result, groups...)
	}
	return result
}

func rootAlertForGroup(alerts []normalizedAlert, root string) normalizedAlert {
	for _, alert := range alerts {
		if alert.service == root {
			return alert
		}
	}
	result := alerts[0]
	result.service = root
	result.serviceRecord = Service{}
	result.alertName = "TopologyCorrelatedDependencyFailure"
	result.fingerprint = "topology-" + root
	result.dedupeKey = BuildDedupeKey(root, result.alertName, result.environment, result.fingerprint)
	result.summary = fmt.Sprintf("Correlated downstream failures point to %s", root)
	result.severity = highestSeverity(alerts)
	return result
}

func relatedOpenIncident(graph *topology.Graph, root, environment string, open []Incident) (*Incident, bool) {
	var upstream *Incident
	upstreamDistance := int(^uint(0) >> 1)
	var downstream *Incident
	downstreamDistance := int(^uint(0) >> 1)
	for i := range open {
		incident := &open[i]
		if incidentEnvironment(*incident) != environment {
			continue
		}
		if incident.Service == root {
			return incident, false
		}
		if path, ok := graph.Path(root, incident.Service); ok && len(path.Services) < upstreamDistance {
			upstream = incident
			upstreamDistance = len(path.Services)
		}
		if path, ok := graph.Path(incident.Service, root); ok && len(path.Services) < downstreamDistance {
			downstream = incident
			downstreamDistance = len(path.Services)
		}
	}
	if upstream != nil {
		return upstream, false
	}
	if downstream != nil {
		return downstream, true
	}
	return nil, false
}

func incidentEnvironment(incident Incident) string {
	parts := strings.SplitN(incident.DedupeKey, ":", 4)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

func rootTitle(group topology.Group, root normalizedAlert) string {
	if group.Inferred {
		return fmt.Sprintf("Correlated downstream failures indicate %s dependency impact", group.Root)
	}
	return root.summary
}

func rootSummary(group topology.Group, root normalizedAlert) string {
	if group.Inferred {
		return fmt.Sprintf(
			"Topology correlation grouped %d affected services behind inferred dependency %s",
			len(group.Members), group.Root,
		)
	}
	return root.summary
}

func rootDedupeKey(group topology.Group, root normalizedAlert) string {
	if group.Inferred {
		return BuildDedupeKey(group.Root, "TopologyCorrelatedDependencyFailure", root.environment, "topology-"+group.Root)
	}
	return root.dedupeKey
}

func rootFingerprint(group topology.Group, root normalizedAlert) string {
	if group.Inferred {
		return "topology-" + group.Root
	}
	return root.fingerprint
}

func highestSeverity(alerts []normalizedAlert) string {
	best := "sev4"
	for _, alert := range alerts {
		if severityRank(alert.severity) < severityRank(best) {
			best = alert.severity
		}
	}
	return best
}

func severityRank(severity string) int {
	switch severity {
	case "sev1":
		return 1
	case "sev2":
		return 2
	case "sev3":
		return 3
	default:
		return 4
	}
}

func topologyConfidence(inferred, suppressed bool) float64 {
	if inferred {
		return 0.75
	}
	if suppressed {
		return 0.92
	}
	return 1
}

func appendOrReplaceIncident(items []Incident, incident Incident) []Incident {
	for i := range items {
		if items[i].ID == incident.ID {
			items[i] = incident
			return items
		}
	}
	return append(items, incident)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
