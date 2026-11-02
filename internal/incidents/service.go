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

// DefaultAlertStaleAfter exceeds Alertmanager's default 4h repeat_interval,
// so a firing alert that is still being re-sent never goes stale.
const DefaultAlertStaleAfter = 6 * time.Hour

type ServiceManager struct {
	store    *Store
	auditor  *audit.Service
	grouping Grouping
}

func NewServiceManager(store *Store, auditor *audit.Service, groupingWindow time.Duration) *ServiceManager {
	return &ServiceManager{
		store:    store,
		auditor:  auditor,
		grouping: Grouping{Window: groupingWindow, AlertStaleAfter: DefaultAlertStaleAfter},
	}
}

// SetAlertStaleAfter overrides how long a firing alert that is no longer
// re-sent keeps its incident open for grouping.
func (m *ServiceManager) SetAlertStaleAfter(staleAfter time.Duration) {
	if staleAfter > 0 {
		m.grouping.AlertStaleAfter = staleAfter
	}
}

func BuildDedupeKey(service, alertName, environment, fingerprint string) string {
	return fmt.Sprintf("%s:%s:%s:%s", service, alertName, environment, fingerprint)
}

// transitions is the incident lifecycle. Automatic steps (RCA, proposals)
// only ever move an incident forward along it; operators get a conflict when
// they request a transition it does not allow. An operator may resolve any
// open incident; resolved and cancelled are terminal, and remediation cannot
// be dispatched for an incident in either state.
var transitions = map[string]map[string]bool{
	StatusDetected: {
		StatusTriaged: true, StatusInvestigating: true, StatusRCAGenerated: true,
		StatusResolved: true, StatusCancelled: true,
	},
	StatusTriaged: {
		StatusInvestigating: true, StatusRCAGenerated: true, StatusResolved: true, StatusCancelled: true,
	},
	StatusInvestigating: {
		StatusRCAGenerated: true, StatusResolved: true, StatusFailed: true,
	},
	StatusRCAGenerated: {
		StatusRemediationProposed: true, StatusAwaitingApproval: true, StatusResolved: true,
	},
	StatusRemediationProposed: {
		StatusAwaitingApproval: true, StatusRemediating: true, StatusResolved: true,
	},
	StatusAwaitingApproval: {
		StatusRemediating: true, StatusResolved: true, StatusCancelled: true,
	},
	StatusRemediating: {
		StatusMitigated: true, StatusResolved: true, StatusFailed: true,
	},
	StatusMitigated: {
		StatusResolved: true,
	},
	StatusFailed: {
		StatusInvestigating: true, StatusResolved: true,
	},
}

func CanTransition(from, to string) bool {
	return transitions[from][to]
}

// IsClosed reports whether an incident is in a terminal state.
func IsClosed(status string) bool {
	return status == StatusResolved || status == StatusCancelled
}

// AllowedFrom lists the states from which an incident may move to the target.
func AllowedFrom(to string) []string {
	var from []string
	for state, targets := range transitions {
		if targets[to] {
			from = append(from, state)
		}
	}
	sort.Strings(from)
	return from
}

func (m *ServiceManager) CreateManual(ctx context.Context, req ManualIncidentRequest, actor string) (Incident, error) {
	var incident Incident
	err := m.store.InTx(ctx, func(tx *Store) error {
		created, err := tx.CreateManualIncident(ctx, req)
		if err != nil {
			return err
		}
		incident = created
		return audit.WriteTx(ctx, tx.Tx(), audit.Entry{
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
	})
	if err != nil {
		return Incident{}, err
	}
	return incident, nil
}

func (m *ServiceManager) IngestAlertmanager(ctx context.Context, payload AlertmanagerWebhook, actor string) ([]Incident, error) {
	result, err := m.IngestAlertmanagerWithResult(ctx, payload, actor)
	return result.Incidents, err
}

func (m *ServiceManager) IngestAlertmanagerWithResult(ctx context.Context, payload AlertmanagerWebhook, actor string) (IngestionResult, error) {
	var result IngestionResult
	// One transaction for the whole delivery: the ingestion lock, every
	// incident/signal/timeline write, and their audit entries commit together
	// or not at all, so a failure never leaves partial incident context and
	// Alertmanager's retry starts from a clean state.
	err := m.store.InTx(ctx, func(tx *Store) error {
		if err := tx.LockIncidentIngestion(ctx); err != nil {
			return err
		}
		var err error
		result, err = m.ingest(ctx, tx, payload, actor)
		return err
	})
	if err != nil {
		return IngestionResult{}, err
	}
	return result, nil
}

func (m *ServiceManager) ingest(ctx context.Context, tx *Store, payload AlertmanagerWebhook, actor string) (IngestionResult, error) {
	writeAudit := func(entry audit.Entry) error {
		if err := audit.WriteTx(ctx, tx.Tx(), entry); err != nil {
			return fmt.Errorf("audit %s: %w", entry.Action, err)
		}
		return nil
	}

	alerts, resolved, err := m.normalizeAlerts(ctx, tx, payload)
	if err != nil {
		return IngestionResult{}, err
	}
	stats := IngestionStats{AlertCount: len(alerts), TruncatedAlerts: payload.TruncatedAlerts}
	// Resolved notifications never create incidents; they only update the
	// open incident on which that alert is firing.
	for _, alert := range resolved {
		if err := m.resolveAlert(ctx, tx, alert, actor, writeAudit, &stats); err != nil {
			return IngestionResult{}, err
		}
	}
	if len(alerts) == 0 {
		return IngestionResult{Incidents: []Incident{}, Stats: stats}, nil
	}
	dependencies, err := tx.ListServiceDependencies(ctx)
	if err != nil {
		return IngestionResult{}, err
	}
	graph := topology.New(dependencies)
	groups := topologyGroupsByEnvironment(graph, alerts)
	openIncidents, err := tx.ListOpenIncidents(ctx, m.grouping)
	if err != nil {
		return IngestionResult{}, err
	}

	incidentsOut := make([]Incident, 0, len(groups))
	for _, group := range groups {
		groupAlerts := alertsForGroup(alerts, group)
		if len(groupAlerts) == 0 {
			continue
		}
		rootAlert := rootAlertForGroup(groupAlerts, group.Root)
		incident, created, promoted, err := m.findOrCreateTopologyIncident(ctx, tx, graph, group, rootAlert, openIncidents)
		if err != nil {
			return IngestionResult{}, err
		}
		rootInferred := group.Inferred
		if !created && !promoted {
			analysis, err := tx.GetIncidentTopology(ctx, incident.ID)
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
			if err := writeAudit(audit.Entry{
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
			}); err != nil {
				return IngestionResult{}, err
			}
		}
		if promoted {
			if err := writeAudit(audit.Entry{
				ActorID:      actor,
				ActorType:    "system",
				Action:       "incident.root_promoted",
				ResourceType: "incident",
				ResourceID:   incident.ID,
				AfterState: map[string]any{
					"root_service":  incident.Service,
					"root_inferred": rootInferred,
				},
			}); err != nil {
				return IngestionResult{}, err
			}
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
			if err := m.attachTopologyAlert(ctx, tx, *incident, normalized, path, rootInferred, suppressed); err != nil {
				return IngestionResult{}, err
			}
			if suppressed {
				stats.SuppressedAlertCount++
				if err := writeAudit(audit.Entry{
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
				}); err != nil {
					return IngestionResult{}, err
				}
			}
		}
		incidentsOut = append(incidentsOut, *incident)
		openIncidents = appendOrReplaceIncident(openIncidents, *incident)
	}
	return IngestionResult{Incidents: incidentsOut, Stats: stats}, nil
}

type normalizedAlert struct {
	alert         AlertmanagerAlert
	status        string
	service       string
	serviceRecord Service
	alertName     string
	environment   string
	severity      string
	fingerprint   string
	summary       string
	dedupeKey     string
}

// normalizeAlerts splits a delivery into firing and resolved alerts. Services
// are only registered for firing alerts, so a stray resolved notification
// cannot create catalog entries.
func (m *ServiceManager) normalizeAlerts(ctx context.Context, store *Store, payload AlertmanagerWebhook) ([]normalizedAlert, []normalizedAlert, error) {
	var firing, resolved []normalizedAlert
	for _, alert := range payload.Alerts {
		service := firstNonEmpty(alert.Labels["service"], payload.CommonLabels["service"], "unknown-service")
		alertName := firstNonEmpty(alert.Labels["alertname"], payload.CommonLabels["alertname"], "unknown-alert")
		environment := firstNonEmpty(alert.Labels["environment"], payload.CommonLabels["environment"], "local")
		severity := firstNonEmpty(alert.Labels["severity"], payload.CommonLabels["severity"], "sev3")
		fingerprint := firstNonEmpty(alert.Fingerprint, alertName)
		summary := firstNonEmpty(alert.Annotations["summary"], payload.CommonAnnotations["summary"], alertName)
		status := strings.ToLower(firstNonEmpty(alert.Status, payload.Status, "firing"))
		if alert.StartsAt.IsZero() {
			alert.StartsAt = time.Now().UTC()
		}
		normalized := normalizedAlert{
			alert:       alert,
			status:      status,
			service:     service,
			alertName:   alertName,
			environment: environment,
			severity:    severity,
			fingerprint: fingerprint,
			summary:     summary,
			dedupeKey:   BuildDedupeKey(service, alertName, environment, fingerprint),
		}
		if status == "resolved" {
			resolved = append(resolved, normalized)
			continue
		}
		serviceRecord, err := store.EnsureService(ctx, service)
		if err != nil {
			return nil, nil, err
		}
		normalized.serviceRecord = serviceRecord
		firing = append(firing, normalized)
	}
	sortAlerts := func(alerts []normalizedAlert) {
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
	}
	sortAlerts(firing)
	sortAlerts(resolved)
	return firing, resolved, nil
}

// resolveAlert applies a resolved notification to the open incident on which
// that alert is firing. When the incident's last firing alert resolves, it
// records that the alerts cleared; the incident stays open for an operator,
// since remediation or approval may still be in progress.
func (m *ServiceManager) resolveAlert(ctx context.Context, tx *Store, alert normalizedAlert, actor string, writeAudit func(audit.Entry) error, stats *IngestionStats) error {
	incident, err := tx.FindIncidentForResolvedAlert(ctx, alert.dedupeKey)
	if err != nil {
		return err
	}
	if incident == nil {
		stats.UnmatchedResolvedAlerts++
		return nil
	}
	serviceRecord, err := tx.EnsureService(ctx, alert.service)
	if err != nil {
		return err
	}
	resolvedAt := alert.alert.EndsAt
	if resolvedAt.IsZero() {
		resolvedAt = time.Now().UTC()
	}
	if err := tx.AddSignal(ctx, Signal{
		IncidentID: incident.ID,
		ServiceID:  serviceRecord.ID,
		Source:     "alertmanager",
		SignalType: "alert",
		Severity:   alert.severity,
		Name:       alert.alertName,
		Body: map[string]any{
			"labels":      alert.alert.Labels,
			"annotations": alert.alert.Annotations,
			"generator":   alert.alert.GeneratorURL,
			"status":      "resolved",
			"ends_at":     resolvedAt,
		},
		ObservedAt: resolvedAt,
	}); err != nil {
		return err
	}
	remaining, err := tx.MarkAlertResolved(ctx, incident.ID, alert.dedupeKey, resolvedAt, m.grouping.AlertStaleAfter)
	if err != nil {
		return err
	}
	if err := tx.AddTimelineEvent(ctx, TimelineEvent{
		IncidentID: incident.ID,
		EventType:  "alert_resolved",
		Source:     "alertmanager",
		Summary:    fmt.Sprintf("Alert %s on %s resolved; %d alert(s) still firing", alert.alertName, alert.service, remaining),
		Evidence:   map[string]any{"alert_name": alert.alertName, "service": alert.service, "dedupe_key": alert.dedupeKey, "still_firing": remaining},
		Confidence: 1,
		OccurredAt: resolvedAt,
	}); err != nil {
		return err
	}
	stats.ResolvedAlerts++
	if remaining > 0 {
		return nil
	}
	if err := tx.MarkAlertsCleared(ctx, incident.ID); err != nil {
		return err
	}
	if err := tx.AddTimelineEvent(ctx, TimelineEvent{
		IncidentID: incident.ID,
		EventType:  "alerts_cleared",
		Source:     "alertmanager",
		Summary:    "Every alert on this incident has resolved. The incident stays open until an operator resolves it.",
		Evidence:   map[string]any{"last_alert": alert.alertName},
		Confidence: 1,
		OccurredAt: resolvedAt,
	}); err != nil {
		return err
	}
	return writeAudit(audit.Entry{
		ActorID:      actor,
		ActorType:    "system",
		Action:       "incident.alerts_cleared",
		ResourceType: "incident",
		ResourceID:   incident.ID,
		AfterState:   map[string]any{"status": incident.Status, "alerts_cleared": true},
		Metadata:     map[string]any{"last_alert": alert.alertName, "service": alert.service},
	})
}

func (m *ServiceManager) findOrCreateTopologyIncident(
	ctx context.Context,
	store *Store,
	graph *topology.Graph,
	group topology.Group,
	root normalizedAlert,
	open []Incident,
) (*Incident, bool, bool, error) {
	if root.service == group.Root {
		exact, err := store.FindOpenByDedupeKey(ctx, root.dedupeKey, m.grouping)
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
		promoted, err := store.PromoteIncidentRoot(
			ctx, existing.ID, group.Root, rootTitle(group, root), root.severity,
			rootDedupeKey(group, root), rootFingerprint(group, root), rootSummary(group, root), root.alert.StartsAt,
		)
		if err != nil {
			return nil, false, false, err
		}
		return &promoted, false, true, nil
	}

	created, err := store.CreateAlertIncident(
		ctx, rootTitle(group, root), group.Root, group.Environment, root.severity, rootDedupeKey(group, root),
		rootFingerprint(group, root), rootSummary(group, root), root.alert.StartsAt,
	)
	if err != nil {
		return nil, false, false, err
	}
	return &created, true, false, nil
}

func (m *ServiceManager) attachTopologyAlert(
	ctx context.Context,
	store *Store,
	incident Incident,
	normalized normalizedAlert,
	path topology.Path,
	rootInferred bool,
	suppressed bool,
) error {
	if err := store.AddSignal(ctx, Signal{
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
	refired, err := store.MarkAlertFiring(ctx, incident.ID, AlertObservation{
		DedupeKey: normalized.dedupeKey, AlertName: normalized.alertName, Service: normalized.service, At: normalized.alert.StartsAt,
	})
	if err != nil {
		return err
	}
	if refired {
		if err := store.AddTimelineEvent(ctx, TimelineEvent{
			IncidentID: incident.ID,
			EventType:  "alerts_refired",
			Source:     "alertmanager",
			Summary:    fmt.Sprintf("Alert %s on %s fired again after all alerts had cleared", normalized.alertName, normalized.service),
			Evidence:   map[string]any{"alert_name": normalized.alertName, "service": normalized.service},
			Confidence: 1,
			OccurredAt: normalized.alert.StartsAt,
		}); err != nil {
			return err
		}
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
	return store.AddTimelineEvent(ctx, TimelineEvent{
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
		if incident.Environment != environment {
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
