package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/gauravgs7/argus/internal/approvals"
	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/auth"
	"github.com/gauravgs7/argus/internal/common"
	"github.com/gauravgs7/argus/internal/config"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/policy"
	"github.com/gauravgs7/argus/internal/queue"
	"github.com/gauravgs7/argus/internal/rca"
	"github.com/gauravgs7/argus/internal/remediation"
	"github.com/gauravgs7/argus/internal/telemetry"
)

type Server struct {
	cfg                config.Config
	logger             *slog.Logger
	db                 *sql.DB
	queue              *queue.Client
	store              *incidents.Store
	incidentManager    *incidents.ServiceManager
	rcaService         *rca.Service
	remediationService *remediation.Service
	auditor            *audit.Service
	metrics            *telemetry.Metrics
	authenticator      auth.Authenticator
	approvalService    *approvals.Service
	approvalCancel     context.CancelFunc
	slackApproval      *approvals.SlackWorkflow
}

func New(ctx context.Context, cfg config.Config, logger *slog.Logger) (*Server, error) {
	database, err := db.Open(ctx, cfg.PostgresDSN)
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(ctx, database); err != nil {
		return nil, err
	}

	queueClient, err := queue.Connect(cfg.NATSURL)
	if err != nil {
		return nil, err
	}
	if err := queueClient.EnsureStreams(); err != nil {
		return nil, err
	}

	metrics := telemetry.MustRegister()
	authenticator, err := auth.NewOIDCAuthenticator(ctx, auth.OIDCConfig{
		IssuerURL:         cfg.OIDCIssuerURL,
		Audience:          cfg.OIDCAudience,
		JWKSURL:           cfg.OIDCJWKSURL,
		RoleClaim:         cfg.OIDCRoleClaim,
		RoleMappings:      cfg.OIDCRoleMappings,
		EmailClaim:        cfg.OIDCEmailClaim,
		DisplayNameClaim:  cfg.OIDCDisplayNameClaim,
		SigningAlgs:       cfg.OIDCSigningAlgs,
		DiscoveryTimeout:  cfg.OIDCDiscoveryTimeout,
		ProviderTimeout:   cfg.OIDCProviderTimeout,
		AllowInsecureHTTP: cfg.Env == "local" || cfg.Env == "test",
	})
	if err != nil {
		return nil, err
	}
	store := incidents.NewStore(database)
	auditor := audit.NewService(database)
	approvalStore := approvals.NewStore(database)
	approvalNotifier, err := approvals.NewWebhookNotifier(
		cfg.ApprovalWebhookURL,
		cfg.ApprovalWebhookSecret,
		cfg.ApprovalCallbackBaseURL,
		cfg.ApprovalWebhookMode,
		cfg.ApprovalNotifyTimeout,
	)
	if err != nil {
		return nil, err
	}
	approvalService := approvals.NewService(
		approvalStore,
		approvalNotifier,
		metrics,
		logger,
		cfg.ApprovalTimeout,
		cfg.ApprovalEscalateAfter,
		cfg.ApprovalSweepInterval,
		cfg.ApprovalAllowSelf,
	)
	slackApproval, err := approvals.NewSlackWorkflow(
		approvalService,
		cfg.ApprovalSlackSigningSecret,
		cfg.ApprovalSlackBotToken,
		cfg.ApprovalSlackApprovers,
		cfg.ApprovalNotifyTimeout,
	)
	if err != nil {
		return nil, err
	}
	if cfg.ApprovalWebhookURL != "" && cfg.ApprovalWebhookMode == "slack" && !slackApproval.Enabled() {
		return nil, fmt.Errorf("Slack approval delivery requires signing secret, bot token, and approver identity mappings")
	}
	approvalContext, approvalCancel := context.WithCancel(context.Background())
	approvalService.Start(approvalContext)
	incidentManager := incidents.NewServiceManager(store, auditor, cfg.IncidentGrouping)
	rcaService := rca.NewService(store, cfg.AIServiceURL, cfg.AIServiceToken, metrics)
	var executor remediation.Executor
	switch cfg.RemediationExecutor {
	case "helios":
		executor = remediation.NewHeliosExecutor(cfg.HeliosBaseURL, cfg.HeliosAdminToken, cfg.HeliosPollTimeout)
	default:
		executor = remediation.NewLocalExecutor(queueClient)
	}
	remediationService := remediation.NewService(store, auditor, policy.NewEngine(), queueClient, executor, metrics, approvalService)

	return &Server{
		cfg:                cfg,
		logger:             logger,
		db:                 database,
		queue:              queueClient,
		store:              store,
		incidentManager:    incidentManager,
		rcaService:         rcaService,
		remediationService: remediationService,
		auditor:            auditor,
		metrics:            metrics,
		authenticator:      authenticator,
		approvalService:    approvalService,
		approvalCancel:     approvalCancel,
		slackApproval:      slackApproval,
	}, nil
}

func (s *Server) Close() error {
	if s.approvalCancel != nil {
		s.approvalCancel()
	}
	if s.queue != nil {
		s.queue.Close()
	}
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)
	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/v1/alerts/alertmanager", s.handleAlertmanager)
	mux.HandleFunc("/v1/signals/manual", s.handleManualSignal)
	mux.HandleFunc("/v1/auth/me", s.handleCurrentPrincipal)

	mux.HandleFunc("/v1/incidents", s.handleIncidents)
	mux.HandleFunc("/v1/incidents/", s.handleIncidentRoutes)
	mux.HandleFunc("/v1/remediations/", s.handleRemediationRoutes)
	mux.HandleFunc("/v1/approval-requests", s.handleApprovalRequests)
	mux.HandleFunc("/v1/approval-requests/", s.handleApprovalRequests)
	mux.HandleFunc("/v1/approval-callbacks/slack", s.handleSlackApprovalCallback)
	mux.HandleFunc("/v1/audit", s.handleAudit)
	mux.HandleFunc("/v1/services", s.handleServices)
	mux.HandleFunc("/v1/runbooks", s.handleRunbooks)
	mux.HandleFunc("/v1/runbooks/reindex", s.handleRunbookReindex)

	return s.loggingMiddleware(s.authMiddleware(mux))
}

func (s *Server) handleCurrentPrincipal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		common.WriteError(w, http.StatusUnauthorized, "authenticated principal unavailable")
		return
	}
	common.WriteJSON(w, http.StatusOK, principal)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.db.PingContext(r.Context()); err != nil {
		common.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleAlertmanager(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var payload incidents.AlertmanagerWebhook
	if err := common.ReadJSON(r, &payload); err != nil {
		common.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	created, err := s.incidentManager.IngestAlertmanager(r.Context(), payload, actorFromRequest(r))
	if err != nil {
		common.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	for _, incident := range created {
		s.metrics.IncidentsTotal.WithLabelValues("created", incident.Severity).Inc()
	}
	s.metrics.IncidentsOpen.Set(float64(len(created)))
	common.WriteJSON(w, http.StatusAccepted, map[string]any{"incidents": created})
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.store.ListIncidents(r.Context())
		if err != nil {
			common.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		common.WriteJSON(w, http.StatusOK, items)
	case http.MethodPost:
		var req incidents.ManualIncidentRequest
		if err := common.ReadJSON(r, &req); err != nil {
			common.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		incident, err := s.incidentManager.CreateManual(r.Context(), req, actorFromRequest(r))
		if err != nil {
			common.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.metrics.IncidentsTotal.WithLabelValues("created", incident.Severity).Inc()
		common.WriteJSON(w, http.StatusCreated, incident)
	default:
		common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleManualSignal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var body struct {
		Scenario string `json:"scenario"`
		Service  string `json:"service"`
		Severity string `json:"severity"`
	}
	if err := common.ReadJSON(r, &body); err != nil {
		common.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Service == "" {
		body.Service = "payments-api"
	}
	if body.Severity == "" {
		body.Severity = "sev2"
	}

	payload := incidents.AlertmanagerWebhook{
		Status:   "firing",
		Receiver: "manual",
		Alerts: []incidents.AlertmanagerAlert{
			{
				Status: "firing",
				Labels: map[string]string{
					"alertname":   scenarioToAlert(body.Scenario),
					"service":     body.Service,
					"environment": "local",
					"severity":    body.Severity,
				},
				Annotations: map[string]string{
					"summary": scenarioToSummary(body.Scenario),
				},
				StartsAt:    time.Now().UTC(),
				Fingerprint: "manual-" + body.Scenario,
			},
		},
	}

	created, err := s.incidentManager.IngestAlertmanager(r.Context(), payload, actorFromRequest(r))
	if err != nil {
		common.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	common.WriteJSON(w, http.StatusAccepted, map[string]any{"incidents": created})
}

func (s *Server) handleIncidentRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/incidents/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		common.WriteError(w, http.StatusNotFound, "incident route not found")
		return
	}
	incidentID := parts[0]

	if len(parts) == 1 && r.Method == http.MethodGet {
		item, err := s.store.GetIncident(r.Context(), incidentID)
		if err != nil {
			common.WriteError(w, http.StatusNotFound, err.Error())
			return
		}
		common.WriteJSON(w, http.StatusOK, item)
		return
	}

	if len(parts) == 2 {
		switch parts[1] {
		case "ack":
			s.handleIncidentStateChange(w, r, incidentID, incidents.StatusTriaged)
			return
		case "resolve":
			s.handleIncidentStateChange(w, r, incidentID, incidents.StatusResolved)
			return
		case "timeline":
			items, err := s.store.ListTimeline(r.Context(), incidentID)
			if err != nil {
				common.WriteError(w, http.StatusInternalServerError, err.Error())
				return
			}
			common.WriteJSON(w, http.StatusOK, items)
			return
		case "signals":
			items, err := s.store.ListSignals(r.Context(), incidentID)
			if err != nil {
				common.WriteError(w, http.StatusInternalServerError, err.Error())
				return
			}
			common.WriteJSON(w, http.StatusOK, items)
			return
		case "rca":
			if r.Method == http.MethodGet {
				report, err := s.store.GetLatestRCAReport(r.Context(), incidentID)
				if err != nil {
					common.WriteError(w, http.StatusNotFound, err.Error())
					return
				}
				common.WriteJSON(w, http.StatusOK, report)
				return
			}
		case "remediations":
			if r.Method == http.MethodGet {
				items, err := s.store.ListRemediations(r.Context(), incidentID)
				if err != nil {
					common.WriteError(w, http.StatusInternalServerError, err.Error())
					return
				}
				common.WriteJSON(w, http.StatusOK, items)
				return
			}
		}
	}

	if len(parts) == 3 && parts[1] == "rca" && parts[2] == "generate" && r.Method == http.MethodPost {
		report, _, err := s.rcaService.Generate(r.Context(), incidentID)
		if err != nil {
			common.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		common.WriteJSON(w, http.StatusAccepted, map[string]any{
			"rca_report_id": report.ID,
			"status":        "queued",
		})
		return
	}

	if len(parts) == 3 && parts[1] == "remediations" && parts[2] == "suggest" && r.Method == http.MethodPost {
		suggestions, err := s.rcaService.SuggestRemediations(r.Context(), incidentID)
		if err != nil {
			common.WriteError(w, http.StatusBadGateway, err.Error())
			return
		}
		common.WriteJSON(w, http.StatusOK, suggestions)
		return
	}

	if len(parts) == 3 && parts[1] == "remediations" && parts[2] == "propose" && r.Method == http.MethodPost {
		incident, err := s.store.GetIncident(r.Context(), incidentID)
		if err != nil {
			common.WriteError(w, http.StatusNotFound, err.Error())
			return
		}
		report, candidates, err := s.rcaService.Generate(r.Context(), incidentID)
		if err != nil {
			common.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		actions, err := s.remediationService.Propose(r.Context(), incident, candidates, actorFromRequest(r), roleFromRequest(r))
		if err != nil {
			common.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = report
		common.WriteJSON(w, http.StatusAccepted, map[string]any{
			"remediations": actions,
		})
		return
	}

	common.WriteError(w, http.StatusNotFound, "incident route not found")
}

func (s *Server) handleIncidentStateChange(w http.ResponseWriter, r *http.Request, incidentID, state string) {
	if r.Method != http.MethodPost {
		common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.store.UpdateIncidentStatus(r.Context(), incidentID, state); err != nil {
		common.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.auditor.Write(r.Context(), audit.Entry{
		ActorID:      actorFromRequest(r),
		ActorType:    "user",
		Action:       "incident." + state,
		ResourceType: "incident",
		ResourceID:   incidentID,
		AfterState:   map[string]any{"status": state},
	})
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": state})
}

func (s *Server) handleRemediationRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/remediations/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		common.WriteError(w, http.StatusNotFound, "remediation route not found")
		return
	}
	remediationID := parts[0]
	action := parts[1]

	switch action {
	case "approve":
		if r.Method != http.MethodPost {
			common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var body struct {
			Reason string `json:"reason"`
		}
		if err := common.ReadJSON(r, &body); err != nil {
			common.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.remediationService.Approve(r.Context(), remediationID, actorFromRequest(r), body.Reason); err != nil {
			common.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		common.WriteJSON(w, http.StatusOK, map[string]string{"status": "approved"})
	case "reject":
		if r.Method != http.MethodPost {
			common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var body struct {
			Reason string `json:"reason"`
		}
		if err := common.ReadJSON(r, &body); err != nil {
			common.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.remediationService.Reject(r.Context(), remediationID, actorFromRequest(r), body.Reason); err != nil {
			common.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		common.WriteJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
	case "execute":
		if r.Method != http.MethodPost {
			common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var body struct {
			DryRun bool `json:"dry_run"`
		}
		if err := common.ReadJSON(r, &body); err != nil && err.Error() != "EOF" {
			common.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		reused, err := s.remediationService.Execute(r.Context(), remediationID, body.DryRun, actorFromRequest(r))
		if err != nil {
			common.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		if reused {
			common.WriteJSON(w, http.StatusOK, map[string]string{"status": "reused"})
			return
		}
		common.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
	case "cancel":
		if r.Method != http.MethodPost {
			common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if err := s.remediationService.Cancel(r.Context(), remediationID, actorFromRequest(r)); err != nil {
			common.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		common.WriteJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
	default:
		common.WriteError(w, http.StatusNotFound, "unknown remediation action")
	}
}

func (s *Server) handleApprovalRequests(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/approval-requests")
	if path == "" || path == "/" {
		if r.Method != http.MethodGet {
			common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		items, err := s.approvalService.List(r.Context(), r.URL.Query().Get("status"), 100)
		if err != nil {
			common.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		common.WriteJSON(w, http.StatusOK, items)
		return
	}

	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 1 && r.Method == http.MethodGet {
		request, err := s.approvalService.Get(r.Context(), parts[0])
		if err != nil {
			common.WriteError(w, http.StatusNotFound, err.Error())
			return
		}
		common.WriteJSON(w, http.StatusOK, request)
		return
	}
	if len(parts) != 2 || parts[1] != "decision" || r.Method != http.MethodPost {
		common.WriteError(w, http.StatusNotFound, "approval route not found")
		return
	}

	var body approvals.Decision
	if err := common.ReadJSON(r, &body); err != nil {
		common.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	request, err := s.approvalService.Decide(
		r.Context(), parts[0], actorFromRequest(r), "user",
		body.Decision, body.Reason, "webhook_callback",
	)
	if err != nil {
		common.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, request)
}

func (s *Server) handleSlackApprovalCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		common.WriteError(w, http.StatusBadRequest, "unable to read Slack callback")
		return
	}
	result, err := s.slackApproval.Handle(r.Context(), r.Header, body)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "signature") || strings.Contains(err.Error(), "authorized") {
			status = http.StatusUnauthorized
		}
		common.WriteError(w, status, err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	items, err := s.auditor.List(r.Context(), 100)
	if err != nil {
		common.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, items)
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.store.ListServices(r.Context())
		if err != nil {
			common.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		common.WriteJSON(w, http.StatusOK, items)
	case http.MethodPost:
		var body struct {
			Name string `json:"name"`
		}
		if err := common.ReadJSON(r, &body); err != nil {
			common.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		item, err := s.store.EnsureService(r.Context(), body.Name)
		if err != nil {
			common.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		common.WriteJSON(w, http.StatusCreated, item)
	default:
		common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleRunbooks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	items, err := s.store.ListRunbooks(r.Context())
	if err != nil {
		common.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, items)
}

func (s *Server) handleRunbookReindex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	common.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

func (s *Server) notImplemented(w http.ResponseWriter, r *http.Request) {
	common.WriteError(w, http.StatusNotImplemented, "not implemented")
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicRoute(r) {
			next.ServeHTTP(w, r)
			return
		}

		principal, err := s.authenticator.Authenticate(r.Context(), auth.BearerToken(r))
		if err != nil {
			reason := auth.FailureReason(err)
			if s.metrics != nil {
				s.metrics.AuthenticationFailuresTotal.WithLabelValues(reason).Inc()
			}
			s.logger.Warn("authentication rejected", "path", r.URL.Path, "reason", reason)
			w.Header().Set("WWW-Authenticate", `Bearer realm="argus", error="invalid_token"`)
			common.WriteError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}

		permission := requiredPermission(r)
		if permission != "" && !principal.Can(permission) {
			if s.metrics != nil {
				s.metrics.AuthorizationDenialsTotal.WithLabelValues(string(principal.Role), string(permission)).Inc()
			}
			common.WriteError(w, http.StatusForbidden, "role is not allowed to perform this action")
			return
		}

		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
	})
}

func isPublicRoute(r *http.Request) bool {
	return r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/metrics" ||
		r.URL.Path == "/v1/approval-callbacks/slack"
}

func requiredPermission(r *http.Request) auth.Permission {
	path := r.URL.Path
	method := r.Method

	switch {
	case path == "/v1/auth/me" && method == http.MethodGet:
		return auth.PermissionView
	case path == "/v1/alerts/alertmanager" || path == "/v1/signals/manual":
		return auth.PermissionIngestSignal
	case path == "/v1/incidents" && method == http.MethodGet:
		return auth.PermissionView
	case path == "/v1/incidents" && method == http.MethodPost:
		return auth.PermissionManageIncident
	case strings.HasPrefix(path, "/v1/incidents/"):
		parts := strings.Split(strings.TrimPrefix(path, "/v1/incidents/"), "/")
		if len(parts) == 1 && method == http.MethodGet {
			return auth.PermissionView
		}
		if len(parts) == 2 {
			switch parts[1] {
			case "timeline", "signals", "rca", "remediations":
				if method == http.MethodGet {
					return auth.PermissionView
				}
			case "ack", "resolve":
				return auth.PermissionManageIncident
			}
		}
		if len(parts) == 3 && parts[1] == "rca" && parts[2] == "generate" {
			return auth.PermissionGenerateRCA
		}
		if len(parts) == 3 && parts[1] == "remediations" && parts[2] == "suggest" {
			return auth.PermissionGenerateRCA
		}
		if len(parts) == 3 && parts[1] == "remediations" && parts[2] == "propose" {
			return auth.PermissionProposeRemediation
		}
	case strings.HasPrefix(path, "/v1/remediations/"):
		parts := strings.Split(strings.TrimPrefix(path, "/v1/remediations/"), "/")
		if len(parts) == 2 {
			switch parts[1] {
			case "approve", "reject":
				return auth.PermissionApproveRemediation
			case "execute", "cancel":
				return auth.PermissionExecuteRemediation
			}
		}
	case path == "/v1/approval-requests" && method == http.MethodGet:
		return auth.PermissionView
	case strings.HasPrefix(path, "/v1/approval-requests/"):
		parts := strings.Split(strings.TrimPrefix(path, "/v1/approval-requests/"), "/")
		if len(parts) == 1 && method == http.MethodGet {
			return auth.PermissionView
		}
		if len(parts) == 2 && parts[1] == "decision" && method == http.MethodPost {
			return auth.PermissionApproveRemediation
		}
	case path == "/v1/audit":
		return auth.PermissionViewAudit
	case path == "/v1/services" && method == http.MethodGet:
		return auth.PermissionView
	case path == "/v1/services" && method == http.MethodPost:
		return auth.PermissionManageService
	case path == "/v1/runbooks" && method == http.MethodGet:
		return auth.PermissionView
	case path == "/v1/runbooks/reindex":
		return auth.PermissionReindexRunbook
	}
	return auth.PermissionView
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := firstHeader(r, "X-Request-ID", "X-Correlation-ID")
		if requestID == "" {
			requestID = fmt.Sprintf("req_%d", time.Now().UnixNano())
		}
		ctx := context.WithValue(r.Context(), ctxKeyRequestID{}, requestID)
		logger := common.WithRequestID(ctx, s.logger, requestID)
		logger.Info("request started", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r.WithContext(ctx))
		logger.Info("request completed", "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(start).Milliseconds())
	})
}

type ctxKeyRequestID struct{}

func actorFromRequest(r *http.Request) string {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		return "system"
	}
	return principal.ID
}

func roleFromRequest(r *http.Request) string {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		return string(auth.RoleOperator)
	}
	return string(principal.Role)
}

func firstHeader(r *http.Request, names ...string) string {
	for _, name := range names {
		if value := r.Header.Get(name); value != "" {
			return value
		}
	}
	return ""
}

func pretty(body any) string {
	data, _ := json.Marshal(body)
	return string(data)
}

func scenarioToAlert(scenario string) string {
	switch scenario {
	case "postgres_connection_exhaustion":
		return "PaymentsAPIPostgresConnectionExhaustion"
	case "redis_memory_pressure":
		return "PaymentsAPIRedisMemoryPressure"
	case "nginx_5xx_spike":
		return "Nginx5xxSpike"
	case "dependency_latency":
		return "PaymentsAPIDependencyLatency"
	case "bad_config_rollout":
		return "PaymentsAPIBadConfigRollout"
	default:
		return "DemoIncident"
	}
}

func scenarioToSummary(scenario string) string {
	switch scenario {
	case "postgres_connection_exhaustion":
		return "payments-api is showing postgres connection exhaustion signals"
	case "redis_memory_pressure":
		return "payments-api cache performance degraded due to redis memory pressure"
	case "nginx_5xx_spike":
		return "nginx is returning elevated 5xx responses for the payments path"
	case "dependency_latency":
		return "notification-api latency is dominating request time"
	case "bad_config_rollout":
		return "recent config rollout likely broke payments-api connectivity"
	default:
		return "generic demo incident"
	}
}
