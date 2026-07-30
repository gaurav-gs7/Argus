package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gauravgs7/argus/internal/auth"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRequiredPermissionForProtectedRoutes(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   auth.Permission
	}{
		{http.MethodPost, "/v1/alerts/alertmanager", auth.PermissionIngestSignal},
		{http.MethodPost, "/v1/signals/manual", auth.PermissionIngestSignal},
		{http.MethodGet, "/v1/incidents", auth.PermissionView},
		{http.MethodPost, "/v1/incidents", auth.PermissionManageIncident},
		{http.MethodGet, "/v1/incidents/inc_1", auth.PermissionView},
		{http.MethodPost, "/v1/incidents/inc_1/ack", auth.PermissionManageIncident},
		{http.MethodPost, "/v1/incidents/inc_1/resolve", auth.PermissionManageIncident},
		{http.MethodGet, "/v1/incidents/inc_1/timeline", auth.PermissionView},
		{http.MethodGet, "/v1/incidents/inc_1/signals", auth.PermissionView},
		{http.MethodGet, "/v1/incidents/inc_1/topology", auth.PermissionView},
		{http.MethodGet, "/v1/incidents/inc_1/rca", auth.PermissionView},
		{http.MethodGet, "/v1/incidents/inc_1/remediations", auth.PermissionView},
		{http.MethodPost, "/v1/incidents/inc_1/rca/generate", auth.PermissionGenerateRCA},
		{http.MethodPost, "/v1/incidents/inc_1/remediations/suggest", auth.PermissionGenerateRCA},
		{http.MethodPost, "/v1/incidents/inc_1/remediations/propose", auth.PermissionProposeRemediation},
		{http.MethodGet, "/v1/auth/me", auth.PermissionView},
		{http.MethodPost, "/v1/remediations/rem_1/approve", auth.PermissionApproveRemediation},
		{http.MethodPost, "/v1/remediations/rem_1/reject", auth.PermissionApproveRemediation},
		{http.MethodPost, "/v1/remediations/rem_1/execute", auth.PermissionExecuteRemediation},
		{http.MethodPost, "/v1/remediations/rem_1/cancel", auth.PermissionExecuteRemediation},
		{http.MethodGet, "/v1/approval-requests", auth.PermissionView},
		{http.MethodGet, "/v1/approval-requests/apr_1", auth.PermissionView},
		{http.MethodPost, "/v1/approval-requests/apr_1/decision", auth.PermissionApproveRemediation},
		{http.MethodGet, "/v1/audit", auth.PermissionViewAudit},
		{http.MethodGet, "/v1/audit/verify", auth.PermissionViewAudit},
		{http.MethodGet, "/v1/services", auth.PermissionView},
		{http.MethodPost, "/v1/services", auth.PermissionManageService},
		{http.MethodGet, "/v1/topology", auth.PermissionView},
		{http.MethodPost, "/v1/topology/dependencies", auth.PermissionManageService},
		{http.MethodGet, "/v1/runbooks", auth.PermissionView},
		{http.MethodPost, "/v1/runbooks/reindex", auth.PermissionReindexRunbook},
		{http.MethodGet, "/v1/not-a-route", auth.PermissionView},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.path, nil)
		if got := requiredPermission(req); got != tt.want {
			t.Fatalf("requiredPermission(%s %s) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestAuthMiddlewareRejectsMissingToken(t *testing.T) {
	srv := &Server{authenticator: fakeAuthenticator{}, logger: discardLogger()}
	handler := srv.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/incidents", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="argus", error="invalid_token"` {
		t.Fatalf("unexpected WWW-Authenticate header %q", got)
	}
}

func TestActorUsesImmutableOIDCIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/incidents", nil)
	principal := auth.Principal{
		ID:      "https://identity.example.test#subject-123",
		Subject: "subject-123",
		Issuer:  "https://identity.example.test",
		Email:   "mutable-address@example.test",
		Role:    auth.RoleOperator,
	}
	req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
	if got := actorFromRequest(req); got != principal.ID {
		t.Fatalf("audit actor=%q, want immutable identity %q", got, principal.ID)
	}
}

func TestOnlySlackCallbackIsPublic(t *testing.T) {
	publicPaths := []string{"/healthz", "/readyz", "/metrics", "/v1/approval-callbacks/slack"}
	for _, path := range publicPaths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if !isPublicRoute(req) {
			t.Fatalf("%s should be public", path)
		}
	}
	protectedPaths := []string{
		"/v1/auth/me",
		"/v1/incidents",
		"/v1/approval-requests/apr_1/decision",
		"/healthz/extra",
		"/metrics/extra",
	}
	for _, path := range protectedPaths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if isPublicRoute(req) {
			t.Fatalf("%s must require bearer authentication", path)
		}
	}
}

func TestAuthMiddlewareAllowsViewerReadButBlocksMutation(t *testing.T) {
	srv := &Server{
		authenticator: fakeAuthenticator{tokens: map[string]auth.Principal{
			"viewer-jwt": {
				ID:      "https://issuer.example#viewer-subject",
				Subject: "viewer-subject",
				Issuer:  "https://issuer.example",
				Email:   "viewer@example.test",
				Role:    auth.RoleViewer,
			},
		}},
		logger: discardLogger(),
	}
	handler := srv.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	readReq := httptest.NewRequest(http.MethodGet, "/v1/incidents", nil)
	readReq.Header.Set("Authorization", "Bearer viewer-jwt")
	readRec := httptest.NewRecorder()
	handler.ServeHTTP(readRec, readReq)
	if readRec.Code != http.StatusNoContent {
		t.Fatalf("expected viewer read to pass, got %d", readRec.Code)
	}

	writeReq := httptest.NewRequest(http.MethodPost, "/v1/services", nil)
	writeReq.Header.Set("Authorization", "Bearer viewer-jwt")
	writeRec := httptest.NewRecorder()
	handler.ServeHTTP(writeRec, writeReq)
	if writeRec.Code != http.StatusForbidden {
		t.Fatalf("expected viewer mutation to be forbidden, got %d", writeRec.Code)
	}
}

func TestAuthMiddlewarePropagatesVerifiedPrincipal(t *testing.T) {
	want := auth.Principal{
		ID:          "https://issuer.example#operator-subject",
		Subject:     "operator-subject",
		Issuer:      "https://issuer.example",
		DisplayName: "On-call Operator",
		Role:        auth.RoleOperator,
	}
	srv := &Server{
		authenticator: fakeAuthenticator{tokens: map[string]auth.Principal{"operator-jwt": want}},
		logger:        discardLogger(),
	}
	handler := srv.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := auth.PrincipalFromContext(r.Context())
		if !ok || got != want {
			t.Fatalf("principal was not propagated: got=%+v ok=%t", got, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/incidents", nil)
	req.Header.Set("Authorization", "Bearer operator-jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected authenticated request to pass, got %d", rec.Code)
	}
}

func TestAuthMiddlewareEmitsFailureAndDenialMetrics(t *testing.T) {
	metrics := &telemetry.Metrics{
		AuthenticationFailuresTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_authentication_failures_total",
		}, []string{"reason"}),
		AuthorizationDenialsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_authorization_denials_total",
		}, []string{"role", "permission"}),
	}
	srv := &Server{
		authenticator: fakeAuthenticator{tokens: map[string]auth.Principal{
			"viewer-jwt": {Role: auth.RoleViewer},
		}},
		logger:  discardLogger(),
		metrics: metrics,
	}
	handler := srv.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	missing := httptest.NewRequest(http.MethodGet, "/v1/incidents", nil)
	handler.ServeHTTP(httptest.NewRecorder(), missing)
	if got := testutil.ToFloat64(metrics.AuthenticationFailuresTotal.WithLabelValues("internal_error")); got != 1 {
		t.Fatalf("authentication failure metric=%v, want 1", got)
	}

	denied := httptest.NewRequest(http.MethodPost, "/v1/services", nil)
	denied.Header.Set("Authorization", "Bearer viewer-jwt")
	handler.ServeHTTP(httptest.NewRecorder(), denied)
	if got := testutil.ToFloat64(metrics.AuthorizationDenialsTotal.WithLabelValues("viewer", "manage_service")); got != 1 {
		t.Fatalf("authorization denial metric=%v, want 1", got)
	}
}

func TestObserveTopologyIngestionSeparatesRootAndSuppressedAlerts(t *testing.T) {
	metrics := &telemetry.Metrics{
		TopologyAlertsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_topology_alerts_total",
		}, []string{"disposition"}),
		TopologyIncidentGroupsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_topology_groups_total",
		}, []string{"root_source"}),
		TopologySuppressionRatio: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "test_topology_suppression_ratio",
		}),
		TopologyAffectedServices: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "test_topology_affected_services",
		}),
	}
	srv := &Server{metrics: metrics}
	srv.observeTopologyIngestion(incidents.IngestionStats{
		AlertCount:           20,
		IncidentGroups:       1,
		AffectedServiceCount: 4,
		ObservedRoots:        1,
		SuppressedAlertCount: 18,
	})

	if got := testutil.ToFloat64(metrics.TopologyAlertsTotal.WithLabelValues("root")); got != 2 {
		t.Fatalf("root alert metric=%v, want 2", got)
	}
	if got := testutil.ToFloat64(metrics.TopologyAlertsTotal.WithLabelValues("suppressed")); got != 18 {
		t.Fatalf("suppressed alert metric=%v, want 18", got)
	}
	if got := testutil.ToFloat64(metrics.TopologyIncidentGroupsTotal.WithLabelValues("observed")); got != 1 {
		t.Fatalf("observed root metric=%v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.TopologyIncidentGroupsTotal.WithLabelValues("inferred")); got != 0 {
		t.Fatalf("inferred root metric=%v, want 0", got)
	}
	if got := testutil.CollectAndCount(metrics.TopologySuppressionRatio); got != 1 {
		t.Fatalf("suppression histogram metric count=%v, want 1", got)
	}
	if got := testutil.CollectAndCount(metrics.TopologyAffectedServices); got != 1 {
		t.Fatalf("affected-services histogram metric count=%v, want 1", got)
	}
}

type fakeAuthenticator struct {
	tokens map[string]auth.Principal
}

func (f fakeAuthenticator) Authenticate(_ context.Context, header string) (auth.Principal, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return auth.Principal{}, errors.New("invalid token")
	}
	principal, ok := f.tokens[strings.TrimPrefix(header, prefix)]
	if !ok {
		return auth.Principal{}, errors.New("invalid token")
	}
	return principal, nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
