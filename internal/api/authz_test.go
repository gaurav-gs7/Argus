package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gauravgs7/argus/internal/auth"
)

func TestRequiredPermissionForStateChangingRoutes(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   auth.Permission
	}{
		{http.MethodPost, "/v1/incidents/inc_1/rca/generate", auth.PermissionGenerateRCA},
		{http.MethodPost, "/v1/incidents/inc_1/remediations/suggest", auth.PermissionGenerateRCA},
		{http.MethodPost, "/v1/incidents/inc_1/remediations/propose", auth.PermissionProposeRemediation},
		{http.MethodPost, "/v1/remediations/rem_1/approve", auth.PermissionApproveRemediation},
		{http.MethodPost, "/v1/remediations/rem_1/execute", auth.PermissionExecuteRemediation},
		{http.MethodPost, "/v1/approval-requests/apr_1/decision", auth.PermissionApproveRemediation},
		{http.MethodPost, "/v1/services", auth.PermissionManageService},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.path, nil)
		if got := requiredPermission(req); got != tt.want {
			t.Fatalf("requiredPermission(%s %s) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestAuthMiddlewareRejectsMissingToken(t *testing.T) {
	authn, err := auth.NewAuthenticator("viewer-token:viewer:viewer@local")
	if err != nil {
		t.Fatalf("unexpected auth config error: %v", err)
	}
	srv := &Server{authenticator: authn}
	handler := srv.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/incidents", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestOnlySlackCallbackIsPublic(t *testing.T) {
	slack := httptest.NewRequest(http.MethodPost, "/v1/approval-callbacks/slack", nil)
	if !isPublicRoute(slack) {
		t.Fatal("signed Slack callback must bypass bearer auth")
	}
	decision := httptest.NewRequest(http.MethodPost, "/v1/approval-requests/apr_1/decision", nil)
	if isPublicRoute(decision) {
		t.Fatal("generic approval decision endpoint must require bearer auth")
	}
}

func TestAuthMiddlewareAllowsViewerReadButBlocksMutation(t *testing.T) {
	authn, err := auth.NewAuthenticator("viewer-token:viewer:viewer@local")
	if err != nil {
		t.Fatalf("unexpected auth config error: %v", err)
	}
	srv := &Server{authenticator: authn}
	handler := srv.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	readReq := httptest.NewRequest(http.MethodGet, "/v1/incidents", nil)
	readReq.Header.Set("Authorization", "Bearer viewer-token")
	readRec := httptest.NewRecorder()
	handler.ServeHTTP(readRec, readReq)
	if readRec.Code != http.StatusNoContent {
		t.Fatalf("expected viewer read to pass, got %d", readRec.Code)
	}

	writeReq := httptest.NewRequest(http.MethodPost, "/v1/services", nil)
	writeReq.Header.Set("Authorization", "Bearer viewer-token")
	writeRec := httptest.NewRecorder()
	handler.ServeHTTP(writeRec, writeReq)
	if writeRec.Code != http.StatusForbidden {
		t.Fatalf("expected viewer mutation to be forbidden, got %d", writeRec.Code)
	}
}
