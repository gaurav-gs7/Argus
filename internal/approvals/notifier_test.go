package approvals

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebhookNotifierSignsBoundApprovalPayload(t *testing.T) {
	const secret = "test-webhook-secret"
	var capturedBody []byte
	var capturedSignature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		capturedSignature = r.Header.Get("X-Argus-Signature-256")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	notifier, err := NewWebhookNotifier(server.URL, secret, "http://localhost:8080", "generic", time.Second)
	if err != nil {
		t.Fatalf("create notifier: %v", err)
	}
	request := Request{
		ID: "apr_1", RemediationID: "rem_1", IncidentID: "inc_1",
		ActionType: "restart_service", Target: "payments-api", Risk: "medium",
		Status: StatusPending, ExpiresAt: time.Unix(1_800_000_000, 0).UTC(),
	}
	if err := notifier.Notify(context.Background(), request, false); err != nil {
		t.Fatalf("notify: %v", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(capturedBody)
	wantSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(capturedSignature), []byte(wantSignature)) {
		t.Fatalf("signature = %q, want %q", capturedSignature, wantSignature)
	}
	var payload map[string]any
	if err := json.Unmarshal(capturedBody, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload["event"] != "approval.requested" {
		t.Fatalf("event = %v", payload["event"])
	}
	if !strings.Contains(payload["decision_url"].(string), "/v1/approval-requests/apr_1/decision") {
		t.Fatalf("decision URL is not bound to approval request: %v", payload["decision_url"])
	}
}

func TestWebhookNotifierRejectsInsecureRemoteURL(t *testing.T) {
	_, err := NewWebhookNotifier("http://example.com/approval", "secret", "http://localhost:8080", "generic", time.Second)
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected insecure remote webhook to be rejected, got %v", err)
	}
}

func TestGenericWebhookRequiresSignatureSecret(t *testing.T) {
	_, err := NewWebhookNotifier("https://approvals.example.com/events", "", "https://argus.example.com", "generic", time.Second)
	if err == nil || !strings.Contains(err.Error(), "WEBHOOK_SECRET") {
		t.Fatalf("expected unsigned generic webhook to be rejected, got %v", err)
	}
}

func TestCallbackURLRequiresHTTPSOutsideLoopback(t *testing.T) {
	_, err := NewWebhookNotifier("", "", "http://argus.example.com", "generic", time.Second)
	if err == nil || !strings.Contains(err.Error(), "callback URL must use HTTPS") {
		t.Fatalf("expected insecure callback URL to be rejected, got %v", err)
	}
}

func TestSlackNotificationDoesNotExposeWebhookURL(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier, err := NewWebhookNotifier(server.URL, "", "http://localhost:8080", "slack", time.Second)
	if err != nil {
		t.Fatalf("create notifier: %v", err)
	}
	request := Request{
		ID: "apr_2", RemediationID: "rem_2", IncidentID: "inc_2",
		ActionType: "rollback_config", Target: "payments-api", Risk: "medium",
		ExpiresAt: time.Unix(1_800_000_000, 0).UTC(),
	}
	if err := notifier.Notify(context.Background(), request, true); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if strings.Contains(body, server.URL) {
		t.Fatal("Slack payload leaked its secret webhook URL")
	}
	if !strings.Contains(body, "Approval escalation") {
		t.Fatalf("expected escalation message, got %s", body)
	}
}
