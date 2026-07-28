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
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVerifySlackSignatureAndReplayWindow(t *testing.T) {
	const secret = "slack-signing-secret"
	now := time.Unix(1_800_000_000, 0)
	body := []byte("payload=%7B%22type%22%3A%22block_actions%22%7D")
	timestamp := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("v0:" + timestamp + ":"))
	_, _ = mac.Write(body)
	headers := http.Header{
		"X-Slack-Request-Timestamp": []string{timestamp},
		"X-Slack-Signature":         []string{"v0=" + hex.EncodeToString(mac.Sum(nil))},
	}
	if err := verifySlackSignature(secret, headers, body, now); err != nil {
		t.Fatalf("valid Slack signature rejected: %v", err)
	}
	headers.Set("X-Slack-Signature", "v0=invalid")
	if err := verifySlackSignature(secret, headers, body, now); err == nil {
		t.Fatal("invalid Slack signature was accepted")
	}
	headers.Set("X-Slack-Request-Timestamp", strconv.FormatInt(now.Add(-301*time.Second).Unix(), 10))
	if err := verifySlackSignature(secret, headers, body, now); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("stale callback error = %v", err)
	}
}

func TestParseSlackApproversRequiresIdentityMapping(t *testing.T) {
	approvers, err := parseSlackApprovers("U123=admin@local,U456=operator2@local")
	if err != nil {
		t.Fatalf("parse approvers: %v", err)
	}
	if approvers["U123"] != "admin@local" {
		t.Fatalf("mapped identity = %q", approvers["U123"])
	}
	if _, err := parseSlackApprovers("U123"); err == nil {
		t.Fatal("unmapped Slack identity was accepted")
	}
}

func TestSlackPayloadReasonExtraction(t *testing.T) {
	var payload slackPayload
	payload.View.State.Values = map[string]map[string]struct {
		Value string `json:"value"`
	}{
		"decision_reason": {
			"reason": {Value: "  Reviewed error-rate recovery and rollback plan  "},
		},
	}
	if got := payload.reason(); got != "Reviewed error-rate recovery and rollback plan" {
		t.Fatalf("reason = %q", got)
	}
}

func TestSlackEscapeNeutralizesMarkupAndControls(t *testing.T) {
	got := slackEscape("<!channel>`\nrestart & approve")
	if strings.Contains(got, "<!channel>") || strings.Contains(got, "`") || strings.Contains(got, "\n") {
		t.Fatalf("unsafe Slack markup survived: %q", got)
	}
	if !strings.Contains(got, "&lt;!channel&gt;") || !strings.Contains(got, "&amp;") {
		t.Fatalf("Slack markup was not escaped: %q", got)
	}
}

func TestSlackButtonOpensBoundReasonModal(t *testing.T) {
	var modal map[string]any
	slackAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer xoxb-test" {
			t.Fatalf("authorization = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &modal); err != nil {
			t.Fatalf("decode modal: %v", err)
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer slackAPI.Close()

	workflow, err := NewSlackWorkflow(nil, "signing-secret", "xoxb-test", "U123=admin@local", time.Second)
	if err != nil {
		t.Fatalf("create Slack workflow: %v", err)
	}
	workflow.viewsOpenURL = slackAPI.URL
	workflow.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	actionValue, _ := json.Marshal(slackActionValue{ApprovalID: "apr_123", Decision: DecisionApprove})
	payload, _ := json.Marshal(map[string]any{
		"type":       "block_actions",
		"trigger_id": "trigger-123",
		"user":       map[string]string{"id": "U123"},
		"actions":    []map[string]string{{"value": string(actionValue)}},
	})
	body := []byte(url.Values{"payload": []string{string(payload)}}.Encode())
	headers := signedSlackHeaders("signing-secret", body, workflow.now())

	if _, err := workflow.Handle(context.Background(), headers, body); err != nil {
		t.Fatalf("handle Slack button: %v", err)
	}
	if modal["trigger_id"] != "trigger-123" {
		t.Fatalf("trigger_id = %v", modal["trigger_id"])
	}
	view := modal["view"].(map[string]any)
	var metadata slackActionValue
	if err := json.Unmarshal([]byte(view["private_metadata"].(string)), &metadata); err != nil {
		t.Fatalf("decode private metadata: %v", err)
	}
	if metadata.ApprovalID != "apr_123" || metadata.Decision != DecisionApprove {
		t.Fatalf("modal metadata = %+v", metadata)
	}
}

func signedSlackHeaders(secret string, body []byte, now time.Time) http.Header {
	timestamp := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("v0:" + timestamp + ":"))
	_, _ = mac.Write(body)
	return http.Header{
		"X-Slack-Request-Timestamp": []string{timestamp},
		"X-Slack-Signature":         []string{"v0=" + hex.EncodeToString(mac.Sum(nil))},
	}
}
