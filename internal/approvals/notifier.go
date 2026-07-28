package approvals

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type WebhookNotifier struct {
	webhookURL string
	secret     string
	baseURL    string
	mode       string
	client     *http.Client
}

func NewWebhookNotifier(webhookURL, secret, baseURL, mode string, timeout time.Duration) (*WebhookNotifier, error) {
	webhookURL = strings.TrimSpace(webhookURL)
	if webhookURL != "" {
		parsed, err := url.Parse(webhookURL)
		if err != nil || parsed.Host == "" {
			return nil, fmt.Errorf("invalid approval webhook URL")
		}
		host := parsed.Hostname()
		if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopback(host)) {
			return nil, fmt.Errorf("approval webhook must use HTTPS except for loopback development")
		}
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "generic"
	}
	if mode != "generic" && mode != "slack" {
		return nil, fmt.Errorf("approval webhook mode must be generic or slack")
	}
	if webhookURL != "" && mode == "generic" && strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("generic approval webhook requires ARGUS_APPROVAL_WEBHOOK_SECRET")
	}
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if err := validateEndpointURL(baseURL, "approval callback"); err != nil {
		return nil, err
	}
	return &WebhookNotifier{
		webhookURL: webhookURL,
		secret:     secret,
		baseURL:    baseURL,
		mode:       mode,
		client:     &http.Client{Timeout: timeout},
	}, nil
}

func validateEndpointURL(raw, label string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("invalid %s URL", label)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopback(parsed.Hostname())) {
		return fmt.Errorf("%s URL must use HTTPS except for loopback development", label)
	}
	return nil
}

func (n *WebhookNotifier) Name() string {
	if n.webhookURL == "" {
		return "disabled"
	}
	return n.mode
}

func (n *WebhookNotifier) Notify(ctx context.Context, request Request, escalation bool) error {
	if n.webhookURL == "" {
		return nil
	}
	payload := n.genericPayload(request, escalation)
	if n.mode == "slack" {
		payload = n.slackPayload(request, escalation)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode approval notification: %w", err)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create approval notification: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("X-Argus-Approval-ID", request.ID)
	if n.secret != "" {
		mac := hmac.New(sha256.New, []byte(n.secret))
		_, _ = mac.Write(body)
		httpRequest.Header.Set("X-Argus-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	response, err := n.client.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("deliver approval notification: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		return fmt.Errorf("approval webhook returned %s: %s", response.Status, strings.TrimSpace(string(limited)))
	}
	return nil
}

func (n *WebhookNotifier) genericPayload(request Request, escalation bool) map[string]any {
	event := "approval.requested"
	if escalation {
		event = "approval.escalated"
	}
	return map[string]any{
		"event":            event,
		"approval_request": request,
		"decision_url":     n.baseURL + "/v1/approval-requests/" + request.ID + "/decision",
		"decision_contract": map[string]string{
			"method": "POST",
			"body":   `{"decision":"approve|deny","reason":"required"}`,
			"auth":   "Argus operator/admin bearer token",
		},
	}
}

func (n *WebhookNotifier) slackPayload(request Request, escalation bool) map[string]any {
	prefix := "Approval required"
	if escalation {
		prefix = "Approval escalation"
	}
	text := fmt.Sprintf("*%s*: `%s` on `%s`\nRisk: *%s* | Incident: `%s`\nDeadline: %s\nRequest: `%s`\nDecision endpoint: `%s`\nA reason and an authenticated operator/admin identity are required.",
		slackEscape(prefix), slackEscape(request.ActionType), slackEscape(request.Target),
		slackEscape(request.Risk), slackEscape(request.IncidentID),
		request.ExpiresAt.UTC().Format(time.RFC3339), slackEscape(request.ID),
		slackEscape(n.baseURL+"/v1/approval-requests/"+request.ID+"/decision"))
	approveValue, _ := json.Marshal(slackActionValue{ApprovalID: request.ID, Decision: DecisionApprove})
	denyValue, _ := json.Marshal(slackActionValue{ApprovalID: request.ID, Decision: DecisionDeny})
	return map[string]any{
		"text": fmt.Sprintf("%s for %s on %s", prefix, request.ActionType, request.Target),
		"blocks": []map[string]any{
			{
				"type": "section",
				"text": map[string]string{"type": "mrkdwn", "text": text},
			},
			{
				"type": "actions",
				"elements": []map[string]any{
					{
						"type": "button", "action_id": "argus_approval_approve",
						"text":  map[string]string{"type": "plain_text", "text": "Approve"},
						"style": "primary", "value": string(approveValue),
					},
					{
						"type": "button", "action_id": "argus_approval_deny",
						"text":  map[string]string{"type": "plain_text", "text": "Deny"},
						"style": "danger", "value": string(denyValue),
					},
				},
			},
		},
	}
}

func slackEscape(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == '`' {
			return -1
		}
		return r
	}, value)
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(value)
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
