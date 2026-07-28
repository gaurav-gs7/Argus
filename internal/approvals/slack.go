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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type SlackWorkflow struct {
	service       *Service
	signingSecret string
	botToken      string
	approvers     map[string]string
	client        *http.Client
	now           func() time.Time
	viewsOpenURL  string
}

func NewSlackWorkflow(service *Service, signingSecret, botToken, rawApprovers string, timeout time.Duration) (*SlackWorkflow, error) {
	approvers, err := parseSlackApprovers(rawApprovers)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &SlackWorkflow{
		service: service, signingSecret: strings.TrimSpace(signingSecret),
		botToken: strings.TrimSpace(botToken), approvers: approvers,
		client: &http.Client{Timeout: timeout}, now: time.Now,
		viewsOpenURL: "https://slack.com/api/views.open",
	}, nil
}

func (s *SlackWorkflow) Enabled() bool {
	return s.signingSecret != "" && s.botToken != "" && len(s.approvers) > 0
}

func (s *SlackWorkflow) Handle(ctx context.Context, headers http.Header, body []byte) (map[string]any, error) {
	if !s.Enabled() {
		return nil, fmt.Errorf("Slack approval callbacks are not configured")
	}
	if err := verifySlackSignature(s.signingSecret, headers, body, s.now()); err != nil {
		return nil, err
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("invalid Slack callback body")
	}
	var payload slackPayload
	if err := json.Unmarshal([]byte(values.Get("payload")), &payload); err != nil {
		return nil, fmt.Errorf("invalid Slack callback payload")
	}
	actor, allowed := s.approvers[payload.User.ID]
	if !allowed {
		return nil, fmt.Errorf("Slack user is not an authorized Argus approver")
	}

	switch payload.Type {
	case "block_actions":
		if len(payload.Actions) != 1 || payload.TriggerID == "" {
			return nil, fmt.Errorf("invalid Slack approval action")
		}
		var value slackActionValue
		if err := json.Unmarshal([]byte(payload.Actions[0].Value), &value); err != nil {
			return nil, fmt.Errorf("invalid Slack approval action")
		}
		if value.ApprovalID == "" || (value.Decision != DecisionApprove && value.Decision != DecisionDeny) {
			return nil, fmt.Errorf("invalid Slack approval action")
		}
		if err := s.openReasonModal(ctx, payload.TriggerID, value); err != nil {
			return nil, err
		}
		return map[string]any{
			"response_type": "ephemeral",
			"text":          "Argus opened a reason prompt. The remediation remains blocked until it is submitted.",
		}, nil
	case "view_submission":
		var value slackActionValue
		if err := json.Unmarshal([]byte(payload.View.PrivateMetadata), &value); err != nil {
			return nil, fmt.Errorf("invalid Slack approval metadata")
		}
		reason := payload.reason()
		request, err := s.service.Decide(ctx, value.ApprovalID, actor, "slack_user", value.Decision, reason, "slack")
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"response_action": "clear",
			"approval_id":     request.ID,
			"status":          request.Status,
			"decided_by":      actor,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported Slack callback type")
	}
}

func (s *SlackWorkflow) openReasonModal(ctx context.Context, triggerID string, value slackActionValue) error {
	metadata, _ := json.Marshal(value)
	title := "Approve remediation"
	submit := "Approve"
	if value.Decision == DecisionDeny {
		title = "Deny remediation"
		submit = "Deny"
	}
	view := map[string]any{
		"type":             "modal",
		"callback_id":      "argus_approval_decision",
		"private_metadata": string(metadata),
		"title":            map[string]string{"type": "plain_text", "text": title},
		"submit":           map[string]string{"type": "plain_text", "text": submit},
		"close":            map[string]string{"type": "plain_text", "text": "Cancel"},
		"blocks": []map[string]any{{
			"type":     "input",
			"block_id": "decision_reason",
			"label":    map[string]string{"type": "plain_text", "text": "Reason"},
			"element": map[string]any{
				"type":        "plain_text_input",
				"action_id":   "reason",
				"multiline":   true,
				"min_length":  8,
				"max_length":  500,
				"placeholder": map[string]string{"type": "plain_text", "text": "What evidence did you review, and why is this decision safe?"},
			},
		}},
	}
	payload, _ := json.Marshal(map[string]any{"trigger_id": triggerID, "view": view})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.viewsOpenURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create Slack modal request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+s.botToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("open Slack approval modal: %w", err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || json.Unmarshal(raw, &result) != nil || !result.OK {
		return fmt.Errorf("Slack rejected approval modal: %s", result.Error)
	}
	return nil
}

func verifySlackSignature(secret string, headers http.Header, body []byte, now time.Time) error {
	rawTimestamp := headers.Get("X-Slack-Request-Timestamp")
	timestamp, err := strconv.ParseInt(rawTimestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid Slack request timestamp")
	}
	if delta := now.Unix() - timestamp; delta > 300 || delta < -300 {
		return fmt.Errorf("Slack request timestamp is outside the replay window")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = fmt.Fprintf(mac, "v0:%s:", rawTimestamp)
	_, _ = mac.Write(body)
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(headers.Get("X-Slack-Signature")), []byte(expected)) {
		return fmt.Errorf("invalid Slack request signature")
	}
	return nil
}

func parseSlackApprovers(raw string) (map[string]string, error) {
	approvers := make(map[string]string)
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, fmt.Errorf("Slack approvers must use SLACK_USER_ID=argus-identity entries")
		}
		approvers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return approvers, nil
}

type slackActionValue struct {
	ApprovalID string `json:"approval_id"`
	Decision   string `json:"decision"`
}

type slackPayload struct {
	Type      string `json:"type"`
	TriggerID string `json:"trigger_id"`
	User      struct {
		ID string `json:"id"`
	} `json:"user"`
	Actions []struct {
		Value string `json:"value"`
	} `json:"actions"`
	View struct {
		PrivateMetadata string `json:"private_metadata"`
		State           struct {
			Values map[string]map[string]struct {
				Value string `json:"value"`
			} `json:"values"`
		} `json:"state"`
	} `json:"view"`
}

func (v slackPayload) reason() string {
	for _, block := range v.View.State.Values {
		for _, action := range block {
			if strings.TrimSpace(action.Value) != "" {
				return strings.TrimSpace(action.Value)
			}
		}
	}
	return ""
}
