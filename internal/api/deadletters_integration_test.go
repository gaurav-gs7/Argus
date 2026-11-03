package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/auth"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/policy"
	"github.com/gauravgs7/argus/internal/queue"
	"github.com/gauravgs7/argus/internal/remediation"
	"github.com/gauravgs7/argus/internal/telemetry"
	"github.com/gauravgs7/argus/internal/testutil"
	"github.com/nats-io/nats.go"
)

var (
	dlqMetricsOnce sync.Once
	dlqMetrics     *telemetry.Metrics
)

// Dead-letter tooling end to end against PostgreSQL and JetStream: list
// with remediation status, replay a dead-lettered job for a queued
// remediation (it is re-sent from the outbox and the dead letter removed),
// refuse to replay one whose remediation moved on or that names none,
// discard with an audit entry, and keep all of it admin-only.
func TestDeadLetterReplayAndDiscard(t *testing.T) {
	url := os.Getenv("ARGUS_TEST_NATS_URL")
	if url == "" {
		t.Skip("ARGUS_TEST_NATS_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	database := testutil.ScratchDatabase(t)
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	dlqMetricsOnce.Do(func() { dlqMetrics = telemetry.MustRegister() })
	store := incidents.NewStore(database)
	auditor := audit.NewService(database)
	client, err := queue.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.EnsureStreams(); err != nil {
		t.Fatal(err)
	}
	js := client.JetStream()
	for _, stream := range []string{queue.RemediationStream, queue.DeadLetterStream} {
		if err := js.PurgeStream(stream); err != nil {
			t.Fatal(err)
		}
	}

	service := remediation.NewService(store, auditor, policy.NewEngine(), client, remediation.NewLocalExecutor(), dlqMetrics, nil)
	server := &Server{
		logger: discardLogger(), store: store, auditor: auditor, queue: client, metrics: dlqMetrics, remediationService: service,
		authenticator: fakeAuthenticator{tokens: map[string]auth.Principal{
			"admin-jwt":    {ID: "https://issuer.example#admin", Role: auth.RoleAdmin},
			"operator-jwt": {ID: "https://issuer.example#operator", Role: auth.RoleOperator},
		}},
	}
	handler := server.Handler()
	call := func(token, method, path string, body any) (int, map[string]any, []map[string]any) {
		t.Helper()
		var reader *bytes.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			reader = bytes.NewReader(raw)
		} else {
			reader = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, reader)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		var obj map[string]any
		var list []map[string]any
		if json.Unmarshal(rec.Body.Bytes(), &obj) != nil {
			_ = json.Unmarshal(rec.Body.Bytes(), &list)
		}
		return rec.Code, obj, list
	}

	incident, err := store.CreateManualIncident(ctx, incidents.ManualIncidentRequest{Title: "dlq", Service: "dlq-svc", Severity: "sev3"})
	if err != nil {
		t.Fatal(err)
	}
	newRemediation := func() incidents.RemediationAction {
		rem := incidents.RemediationAction{
			ID: fmt.Sprintf("rem_dlq_%d", time.Now().UnixNano()), IncidentID: incident.ID, ActionType: "collect_diagnostics", Target: "dlq-svc",
			Status: remediation.StateApproved, Risk: "low", IdempotencyKey: fmt.Sprintf("dlq-%d", time.Now().UnixNano()), ProposedBy: "test",
			MaxAttempts: 1, PolicyDecision: map[string]any{},
		}
		if err := store.CreateRemediation(ctx, rem); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Execute(ctx, rem.ID, false, "operator"); err != nil {
			t.Fatal(err)
		}
		return rem
	}
	// Dead-letter a job the way a worker does: fetch it, republish it with
	// a reason, terminate the original.
	sub, err := js.PullSubscribe(queue.RemediationSubject, "", nats.BindStream(queue.RemediationStream))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	deadLetter := func(remediationID string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			msgs, _ := sub.Fetch(10, nats.MaxWait(time.Second))
			for _, msg := range msgs {
				var event queue.Event
				_ = json.Unmarshal(msg.Data, &event)
				_ = msg.Term()
				if event.Payload["remediation_id"] == remediationID {
					if err := client.DeadLetter(ctx, msg, "retries_exhausted"); err != nil {
						t.Fatal(err)
					}
					return
				}
			}
		}
		t.Fatalf("job for %s never arrived", remediationID)
	}

	stuck := newRemediation()
	deadLetter(stuck.ID)
	moved := newRemediation()
	deadLetter(moved.ID)
	if _, err := database.Exec(`UPDATE remediation_actions SET status = 'cancelled' WHERE id = $1`, moved.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := js.PublishMsg(&nats.Msg{Subject: queue.DeadLetterSubject, Data: []byte("not json"), Header: nats.Header{"Argus-Dead-Letter-Reason": []string{"undecodable_payload"}}}); err != nil {
		t.Fatal(err)
	}

	// Operators cannot see or touch dead letters.
	if code, _, _ := call("operator-jwt", http.MethodGet, "/v1/dead-letters", nil); code != http.StatusForbidden {
		t.Fatalf("operator list: %d", code)
	}
	code, _, letters := call("admin-jwt", http.MethodGet, "/v1/dead-letters", nil)
	if code != http.StatusOK || len(letters) != 3 {
		t.Fatalf("list: %d %v", code, letters)
	}
	seqOf := map[string]string{}
	for _, l := range letters {
		id, _ := l["remediation_id"].(string)
		seqOf[id] = strconv.FormatFloat(l["sequence"].(float64), 'f', 0, 64)
		switch id {
		case stuck.ID:
			if l["replayable"] != true || l["remediation_status"] != "queued" || l["reason"] != "retries_exhausted" {
				t.Fatalf("stuck letter: %v", l)
			}
		case moved.ID:
			if l["replayable"] != false || l["remediation_status"] != "cancelled" {
				t.Fatalf("moved letter: %v", l)
			}
		case "":
			if l["reason"] != "undecodable_payload" || l["replayable"] != false {
				t.Fatalf("poison letter: %v", l)
			}
		}
	}

	if code, _, _ := call("operator-jwt", http.MethodPost, "/v1/dead-letters/"+seqOf[stuck.ID]+"/replay", map[string]string{"reason": "db back"}); code != http.StatusForbidden {
		t.Fatalf("operator replay: %d", code)
	}
	if code, _, _ := call("admin-jwt", http.MethodPost, "/v1/dead-letters/"+seqOf[stuck.ID]+"/replay", map[string]string{}); code != http.StatusBadRequest {
		t.Fatalf("replay without a reason: %d", code)
	}
	code, body, _ := call("admin-jwt", http.MethodPost, "/v1/dead-letters/"+seqOf[stuck.ID]+"/replay", map[string]string{"reason": "database recovered"})
	if code != http.StatusAccepted || body["dispatch_id"] == nil {
		t.Fatalf("replay: %d %v", code, body)
	}
	// The job is back on the remediation stream.
	deadline := time.Now().Add(10 * time.Second)
	found := false
	for time.Now().Before(deadline) && !found {
		msgs, _ := sub.Fetch(10, nats.MaxWait(time.Second))
		for _, msg := range msgs {
			var event queue.Event
			_ = json.Unmarshal(msg.Data, &event)
			_ = msg.Ack()
			found = found || (event.Payload["remediation_id"] == stuck.ID && event.EventID == body["dispatch_id"])
		}
	}
	if !found {
		t.Fatal("replayed job was not re-published")
	}
	if code, _, _ := call("admin-jwt", http.MethodPost, "/v1/dead-letters/"+seqOf[stuck.ID]+"/replay", map[string]string{"reason": "again"}); code != http.StatusNotFound {
		t.Fatalf("replayed dead letter still present: %d", code)
	}

	if code, body, _ := call("admin-jwt", http.MethodPost, "/v1/dead-letters/"+seqOf[moved.ID]+"/replay", map[string]string{"reason": "try"}); code != http.StatusConflict || body["remediation_status"] != "cancelled" {
		t.Fatalf("replay of a cancelled remediation: %d %v", code, body)
	}
	if code, _, _ := call("admin-jwt", http.MethodPost, "/v1/dead-letters/"+seqOf[""]+"/replay", map[string]string{"reason": "try"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("replay of a poison message: %d", code)
	}
	for _, id := range []string{moved.ID, ""} {
		if code, body, _ := call("admin-jwt", http.MethodPost, "/v1/dead-letters/"+seqOf[id]+"/discard", map[string]string{"reason": "triaged"}); code != http.StatusOK || body["status"] != "discarded" {
			t.Fatalf("discard %q: %d %v", id, code, body)
		}
	}
	if code, _, letters := call("admin-jwt", http.MethodGet, "/v1/dead-letters", nil); code != http.StatusOK || len(letters) != 0 {
		t.Fatalf("after replay and discards: %d %v", code, letters)
	}
	if testutil.AuditCount(t, database, stuck.ID, "remediation.redispatched") != 1 ||
		testutil.AuditCount(t, database, moved.ID, "remediation.dead_letter_discarded") != 1 ||
		testutil.AuditCount(t, database, seqOf[""], "remediation.dead_letter_discarded") != 1 {
		t.Fatal("dead-letter actions were not audited")
	}
	var reason string
	if err := database.QueryRow(`SELECT reason FROM remediation_dispatches WHERE id = $1`, body["dispatch_id"]).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != remediation.DispatchReplay {
		t.Fatalf("latest dispatch reason=%q, want replay", reason)
	}
}
