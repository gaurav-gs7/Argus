package remediation_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/policy"
	"github.com/gauravgs7/argus/internal/remediation"
	"github.com/gauravgs7/argus/internal/telemetry"
	"github.com/gauravgs7/argus/internal/testutil"
)

// Against a real Helios control plane and worker (CI job
// helios-integration): a remediation delegated to Helios runs to
// succeeded; one whose poll ends early is followed to succeeded by the
// reconciler; and a submission Helios accepted while Argus "crashed" is
// adopted rather than submitted twice.
func TestHeliosLive(t *testing.T) {
	url, token := os.Getenv("ARGUS_TEST_HELIOS_URL"), os.Getenv("ARGUS_TEST_HELIOS_TOKEN")
	if url == "" || token == "" {
		t.Skip("ARGUS_TEST_HELIOS_URL and ARGUS_TEST_HELIOS_TOKEN are not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	database := testutil.ScratchDatabase(t)
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	metricsOnce.Do(func() { metrics = telemetry.MustRegister() })
	store := incidents.NewStore(database)
	auditor := audit.NewService(database)
	service := func(poll time.Duration) *remediation.Service {
		return remediation.NewService(store, auditor, policy.NewEngine(), nil, remediation.NewHeliosExecutor(url, token, poll), metrics, nil)
	}
	waitStatus := func(svc *remediation.Service, id, want string) {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := svc.ReconcileHelios(ctx, remediation.HeliosReconcileConfig{SubmitLostAfter: time.Second}); err != nil {
				t.Fatal(err)
			}
			if got := status(t, ctx, store, id); got == want {
				return
			} else if got != remediation.StateRunning && got != remediation.StateQueued {
				rem, _ := store.GetRemediation(ctx, id)
				t.Fatalf("%s ended %s, want %s: %s %v", id, got, want, rem.Error, rem.Result)
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("%s never reached %s (status %s)", id, want, status(t, ctx, store, id))
	}

	// 1. Normal delegation.
	direct := approvedRemediation(t, ctx, store, remediation.StateApproved)
	if _, err := service(30*time.Second).Execute(ctx, direct.ID, false, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if got := status(t, ctx, store, direct.ID); got != remediation.StateSucceeded {
		rem, _ := store.GetRemediation(ctx, direct.ID)
		t.Fatalf("delegated remediation: %s %s %v", got, rem.Error, rem.Result)
	}

	// 2. The poll ends before the workflow; the reconciler finishes the job.
	impatient := service(time.Millisecond)
	early := approvedRemediation(t, ctx, store, remediation.StateApproved)
	if _, err := impatient.Execute(ctx, early.ID, false, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if got := status(t, ctx, store, early.ID); got != remediation.StateRunning && got != remediation.StateSucceeded {
		t.Fatalf("early-poll remediation: %s", got)
	}
	waitStatus(impatient, early.ID, remediation.StateSucceeded)

	// 3. Helios accepted the workflow but Argus never recorded it.
	lost := approvedRemediation(t, ctx, store, remediation.StateApproved)
	if _, err := store.MarkRemediationQueued(ctx, lost.ID, false); err != nil {
		t.Fatal(err)
	}
	rem, _ := store.GetRemediation(ctx, lost.ID)
	incident, _ := store.GetIncident(ctx, rem.IncidentID)
	if _, err := remediation.NewHeliosExecutor(url, token, time.Millisecond).Execute(ctx, rem, incident, false); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE remediation_actions SET queued_at = now() - interval '1 hour' WHERE id = $1`, lost.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(impatient, lost.ID, remediation.StateSucceeded)
	if n := testutil.AuditCount(t, database, lost.ID, "remediation.running"); n != 1 {
		t.Fatalf("lost submission was not adopted (running audit entries=%d)", n)
	}
	if n := heliosWorkflowsFor(t, ctx, url, token, lost.ID); n != 1 {
		t.Fatalf("Helios has %d workflows for the lost submission, want 1", n)
	}
}

func heliosWorkflowsFor(t *testing.T, ctx context.Context, url, token, remediationID string) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url+"/api/v1/workflows?limit=500", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var list struct {
		Workflows []struct {
			Labels map[string]string `json:"labels"`
		} `json:"workflows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, wf := range list.Workflows {
		if wf.Labels["remediation_id"] == remediationID {
			n++
		}
	}
	return n
}
