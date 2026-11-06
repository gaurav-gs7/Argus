package remediation_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

// fakeHelios implements the parts of the Helios API Argus uses.
type fakeHelios struct {
	mu          sync.Mutex
	workflows   map[string]map[string]any
	order       []string
	createState string
	submits     atomic.Int32
	cancels     []string
	failGets    atomic.Bool
}

func newFakeHelios(createState string) (*fakeHelios, *httptest.Server) {
	f := &fakeHelios{workflows: map[string]map[string]any{}, createState: createState}
	return f, httptest.NewServer(http.HandlerFunc(f.serve))
}

func (f *fakeHelios) add(labels map[string]string, state string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := fmt.Sprintf("wf_%d", len(f.order)+1)
	f.workflows[id] = map[string]any{"workflow_id": id, "name": "argus-remediation-" + labels["remediation_id"], "state": state, "labels": labels}
	f.order = append(f.order, id)
	return id
}

func (f *fakeHelios) set(id, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.workflows[id]["state"] = state
}

func (f *fakeHelios) serve(w http.ResponseWriter, r *http.Request) {
	write := func(status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workflows":
		var spec struct {
			Labels map[string]string `json:"labels"`
		}
		_ = json.NewDecoder(r.Body).Decode(&spec)
		f.submits.Add(1)
		id := f.add(spec.Labels, f.createState)
		write(http.StatusAccepted, map[string]any{"workflow_id": id, "state": "submitted"})
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/workflows":
		f.mu.Lock()
		var list []map[string]any
		for i := len(f.order) - 1; i >= 0; i-- {
			list = append(list, f.workflows[f.order[i]])
		}
		f.mu.Unlock()
		write(http.StatusOK, map[string]any{"workflows": list})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/workflows/"):
		if f.failGets.Load() {
			write(http.StatusInternalServerError, map[string]string{"error": "store unavailable"})
			return
		}
		f.mu.Lock()
		wf, ok := f.workflows[strings.TrimPrefix(r.URL.Path, "/api/v1/workflows/")]
		f.mu.Unlock()
		if !ok {
			write(http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		write(http.StatusOK, wf)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/cancel"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/workflows/"), "/cancel")
		f.mu.Lock()
		f.cancels = append(f.cancels, id)
		f.mu.Unlock()
		f.set(id, "cancelled")
		write(http.StatusAccepted, map[string]string{"status": "cancelled"})
	default:
		write(http.StatusNotFound, map[string]string{"error": r.Method + " " + r.URL.Path})
	}
}

func heliosEnv(t *testing.T, ctx context.Context, url string) (*sql.DB, *incidents.Store, *remediation.Service) {
	t.Helper()
	database := testutil.ScratchDatabase(t)
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	metricsOnce.Do(func() { metrics = telemetry.MustRegister() })
	store := incidents.NewStore(database)
	executor := remediation.NewHeliosExecutor(url, "admin-token", 100*time.Millisecond)
	return database, store, remediation.NewService(store, audit.NewService(database), policy.NewEngine(), nil, executor, metrics, nil)
}

func status(t *testing.T, ctx context.Context, store *incidents.Store, id string) string {
	t.Helper()
	rem, err := store.GetRemediation(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return rem.Status
}

// The executor's poll ends while the workflow is still running. Previously
// the remediation stayed running forever and the workflow id was only in
// the audit log. Now the id is stored and the reconciler follows the
// workflow to its final state.
func TestHeliosWorkflowsAreFollowedToTheirFinalState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	helios, server := newFakeHelios("running")
	defer server.Close()
	database, store, service := heliosEnv(t, ctx, server.URL)

	ok := approvedRemediation(t, ctx, store, remediation.StateApproved)
	bad := approvedRemediation(t, ctx, store, remediation.StateApproved)
	for _, rem := range []incidents.RemediationAction{ok, bad} {
		if _, err := service.Execute(ctx, rem.ID, false, "operator-1"); err != nil {
			t.Fatal(err)
		}
		after, _ := store.GetRemediation(ctx, rem.ID)
		if after.Status != remediation.StateRunning || after.Result["helios_workflow_id"] == nil {
			t.Fatalf("running Helios remediation lost its workflow id: %s %v", after.Status, after.Result)
		}
	}
	cfg := remediation.HeliosReconcileConfig{MaxRuntime: time.Hour}
	if result, err := service.ReconcileHelios(ctx, cfg); err != nil || len(result.Succeeded)+len(result.Failed)+len(result.TimedOut) != 0 {
		t.Fatalf("settled a workflow that is still running: %+v err=%v", result, err)
	}
	helios.set("wf_1", "succeeded")
	helios.set("wf_2", "failed")
	result, err := service.ReconcileHelios(ctx, cfg)
	if err != nil || !contains(result.Succeeded, ok.ID) || !contains(result.Failed, bad.ID) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if status(t, ctx, store, ok.ID) != remediation.StateSucceeded || status(t, ctx, store, bad.ID) != remediation.StateFailed {
		t.Fatal("final Helios states were not recorded")
	}
	if testutil.AuditCount(t, database, ok.ID, "remediation.completed") != 1 || testutil.AuditCount(t, database, bad.ID, "remediation.failed") != 1 {
		t.Fatal("reconciled outcomes were not audited")
	}
}

// A workflow that outlives MaxRuntime is cancelled in Helios and the
// remediation times out; while Helios is unreachable nothing changes.
func TestOverdueHeliosWorkflowIsCancelledAndUnreachableHeliosChangesNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	helios, server := newFakeHelios("running")
	defer server.Close()
	_, store, service := heliosEnv(t, ctx, server.URL)
	rem := approvedRemediation(t, ctx, store, remediation.StateApproved)
	if _, err := service.Execute(ctx, rem.ID, false, "operator-1"); err != nil {
		t.Fatal(err)
	}
	cfg := remediation.HeliosReconcileConfig{MaxRuntime: 300 * time.Millisecond}
	time.Sleep(500 * time.Millisecond)

	helios.failGets.Store(true)
	result, err := service.ReconcileHelios(ctx, cfg)
	if err != nil || !contains(result.Errors, rem.ID) || status(t, ctx, store, rem.ID) != remediation.StateRunning {
		t.Fatalf("unreachable Helios: %+v err=%v status=%s", result, err, status(t, ctx, store, rem.ID))
	}
	helios.failGets.Store(false)
	result, err = service.ReconcileHelios(ctx, cfg)
	if err != nil || !contains(result.TimedOut, rem.ID) {
		t.Fatalf("overdue workflow: %+v err=%v", result, err)
	}
	if status(t, ctx, store, rem.ID) != remediation.StateTimedOut || len(helios.cancels) != 1 || helios.cancels[0] != "wf_1" {
		t.Fatalf("status=%s cancels=%v", status(t, ctx, store, rem.ID), helios.cancels)
	}
}

// The API died during submission. If Helios created the workflow, Argus
// adopts it instead of submitting a second one; if not, it submits once,
// even with several replicas reconciling; if the incident closed meanwhile,
// the remediation is cancelled instead.
func TestLostHeliosSubmissionsAreAdoptedOrResubmittedOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	helios, server := newFakeHelios("succeeded")
	defer server.Close()
	database, store, service := heliosEnv(t, ctx, server.URL)
	lost := func() incidents.RemediationAction {
		rem := approvedRemediation(t, ctx, store, remediation.StateApproved)
		if _, err := store.MarkRemediationQueued(ctx, rem.ID, false); err != nil {
			t.Fatal(err)
		}
		return rem
	}
	accepted := lost()
	helios.add(map[string]string{"source": "argus", "remediation_id": accepted.ID}, "succeeded")
	neverSent := lost()
	closed := lost()
	if _, err := database.Exec(`UPDATE incidents SET status = 'resolved' WHERE id = $1`, closed.IncidentID); err != nil {
		t.Fatal(err)
	}

	cfg := remediation.HeliosReconcileConfig{SubmitLostAfter: time.Hour}
	if result, err := service.ReconcileHelios(ctx, cfg); err != nil || len(result.Adopted)+len(result.Resubmitted) != 0 {
		t.Fatalf("treated a fresh submission as lost: %+v err=%v", result, err)
	}
	if _, err := database.Exec(`UPDATE remediation_actions SET queued_at = now() - interval '1 hour' WHERE id IN ($1, $2, $3)`, accepted.ID, neverSent.ID, closed.ID); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan remediation.HeliosReconcileResult, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := service.ReconcileHelios(ctx, cfg)
			if err != nil {
				t.Error(err)
			}
			results <- r
		}()
	}
	wg.Wait()
	close(results)
	var adopted, resubmitted []string
	for r := range results {
		adopted = append(adopted, r.Adopted...)
		resubmitted = append(resubmitted, r.Resubmitted...)
	}
	if len(adopted) != 1 || adopted[0] != accepted.ID || len(resubmitted) != 1 || resubmitted[0] != neverSent.ID {
		t.Fatalf("adopted=%v resubmitted=%v", adopted, resubmitted)
	}
	if n := helios.submits.Load(); n != 1 {
		t.Fatalf("Helios received %d submissions, want 1", n)
	}
	for id, want := range map[string]string{accepted.ID: remediation.StateSucceeded, neverSent.ID: remediation.StateSucceeded, closed.ID: remediation.StateCancelled} {
		if got := status(t, ctx, store, id); got != want {
			t.Fatalf("%s: status=%s want %s", id, got, want)
		}
	}
}
