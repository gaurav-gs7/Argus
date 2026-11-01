package remediation_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/policy"
	"github.com/gauravgs7/argus/internal/rca"
	"github.com/gauravgs7/argus/internal/remediation"
	"github.com/gauravgs7/argus/internal/telemetry"
)

var (
	metricsOnce sync.Once
	metrics     *telemetry.Metrics
)

// The policy used to be told every incident was "local", so production
// incidents passed the environment gate.
func TestProposalUsesIncidentEnvironment(t *testing.T) {
	dsn := os.Getenv("ARGUS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ARGUS_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	metricsOnce.Do(func() { metrics = telemetry.MustRegister() })
	store := incidents.NewStore(database)
	auditor := audit.NewService(database)
	manager := incidents.NewServiceManager(store, auditor, 30*time.Minute)

	ingest := func(environment string) incidents.Incident {
		created, err := manager.IngestAlertmanager(ctx, incidents.AlertmanagerWebhook{Alerts: []incidents.AlertmanagerAlert{{
			Status: "firing", StartsAt: time.Now().UTC(), Fingerprint: fmt.Sprintf("env-%s-%d", environment, time.Now().UnixNano()),
			Labels: map[string]string{"alertname": "PolicyEnvTest", "service": "policy-" + environment, "environment": environment},
		}}}, "test")
		if err != nil {
			t.Fatal(err)
		}
		return created[0]
	}
	diagnostics := []rca.Candidate{{ActionType: "collect_diagnostics", Target: "payments-api", Risk: "low"}}

	service := remediation.NewService(store, auditor, policy.NewEngine(), nil, nil, metrics, nil)
	production := ingest("production")
	actions, err := service.Propose(ctx, production, diagnostics, "operator-1", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if actions[0].Status != remediation.StatePolicyBlocked || !strings.Contains(fmt.Sprint(actions[0].PolicyDecision["reason"]), `"production"`) {
		t.Fatalf("production proposal not blocked: %s %v", actions[0].Status, actions[0].PolicyDecision)
	}

	local := ingest("local")
	actions, err = service.Propose(ctx, local, diagnostics, "operator-1", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if actions[0].Status != remediation.StateApproved || actions[0].Risk != "low" {
		t.Fatalf("local low-risk proposal: %s risk=%s %v", actions[0].Status, actions[0].Risk, actions[0].PolicyDecision)
	}

	enabled := remediation.NewService(store, auditor, policy.NewEngineForEnvironments([]string{"local", "production"}), nil, nil, metrics, nil)
	other := ingest("production")
	actions, err = enabled.Propose(ctx, other, diagnostics, "operator-1", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if actions[0].Status != remediation.StateApproved {
		t.Fatalf("explicitly enabled production proposal: %s %v", actions[0].Status, actions[0].PolicyDecision)
	}
}
