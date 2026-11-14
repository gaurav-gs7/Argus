package incidents_test

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/db"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/gauravgs7/argus/internal/testutil"
)

// Ingesting an alert used to read every open incident and run two graph
// searches per incident, so a delivery took 3ms with no open incidents and
// 22ms with 3,000. The cost must follow the alert's topology neighbourhood,
// not the size of the incident table.
func TestIngestionCostDoesNotGrowWithOpenIncidents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	database := testutil.ScratchDatabase(t)
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	store := incidents.NewStore(database)
	manager := incidents.NewServiceManager(store, audit.NewService(database), 5*time.Minute)

	next := 0
	median := func(n int) time.Duration {
		samples := make([]time.Duration, n)
		for i := range samples {
			next++
			start := time.Now()
			if _, err := manager.IngestAlertmanager(ctx, incidents.AlertmanagerWebhook{Alerts: []incidents.AlertmanagerAlert{{
				Status: "firing", StartsAt: time.Now().UTC(), Fingerprint: fmt.Sprintf("scale-%d", next),
				Labels: map[string]string{"alertname": "HighErrorRate", "service": fmt.Sprintf("scale-svc-%d", next), "environment": "prod"},
			}}}, "scale-test"); err != nil {
				t.Fatal(err)
			}
			samples[i] = time.Since(start)
		}
		sort.Slice(samples, func(a, b int) bool { return samples[a] < samples[b] })
		return samples[n/2]
	}

	_ = median(30) // warm connections and plans
	empty := median(150)

	// 5,000 open incidents on unrelated services, all recently active.
	const open = 5000
	if _, err := database.ExecContext(ctx, `
		INSERT INTO services (id, name, tier, environment)
		SELECT 'svc_bulk_' || n, 'bulk-svc-' || n, 'tier2', 'prod' FROM generate_series(1, $1) n`, open); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
		INSERT INTO incidents (id, title, service_id, severity, status, dedupe_key, fingerprint, started_at, environment, last_seen_at)
		SELECT 'inc_bulk_' || n, 'bulk', 'svc_bulk_' || n, 'sev3', 'open', 'bulk-svc-' || n || ':Bulk:prod:fp' || n, 'fp' || n, now(), 'prod', now()
		FROM generate_series(1, $1) n`, open); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `ANALYZE`); err != nil {
		t.Fatal(err)
	}
	loaded := median(150)
	t.Logf("median delivery: %s with no other open incidents, %s with %d", empty.Round(100*time.Microsecond), loaded.Round(100*time.Microsecond), open)
	if loaded > 3*empty+2*time.Millisecond {
		t.Fatalf("ingestion slowed from %s to %s with %d open incidents", empty, loaded, open)
	}
}
