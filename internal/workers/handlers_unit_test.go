package workers

import (
	"context"
	"testing"

	"github.com/gauravgs7/argus/internal/actions"
	"github.com/gauravgs7/argus/internal/incidents"
	"github.com/nats-io/nats.go"
)

// Every handler a worker registers is an action the catalog knows, and the
// static handlers refuse actions that are not theirs.
func TestDefaultHandlersMatchTheActionCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, h := range DefaultHandlers(nil) {
		if !actions.IsRegistered(h.Name()) {
			t.Fatalf("handler %s is not in the action catalog", h.Name())
		}
		if seen[h.Name()] {
			t.Fatalf("handler %s registered twice", h.Name())
		}
		seen[h.Name()] = true
	}
	if actions.IsRegistered("rm -rf /") {
		t.Fatal("an arbitrary command is registered")
	}
	static := staticHandler{name: "restart_service", message: "ok"}
	if err := static.Validate(incidents.RemediationAction{ActionType: "reload_nginx", Target: "nginx"}); err == nil {
		t.Fatal("a static handler accepted another action")
	}
	req := incidents.RemediationAction{ActionType: "restart_service", Target: "payments-api"}
	exec, err := static.Execute(context.Background(), req)
	if err != nil || exec["mode"] != "execute" || exec["target"] != "payments-api" {
		t.Fatalf("execute=%v err=%v", exec, err)
	}
	dry, err := static.DryRun(context.Background(), req)
	if err != nil || dry["mode"] != "dry-run" {
		t.Fatalf("dry-run=%v err=%v", dry, err)
	}
}

// A message that did not come from JetStream counts as a first delivery.
func TestDeliveriesDefaultsToOne(t *testing.T) {
	if got := deliveries(&nats.Msg{Subject: "remediation.execute"}); got != 1 {
		t.Fatalf("deliveries=%d", got)
	}
}
