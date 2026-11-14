package topology

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
)

func TestGroupsCollapseAlertStormToDeepestRoot(t *testing.T) {
	graph := New(demoDependencies())
	groups := graph.Groups([]string{"nginx", "checkout-api", "postgres", "payments-api", "payments-api"})
	if len(groups) != 1 {
		t.Fatalf("expected one topology group, got %#v", groups)
	}
	group := groups[0]
	if group.Root != "postgres" || group.Inferred {
		t.Fatalf("expected observed postgres root, got %#v", group)
	}
	if !reflect.DeepEqual(group.Members, []string{"checkout-api", "nginx", "payments-api", "postgres"}) {
		t.Fatalf("unexpected affected services: %#v", group.Members)
	}
	wantPath := []string{"nginx", "payments-api", "postgres"}
	if !reflect.DeepEqual(group.Paths["nginx"].Services, wantPath) {
		t.Fatalf("nginx path = %#v, want %#v", group.Paths["nginx"].Services, wantPath)
	}
}

func TestGroupsInferCommonDependencyForSiblingAlerts(t *testing.T) {
	graph := New(demoDependencies())
	groups := graph.Groups([]string{"checkout-api", "nginx"})
	if len(groups) != 1 || groups[0].Root != "payments-api" || !groups[0].Inferred {
		t.Fatalf("expected inferred payments-api root, got %#v", groups)
	}
}

func TestGroupsKeepIndependentRootCausesSeparate(t *testing.T) {
	graph := New(demoDependencies())
	groups := graph.Groups([]string{"postgres", "redis"})
	if len(groups) != 2 || groups[0].Root != "postgres" || groups[1].Root != "redis" {
		t.Fatalf("expected independent datastore incidents, got %#v", groups)
	}
}

func TestPathIsCycleSafeAndDeterministic(t *testing.T) {
	graph := New([]Dependency{
		{Service: "a", DependsOn: "b"},
		{Service: "b", DependsOn: "c"},
		{Service: "c", DependsOn: "a"},
		{Service: "a", DependsOn: "d"},
	})
	path, ok := graph.Path("a", "c")
	if !ok || !reflect.DeepEqual(path.Services, []string{"a", "b", "c"}) {
		t.Fatalf("unexpected cycle-safe path: %#v ok=%t", path, ok)
	}
	if _, ok := graph.Path("d", "a"); ok {
		t.Fatal("dependency direction must not be reversed")
	}
}

func TestGroupsAreIndependentOfAlertOrder(t *testing.T) {
	graph := New(demoDependencies())
	first := graph.Groups([]string{"postgres", "payments-api", "checkout-api", "nginx"})
	second := graph.Groups([]string{"nginx", "checkout-api", "payments-api", "postgres"})
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("groups changed with input order:\nfirst=%#v\nsecond=%#v", first, second)
	}
}

func demoDependencies() []Dependency {
	return []Dependency{
		{Service: "nginx", DependsOn: "payments-api"},
		{Service: "checkout-api", DependsOn: "payments-api"},
		{Service: "payments-api", DependsOn: "postgres"},
		{Service: "payments-api", DependsOn: "redis"},
		{Service: "payments-api", DependsOn: "notification-api"},
	}
}

// Related must name exactly the services Path can connect to a service in
// either direction: ingestion uses it to decide which open incidents can be
// correlated, so a missing service would split an incident.
func TestRelatedMatchesPathOnRandomGraphs(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for round := 0; round < 200; round++ {
		n := 2 + rng.Intn(9)
		var edges []Dependency
		for i := 0; i < rng.Intn(n*2+1); i++ {
			edges = append(edges, Dependency{Service: fmt.Sprintf("s%d", rng.Intn(n)), DependsOn: fmt.Sprintf("s%d", rng.Intn(n))})
		}
		graph := New(edges)
		for i := 0; i < n; i++ {
			service := fmt.Sprintf("s%d", i)
			want := map[string]bool{service: true}
			for j := 0; j < n; j++ {
				other := fmt.Sprintf("s%d", j)
				if _, ok := graph.Path(service, other); ok {
					want[other] = true
				}
				if _, ok := graph.Path(other, service); ok {
					want[other] = true
				}
			}
			got := graph.Related(service)
			if len(got) != len(want) {
				t.Fatalf("round %d: Related(%s)=%v, want %v (edges %v)", round, service, got, want, edges)
			}
			for _, name := range got {
				if !want[name] {
					t.Fatalf("round %d: Related(%s) includes unrelated %s", round, service, name)
				}
			}
		}
	}
	if got := New(nil).Related("isolated"); len(got) != 1 || got[0] != "isolated" {
		t.Fatalf("a service outside the graph relates only to itself: %v", got)
	}
	if New(nil).Related("") != nil {
		t.Fatal("empty service")
	}
}
