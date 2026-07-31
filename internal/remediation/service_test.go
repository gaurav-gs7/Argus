package remediation

import "testing"

func TestBuildIdempotencyKey(t *testing.T) {
	got := BuildIdempotencyKey("inc_1", "restart_service", "payments-api", 2)
	want := "inc_1_restart_service_payments-api_2"
	if got != want {
		t.Fatalf("BuildIdempotencyKey() = %q, want %q", got, want)
	}
}

func TestBuildIdempotencyKeyIncludesCanonicalParameters(t *testing.T) {
	first := BuildIdempotencyKey("inc_1", "resize_connection_pool", "payments-api", 1, map[string]any{
		"size": 20,
		"mode": "bounded",
	})
	same := BuildIdempotencyKey("inc_1", "resize_connection_pool", "payments-api", 1, map[string]any{
		"mode": "bounded",
		"size": 20,
	})
	different := BuildIdempotencyKey("inc_1", "resize_connection_pool", "payments-api", 1, map[string]any{
		"size": 30,
		"mode": "bounded",
	})
	if first != same {
		t.Fatalf("canonical parameter order changed key: %q != %q", first, same)
	}
	if first == different {
		t.Fatalf("different desired states share idempotency key %q", first)
	}
}
