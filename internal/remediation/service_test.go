package remediation

import "testing"

func TestBuildIdempotencyKey(t *testing.T) {
	got := BuildIdempotencyKey("inc_1", "restart_service", "payments-api", 2)
	want := "inc_1_restart_service_payments-api_2"
	if got != want {
		t.Fatalf("BuildIdempotencyKey() = %q, want %q", got, want)
	}
}
