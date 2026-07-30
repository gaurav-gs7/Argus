package audit

import (
	"math"
	"testing"
	"time"
)

func TestAuditHashIsCanonicalAndSensitiveToEveryField(t *testing.T) {
	entry := Entry{
		ID:           "aud_1",
		ActorID:      "issuer#subject",
		ActorType:    "user",
		Action:       "remediation.approved",
		ResourceType: "remediation",
		ResourceID:   "rem_1",
		RequestID:    "req_1",
		IPAddress:    "127.0.0.1",
		BeforeState:  map[string]any{"status": "pending", "attempt": 1},
		AfterState:   map[string]any{"approved": true, "status": "approved"},
		Metadata:     map[string]any{"reason": "evidence reviewed"},
		CreatedAt:    time.Date(2026, 7, 30, 10, 11, 12, 123456789, time.FixedZone("offset", 5*60*60+30*60)),
	}
	reordered := entry
	reordered.BeforeState = map[string]any{"attempt": 1, "status": "pending"}
	reordered.AfterState = map[string]any{"status": "approved", "approved": true}

	first := hashForTest(t, entry, 7, GenesisHash)
	second := hashForTest(t, reordered, 7, GenesisHash)
	if first != second {
		t.Fatalf("canonical map ordering changed the hash: %s != %s", first, second)
	}

	mutations := []struct {
		name   string
		mutate func(*Entry)
	}{
		{name: "actor", mutate: func(e *Entry) { e.ActorID = "issuer#attacker" }},
		{name: "action", mutate: func(e *Entry) { e.Action = "remediation.rejected" }},
		{name: "resource", mutate: func(e *Entry) { e.ResourceID = "rem_2" }},
		{name: "request", mutate: func(e *Entry) { e.RequestID = "req_2" }},
		{name: "ip", mutate: func(e *Entry) { e.IPAddress = "10.0.0.1" }},
		{name: "before state", mutate: func(e *Entry) { e.BeforeState = map[string]any{"status": "approved"} }},
		{name: "after state", mutate: func(e *Entry) { e.AfterState = map[string]any{"status": "failed"} }},
		{name: "metadata", mutate: func(e *Entry) { e.Metadata = map[string]any{"reason": "changed"} }},
		{name: "timestamp", mutate: func(e *Entry) { e.CreatedAt = e.CreatedAt.Add(time.Nanosecond) }},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			changed := entry
			tt.mutate(&changed)
			if got := hashForTest(t, changed, 7, GenesisHash); got == first {
				t.Fatalf("mutation did not change audit hash %s", first)
			}
		})
	}
	if got := hashForTest(t, entry, 8, GenesisHash); got == first {
		t.Fatal("chain position must be covered by the hash")
	}
	if got := hashForTest(t, entry, 7, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); got == first {
		t.Fatal("previous hash must be covered by the hash")
	}
}

func TestCanonicalJSONPreservesLargeIntegersAndRejectsInvalidNumbers(t *testing.T) {
	const large = int64(9223372036854775807)
	canonical, err := canonicalJSON(map[string]any{"large": large})
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != `{"large":9223372036854775807}` {
		t.Fatalf("large integer lost precision: %s", canonical)
	}
	if _, err := canonicalJSON(map[string]any{"invalid": math.NaN()}); err == nil {
		t.Fatal("non-JSON numeric values must be rejected")
	}
}

func TestHashValidation(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for value, want := range map[string]bool{
		valid:                         true,
		"":                            false,
		valid[:63]:                    false,
		"g" + valid[1:]:               false,
		"ABCDEF" + valid[6:]:          false,
		GenesisHash:                   true,
		GenesisHash + GenesisHash[:1]: false,
	} {
		if got := validHash(value); got != want {
			t.Errorf("validHash(%q)=%t, want %t", value, got, want)
		}
	}
}

func hashForTest(t *testing.T, entry Entry, position int64, previousHash string) string {
	t.Helper()
	prepared, err := prepareEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := calculateHash(entry, position, previousHash, prepared.beforeJSON, prepared.afterJSON, prepared.metadataJSON)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
