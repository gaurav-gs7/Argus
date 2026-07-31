package actions

import "testing"

func TestValidateTypedActions(t *testing.T) {
	tests := []struct {
		name       string
		action     string
		target     string
		parameters map[string]any
		wantError  bool
	}{
		{"pod", RestartPod, "local/payments-api", nil, false},
		{"pod namespace", RestartPod, "production/payments-api", nil, true},
		{"pool", ResizeConnectionPool, "payments-api", map[string]any{"size": 20.0}, false},
		{"pool too large", ResizeConnectionPool, "payments-api", map[string]any{"size": 200}, true},
		{"flag", ToggleFeatureFlag, "payments-api/optional-notifications", map[string]any{"enabled": false}, false},
		{"flag unknown", ToggleFeatureFlag, "payments-api/delete-auth", map[string]any{"enabled": false}, true},
		{"cache", PurgeCache, "demo:pressure:*", map[string]any{"max_keys": 500}, false},
		{"cache broad", PurgeCache, "demo:*", map[string]any{"max_keys": 500}, true},
		{"cache unbounded", PurgeCache, "demo:pressure:*", map[string]any{"max_keys": 1001}, true},
		{"unknown parameter", ResizeConnectionPool, "payments-api", map[string]any{"size": 20, "force": true}, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Validate(test.action, test.target, test.parameters)
			if (err != nil) != test.wantError {
				t.Fatalf("Validate() error=%v, wantError=%t", err, test.wantError)
			}
		})
	}
}
