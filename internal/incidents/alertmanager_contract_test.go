package incidents_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gauravgs7/argus/internal/common"
	"github.com/gauravgs7/argus/internal/incidents"
)

// Payloads captured from a real Alertmanager v0.27.0 (testdata/).
func TestHandlerDecodingAcceptsRealAlertmanagerWebhook(t *testing.T) {
	for _, name := range []string{"alertmanager-0.27-firing.json", "alertmanager-0.27-resolved.json"} {
		body, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/alerts/alertmanager", bytes.NewReader(body))
		var payload incidents.AlertmanagerWebhook
		if err := common.ReadExternalJSON(httptest.NewRecorder(), req, &payload, 8<<20); err != nil {
			t.Fatalf("%s: a real Alertmanager webhook is rejected with 400: %v", name, err)
		}
		if payload.Version != "4" || payload.GroupKey == "" || len(payload.Alerts) != 1 || payload.Alerts[0].Fingerprint == "" {
			t.Fatalf("%s decoded incompletely: %+v", name, payload)
		}
	}
}
