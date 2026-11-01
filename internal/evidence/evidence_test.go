package evidence

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeQuerier struct {
	value float64
	ok    bool
	err   error
	delay time.Duration
	mu    sync.Mutex
	seen  []string
}

func (f *fakeQuerier) Instant(ctx context.Context, query string, _ time.Time) (float64, bool, error) {
	f.mu.Lock()
	f.seen = append(f.seen, query)
	f.mu.Unlock()
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return 0, false, ctx.Err()
		}
	}
	return f.value, f.ok, f.err
}

func probe(id string, backend Backend, cmp Comparator, threshold float64) Probe {
	return Probe{
		ID: id, Backend: backend, Comparator: cmp, Threshold: threshold, Weight: 0.2,
		Query: `max(db_connection_pool_in_use{service="{{service}}"})`, Claim: "pool is saturated",
	}
}

func TestCollectorClassifiesProbeOutcomes(t *testing.T) {
	at := time.Date(2026, 11, 1, 5, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		querier Querier
		want    Status
		value   bool
		errText string
	}{
		{"condition holds", &fakeQuerier{value: 0.95, ok: true}, StatusCorroborated, true, ""},
		{"condition does not hold", &fakeQuerier{value: 0.20, ok: true}, StatusRefuted, true, ""},
		{"no series", &fakeQuerier{ok: false}, StatusNoData, false, ""},
		{"backend error", &fakeQuerier{err: errors.New("boom")}, StatusUnavailable, false, "boom"},
		{"backend not configured", nil, StatusUnavailable, false, "not configured"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			collector := NewCollector(time.Second, map[Backend]Querier{Prometheus: tc.querier})
			got := collector.Run(context.Background(), []Probe{probe("pool", Prometheus, AtLeast, 0.9)}, "payments-api", at)[0]
			if got.Status != tc.want {
				t.Fatalf("status=%s want %s (%+v)", got.Status, tc.want, got)
			}
			if (got.Value != nil) != tc.value {
				t.Fatalf("value presence=%v want %v", got.Value != nil, tc.value)
			}
			if tc.errText != "" && !strings.Contains(got.Error, tc.errText) {
				t.Fatalf("error=%q want substring %q", got.Error, tc.errText)
			}
			if got.Query != `max(db_connection_pool_in_use{service="payments-api"})` {
				t.Fatalf("query not rendered: %q", got.Query)
			}
			if !got.EvaluatedAt.Equal(at) {
				t.Fatalf("evaluated_at=%s", got.EvaluatedAt)
			}
		})
	}
}

func TestCollectorTimesOutSlowBackends(t *testing.T) {
	slow := &fakeQuerier{value: 1, ok: true, delay: time.Second}
	collector := NewCollector(20*time.Millisecond, map[Backend]Querier{Loki: slow})
	start := time.Now()
	got := collector.Run(context.Background(), []Probe{probe("logs", Loki, AtLeast, 1)}, "payments-api", time.Now())[0]
	if got.Status != StatusUnavailable || !strings.Contains(got.Error, "deadline") {
		t.Fatalf("slow backend should be unavailable, got %+v", got)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("probe timeout not enforced: %s", elapsed)
	}
}

func TestCollectorRunsProbesConcurrentlyInOrder(t *testing.T) {
	slow := &fakeQuerier{value: 1, ok: true, delay: 100 * time.Millisecond}
	collector := NewCollector(time.Second, map[Backend]Querier{Prometheus: slow})
	probes := []Probe{probe("a", Prometheus, AtLeast, 1), probe("b", Prometheus, AtLeast, 2), probe("c", Prometheus, Below, 2)}
	probes[2].Symptom = true
	start := time.Now()
	got := collector.Run(context.Background(), probes, "svc", time.Now())
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("probes ran serially: %s", elapsed)
	}
	want := []struct {
		id     string
		status Status
	}{{"a", StatusCorroborated}, {"b", StatusRefuted}, {"c", StatusCorroborated}}
	for i, w := range want {
		if got[i].ProbeID != w.id || got[i].Status != w.status {
			t.Fatalf("result %d = %s/%s, want %s/%s", i, got[i].ProbeID, got[i].Status, w.id, w.status)
		}
	}
	if got[0].Symptom || !got[2].Symptom {
		t.Fatal("symptom flag not carried onto results")
	}
}

func TestRenderRejectsLabelInjection(t *testing.T) {
	querier := &fakeQuerier{value: 1, ok: true}
	collector := NewCollector(time.Second, map[Backend]Querier{Prometheus: querier})
	for _, service := range []string{
		`payments"} or vector(1) #`,
		`payments-api"}`,
		"Payments-API",
		"",
		strings.Repeat("a", 64),
		"svc\nname",
	} {
		got := collector.Run(context.Background(), []Probe{probe("pool", Prometheus, AtLeast, 0.9)}, service, time.Now())[0]
		if got.Status != StatusUnavailable || !strings.Contains(got.Error, "not a safe label value") {
			t.Fatalf("service %q was not rejected: %+v", service, got)
		}
	}
	if len(querier.seen) != 0 {
		t.Fatalf("unsafe service reached the backend: %v", querier.seen)
	}
	if _, err := Render("up{{{other}}}", "svc"); err == nil {
		t.Fatal("unknown placeholder accepted")
	}
}

func TestCompareOperators(t *testing.T) {
	cases := []struct {
		value     float64
		cmp       Comparator
		threshold float64
		want      bool
	}{
		{1, AtLeast, 1, true}, {0.99, AtLeast, 1, false},
		{1, Above, 1, false}, {1.01, Above, 1, true},
		{1, AtMost, 1, true}, {1.01, AtMost, 1, false},
		{1, Below, 1, false}, {0.5, Below, 1, true},
		{1, Comparator("=="), 1, false},
	}
	for _, tc := range cases {
		if got := Compare(tc.value, tc.cmp, tc.threshold); got != tc.want {
			t.Fatalf("Compare(%v %s %v)=%v", tc.value, tc.cmp, tc.threshold, got)
		}
	}
}

func TestValidateProbe(t *testing.T) {
	valid := probe("pool", Prometheus, AtLeast, 0.9)
	if err := ValidateProbe(valid); err != nil {
		t.Fatalf("valid probe rejected: %v", err)
	}
	mutations := map[string]func(*Probe){
		"empty id":        func(p *Probe) { p.ID = "" },
		"unknown backend": func(p *Probe) { p.Backend = "tempo" },
		"unscoped query":  func(p *Probe) { p.Query = "up" },
		"zero weight":     func(p *Probe) { p.Weight = 0 },
		"heavy weight":    func(p *Probe) { p.Weight = 0.6 },
		"no claim":        func(p *Probe) { p.Claim = " " },
		"bad comparator":  func(p *Probe) { p.Comparator = "==" },
		"extra template":  func(p *Probe) { p.Query = `up{service="{{service}}",env="{{env}}"}` },
	}
	for name, mutate := range mutations {
		p := valid
		mutate(&p)
		if err := ValidateProbe(p); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestPrometheusQuerierParsesInstantVector(t *testing.T) {
	at := time.Date(2026, 11, 1, 5, 0, 0, 500_000_000, time.UTC)
	var gotQuery, gotTime, gotAuth, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, gotTime, gotAuth = r.URL.Path, r.URL.Query().Get("query"), r.URL.Query().Get("time"), r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{"instance":"a"},"value":[1793509200.5,"0.42"]},
			{"metric":{"instance":"b"},"value":[1793509200.5,"NaN"]},
			{"metric":{"instance":"c"},"value":[1793509200.5,"0.97"]}]}}`))
	}))
	defer server.Close()

	value, ok, err := NewPrometheus(server.URL+"/", "secret", server.Client()).Instant(context.Background(), `max(up{service="x"})`, at)
	if err != nil || !ok || value != 0.97 {
		t.Fatalf("value=%v ok=%v err=%v; want max non-NaN sample 0.97", value, ok, err)
	}
	if gotPath != "/api/v1/query" || gotQuery != `max(up{service="x"})` || gotAuth != "Bearer secret" {
		t.Fatalf("path=%q query=%q auth=%q", gotPath, gotQuery, gotAuth)
	}
	if gotTime != "1793509200.500" {
		t.Fatalf("time=%q", gotTime)
	}
}

func TestLokiQuerierUsesQueryEndpointAndNanoseconds(t *testing.T) {
	at := time.Date(2026, 11, 1, 5, 0, 0, 0, time.UTC)
	var gotPath, gotTime string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotTime = r.URL.Path, r.URL.Query().Get("time")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1793509200,"12"]}]}}`))
	}))
	defer server.Close()

	value, ok, err := NewLoki(server.URL, "", server.Client()).Instant(context.Background(), `sum(count_over_time({service="x"}[5m]))`, at)
	if err != nil || !ok || value != 12 {
		t.Fatalf("value=%v ok=%v err=%v", value, ok, err)
	}
	if gotPath != "/loki/api/v1/query" || gotTime != strconv.FormatInt(at.UnixNano(), 10) {
		t.Fatalf("path=%q time=%q", gotPath, gotTime)
	}
}

func TestHTTPQuerierResponses(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		value   float64
		ok      bool
		errText string
	}{
		{"empty vector", 200, `{"status":"success","data":{"resultType":"vector","result":[]}}`, 0, false, ""},
		{"all NaN", 200, `{"status":"success","data":{"resultType":"vector","result":[{"value":[1,"NaN"]}]}}`, 0, false, ""},
		{"scalar", 200, `{"status":"success","data":{"resultType":"scalar","result":[1,"3.5"]}}`, 3.5, true, ""},
		{"matrix rejected", 200, `{"status":"success","data":{"resultType":"matrix","result":[]}}`, 0, false, "vector or scalar"},
		{"streams rejected", 200, `{"status":"success","data":{"resultType":"streams","result":[]}}`, 0, false, "vector or scalar"},
		{"api error", 400, `{"status":"error","errorType":"bad_data","error":"parse error at char 3"}`, 0, false, "parse error"},
		{"server error", 502, `bad gateway`, 0, false, "HTTP 502"},
		{"invalid json", 200, `not json`, 0, false, "invalid JSON"},
		{"bad sample", 200, `{"status":"success","data":{"resultType":"vector","result":[{"value":[1,"abc"]}]}}`, 0, false, "invalid sample"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			value, ok, err := NewPrometheus(server.URL, "", server.Client()).Instant(context.Background(), "q", time.Now())
			if tc.errText != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errText) {
					t.Fatalf("err=%v want %q", err, tc.errText)
				}
				return
			}
			if err != nil || ok != tc.ok || value != tc.value {
				t.Fatalf("value=%v ok=%v err=%v", value, ok, err)
			}
		})
	}
}

func TestHTTPQuerierRejectsOversizedResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxResponseBytes+10)))
	}))
	defer server.Close()
	if _, _, err := NewPrometheus(server.URL, "", server.Client()).Instant(context.Background(), "q", time.Now()); err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("oversized response accepted: %v", err)
	}
}

func TestEmptyBaseURLMeansUnconfigured(t *testing.T) {
	if NewPrometheus("  ", "", nil) != nil || NewLoki("", "", nil) != nil {
		t.Fatal("empty base URL should yield a nil querier")
	}
	collector := NewCollector(0, map[Backend]Querier{Prometheus: NewPrometheus("", "", nil)})
	if collector.Configured(Prometheus) || collector.Configured(Loki) {
		t.Fatal("nil queriers must not count as configured")
	}
}
