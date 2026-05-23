package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type state struct {
	mu               sync.Mutex
	scenario         string
	httpStatusCounts map[string]int
	durations        []float64
	dbPoolInUse      int
	dbPoolMax        int
	redisErrorsTotal int
	paymentFailures  int
}

func newState() *state {
	return &state{
		httpStatusCounts: map[string]int{},
		dbPoolMax:        100,
	}
}

func main() {
	addr := getenv("PAYMENTS_API_ADDR", ":9001")
	st := newState()
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("/checkout/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		status := st.applyScenario()
		record(st, start, status)
		respondJSON(w, status, map[string]any{"checkout_id": strings.TrimPrefix(r.URL.Path, "/checkout/"), "status": statusText(status)})
	})
	mux.HandleFunc("/payments", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		status := st.applyScenario()
		record(st, start, status)
		respondJSON(w, status, map[string]any{"payment_id": fmt.Sprintf("pay_%d", time.Now().UnixNano()), "status": statusText(status)})
	})
	mux.HandleFunc("/admin/scenarios/activate", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Scenario string `json:"scenario"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		st.mu.Lock()
		st.scenario = body.Scenario
		st.mu.Unlock()
		respondJSON(w, http.StatusOK, map[string]string{"scenario": body.Scenario})
	})
	mux.HandleFunc("/admin/reset", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		st.scenario = ""
		st.dbPoolInUse = 0
		st.redisErrorsTotal = 0
		st.paymentFailures = 0
		st.httpStatusCounts = map[string]int{}
		st.durations = nil
		st.mu.Unlock()
		respondJSON(w, http.StatusOK, map[string]string{"status": "reset"})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "db_connection_pool_in_use %d\n", st.dbPoolInUse)
		fmt.Fprintf(w, "db_connection_pool_max %d\n", st.dbPoolMax)
		fmt.Fprintf(w, "redis_operation_errors_total %d\n", st.redisErrorsTotal)
		fmt.Fprintf(w, "payment_failures_total %d\n", st.paymentFailures)
		for code, count := range st.httpStatusCounts {
			fmt.Fprintf(w, "http_requests_total{service=\"payments-api\",status=\"%s\"} %d\n", code, count)
		}
		sum := 0.0
		for _, duration := range st.durations {
			sum += duration
		}
		count := len(st.durations)
		buckets := []float64{0.1, 0.3, 0.5, 0.8, 1.0, 2.5, 5.0}
		for _, bucket := range buckets {
			bucketCount := 0
			for _, duration := range st.durations {
				if duration <= bucket {
					bucketCount++
				}
			}
			fmt.Fprintf(w, "http_request_duration_seconds_bucket{service=\"payments-api\",le=\"%s\"} %d\n", trimFloat(bucket), bucketCount)
		}
		fmt.Fprintf(w, "http_request_duration_seconds_bucket{service=\"payments-api\",le=\"+Inf\"} %d\n", count)
		fmt.Fprintf(w, "http_request_duration_seconds_sum{service=\"payments-api\"} %s\n", trimFloat(sum))
		fmt.Fprintf(w, "http_request_duration_seconds_count{service=\"payments-api\"} %d\n", count)
	})

	log.Printf("payments-api listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func (s *state) applyScenario() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.scenario {
	case "postgres_connection_exhaustion":
		s.dbPoolInUse = 95
		time.Sleep(900 * time.Millisecond)
		s.paymentFailures++
		logJSON("error", "postgres connection acquisition timeout")
		return http.StatusInternalServerError
	case "redis_memory_pressure":
		s.redisErrorsTotal++
		time.Sleep(650 * time.Millisecond)
		logJSON("error", "redis memory pressure on demo keys")
		return http.StatusServiceUnavailable
	case "dependency_latency":
		time.Sleep(2 * time.Second)
		logJSON("warn", "notification-api latency dominated request path")
		return http.StatusOK
	case "bad_config_rollout":
		time.Sleep(200 * time.Millisecond)
		s.paymentFailures++
		logJSON("error", "config parse or db host resolution failed")
		return http.StatusInternalServerError
	default:
		time.Sleep(40 * time.Millisecond)
		return http.StatusOK
	}
}

func record(s *state, start time.Time, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	duration := time.Since(start).Seconds()
	s.httpStatusCounts[strconv.Itoa(status)]++
	s.durations = append(s.durations, duration)
	if len(s.durations) > 2000 {
		s.durations = s.durations[len(s.durations)-2000:]
	}
}

func logJSON(level, message string) {
	payload := map[string]any{
		"level":    level,
		"service":  "payments-api",
		"trace_id": fmt.Sprintf("trace-%d", time.Now().UnixNano()),
		"message":  message,
	}
	data, _ := json.Marshal(payload)
	log.Println(string(data))
}

func respondJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func trimFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func statusText(status int) string {
	if status >= 500 {
		return "failed"
	}
	return "ok"
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
