package main

import (
	"bytes"
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
	startLokiShipper(os.Getenv("LOKI_PUSH_URL"))
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
		fmt.Fprintf(w, "db_connection_pool_in_use{service=\"payments-api\"} %d\n", st.dbPoolInUse)
		fmt.Fprintf(w, "db_connection_pool_max{service=\"payments-api\"} %d\n", st.dbPoolMax)
		fmt.Fprintf(w, "redis_operation_errors_total{service=\"payments-api\"} %d\n", st.redisErrorsTotal)
		fmt.Fprintf(w, "payment_failures_total{service=\"payments-api\"} %d\n", st.paymentFailures)
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
	// Mutate state under the lock, but sleep outside it so /metrics stays
	// scrapeable while a slow scenario is active.
	var delay time.Duration
	status := http.StatusOK
	level, message := "", ""

	s.mu.Lock()
	switch s.scenario {
	case "postgres_connection_exhaustion":
		s.dbPoolInUse = 95
		s.paymentFailures++
		delay, status = 900*time.Millisecond, http.StatusInternalServerError
		level, message = "error", "postgres connection acquisition timeout"
	case "redis_memory_pressure":
		s.redisErrorsTotal++
		delay, status = 650*time.Millisecond, http.StatusServiceUnavailable
		level, message = "error", "redis memory pressure on demo keys"
	case "dependency_latency":
		delay = 2 * time.Second
		level, message = "warn", "notification-api latency dominated request path"
	case "bad_config_rollout":
		s.paymentFailures++
		delay, status = 200*time.Millisecond, http.StatusInternalServerError
		level, message = "error", "config parse or db host resolution failed"
	default:
		delay = 40 * time.Millisecond
	}
	s.mu.Unlock()

	time.Sleep(delay)
	if message != "" {
		logJSON(level, message)
	}
	return status
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
	shipLog(level, string(data))
}

// The demo stack has no log agent, so the service pushes its own structured
// logs to Loki when LOKI_PUSH_URL is set. Argus RCA queries Loki for these
// lines as corroborating evidence. Shipping is best effort and never blocks
// request handling.
type lokiLine struct {
	level string
	at    time.Time
	line  string
}

var lokiLines chan lokiLine

func startLokiShipper(pushURL string) {
	if pushURL == "" {
		return
	}
	lokiLines = make(chan lokiLine, 1024)
	client := &http.Client{Timeout: 3 * time.Second}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var batch []lokiLine
		for {
			select {
			case line := <-lokiLines:
				batch = append(batch, line)
				if len(batch) < 200 {
					continue
				}
			case <-ticker.C:
				if len(batch) == 0 {
					continue
				}
			}
			pushToLoki(client, pushURL, batch)
			batch = nil
		}
	}()
}

func shipLog(level, line string) {
	if lokiLines == nil {
		return
	}
	select {
	case lokiLines <- lokiLine{level: level, at: time.Now(), line: line}:
	default:
	}
}

func pushToLoki(client *http.Client, pushURL string, batch []lokiLine) {
	byLevel := map[string][][2]string{}
	for _, item := range batch {
		byLevel[item.level] = append(byLevel[item.level], [2]string{strconv.FormatInt(item.at.UnixNano(), 10), item.line})
	}
	type stream struct {
		Stream map[string]string `json:"stream"`
		Values [][2]string       `json:"values"`
	}
	streams := make([]stream, 0, len(byLevel))
	for level, values := range byLevel {
		streams = append(streams, stream{Stream: map[string]string{"service": "payments-api", "level": level}, Values: values})
	}
	body, _ := json.Marshal(map[string]any{"streams": streams})
	resp, err := client.Post(pushURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("loki push failed: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("loki push returned %s", resp.Status)
	}
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
