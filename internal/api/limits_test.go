package api

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/common"
)

func echoJSON() http.Handler {
	return limitRequestBodies(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := common.ReadJSON(r, &body); err != nil {
			common.WriteDecodeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

func jsonOfSize(n int) string {
	return `{"pad":"` + strings.Repeat("x", n) + `"}`
}

func TestRequestBodiesAreCapped(t *testing.T) {
	handler := echoJSON()
	cases := []struct {
		name   string
		path   string
		body   string
		chunk  bool
		status int
	}{
		{"small body", "/v1/services", jsonOfSize(100), false, http.StatusNoContent},
		{"declared oversize rejected before reading", "/v1/services", jsonOfSize(defaultMaxBodyBytes + 10), false, http.StatusRequestEntityTooLarge},
		{"chunked oversize caught while reading", "/v1/services", jsonOfSize(defaultMaxBodyBytes + 10), true, http.StatusRequestEntityTooLarge},
		{"alertmanager allowance above default", "/v1/alerts/alertmanager", jsonOfSize(4 << 20), false, http.StatusNoContent},
		{"alertmanager cap", "/v1/alerts/alertmanager", jsonOfSize(maxAlertmanagerPayloadBytes + 10), true, http.StatusRequestEntityTooLarge},
		{"malformed is still 400", "/v1/services", `{"pad":`, false, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reader io.Reader = strings.NewReader(tc.body)
			if tc.chunk {
				reader = io.MultiReader(reader) // hides the length, forcing chunked transfer
			}
			req := httptest.NewRequest(http.MethodPost, tc.path, reader)
			if tc.chunk {
				req.ContentLength = -1
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status=%d want %d body=%s", rec.Code, tc.status, rec.Body.String()[:min(rec.Body.Len(), 200)])
			}
		})
	}
}

func TestNewHTTPServerSetsTimeouts(t *testing.T) {
	srv := NewHTTPServer(":0", http.NotFoundHandler(), HTTPTimeouts{ReadHeader: 1 * time.Second, Read: 2 * time.Second, Write: 3 * time.Second, Idle: 4 * time.Second})
	if srv.ReadHeaderTimeout != time.Second || srv.ReadTimeout != 2*time.Second || srv.WriteTimeout != 3*time.Second || srv.IdleTimeout != 4*time.Second || srv.MaxHeaderBytes != 32<<10 {
		t.Fatalf("server=%+v", srv)
	}
}

// trickle sends headers and then one body byte every 50ms until the server
// drops the connection or limit passes; it returns how long that took.
func trickle(t *testing.T, timeouts HTTPTimeouts, limit time.Duration) (time.Duration, *http.Response) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewHTTPServer("", echoJSON(), timeouts)
	go func() { _ = srv.Serve(listener) }()
	defer srv.Close()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST /v1/services HTTP/1.1\r\nHost: argus\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"pad\":\"")
	start := time.Now()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := conn.Write([]byte("x")); err != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	elapsed := time.Since(start)
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return elapsed, nil
	}
	resp.Body.Close()
	return elapsed, resp
}

// A client that sends headers and then trickles its body is disconnected
// once ReadTimeout passes instead of holding the connection.
func TestSlowBodyIsCutOffByReadTimeout(t *testing.T) {
	const limit = 4 * time.Second
	// Control: without a read timeout the trickling client is never cut off.
	held, _ := trickle(t, HTTPTimeouts{}, limit)
	if held < limit {
		t.Fatalf("control: connection dropped after %s without a read timeout", held)
	}
	elapsed, resp := trickle(t, HTTPTimeouts{ReadHeader: time.Second, Read: 300 * time.Millisecond, Write: time.Second, Idle: time.Second}, limit)
	if resp != nil && resp.StatusCode < 400 {
		t.Fatalf("slow body accepted with %d", resp.StatusCode)
	}
	if elapsed >= limit {
		t.Fatalf("slow client held the connection for the full %s", limit)
	}
	t.Logf("without a timeout the client held the connection for %s; with a 300ms read timeout it was cut off after %s", held.Round(10*time.Millisecond), elapsed.Round(10*time.Millisecond))
}
