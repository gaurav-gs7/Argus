package workers

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/queue"
	remediationpkg "github.com/gauravgs7/argus/internal/remediation"
	"github.com/gauravgs7/argus/internal/testutil"
)

// A worker that lived through a NATS outage of more than sixty reconnect
// attempts used to keep running with a closed connection and never pull
// another job. It must report not-ready during the outage, then resume, and
// also recover when its consumer has disappeared (a JetStream node that
// came back without its storage).
func TestWorkerResumesAfterNATSOutageAndLostConsumer(t *testing.T) {
	url := os.Getenv("ARGUS_TEST_NATS_URL")
	if url == "" {
		t.Skip("ARGUS_TEST_NATS_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	env := newSafetyEnv(t, ctx)

	direct, err := queue.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	if err := direct.EnsureStreams(); err != nil {
		t.Fatal(err)
	}
	js := direct.JetStream()
	if err := js.PurgeStream(queue.RemediationStream); err != nil {
		t.Fatal(err)
	}
	_ = js.DeleteConsumer(queue.RemediationStream, WorkerConsumer)

	proxy := testutil.NewTCPProxy(t, strings.TrimPrefix(url, "nats://"))
	viaProxy, err := queue.ConnectWith("nats://"+proxy.Addr(), queue.ConnectOptions{Name: "worker-outage-test", ReconnectWait: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer viaProxy.Close()

	var mu sync.Mutex
	seen := map[string][]string{}
	runner := NewRunner(env.store, env.auditor, viaProxy, safetyMetrics, countingHandler{runner: "survivor", mu: &mu, seen: seen})
	runner.Configure(RunnerConfig{Concurrency: 2, FetchWait: 200 * time.Millisecond, FetchRetryWait: 100 * time.Millisecond})
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	go func() { _ = runner.Start(runCtx, "survivor") }()
	waitFor(t, 10*time.Second, runner.Ready)

	execute := func(label string) {
		t.Helper()
		rem := env.queuedRemediation(t, ctx, "test_counter")
		if _, err := direct.Publish(ctx, queue.RemediationSubject, queue.Event{
			EventID: fmt.Sprintf("%s-%d", label, time.Now().UnixNano()), Payload: map[string]any{"remediation_id": rem.ID},
		}); err != nil {
			t.Fatal(err)
		}
		waitFor(t, 15*time.Second, func() bool {
			after, _ := env.store.GetRemediation(ctx, rem.ID)
			return after.Status == remediationpkg.StateSucceeded
		})
	}
	execute("before-outage")

	proxy.Sever()
	time.Sleep(3 * time.Second) // well over sixty attempts at 20-30ms each
	if runner.Ready() {
		t.Fatal("worker reports ready with NATS unreachable")
	}
	if !runner.Alive(5 * time.Second) {
		t.Fatal("fetch loop stopped turning during the outage")
	}
	proxy.Restore()
	waitFor(t, 10*time.Second, runner.Ready)
	execute("after-outage")

	// The consumer vanishes while the worker is connected.
	if err := js.DeleteConsumer(queue.RemediationStream, WorkerConsumer); err != nil {
		t.Fatal(err)
	}
	execute("after-lost-consumer")
}
