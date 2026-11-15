package queue_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/queue"
	"github.com/gauravgs7/argus/internal/testutil"
	"github.com/nats-io/nats.go"
)

func connect(t *testing.T) *queue.Client {
	t.Helper()
	url := os.Getenv("ARGUS_TEST_NATS_URL")
	if url == "" {
		t.Skip("ARGUS_TEST_NATS_URL is not set")
	}
	client, err := queue.Connect(url)
	if err != nil {
		t.Fatalf("connect to NATS: %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestJetStreamPublishAndDelivery(t *testing.T) {
	client := connect(t)
	if err := client.EnsureStreams(); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}
	if err := client.EnsureStreams(); err != nil {
		t.Fatalf("ensure streams idempotently: %v", err)
	}

	durable := "argus-integration-" + time.Now().UTC().Format("150405000000")
	subscription, err := client.JetStream().PullSubscribe(queue.RemediationSubject, durable, nats.BindStream(queue.RemediationStream))
	if err != nil {
		t.Fatalf("create pull subscription: %v", err)
	}
	defer func() {
		_ = subscription.Unsubscribe()
		_ = client.JetStream().DeleteConsumer(queue.RemediationStream, durable)
	}()

	expected := queue.Event{
		EventID:    "evt-integration-" + time.Now().UTC().Format("150405.000000000"),
		EventType:  queue.RemediationSubject,
		OccurredAt: time.Now().UTC(),
		Producer:   "integration-test",
		Payload:    map[string]any{"remediation_id": "rem-integration-1"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.Publish(ctx, queue.RemediationSubject, expected); err != nil {
		t.Fatalf("publish event: %v", err)
	}

	// A consumer created after older messages exist starts at the stream
	// head; find ours.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		messages, err := subscription.Fetch(10, nats.MaxWait(time.Second))
		if err != nil {
			continue
		}
		for _, message := range messages {
			_ = message.Ack()
			var actual queue.Event
			if err := json.Unmarshal(message.Data, &actual); err != nil {
				t.Fatalf("decode event: %v", err)
			}
			if actual.EventID == expected.EventID {
				if got := message.Header.Get(nats.MsgIdHdr); got != expected.EventID {
					t.Fatalf("Nats-Msg-Id=%q, want %q", got, expected.EventID)
				}
				return
			}
		}
	}
	t.Fatal("published event was not delivered")
}

// A publish retried after a lost ack must be stored once.
func TestPublishDeduplicatesByEventID(t *testing.T) {
	client := connect(t)
	if err := client.EnsureStreams(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	event := queue.Event{EventID: "dedupe-" + time.Now().UTC().Format("150405.000000000"), EventType: queue.RemediationSubject}
	before, err := client.JetStream().StreamInfo(queue.RemediationStream)
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.Publish(ctx, queue.RemediationSubject, event)
	if err != nil || first {
		t.Fatalf("first publish duplicate=%v err=%v", first, err)
	}
	second, err := client.Publish(ctx, queue.RemediationSubject, event)
	if err != nil || !second {
		t.Fatalf("retried publish duplicate=%v err=%v, want a duplicate", second, err)
	}
	after, _ := client.JetStream().StreamInfo(queue.RemediationStream)
	if got := after.State.Msgs - before.State.Msgs; got != 1 {
		t.Fatalf("stream grew by %d messages, want 1", got)
	}
}

func TestEnsureStreamsAppliesRetentionToExistingStreams(t *testing.T) {
	client := connect(t)
	js := client.JetStream()
	if err := client.EnsureStreams(); err != nil {
		t.Fatal(err)
	}
	// Simulate a stream created by an older version: no retention.
	info, err := js.StreamInfo(queue.RemediationStream)
	if err != nil {
		t.Fatal(err)
	}
	legacy := info.Config
	legacy.MaxAge, legacy.Duplicates = 0, 2*time.Minute
	if _, err := js.UpdateStream(&legacy); err != nil {
		t.Fatalf("simulate legacy stream: %v", err)
	}
	if err := client.EnsureStreams(); err != nil {
		t.Fatal(err)
	}
	for _, want := range queue.StreamConfigs() {
		got, err := js.StreamInfo(want.Name)
		if err != nil {
			t.Fatalf("%s missing: %v", want.Name, err)
		}
		if got.Config.MaxAge != want.MaxAge || got.Config.Duplicates != want.Duplicates {
			t.Fatalf("%s: max_age=%s duplicates=%s, want %s/%s", want.Name, got.Config.MaxAge, got.Config.Duplicates, want.MaxAge, want.Duplicates)
		}
	}
	if len(queue.StreamConfigs()) != 2 {
		t.Fatalf("only the remediation and dead-letter streams should be created")
	}
}

// A worker that keeps crashing never acknowledges or dead-letters its job.
// JetStream gives up after MaxDeliver and its advisory lands in the
// dead-letter stream; listing resolves it back to the remediation.
func TestMaxDeliveriesAdvisoryIsListedWithItsRemediation(t *testing.T) {
	client := connect(t)
	if err := client.EnsureStreams(); err != nil {
		t.Fatal(err)
	}
	js := client.JetStream()
	if err := js.PurgeStream(queue.DeadLetterStream); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	durable := "argus-crashing-" + time.Now().UTC().Format("150405000000")
	if _, err := js.AddConsumer(queue.RemediationStream, &nats.ConsumerConfig{
		Durable: durable, AckPolicy: nats.AckExplicitPolicy, AckWait: time.Second, MaxDeliver: 2,
		FilterSubject: queue.RemediationSubject, DeliverPolicy: nats.DeliverNewPolicy,
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteConsumer(queue.RemediationStream, durable) }()
	sub, err := js.PullSubscribe(queue.RemediationSubject, durable, nats.Bind(queue.RemediationStream, durable))
	if err != nil {
		t.Fatal(err)
	}
	remediationID := "rem_crashing_" + time.Now().UTC().Format("150405.000000000")
	if _, err := client.Publish(ctx, queue.RemediationSubject, queue.Event{EventID: remediationID, Payload: map[string]any{"remediation_id": remediationID}}); err != nil {
		t.Fatal(err)
	}
	for delivery := 0; delivery < 2; delivery++ {
		if _, err := sub.Fetch(1, nats.MaxWait(3*time.Second)); err != nil {
			t.Fatalf("delivery %d: %v", delivery+1, err) // fetched, never acked: the worker "crashed"
		}
	}
	// JetStream decides it has hit MaxDeliver when the ack wait of the last
	// delivery expires and a pull is waiting for the next message.
	go func() { _, _ = sub.Fetch(1, nats.MaxWait(4*time.Second)) }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		letters, err := client.ListDeadLetters(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		for _, letter := range letters {
			if letter.Kind == queue.DeadLetterAdvisory && letter.RemediationID == remediationID {
				if letter.Reason != "max_deliveries" || letter.Deliveries != 2 || letter.OriginalStream != queue.RemediationStream {
					t.Fatalf("advisory=%+v", letter)
				}
				if err := client.DeleteDeadLetter(ctx, letter.Sequence); err != nil {
					t.Fatal(err)
				}
				if _, err := client.GetDeadLetter(ctx, letter.Sequence); !errors.Is(err, queue.ErrDeadLetterNotFound) {
					t.Fatalf("deleted dead letter still readable: %v", err)
				}
				return
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("max-deliveries advisory never reached the dead-letter stream")
}

// Streams older versions created and never used are deleted when empty and
// kept, with a report, when something else has written to them.
func TestRetireLegacyStreams(t *testing.T) {
	client := connect(t)
	js := client.JetStream()
	for _, name := range queue.LegacyStreams {
		_ = js.DeleteStream(name)
	}
	if report, err := client.RetireLegacyStreams(); err != nil || len(report.Deleted) != 0 || len(report.Kept) != 0 {
		t.Fatalf("nothing to retire: %+v err=%v", report, err)
	}
	legacySubjects := map[string]string{"ARGUS_INCIDENTS": "incident.*", "ARGUS_RCA": "rca.*", "ARGUS_AUDIT": "audit.*"}
	for name, subject := range legacySubjects {
		if _, err := js.AddStream(&nats.StreamConfig{Name: name, Subjects: []string{subject}}); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, name := range queue.LegacyStreams {
			_ = js.DeleteStream(name)
		}
	}()
	if _, err := js.Publish("rca.someone-else", []byte("not ours")); err != nil {
		t.Fatal(err)
	}
	report, err := client.RetireLegacyStreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Deleted) != 2 || report.Kept["ARGUS_RCA"] != 1 {
		t.Fatalf("report=%+v", report)
	}
	for _, name := range []string{"ARGUS_INCIDENTS", "ARGUS_AUDIT"} {
		if _, err := js.StreamInfo(name); !errors.Is(err, nats.ErrStreamNotFound) {
			t.Fatalf("%s still exists: %v", name, err)
		}
	}
	if info, err := js.StreamInfo("ARGUS_RCA"); err != nil || info.State.Msgs != 1 {
		t.Fatalf("a legacy stream with foreign data was touched: %v", err)
	}
}

// natsHostPort is the test server's address without the scheme.
func natsHostPort(t *testing.T) string {
	t.Helper()
	url := os.Getenv("ARGUS_TEST_NATS_URL")
	if url == "" {
		t.Skip("ARGUS_TEST_NATS_URL is not set")
	}
	return strings.TrimPrefix(url, "nats://")
}

// The nats.go default gives up after 60 reconnect attempts and closes the
// connection for good; an Argus process that outlived a two-minute NATS
// outage then never published or consumed again until it was restarted.
// The client must keep trying for as long as the outage lasts.
func TestClientReconnectsAfterAnOutageLongerThanSixtyAttempts(t *testing.T) {
	proxy := testutil.NewTCPProxy(t, natsHostPort(t))
	var mu sync.Mutex
	var states []bool
	client, err := queue.ConnectWith("nats://"+proxy.Addr(), queue.ConnectOptions{
		Name: "outage-test", ReconnectWait: 20 * time.Millisecond,
		OnStatus: func(connected bool) { mu.Lock(); states = append(states, connected); mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.EnsureStreams(); err != nil {
		t.Fatal(err)
	}

	proxy.Sever()
	// 20ms wait + up to 10ms jitter: at least 100 attempts in 3s.
	time.Sleep(3 * time.Second)
	if client.Connected() {
		t.Fatal("client reports connected through a severed link")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	if _, err := client.Publish(ctx, queue.RemediationSubject, queue.Event{EventID: "during-outage-" + time.Now().Format("150405.000000000")}); err == nil {
		t.Fatal("publish succeeded during the outage")
	}
	cancel()

	proxy.Restore()
	deadline := time.Now().Add(5 * time.Second)
	for !client.Connected() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !client.Connected() {
		t.Fatal("client never reconnected after the outage ended")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Publish(ctx, queue.RemediationSubject, queue.Event{EventID: "after-outage-" + time.Now().Format("150405.000000000")}); err != nil {
		t.Fatalf("publish after the outage: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(states) < 3 || !states[0] || states[1] || !states[len(states)-1] {
		t.Fatalf("status callbacks=%v, want connected, disconnected, ..., connected", states)
	}
}

// A JetStream node that restarts without its storage comes back with no
// streams. Publishing must recreate them instead of failing forever.
func TestPublishRecreatesALostStream(t *testing.T) {
	client := connect(t)
	if err := client.EnsureStreams(); err != nil {
		t.Fatal(err)
	}
	if err := client.JetStream().DeleteStream(queue.RemediationStream); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.Publish(ctx, queue.RemediationSubject, queue.Event{EventID: "lost-stream-" + time.Now().Format("150405.000000000")}); err != nil {
		t.Fatalf("publish with the stream gone: %v", err)
	}
	info, err := client.JetStream().StreamInfo(queue.RemediationStream)
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("stream after publish: %+v err=%v", info, err)
	}
}

// Stream sequences restart when a stream is recreated. A dead letter whose
// id was only stream+sequence then matched an earlier one inside the
// duplicate window and was dropped without an error.
func TestDeadLettersSurviveStreamRecreation(t *testing.T) {
	client := connect(t)
	js := client.JetStream()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	deadLetterFirstMessage := func(label string) {
		t.Helper()
		_ = js.DeleteStream(queue.RemediationStream)
		if err := client.EnsureStreams(); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Publish(ctx, queue.RemediationSubject, queue.Event{EventID: label + time.Now().Format("150405.000000000"), Payload: map[string]any{"remediation_id": label}}); err != nil {
			t.Fatal(err)
		}
		sub, err := js.PullSubscribe(queue.RemediationSubject, "", nats.BindStream(queue.RemediationStream))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sub.Unsubscribe() }()
		msgs, err := sub.Fetch(1, nats.MaxWait(5*time.Second))
		if err != nil || len(msgs) != 1 {
			t.Fatalf("fetch: %v", err)
		}
		if meta, _ := msgs[0].Metadata(); meta.Sequence.Stream != 1 {
			t.Fatalf("expected the recreated stream to restart at sequence 1, got %d", meta.Sequence.Stream)
		}
		if err := client.DeadLetter(ctx, msgs[0], "retries_exhausted"); err != nil {
			t.Fatal(err)
		}
		// Giving up on the same message twice is still one dead letter.
		if err := client.DeadLetter(ctx, msgs[0], "retries_exhausted"); err != nil {
			t.Fatal(err)
		}
		_ = msgs[0].Term()
	}
	if err := client.EnsureStreams(); err != nil {
		t.Fatal(err)
	}
	if err := js.PurgeStream(queue.DeadLetterStream); err != nil {
		t.Fatal(err)
	}
	deadLetterFirstMessage("first-life-")
	deadLetterFirstMessage("second-life-")
	letters, err := client.ListDeadLetters(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(letters) != 2 || letters[0].RemediationID != "first-life-" || letters[1].RemediationID != "second-life-" {
		t.Fatalf("dead letters after stream recreation: %+v", letters)
	}
}
