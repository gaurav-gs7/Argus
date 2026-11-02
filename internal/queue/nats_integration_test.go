package queue_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/gauravgs7/argus/internal/queue"
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
