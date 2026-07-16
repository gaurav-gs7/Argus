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

func TestJetStreamPublishAndDelivery(t *testing.T) {
	url := os.Getenv("ARGUS_TEST_NATS_URL")
	if url == "" {
		t.Skip("ARGUS_TEST_NATS_URL is not set")
	}

	client, err := queue.Connect(url)
	if err != nil {
		t.Fatalf("connect to NATS: %v", err)
	}
	defer client.Close()
	if err := client.EnsureStreams(); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}
	if err := client.EnsureStreams(); err != nil {
		t.Fatalf("ensure streams idempotently: %v", err)
	}

	durable := "argus-integration-" + time.Now().UTC().Format("150405000000")
	subscription, err := client.JetStream().PullSubscribe(
		"incident.detected",
		durable,
		nats.BindStream("ARGUS_INCIDENTS"),
	)
	if err != nil {
		t.Fatalf("create pull subscription: %v", err)
	}
	defer subscription.Unsubscribe()

	expected := queue.Event{
		EventID:    "evt-integration-1",
		EventType:  "incident.detected",
		OccurredAt: time.Now().UTC(),
		Producer:   "integration-test",
		Payload:    map[string]any{"incident_id": "inc-integration-1"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Publish(ctx, "incident.detected", expected); err != nil {
		t.Fatalf("publish event: %v", err)
	}

	messages, err := subscription.Fetch(1, nats.Context(ctx))
	if err != nil {
		t.Fatalf("fetch event: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected one message, got %d", len(messages))
	}
	var actual queue.Event
	if err := json.Unmarshal(messages[0].Data, &actual); err != nil {
		t.Fatalf("decode event: %v", err)
	}
	if actual.EventID != expected.EventID || actual.EventType != expected.EventType {
		t.Fatalf("unexpected event: %#v", actual)
	}
	if err := messages[0].AckSync(); err != nil {
		t.Fatalf("ack event: %v", err)
	}
}
