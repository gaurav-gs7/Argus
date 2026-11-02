package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	// RemediationStream carries remediation execution jobs.
	RemediationStream = "ARGUS_REMEDIATION"
	// RemediationSubject is the only subject workers consume.
	RemediationSubject = "remediation.execute"
	// DeadLetterStream holds jobs workers gave up on, plus JetStream's own
	// max-deliveries advisories for the remediation stream.
	DeadLetterStream = "ARGUS_DEAD_LETTER"
	// DeadLetterSubject is where workers republish poison or exhausted jobs.
	DeadLetterSubject = "argus.dlq.remediation"

	// RemediationRetention bounds how long executed or abandoned jobs stay in
	// the stream. Durable state lives in PostgreSQL, not JetStream.
	RemediationRetention = 7 * 24 * time.Hour
	// DuplicateWindow is how long JetStream remembers a Nats-Msg-Id, so a
	// retried publish of the same queue reservation is stored once.
	DuplicateWindow = 10 * time.Minute
	// DeadLetterRetention keeps dead letters long enough to investigate.
	DeadLetterRetention = 30 * 24 * time.Hour

	maxDeliveriesAdvisory = "$JS.EVENT.ADVISORY.CONSUMER.MAX_DELIVERIES." + RemediationStream + ".>"
)

type Client struct {
	conn *nats.Conn
	js   nats.JetStreamContext
}

type Event struct {
	EventID        string         `json:"event_id"`
	EventType      string         `json:"event_type"`
	OccurredAt     time.Time      `json:"occurred_at"`
	Producer       string         `json:"producer"`
	TraceID        string         `json:"trace_id,omitempty"`
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
	Payload        map[string]any `json:"payload"`
}

func Connect(url string) (*Client, error) {
	conn, err := nats.Connect(url)
	if err != nil {
		return nil, fmt.Errorf("connect nats: %w", err)
	}
	js, err := conn.JetStream()
	if err != nil {
		return nil, fmt.Errorf("create jetstream context: %w", err)
	}
	return &Client{conn: conn, js: js}, nil
}

// StreamConfigs are the streams Argus owns. Earlier versions also created
// ARGUS_INCIDENTS, ARGUS_RCA and ARGUS_AUDIT, which nothing ever published
// to; they are no longer created and can be deleted by an operator.
func StreamConfigs() []nats.StreamConfig {
	return []nats.StreamConfig{
		{
			Name:       RemediationStream,
			Subjects:   []string{"remediation.*"},
			Retention:  nats.LimitsPolicy,
			Storage:    nats.FileStorage,
			MaxAge:     RemediationRetention,
			Duplicates: DuplicateWindow,
		},
		{
			Name:       DeadLetterStream,
			Subjects:   []string{"argus.dlq.>", maxDeliveriesAdvisory},
			Retention:  nats.LimitsPolicy,
			Storage:    nats.FileStorage,
			MaxAge:     DeadLetterRetention,
			Duplicates: DuplicateWindow,
		},
	}
}

// EnsureStreams creates the streams, or updates existing ones whose
// retention, subjects or duplicate window drifted from StreamConfigs.
func (c *Client) EnsureStreams() error {
	for _, want := range StreamConfigs() {
		info, err := c.js.StreamInfo(want.Name)
		switch {
		case errors.Is(err, nats.ErrStreamNotFound):
			if _, err := c.js.AddStream(&want); err != nil {
				return fmt.Errorf("create stream %s: %w", want.Name, err)
			}
		case err != nil:
			return fmt.Errorf("inspect stream %s: %w", want.Name, err)
		default:
			got := info.Config
			if got.MaxAge == want.MaxAge && got.Duplicates == want.Duplicates && reflect.DeepEqual(got.Subjects, want.Subjects) {
				continue
			}
			updated := got
			updated.Subjects, updated.MaxAge, updated.Duplicates = want.Subjects, want.MaxAge, want.Duplicates
			if _, err := c.js.UpdateStream(&updated); err != nil {
				return fmt.Errorf("update stream %s: %w", want.Name, err)
			}
		}
	}
	return nil
}

// Publish stores an event on JetStream. A non-empty EventID is sent as
// Nats-Msg-Id, so publishing the same event twice inside DuplicateWindow
// (for example a retry after a lost publish ack) stores it once. The returned
// flag reports whether JetStream treated it as a duplicate.
func (c *Client) Publish(ctx context.Context, subject string, event Event) (bool, error) {
	body, err := json.Marshal(event)
	if err != nil {
		return false, fmt.Errorf("encode event: %w", err)
	}
	opts := []nats.PubOpt{nats.Context(ctx)}
	if event.EventID != "" {
		opts = append(opts, nats.MsgId(event.EventID))
	}
	ack, err := c.js.PublishMsg(&nats.Msg{
		Subject: subject,
		Data:    body,
		Header:  nats.Header{"Content-Type": []string{"application/json"}},
	}, opts...)
	if err != nil {
		return false, fmt.Errorf("publish event: %w", err)
	}
	return ack.Duplicate, nil
}

// DeadLetter republishes a job a worker has given up on, with the reason and
// its original delivery coordinates, to DeadLetterSubject.
func (c *Client) DeadLetter(ctx context.Context, msg *nats.Msg, reason string) error {
	header := nats.Header{
		"Content-Type":             []string{"application/json"},
		"Argus-Dead-Letter-Reason": []string{reason},
		"Argus-Original-Subject":   []string{msg.Subject},
	}
	opts := []nats.PubOpt{nats.Context(ctx)}
	if meta, err := msg.Metadata(); err == nil {
		header.Set("Argus-Original-Stream", meta.Stream)
		header.Set("Argus-Stream-Sequence", strconv.FormatUint(meta.Sequence.Stream, 10))
		header.Set("Argus-Deliveries", strconv.FormatUint(meta.NumDelivered, 10))
		opts = append(opts, nats.MsgId(fmt.Sprintf("dlq-%s-%d", meta.Stream, meta.Sequence.Stream)))
	}
	if _, err := c.js.PublishMsg(&nats.Msg{Subject: DeadLetterSubject, Data: msg.Data, Header: header}, opts...); err != nil {
		return fmt.Errorf("publish dead letter: %w", err)
	}
	return nil
}

func (c *Client) JetStream() nats.JetStreamContext {
	return c.js
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}
