package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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

// ConnectOptions tune the connection. The zero value is right for
// production.
type ConnectOptions struct {
	// Name identifies this client in NATS server logs and monitoring.
	Name string
	// ReconnectWait is the pause between reconnect attempts (default 2s).
	ReconnectWait time.Duration
	// Logger receives connection state changes (default slog.Default()).
	Logger *slog.Logger
	// OnStatus is called with false when the connection drops and true when
	// it is re-established.
	OnStatus func(connected bool)
}

// Connect connects with the default options.
func Connect(url string) (*Client, error) {
	return ConnectWith(url, ConnectOptions{})
}

// ConnectWith connects to NATS and keeps reconnecting for as long as the
// process runs. The nats.go default gives up after 60 attempts (about two
// minutes) and closes the connection for good; a process that outlived a
// longer outage then held a dead connection forever, with nothing logged
// and no way to recover short of a restart.
func ConnectWith(url string, opts ConnectOptions) (*Client, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	wait := opts.ReconnectWait
	if wait <= 0 {
		wait = 2 * time.Second
	}
	status := func(connected bool) {
		if opts.OnStatus != nil {
			opts.OnStatus(connected)
		}
	}
	conn, err := nats.Connect(url,
		nats.Name(opts.Name),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(wait),
		nats.ReconnectJitter(wait/2, wait/2),
		nats.DisconnectErrHandler(func(c *nats.Conn, err error) {
			if c.IsClosed() {
				return // a deliberate Close, reported by the closed handler
			}
			logger.Warn("NATS connection lost; reconnecting", "error", err)
			status(false)
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			logger.Info("NATS connection re-established", "server", c.ConnectedUrlRedacted())
			status(true)
		}),
		nats.ClosedHandler(func(c *nats.Conn) {
			// With unlimited reconnects this only follows Close.
			logger.Info("NATS connection closed")
			status(false)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("connect nats: %w", err)
	}
	status(true)
	js, err := conn.JetStream()
	if err != nil {
		return nil, fmt.Errorf("create jetstream context: %w", err)
	}
	return &Client{conn: conn, js: js}, nil
}

// StreamConfigs are the streams Argus owns. Earlier versions also created
// ARGUS_INCIDENTS, ARGUS_RCA and ARGUS_AUDIT, which nothing ever published
// to; RetireLegacyStreams removes them.
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

// LegacyStreams are streams earlier Argus versions created and never
// published to.
var LegacyStreams = []string{"ARGUS_INCIDENTS", "ARGUS_RCA", "ARGUS_AUDIT"}

// LegacyStreamReport says what RetireLegacyStreams did.
type LegacyStreamReport struct {
	Deleted []string
	// Kept maps a legacy stream that holds messages to its message count.
	// Argus never wrote to these streams, so messages mean something else
	// publishes on their subjects; they are left for an operator to decide.
	Kept map[string]uint64
}

// RetireLegacyStreams deletes legacy streams that are empty and have no
// consumers, and reports the ones it keeps.
func (c *Client) RetireLegacyStreams() (LegacyStreamReport, error) {
	report := LegacyStreamReport{Kept: map[string]uint64{}}
	for _, name := range LegacyStreams {
		info, err := c.js.StreamInfo(name)
		if errors.Is(err, nats.ErrStreamNotFound) {
			continue
		}
		if err != nil {
			return report, fmt.Errorf("inspect legacy stream %s: %w", name, err)
		}
		if info.State.Msgs > 0 || info.State.Consumers > 0 {
			report.Kept[name] = info.State.Msgs
			continue
		}
		if err := c.js.DeleteStream(name); err != nil && !errors.Is(err, nats.ErrStreamNotFound) {
			return report, fmt.Errorf("delete legacy stream %s: %w", name, err)
		}
		report.Deleted = append(report.Deleted, name)
	}
	return report, nil
}

// Connected reports whether the client currently has a live connection.
func (c *Client) Connected() bool {
	return c.conn != nil && c.conn.IsConnected()
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
	publish := func() (*nats.PubAck, error) {
		return c.js.PublishMsg(&nats.Msg{
			Subject: subject,
			Data:    body,
			Header:  nats.Header{"Content-Type": []string{"application/json"}},
		}, opts...)
	}
	ack, err := publish()
	if errors.Is(err, nats.ErrNoStreamResponse) || errors.Is(err, nats.ErrNoResponders) {
		// No stream owns the subject: the stream was lost, for example a
		// JetStream node restarted without its storage. Recreate and retry.
		if ensureErr := c.EnsureStreams(); ensureErr != nil {
			return false, fmt.Errorf("publish event: %w (recreating streams also failed: %v)", err, ensureErr)
		}
		ack, err = publish()
	}
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
		// One dead letter per original message, even if two workers give up
		// on it. The message timestamp is part of the id because stream
		// sequences restart when a stream is recreated, and a sequence-only
		// id then collided with an earlier dead letter inside the duplicate
		// window and was silently dropped.
		opts = append(opts, nats.MsgId(fmt.Sprintf("dlq-%s-%d-%d", meta.Stream, meta.Sequence.Stream, meta.Timestamp.UnixNano())))
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
