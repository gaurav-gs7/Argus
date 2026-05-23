package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
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

func (c *Client) EnsureStreams() error {
	streams := []struct {
		Name     string
		Subjects []string
	}{
		{Name: "ARGUS_INCIDENTS", Subjects: []string{"incident.*"}},
		{Name: "ARGUS_RCA", Subjects: []string{"rca.*"}},
		{Name: "ARGUS_REMEDIATION", Subjects: []string{"remediation.*"}},
		{Name: "ARGUS_AUDIT", Subjects: []string{"audit.*"}},
	}

	for _, stream := range streams {
		if _, err := c.js.AddStream(&nats.StreamConfig{
			Name:      stream.Name,
			Subjects:  stream.Subjects,
			Retention: nats.LimitsPolicy,
			Storage:   nats.FileStorage,
		}); err != nil && err != nats.ErrStreamNameAlreadyInUse {
			if _, infoErr := c.js.StreamInfo(stream.Name); infoErr != nil {
				return fmt.Errorf("ensure stream %s: %w", stream.Name, err)
			}
		}
	}
	return nil
}

func (c *Client) Publish(ctx context.Context, subject string, event Event) error {
	body, _ := json.Marshal(event)
	_, err := c.js.PublishMsg(&nats.Msg{
		Subject: subject,
		Data:    body,
		Header:  nats.Header{"Content-Type": []string{"application/json"}},
	}, nats.Context(ctx))
	if err != nil {
		return fmt.Errorf("publish event: %w", err)
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
