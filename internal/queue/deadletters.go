package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

// Dead letter kinds.
const (
	// DeadLetterJob is a job a worker republished with a reason.
	DeadLetterJob = "job"
	// DeadLetterAdvisory is JetStream's max-deliveries advisory for a job
	// the consumer stopped redelivering (for example a worker that crashed
	// on every attempt and never acknowledged it).
	DeadLetterAdvisory = "max_deliveries_advisory"
)

// ErrDeadLetterNotFound means the sequence is not (or no longer) in the
// dead-letter stream.
var ErrDeadLetterNotFound = errors.New("dead letter not found")

// DeadLetter is one entry of the dead-letter stream.
type DeadLetter struct {
	Sequence         uint64          `json:"sequence"`
	Kind             string          `json:"kind"`
	Reason           string          `json:"reason"`
	ReceivedAt       time.Time       `json:"received_at"`
	OriginalStream   string          `json:"original_stream,omitempty"`
	OriginalSequence uint64          `json:"original_sequence,omitempty"`
	Deliveries       uint64          `json:"deliveries,omitempty"`
	RemediationID    string          `json:"remediation_id,omitempty"`
	Data             json.RawMessage `json:"data,omitempty"`
}

// maxScan bounds how many stream sequences one listing inspects, so a
// stream with many deleted entries cannot make a request unbounded.
const maxScan = 10000

// ListDeadLetters returns up to limit dead letters, oldest first.
func (c *Client) ListDeadLetters(ctx context.Context, limit int) ([]DeadLetter, error) {
	info, err := c.js.StreamInfo(DeadLetterStream, nats.Context(ctx))
	if err != nil {
		return nil, fmt.Errorf("inspect dead-letter stream: %w", err)
	}
	var out []DeadLetter
	if info.State.Msgs == 0 {
		return out, nil
	}
	for seq, scanned := info.State.FirstSeq, 0; seq <= info.State.LastSeq && len(out) < limit && scanned < maxScan; seq, scanned = seq+1, scanned+1 {
		letter, err := c.GetDeadLetter(ctx, seq)
		if errors.Is(err, ErrDeadLetterNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, letter)
	}
	return out, nil
}

// GetDeadLetter reads one dead letter and resolves which remediation it
// belongs to. For an advisory that means reading the original job, while
// the remediation stream still retains it.
func (c *Client) GetDeadLetter(ctx context.Context, seq uint64) (DeadLetter, error) {
	msg, err := c.js.GetMsg(DeadLetterStream, seq, nats.Context(ctx))
	if errors.Is(err, nats.ErrMsgNotFound) {
		return DeadLetter{}, fmt.Errorf("%w: sequence %d", ErrDeadLetterNotFound, seq)
	}
	if err != nil {
		return DeadLetter{}, fmt.Errorf("read dead letter %d: %w", seq, err)
	}
	letter := DeadLetter{Sequence: msg.Sequence, ReceivedAt: msg.Time.UTC(), Data: json.RawMessage(msg.Data)}
	if !json.Valid(msg.Data) {
		letter.Data, _ = json.Marshal(string(msg.Data))
	}
	if strings.HasPrefix(msg.Subject, "$JS.EVENT.ADVISORY.") {
		var advisory struct {
			Stream     string `json:"stream"`
			StreamSeq  uint64 `json:"stream_seq"`
			Deliveries uint64 `json:"deliveries"`
		}
		_ = json.Unmarshal(msg.Data, &advisory)
		letter.Kind, letter.Reason = DeadLetterAdvisory, "max_deliveries"
		letter.OriginalStream, letter.OriginalSequence, letter.Deliveries = advisory.Stream, advisory.StreamSeq, advisory.Deliveries
		if advisory.Stream != "" && advisory.StreamSeq > 0 {
			if original, err := c.js.GetMsg(advisory.Stream, advisory.StreamSeq, nats.Context(ctx)); err == nil {
				letter.RemediationID = remediationID(original.Data)
			}
		}
		return letter, nil
	}
	letter.Kind = DeadLetterJob
	letter.Reason = msg.Header.Get("Argus-Dead-Letter-Reason")
	letter.OriginalStream = msg.Header.Get("Argus-Original-Stream")
	letter.OriginalSequence, _ = strconv.ParseUint(msg.Header.Get("Argus-Stream-Sequence"), 10, 64)
	letter.Deliveries, _ = strconv.ParseUint(msg.Header.Get("Argus-Deliveries"), 10, 64)
	letter.RemediationID = remediationID(msg.Data)
	return letter, nil
}

// DeleteDeadLetter removes one dead letter after it was replayed or
// discarded.
func (c *Client) DeleteDeadLetter(ctx context.Context, seq uint64) error {
	if err := c.js.DeleteMsg(DeadLetterStream, seq, nats.Context(ctx)); err != nil {
		if errors.Is(err, nats.ErrMsgNotFound) {
			return fmt.Errorf("%w: sequence %d", ErrDeadLetterNotFound, seq)
		}
		return fmt.Errorf("delete dead letter %d: %w", seq, err)
	}
	return nil
}

func remediationID(data []byte) string {
	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		return ""
	}
	id, _ := event.Payload["remediation_id"].(string)
	return id
}
