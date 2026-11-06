package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gauravgs7/argus/internal/audit"
	"github.com/gauravgs7/argus/internal/common"
	"github.com/gauravgs7/argus/internal/queue"
	"github.com/gauravgs7/argus/internal/remediation"
)

// deadLetterQueue is the JetStream side of dead-letter handling
// (*queue.Client).
type deadLetterQueue interface {
	ListDeadLetters(ctx context.Context, limit int) ([]queue.DeadLetter, error)
	GetDeadLetter(ctx context.Context, seq uint64) (queue.DeadLetter, error)
	DeleteDeadLetter(ctx context.Context, seq uint64) error
}

type deadLetterView struct {
	queue.DeadLetter
	// RemediationStatus is the remediation's current status, when known.
	RemediationStatus string `json:"remediation_status,omitempty"`
	// Replayable is true when replay would re-send a job: the remediation
	// exists and is still queued or running.
	Replayable bool `json:"replayable"`
}

// GET /v1/dead-letters?limit=N
func (s *Server) handleDeadLetters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			common.WriteError(w, http.StatusBadRequest, "limit must be between 1 and 500")
			return
		}
		limit = parsed
	}
	letters, err := s.deadLetters().ListDeadLetters(r.Context(), limit)
	if err != nil {
		common.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	views := make([]deadLetterView, 0, len(letters))
	for _, letter := range letters {
		views = append(views, s.viewDeadLetter(r.Context(), letter))
	}
	common.WriteJSON(w, http.StatusOK, views)
}

func (s *Server) viewDeadLetter(ctx context.Context, letter queue.DeadLetter) deadLetterView {
	view := deadLetterView{DeadLetter: letter}
	if letter.RemediationID == "" {
		return view
	}
	if rem, err := s.store.GetRemediation(ctx, letter.RemediationID); err == nil {
		view.RemediationStatus = rem.Status
		view.Replayable = remediation.Dispatchable(rem.Status)
	}
	return view
}

// POST /v1/dead-letters/{sequence}/replay|discard  {"reason": "..."}
func (s *Server) handleDeadLetterRoutes(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/dead-letters/"), "/")
	if len(parts) != 2 || (parts[1] != "replay" && parts[1] != "discard") {
		common.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		common.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	seq, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil || seq == 0 {
		common.WriteError(w, http.StatusBadRequest, "dead letter sequence must be a positive integer")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if err := common.ReadJSON(r, &body); err != nil {
		common.WriteDecodeError(w, err)
		return
	}
	if strings.TrimSpace(body.Reason) == "" {
		common.WriteError(w, http.StatusBadRequest, "reason is required")
		return
	}
	ctx := r.Context()
	letter, err := s.deadLetters().GetDeadLetter(ctx, seq)
	if errors.Is(err, queue.ErrDeadLetterNotFound) {
		common.WriteError(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		common.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	view := s.viewDeadLetter(ctx, letter)
	metadata := map[string]any{
		"dead_letter_sequence": letter.Sequence, "dead_letter_kind": letter.Kind,
		"dead_letter_reason": letter.Reason, "deliveries": letter.Deliveries, "reason": body.Reason,
	}

	if parts[1] == "replay" {
		s.replayDeadLetter(w, r, view, metadata)
		return
	}
	resourceType, resourceID := "dead_letter", strconv.FormatUint(letter.Sequence, 10)
	if letter.RemediationID != "" {
		resourceType, resourceID = "remediation", letter.RemediationID
	}
	// Audit before deleting, so a discard is never unrecorded.
	if err := s.auditor.Write(ctx, audit.Entry{
		ActorID: actorFromRequest(r), ActorType: "user", Action: "remediation.dead_letter_discarded",
		ResourceType: resourceType, ResourceID: resourceID, Metadata: metadata,
	}); err != nil {
		common.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.deadLetters().DeleteDeadLetter(ctx, seq); err != nil {
		common.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"status": "discarded", "sequence": seq, "remediation_status": view.RemediationStatus})
}

func (s *Server) replayDeadLetter(w http.ResponseWriter, r *http.Request, view deadLetterView, metadata map[string]any) {
	ctx := r.Context()
	if view.RemediationID == "" {
		common.WriteError(w, http.StatusUnprocessableEntity, "this dead letter names no remediation (malformed job, or an advisory whose job has expired); discard it")
		return
	}
	if !view.Replayable {
		status := view.RemediationStatus
		if status == "" {
			status = "unknown"
		}
		common.WriteJSON(w, http.StatusConflict, map[string]any{
			"error":              "only a queued or running remediation can be replayed; discard the dead letter and propose the remediation again",
			"remediation_id":     view.RemediationID,
			"remediation_status": status,
		})
		return
	}
	dispatcher := s.remediationService.Dispatcher()
	if dispatcher == nil {
		common.WriteError(w, http.StatusServiceUnavailable, "replay needs the local executor's remediation outbox")
		return
	}
	dispatchID, err := dispatcher.Redispatch(ctx, view.RemediationID, remediation.DispatchReplay, actorFromRequest(r), "user", metadata)
	if errors.Is(err, remediation.ErrNotDispatchable) {
		common.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		common.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The job is re-sent from the outbox; the dead letter has served its
	// purpose. A failed delete leaves it listed, and replaying it again is
	// refused once the remediation leaves queued.
	if err := s.deadLetters().DeleteDeadLetter(ctx, view.Sequence); err != nil {
		common.WriteJSON(w, http.StatusAccepted, map[string]any{"status": "replayed", "dispatch_id": dispatchID, "warning": "job re-sent but the dead letter could not be deleted: " + err.Error()})
		return
	}
	common.WriteJSON(w, http.StatusAccepted, map[string]any{"status": "replayed", "dispatch_id": dispatchID, "remediation_id": view.RemediationID})
}

func (s *Server) deadLetters() deadLetterQueue {
	if s.deadLetterQueue != nil {
		return s.deadLetterQueue
	}
	return s.queue
}
