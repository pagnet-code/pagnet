package actions

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events"
)

// WebhookConfig selects one explicit, generic external webhook ingress. The
// event source is configuration, never a core type switch: the same handler
// translates any configured producer event into new work through the store.
type WebhookConfig struct {
	ID             string
	Mode           string // "trigger" or "emit"
	Target         fabric.EndpointRef
	TargetRevision fabric.Revision
	Store          *Store
	// MaxEventBytes bounds the received exact event; it must not exceed the
	// queue's own bound.
	MaxEventBytes int
	MaxProofBytes int
	Timeout       time.Duration
	MaxConcurrent int
}

// Webhook is a generic external webhook provider. It accepts one bounded HTTP
// POST carrying the exact signed event bytes and the producer proof, then
// translates the event into new work through Store.Trigger (matching installed
// definitions) or Store.Emit (one explicit target). Delivery is at-least-once:
// the 2xx is returned only after the durable queue commit, and an identical
// retry recovers the same queued identity rather than new work. It never claims
// exactly-once external effects.
type Webhook struct {
	config   WebhookConfig
	capacity chan struct{}
	mu       sync.Mutex
	closed   bool
}

func NewWebhook(c WebhookConfig) (*Webhook, error) {
	if c.Store == nil || c.ID == "" || len(c.ID) > 256 ||
		(c.Mode != "trigger" && c.Mode != "emit") ||
		(c.Mode == "emit" && (c.Target.String() == "" || c.TargetRevision == "")) ||
		c.MaxEventBytes < 1 || c.MaxEventBytes > 1<<20 || c.MaxProofBytes < 1 || c.MaxProofBytes > 65536 ||
		c.Timeout < time.Millisecond || c.Timeout > time.Minute || c.MaxConcurrent < 1 || c.MaxConcurrent > 4096 {
		return nil, invalid()
	}
	return &Webhook{config: c, capacity: make(chan struct{}, c.MaxConcurrent)}, nil
}

type webhookRequest struct {
	ExactEvent []byte `json:"exactEvent"`
	Proof      []byte `json:"proof"`
}

func (w *Webhook) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request == nil || request.Method != http.MethodPost {
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		http.Error(response, "webhook closed", http.StatusServiceUnavailable)
		return
	}
	w.mu.Unlock()
	ctx, cancel := context.WithTimeout(request.Context(), w.config.Timeout)
	defer cancel()
	select {
	case w.capacity <- struct{}{}:
		defer func() { <-w.capacity }()
	case <-ctx.Done():
		http.Error(response, "webhook busy", http.StatusServiceUnavailable)
		return
	}
	body := io.LimitReader(request.Body, int64(w.config.MaxEventBytes)+int64(w.config.MaxProofBytes)+4096)
	var req webhookRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		http.Error(response, "invalid webhook body", http.StatusBadRequest)
		return
	}
	input := SourceInput{ExactEvent: req.ExactEvent, Proof: req.Proof}
	var receipt QueueReceipt
	var err error
	if w.config.Mode == "emit" {
		decoded, decodeErr := events.Decode(req.ExactEvent, w.config.MaxEventBytes)
		if decodeErr != nil {
			http.Error(response, "invalid event", http.StatusBadRequest)
			return
		}
		receipt, err = w.config.Store.Emit(ctx, input, EmitRequest{Target: w.config.Target, Revision: w.config.TargetRevision, Input: decoded.Data()})
	} else {
		receipt, err = w.config.Store.Trigger(ctx, input)
	}
	if err != nil {
		code := http.StatusBadGateway
		var structured *fabric.Error
		if errors.As(err, &structured) {
			switch structured.Code {
			case fabric.CodeInvalidInput, fabric.CodeUnauthenticated:
				code = http.StatusBadRequest
			case fabric.CodeNotFound:
				code = http.StatusNotFound
			}
		}
		http.Error(response, "webhook admission failed", code)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusAccepted)
	_, _ = io.WriteString(response, string(mustMarshal(receipt)))
}

func (w *Webhook) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
}

func mustMarshal(v any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}
