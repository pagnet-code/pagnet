package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

var ErrNativeSourceUnsupported = errors.New("native original source has no durable backend adapter")

// NativeWorkerWireObservation is deterministic: it never decrypts private
// capture, re-encrypts an envelope, rewrites source time, or substitutes B's
// admission for the original A descriptor. Unsupported evidence stays private.
func NativeWorkerWireObservation(o sessionworker.NativeObservation) (transport.NativeObservationPayload, error) {
	var origin transport.NativeObservationOrigin
	if json.Unmarshal(o.Origin, &origin) != nil || origin.ID == "" || origin.InstanceID == "" || origin.Runtime == "" || origin.NativeGeneration != o.NativeGeneration || o.NativeSessionID == "" || o.ObservedAt.IsZero() {
		return transport.NativeObservationPayload{}, ErrNativeObservationConflict
	}
	var body any
	typ := sessionworker.NativeSourceType(o)
	if typ == transport.MsgRuntimeTurnStarted || typ == transport.MsgRuntimeTurnCompleted || typ == transport.MsgRuntimeTurnFailed {
		source := o.TurnSource
		if o.SourceSequence <= 0 || source == nil {
			return transport.NativeObservationPayload{}, ErrNativeObservationConflict
		}
		p := transport.NativeTurnSourcePayload{InstanceID: origin.InstanceID, Runtime: origin.Runtime, NativeGeneration: o.NativeGeneration, SessionID: o.NativeSessionID, SourceSequence: o.SourceSequence, LogicalTurnID: source.LogicalTurnID, NativeTurnSequence: source.Sequence, SourceCommandID: source.SourceCommandID, SourceAdmissionID: source.SourceAdmissionID, InputKind: source.InputKind}
		if typ == transport.MsgRuntimeTurnFailed {
			p.Kind = nativeFailureMetadata(o.Event.FailureKind)
			if o.Event.RetryAt != nil {
				if parsed, err := time.Parse(time.RFC3339Nano, *o.Event.RetryAt); err == nil && parsed.Location() == time.UTC {
					p.RetryAt = *o.Event.RetryAt
				}
			}
		}
		// Token counts are numeric source metadata. No arbitrary vendor model/error
		// text crosses this adapter without a separate bounded public contract.
		if typ != transport.MsgRuntimeTurnStarted {
			p.InputTokens = nativeTokenCount(o.Event.InputTokens)
			p.OutputTokens = nativeTokenCount(o.Event.OutputTokens)
			p.CachedTokens = nativeTokenCount(o.Event.CachedTokens)
		}
		body = p
	} else if typ != "" {
		if o.SourceSequence <= 0 {
			return transport.NativeObservationPayload{}, ErrNativeObservationConflict
		}
		p := struct {
			InstanceID       string `json:"instanceId"`
			NativeGeneration string `json:"nativeGeneration"`
			Runtime          string `json:"runtime"`
			SessionID        string `json:"sessionId"`
			SourceSequence   int64  `json:"sourceSequence"`
			Status           string `json:"status,omitempty"`
			State            string `json:"state,omitempty"`
			Resumed          bool   `json:"resumed,omitempty"`
		}{InstanceID: origin.InstanceID, NativeGeneration: o.NativeGeneration, Runtime: origin.Runtime, SessionID: o.NativeSessionID, SourceSequence: o.SourceSequence}
		switch o.Event.Type {
		case session.EventBusy:
			p.Status = "working"
		case session.EventIdle:
			p.Status = "idle"
		case session.EventSessionStarted:
			p.State = "active"
		case session.EventSessionResumed:
			p.State = "active"
			p.Resumed = true
		}
		body = p
	} else {
		if o.Event.Type != session.EventInteractionStarted && o.Event.Type != session.EventInteractionResolved {
			return transport.NativeObservationPayload{}, ErrNativeSourceUnsupported
		}
		if o.Event.Interaction == nil || o.InteractionID == "" {
			return transport.NativeObservationPayload{}, ErrNativeObservationConflict
		}
		n := o.Event.Interaction
		p := transport.InteractionEventPayload{InteractionID: o.InteractionID, InstanceID: origin.InstanceID, NativeGeneration: o.NativeGeneration, SessionID: o.NativeSessionID, Runtime: origin.Runtime, NativeInteractionID: n.NativeInteractionID, Kind: n.Kind, Options: n.Options, Resolved: n.Resolved, Decision: n.Decision}
		if o.Event.Type == session.EventInteractionStarted {
			typ = "interaction.started"
			if o.Inspection == nil {
				return transport.NativeObservationPayload{}, ErrNativeSourceUnsupported
			}
			i := o.Inspection
			p.DetailContent = i.DetailContent
			if i.DetailContent == nil {
				if i.DetailEnvelope.Version == 0 {
					return transport.NativeObservationPayload{}, ErrNativeSourceUnsupported
				}
				p.DetailEnvelope = &i.DetailEnvelope
				p.DetailAAD = &i.DetailAAD
			}
		} else {
			typ = "interaction.resolved"
			if o.Resolution == nil {
				return transport.NativeObservationPayload{}, ErrNativeSourceUnsupported
			}
			r := o.Resolution
			p.DetailContent = r.DetailContent
			if r.DetailContent == nil {
				if r.DetailEnvelope.Version == 0 {
					return transport.NativeObservationPayload{}, ErrNativeSourceUnsupported
				}
				p.DetailEnvelope = &r.DetailEnvelope
				p.DetailAAD = &r.DetailAAD
			}
			if ref := o.OriginalNativePayloadContent; ref != nil {
				p.OriginalDetailContent = &transport.NativeContentDependency{ContentID: ref.ContentID, CiphertextDigest: ref.CiphertextDigest}
			}
		}
		body = p
	}
	raw, err := json.Marshal(body)
	if err != nil || len(raw) > NativeObservationMaxPayload {
		return transport.NativeObservationPayload{}, ErrNativeObservationCapacity
	}
	digest := sha256.Sum256(raw)
	return transport.NativeObservationPayload{ObservationID: o.ID, OriginID: origin.ID, MessageType: typ, Digest: hex.EncodeToString(digest[:]), ObservedAt: o.ObservedAt, ExpiresAt: o.ObservedAt.Add(NativeObservationRetryHorizon), Payload: raw}, nil
}

// DrainNativeWorkerSources retains the legacy one-page adapter. Controller
// integrations use DrainNativeWorkerSourcesPage and retain its per-worker cursor.
func (c *NativeObservationConnection) DrainNativeWorkerSources(ctx context.Context, call func(context.Context, sessionworker.Request) (sessionworker.Response, error)) error {
	_, err := c.drainNativeWorkerSourcesPage(ctx, call, 0, 1)
	return err
}

// DrainNativeWorkerSourcesPage scans at most 128 rows and writes at most 16
// ciphertext fragments per call. After is side metadata from this exact worker's
// prior result. Keep it with the pinned worker proxy, reset it on replacement.
// A zero result starts the next bounded pass from the oldest retained evidence.
// Failed or unfinished supported sources never advance beyond their page.
func (c *NativeObservationConnection) DrainNativeWorkerSourcesPage(ctx context.Context, call func(context.Context, sessionworker.Request) (sessionworker.Response, error), after int64) (int64, error) {
	return c.drainNativeWorkerSourcesPage(ctx, call, after, 4)
}
func (c *NativeObservationConnection) drainNativeWorkerSourcesPage(ctx context.Context, call func(context.Context, sessionworker.Request) (sessionworker.Response, error), after int64, maxPages int) (int64, error) {
	if after < 0 {
		return after, ErrNativeObservationConflict
	}
	c.mu.Lock()
	err := c.deliveryReadyLocked(false)
	c.mu.Unlock()
	if err != nil {
		return after, err
	}
	budget := transport.NativeContentMaxFragmentPage
	for pages := 0; pages < maxPages; pages++ {
		page, err := call(ctx, sessionworker.Request{Type: "observations", Limit: 32, Cursor: after})
		if err != nil {
			return after, err
		}
		if page.Error != "" {
			return after, errors.New(page.Error)
		}
		if len(page.Observations) > 32 {
			return after, ErrNativeObservationCapacity
		}
		cursor := page.ObservationPage
		// Old worker protocols return no page metadata and remain one-page only.
		if cursor != nil && (cursor.After != after || cursor.NextCursor < after || (len(page.Observations) > 0 && cursor.NextCursor <= after) || (cursor.More && len(page.Observations) == 0)) {
			return after, ErrNativeObservationConflict
		}
		for _, o := range page.Observations {
			var original transport.NativeObservationOrigin
			if json.Unmarshal(o.Origin, &original) != nil || original.HostID != c.hostID {
				return after, ErrNativeObservationConflict
			}
			p, err := NativeWorkerWireObservation(o)
			if errors.Is(err, ErrNativeSourceUnsupported) {
				continue
			}
			if err != nil {
				return after, err
			}
			var ref *transport.NativeContentReference
			if o.Event.Type == session.EventInteractionStarted && o.Inspection != nil {
				ref = o.Inspection.DetailContent
			}
			if o.Event.Type == session.EventInteractionResolved && o.Resolution != nil {
				ref = o.Resolution.DetailContent
			}
			if ref != nil {
				ready, err := c.stageWorkerContent(ctx, o, *ref, call, &budget)
				if err != nil {
					return after, err
				}
				if !ready {
					return after, nil
				}
			}
			receipt, err := c.deliverWorkerObservation(ctx, p)
			if err != nil {
				return after, err
			}
			if receipt.Disposition != "committed" {
				return after, ErrNativeOriginAdmissionRejected
			}
			ack, err := call(ctx, sessionworker.Request{Type: "observation_ack", ObservationID: o.ID, SourceDigest: o.SourceDigest})
			if err != nil {
				return after, err
			}
			if ack.Error != "" {
				return after, errors.New(ack.Error)
			}
		}
		if cursor == nil || !cursor.More {
			return 0, nil
		}
		after = cursor.NextCursor
	}
	return after, nil
}

// Timeouts free all pending entries, and disconnect wakes every waiter. A fresh
// connection retries the worker's original payload and exact fragment bytes.
func nativeDeliveryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 30*time.Second)
}

func nativeFailureMetadata(kind string) string {
	switch kind {
	case "rate_limited", "quota_exhausted", "auth_required", "context_limit", "network_error", "process_error", "permission_error", "unknown", "interrupted", "runtime_error":
		return kind
	default:
		return ""
	}
}
func nativeTokenCount(value *int) *int {
	if value == nil || *value < 0 {
		return nil
	}
	copy := *value
	return &copy
}
