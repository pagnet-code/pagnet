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
	typ := sessionworker.LifecycleSourceType(o.Event.Type)
	if typ != "" {
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

// DrainNativeWorkerSources makes at most one bounded journal page and 16
// ciphertext fragment writes per invocation. A backend durable commit is the
// sole event that permits the worker's atomic source/capture/fragment ACK.
// Call belongs to the exact authenticated, lease-fenced private controller.
func (c *NativeObservationConnection) DrainNativeWorkerSources(ctx context.Context, call func(context.Context, sessionworker.Request) (sessionworker.Response, error)) error {
	c.mu.Lock()
	err := c.deliveryReadyLocked(false)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	page, err := call(ctx, sessionworker.Request{Type: "observations", Limit: 32})
	if err != nil {
		return err
	}
	if page.Error != "" {
		return errors.New(page.Error)
	}
	if len(page.Observations) > 32 {
		return ErrNativeObservationCapacity
	}
	budget := transport.NativeContentMaxFragmentPage
	for _, o := range page.Observations {
		var original transport.NativeObservationOrigin
		if json.Unmarshal(o.Origin, &original) != nil || original.HostID != c.hostID {
			return ErrNativeObservationConflict
		}
		p, err := NativeWorkerWireObservation(o)
		if errors.Is(err, ErrNativeSourceUnsupported) {
			continue
		}
		if err != nil {
			return err
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
				return err
			}
			if !ready {
				return nil
			}
		}
		receipt, err := c.deliverWorkerObservation(ctx, p)
		if err != nil {
			return err
		}
		if receipt.Disposition != "committed" {
			return ErrNativeOriginAdmissionRejected
		}
		ack, err := call(ctx, sessionworker.Request{Type: "observation_ack", ObservationID: o.ID, SourceDigest: o.SourceDigest})
		if err != nil {
			return err
		}
		if ack.Error != "" {
			return errors.New(ack.Error)
		}
	}
	return nil
}

// Timeouts free all pending entries, and disconnect wakes every waiter. A fresh
// connection retries the worker's original payload and exact fragment bytes.
func nativeDeliveryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 30*time.Second)
}
