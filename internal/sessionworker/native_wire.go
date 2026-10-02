package sessionworker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
	"time"
)

const nativeBackendMaxPayload = 128 << 10
const nativeBackendRetryHorizon = 7 * 24 * time.Hour

var ErrNativeSourceUnsupported = errors.New("native original source has no durable backend adapter")

// NativeBackendObservation is deterministic: it never decrypts private
// capture, re-encrypts an envelope, rewrites source time, or substitutes B's
// admission for the original A descriptor. Unsupported evidence stays private.
func NativeBackendObservation(o NativeObservation) (transport.NativeObservationPayload, error) {
	var origin transport.NativeObservationOrigin
	if json.Unmarshal(o.Origin, &origin) != nil || origin.ID == "" || origin.InstanceID == "" || origin.Runtime == "" || origin.NativeGeneration != o.NativeGeneration || o.NativeSessionID == "" || o.ObservedAt.IsZero() {
		return transport.NativeObservationPayload{}, ErrConflict
	}
	if o.SourceContentUnavailable {
		return transport.NativeObservationPayload{}, ErrNativeSourceUnsupported
	}
	var body any
	typ := NativeSourceType(o)
	if typ == transport.MsgRuntimeTurnStarted || typ == transport.MsgRuntimeTurnCompleted || typ == transport.MsgRuntimeTurnFailed || typ == transport.MsgRuntimeTurnOutput || typ == transport.MsgRuntimeTurnPlan {
		source := o.TurnSource
		if o.SourceSequence <= 0 || source == nil {
			return transport.NativeObservationPayload{}, ErrConflict
		}
		p := transport.NativeTurnSourcePayload{InstanceID: origin.InstanceID, Runtime: origin.Runtime, NativeGeneration: o.NativeGeneration, SessionID: o.NativeSessionID, SourceSequence: o.SourceSequence, LogicalTurnID: source.LogicalTurnID, NativeTurnSequence: source.Sequence, SourceCommandID: source.SourceCommandID, SourceAdmissionID: source.SourceAdmissionID, InputKind: source.InputKind, OutputContent: o.OutputContent, PlanContent: o.PlanContent}
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
			return transport.NativeObservationPayload{}, ErrConflict
		}
		p := struct {
			InstanceID           string                                `json:"instanceId"`
			NativeGeneration     string                                `json:"nativeGeneration"`
			Runtime              string                                `json:"runtime"`
			SessionID            string                                `json:"sessionId"`
			SourceSequence       int64                                 `json:"sourceSequence"`
			Status               string                                `json:"status,omitempty"`
			State                string                                `json:"state,omitempty"`
			Resumed              bool                                  `json:"resumed,omitempty"`
			ResourceInterruption *transport.NativeResourceInterruption `json:"resourceInterruption,omitempty"`
		}{InstanceID: origin.InstanceID, NativeGeneration: o.NativeGeneration, Runtime: origin.Runtime, SessionID: o.NativeSessionID, SourceSequence: o.SourceSequence}
		if o.ResourceInterruption != nil {
			if o.Event.Type != session.EventSessionStopped {
				return transport.NativeObservationPayload{}, ErrConflict
			}
			p.ResourceInterruption = o.ResourceInterruption
		}
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
			return transport.NativeObservationPayload{}, ErrConflict
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
	if err != nil || len(raw) > nativeBackendMaxPayload {
		return transport.NativeObservationPayload{}, ErrFull
	}
	digest := sha256.Sum256(raw)
	return transport.NativeObservationPayload{ObservationID: o.ID, OriginID: origin.ID, MessageType: typ, Digest: hex.EncodeToString(digest[:]), ObservedAt: o.ObservedAt, ExpiresAt: o.ObservedAt.Add(nativeBackendRetryHorizon), Payload: raw}, nil
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
