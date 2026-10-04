// Package events implements observation, never inline execution control.
// Its wire representation is the official CloudEvents SDK representation.
package events

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/pagnet-code/pagnet/fabric"
)

// EventBus must have finite admission capacity. TryPublish never waits for an
// observer. An error is observable transport loss, not an invocation failure.
// Durable implementations must explicitly document their admission boundary.
type EventBus interface {
	TryPublish(context.Context, event.Event) error
}

// LifecycleMetadata deliberately has no payload, response, principal assertion,
// credential, runtime path or continuation capability. This data lives inside
// the trusted node; any external observer requires an explicit private binding.
type LifecycleMetadata struct {
	InvocationID string           `json:"invocationId"`
	Operation    fabric.Operation `json:"operation"`
	Disposition  string           `json:"disposition"`
}

// Lifecycle accepts only engine-owned operation metadata, not arbitrary event
// data. Extensions may explicitly publish richer events through their bindings.
func Lifecycle(source, subject string, metadata LifecycleMetadata, at time.Time) (event.Event, error) {
	if len(source) == 0 || len(source) > 4096 || len(subject) > 4096 || len(metadata.InvocationID) == 0 || len(metadata.InvocationID) > 256 || at.IsZero() {
		return event.Event{}, fabric.NewError(fabric.CodeInvalidInput, "Invalid lifecycle event metadata")
	}
	switch metadata.Operation {
	case fabric.OperationDiscover, fabric.OperationDescribe, fabric.OperationInvoke:
	default:
		return event.Event{}, fabric.NewError(fabric.CodeUnsupported, "Unsupported lifecycle operation")
	}
	switch metadata.Disposition {
	case "started", "completed", "failed", "deferred", "cancelled":
	default:
		return event.Event{}, fabric.NewError(fabric.CodeInvalidInput, "Invalid lifecycle disposition")
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return event.Event{}, fabric.NewError(fabric.CodeProtocolError, "Event identity unavailable")
	}
	e := event.New("1.0")
	e.SetID(hex.EncodeToString(id))
	e.SetSource(source)
	e.SetSubject(subject)
	e.SetType("dev.pagnet." + string(metadata.Operation) + "." + metadata.Disposition)
	e.SetTime(at)
	if e.SetData("application/json", metadata) != nil || e.Validate() != nil {
		return event.Event{}, fabric.NewError(fabric.CodeInvalidInput, "Invalid CloudEvent")
	}
	return e, nil
}

// Encode validates with the official SDK, owns the bytes, and enforces the
// canonical bounded JSON grammar before queue admission. No raw error leaks.
func Encode(e event.Event, maxBytes int) ([]byte, error) {
	if maxBytes < 1 || maxBytes > 1<<20 || len(e.DataEncoded) > maxBytes || e.Context == nil || e.SpecVersion() != "1.0" || e.Validate() != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid CloudEvent")
	}
	raw, err := json.Marshal(e)
	if err != nil || len(raw) > maxBytes {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "CloudEvent exceeds configured limits")
	}
	var value any
	if fabric.DecodeJSONWithLimits(raw, &value, fabric.WireLimits{MaxBytes: maxBytes, MaxDepth: 64, MaxMembers: 4096}) != nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid CloudEvent JSON")
	}
	return raw, nil
}

// Decode preserves data as SDK-owned raw bytes; consumers choose explicitly
// whether to decode application data. Large integers are not round-tripped
// through float64 by this boundary.
func Decode(raw []byte, maxBytes int) (event.Event, error) {
	if maxBytes < 1 || maxBytes > 1<<20 {
		return event.Event{}, fabric.NewError(fabric.CodeInvalidInput, "Invalid event byte limit")
	}
	var value any
	if fabric.DecodeJSONWithLimits(raw, &value, fabric.WireLimits{MaxBytes: maxBytes, MaxDepth: 64, MaxMembers: 4096}) != nil {
		return event.Event{}, fabric.NewError(fabric.CodeInvalidInput, "Invalid CloudEvent JSON")
	}
	var e event.Event
	if json.Unmarshal(raw, &e) != nil || e.Context == nil || e.SpecVersion() != "1.0" || e.Validate() != nil {
		return event.Event{}, fabric.NewError(fabric.CodeInvalidInput, "Invalid CloudEvent")
	}
	return e, nil
}
