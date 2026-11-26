package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/internal/nativedirect"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// reserveDirectASK records encrypted provenance only. It never submits a native
// prompt or supplies authority for execution.
func (p *NativeWorkerProxy) reserveDirectASK(ctx context.Context, source nativedirect.NativeDirectASKSource, wire json.RawMessage) (*sessionworker.DirectASKReservation, error) {
	return p.directASK(ctx, source, wire, true)
}

// lookupDirectASK recovers an exact reservation without inserting one. A nil
// result means an authenticated, fenced lookup explicitly reported absence.
func (p *NativeWorkerProxy) lookupDirectASK(ctx context.Context, source nativedirect.NativeDirectASKSource, wire json.RawMessage) (*sessionworker.DirectASKReservation, error) {
	return p.directASK(ctx, source, wire, false)
}

func (p *NativeWorkerProxy) directASK(ctx context.Context, source nativedirect.NativeDirectASKSource, wire json.RawMessage, reserve bool) (*sessionworker.DirectASKReservation, error) {
	if ctx == nil || source.ValidateWire(wire) != nil || source.Scope != p.scope {
		return nil, errors.Join(sessionworker.ErrControllerCallNotStarted, ErrNativeObservationConflict)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	verify := func() error {
		result, err := p.verifyEndpointOwnership(ctx, source.Ownership)
		if err != nil {
			return err
		}
		s := result.Snapshot
		if s.NativeSessionID != source.NativeSessionID || s.NativeGeneration != source.NativeGeneration || s.NativeStartIdentity != source.NativeStartIdentity || s.PID != source.NativePID {
			return ErrNativeObservationConflict
		}
		return nil
	}
	if err := verify(); err != nil {
		return nil, errors.Join(sessionworker.ErrControllerCallNotStarted, err)
	}
	kind := "direct_ask_lookup_v1"
	if reserve {
		kind = "direct_ask_reserve_v1"
	}
	response, err := p.controller.CallEndpoint(ctx, sessionworker.Request{Type: kind, DirectASK: &sessionworker.DirectASKRequest{Source: source, Wire: wire}})
	if err != nil {
		if errors.Is(err, sessionworker.ErrControllerCallNotStarted) {
			var cause error = ErrNativeOriginAdmissionDeferred
			switch {
			case errors.Is(err, context.Canceled):
				cause = context.Canceled
			case errors.Is(err, context.DeadlineExceeded):
				cause = context.DeadlineExceeded
			case errors.Is(err, sessionworker.ErrControllerCallBusy):
				cause = sessionworker.ErrControllerCallBusy
			}
			return nil, errors.Join(sessionworker.ErrControllerCallNotStarted, cause)
		}
		p.abort()
		return nil, errDirectEndpointRPCUnknown
	}
	if p.aborted() {
		return nil, errDirectEndpointRPCUnknown
	}
	if response.Error != "" {
		if response.Retryable {
			return nil, ErrNativeOriginAdmissionDeferred
		}
		return nil, ErrNativeObservationConflict
	}
	result := response.DirectASK
	if result == nil || result.Found != (result.Reservation != nil) || reserve && !result.Found {
		p.abort()
		return nil, errDirectEndpointRPCUnknown
	}
	if r := result.Reservation; r != nil {
		want, wantErr := source.CanonicalBytes()
		got, gotErr := r.Source.CanonicalBytes()
		if wantErr != nil || gotErr != nil || !bytes.Equal(want, got) || !bytes.Equal(r.Wire, wire) || r.State != "reserved" && r.State != "unknown" {
			p.abort()
			return nil, errDirectEndpointRPCUnknown
		}
	}
	// A failed postflight cannot turn a potentially committed reservation into
	// a no-dispatch result, even if ownership verification itself did not start.
	if err := verify(); err != nil || p.aborted() {
		return nil, errDirectEndpointRPCUnknown
	}
	return result.Reservation, nil
}
