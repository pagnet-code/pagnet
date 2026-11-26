package daemon

import (
	"context"
	"errors"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

var errDirectEndpointRPCUnknown = errors.New("direct endpoint worker RPC outcome unknown")

// verifyEndpointOwnership is the bounded ownership-only RPC prerequisite for
// endpoint verification. It is deliberately separate from legacy proxy calls.
func (p *NativeWorkerProxy) verifyEndpointOwnership(ctx context.Context, ownership transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
	if p.aborted() {
		return nil, errors.Join(sessionworker.ErrControllerCallNotStarted, ErrNativeOriginAdmissionDeferred)
	}
	if _, err := p.connection.nativeWorkerEndpointAdmission(ctx, p.scope, p.bootstrap.Native.NetworkID, p.bootstrap.Native.Kind); err != nil {
		return nil, errors.Join(sessionworker.ErrControllerCallNotStarted, err)
	}
	if p.aborted() {
		return nil, errors.Join(sessionworker.ErrControllerCallNotStarted, ErrNativeOriginAdmissionDeferred)
	}
	response, err := p.controller.CallEndpoint(ctx, sessionworker.Request{Type: "ownership_verify", OwnershipVerify: &sessionworker.NativeOwnershipVerifyRequest{Ownership: ownership}})
	if err != nil {
		if errors.Is(err, sessionworker.ErrControllerCallNotStarted) {
			// Preserve only public preflight dispositions, never wire diagnostics.
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
		// Dispatch may have reached the worker. Never wait for publication or
		// subscription cleanup on this RPC error path.
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
	if response.OwnershipVerify == nil {
		p.abort()
		return nil, errDirectEndpointRPCUnknown
	}
	if _, err := p.connection.nativeWorkerEndpointAdmission(ctx, p.scope, p.bootstrap.Native.NetworkID, p.bootstrap.Native.Kind); err != nil {
		return nil, err
	}
	if p.aborted() {
		return nil, errDirectEndpointRPCUnknown
	}
	return response.OwnershipVerify, nil
}
