// Destination-side control actuation for the installed federation serving
// (E1 slice-2c). The actuations run OUTSIDE the control ledger transactions:
// after ControlLedger.Begin FULL-commits the intent (and, for an ACK, the
// verified consumer floor), the genuine source actuation runs under a fresh
// live control caller, and ControlLedger.Complete records its digestable
// evidence under the mandatory production result verifier. A failure at any
// point closes the control connection without a reply; the retained state is
// never a wire self-attestation.

package fabricnode

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
)

// serveControl serves one committed control unit: Begin (intent plus in-TX
// cursor verification), the genuine source actuation, and Complete (in-TX
// result verification) for the ack/cancel actions. It returns the reply
// state and, for a pull, the retained frames the caller sends as record 6
// after the record-5 reply. Pull is read-only and carries no Result: the
// served frames are the evidence, and a replay re-serves.
func (s *linkServing) serveControl(ctx context.Context, request federation.ControlRequest) (federation.ControlState, []fabric.InvocationFrame, error) {
	if s == nil || s.controls == nil {
		return federation.ControlState{}, nil, localDenied()
	}
	permit, state, _, e := s.controls.Begin(ctx, s.configuration, request)
	if e != nil {
		return federation.ControlState{}, nil, e
	}
	switch request.Proof.Frame.Action {
	case "status":
		// Read-only: the committed intent state is the whole reply.
		return state, nil, nil
	case "pull":
		frames, e := s.actuatePull(ctx, request, permit)
		if e != nil {
			return federation.ControlState{}, nil, e
		}
		return state, frames, nil
	case "ack":
		var payload federation.ControlPayload
		if e := controlPayloadOf(request, &payload); e != nil {
			return federation.ControlState{}, nil, e
		}
		if state.Result == nil {
			digest, e := s.actuateAck(ctx, request, permit, *payload.NextCursor)
			if e != nil {
				return federation.ControlState{}, nil, e
			}
			result := federation.ControlResult{State: "confirmed", ResponseDigest: digest, Cursor: payload.NextCursor}
			if e = s.controls.Complete(ctx, s.configuration, permit, result); e != nil {
				return federation.ControlState{}, nil, e
			}
			state.Result = &result
		}
		return state, nil, nil
	case "cancel":
		if state.Result == nil {
			digest, e := s.actuateStop(ctx, request, permit)
			if e != nil {
				return federation.ControlState{}, nil, e
			}
			result := federation.ControlResult{State: "confirmed", ResponseDigest: digest, StopAcknowledged: true}
			if e = s.controls.Complete(ctx, s.configuration, permit, result); e != nil {
				return federation.ControlState{}, nil, e
			}
			state.Result = &result
		}
		return state, nil, nil
	default:
		return federation.ControlState{}, nil, fabric.NewError(fabric.CodeInvalidInput, "Unsupported federation control action")
	}
}

// controlPayloadOf re-decodes the closed action-specific payload union under
// the wire bounds (Begin already validated it; this copy stays inside the
// actuation scope).
func controlPayloadOf(request federation.ControlRequest, out *federation.ControlPayload) error {
	if fabric.DecodeJSONWithLimits(request.Payload, out, fabric.WireLimits{MaxBytes: 4096, MaxDepth: 4, MaxMembers: 128}) != nil {
		return fabric.NewError(fabric.CodeProtocolError, "Malformed federation control payload")
	}
	return nil
}

// controlReference resolves the retained final-output reference for a live
// control caller: the committed association's private reference plus the
// control frame's original identity. Every frame read still re-verifies the
// reference against the retained head.
func (s *linkServing) controlReference(ctx context.Context, caller fabric.ExecutionContext, request federation.ControlRequest, permit federation.ControlPermit) (FinalOutputReference, error) {
	status, e := s.admissions.Status(ctx, s.configuration, permit.Invocation(), caller)
	if e != nil {
		return FinalOutputReference{}, e
	}
	if status.Association == nil {
		return FinalOutputReference{}, fabric.NewError(fabric.CodeTargetUnavailable, "Original federation association not retained")
	}
	return controlFinalOutputReference(request.Proof.Frame.OriginalPrincipal, request.Proof.Frame.InvocationID, *status.Association)
}

// actuatePull serves up to the credit's retained final frames under a fresh
// live control caller. Serving retained projections is read-only: the frames
// were committed before delivery, so a replay re-serves the exact same
// evidence and never re-executes the endpoint.
func (s *linkServing) actuatePull(ctx context.Context, request federation.ControlRequest, permit federation.ControlPermit) ([]fabric.InvocationFrame, error) {
	var payload federation.ControlPayload
	if e := controlPayloadOf(request, &payload); e != nil {
		return nil, e
	}
	var frames []fabric.InvocationFrame
	e := s.boundary.AuthenticateControl(ctx, s.configuration, request, func(ctx context.Context, caller fabric.ExecutionContext) error {
		ref, e := s.controlReference(ctx, caller, request, permit)
		if e != nil {
			return e
		}
		start := uint64(payload.Cursor.Ordinal) + 1
		for n := uint8(0); n < payload.Credit; n++ {
			frame, e := s.outputs.Frame(ctx, caller, ref, start+uint64(n))
			if errors.Is(e, io.EOF) {
				return nil
			}
			if e != nil {
				return e
			}
			frames = append(frames, frame)
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return frames, nil
}

// actuateAck is the genuine service-path source ACK: under a fresh live
// control caller it re-reads the retained final frame at the committed cursor
// ordinal and returns its exact digest as the actuation evidence. The
// consumer floor itself is FULL-committed by ControlLedger.Begin in the same
// serving stack; the service path retains no other consumer state, and the
// frame re-read is read-only, so a replay re-actuation is safe.
func (s *linkServing) actuateAck(ctx context.Context, request federation.ControlRequest, permit federation.ControlPermit, cursor federation.ConsumerCursor) ([32]byte, error) {
	var digest [32]byte
	e := s.boundary.AuthenticateControl(ctx, s.configuration, request, func(ctx context.Context, caller fabric.ExecutionContext) error {
		ref, e := s.controlReference(ctx, caller, request, permit)
		if e != nil {
			return e
		}
		frame, e := s.outputs.Frame(ctx, caller, ref, uint64(cursor.Ordinal))
		if e != nil {
			return e
		}
		raw, e := json.Marshal(frame)
		if e != nil {
			return localDenied()
		}
		defer clear(raw)
		digest = sha256.Sum256(raw)
		return nil
	})
	if e != nil {
		return [32]byte{}, e
	}
	return digest, nil
}

// actuateStop is the genuine service-path source stop: under a fresh live
// control caller it re-reads the committed head state (Begin FULL-committed
// the stop intent in the same serving stack), stops any in-flight execution
// pipeline for the exact invocation (a completed invocation has no live
// effect to revoke; the stop is acknowledged against the committed head
// state), and returns the head-state digest as the actuation evidence.
func (s *linkServing) actuateStop(ctx context.Context, request federation.ControlRequest, permit federation.ControlPermit) ([32]byte, error) {
	var digest [32]byte
	e := s.boundary.AuthenticateControl(ctx, s.configuration, request, func(ctx context.Context, caller fabric.ExecutionContext) error {
		status, e := s.admissions.Status(ctx, s.configuration, permit.Invocation(), caller)
		if e != nil {
			return e
		}
		if !status.CancelRequested {
			return localDenied()
		}
		if s.runtime != nil {
			s.runtime.StopInvocation(request.Proof.Frame.InvocationID)
		}
		digest = controlHeadStateDigest(status)
		return nil
	})
	if e != nil {
		return [32]byte{}, e
	}
	return digest, nil
}
