package node

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

// ResumeDispatchVerifier recognizes an actual private once-claim admission and
// its separate current resumer. Historical/static authenticated contexts alone
// must be rejected. Implementations preserve the original identity and deadline
// and recheck the current plan/source/target at destination admission.
type ResumeDispatchVerifier interface {
	VerifyResumeDispatch(context.Context, fabric.ExecutionContext, []byte, fabric.Envelope) error
}

// InvokeResumed is a trusted continuation builder port, never a wire operation
// or alternate invoke route. It supplies the same private node capability used
// by ordinary exact dispatch only AFTER a configured actual resume authority.
func (s *Service) InvokeResumed(ctx context.Context, caller fabric.ExecutionContext, exactOriginal []byte, final fabric.Envelope) (Result, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.config.ResumeDispatchVerifier == nil {
		return Result{}, fabric.NewError(fabric.CodeUnauthenticated, "Current verified continuation dispatch required")
	}
	if len(exactOriginal) > fabric.DefaultWireLimits.MaxBytes {
		return Result{}, fabric.NewError(fabric.CodeInvalidInput, "Original continuation exceeds wire bounds")
	}
	if err := final.Validate(); err != nil {
		return Result{}, err
	}
	// Validate aggregate raw content before JSON marshaling allocates a buffer.
	budget := fabric.DefaultWireLimits.MaxBytes - len(final.Payload)
	for key, value := range final.Metadata {
		budget -= len(key) + len(value)
	}
	budget -= len(final.ExpectedRevision) + len(final.Trace.TraceParent) + len(final.Trace.TraceState) + len(final.Trace.Baggage)
	if budget < 0 {
		return Result{}, fabric.NewError(fabric.CodeInvalidInput, "Finalized continuation exceeds wire bounds")
	}
	original := bytes.Clone(exactOriginal)
	initial, err := caller.DecodeVerifiedEnvelope(original, s.config.Audience)
	if err != nil {
		return Result{}, err
	}
	if initial.Operation != fabric.OperationInvoke || final.Operation != fabric.OperationInvoke {
		return Result{}, fabric.NewError(fabric.CodeUnsupported, "Continuation dispatch requires invocation")
	}
	finalBytes, err := json.Marshal(final)
	if err != nil {
		return Result{}, fabric.NewError(fabric.CodeInvalidInput, "Invalid resumed invocation")
	}
	var owned fabric.Envelope
	if err = fabric.DecodeJSON(finalBytes, &owned); err != nil {
		return Result{}, err
	}
	if err = owned.Validate(); err != nil {
		return Result{}, err
	}
	a, b := initial, owned
	a.Payload = nil
	b.Payload = nil
	a.Metadata = nil
	b.Metadata = nil
	a.Target = nil
	b.Target = nil
	a.ExpectedRevision = ""
	b.ExpectedRevision = ""
	if !reflect.DeepEqual(a, b) {
		return Result{}, fabric.NewError(fabric.CodeInvalidMutation, "Continuation changed immutable invocation fields")
	}
	if initial.Context.Deadline != nil && !time.Now().Before(*initial.Context.Deadline) {
		return Result{}, fabric.NewError(fabric.CodeDeadlineExceeded, "Original invocation deadline expired")
	}
	// Give the verifier separate owned arguments: a trusted callback cannot
	// accidentally change the sealed bytes later passed to existing admission.
	var verification fabric.Envelope
	if err = fabric.DecodeJSON(finalBytes, &verification); err != nil {
		return Result{}, err
	}
	if err = s.config.ResumeDispatchVerifier.VerifyResumeDispatch(ctx, caller, bytes.Clone(original), verification); err != nil {
		return Result{}, publicError(err)
	}
	ctx = context.WithValue(ctx, callerContextKey{}, caller)
	ctx = context.WithValue(ctx, originalRequestKey{}, original)
	if initial.Context.Deadline != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, *initial.Context.Deadline)
		result, err := s.invoke(ctx, caller, owned)
		if err != nil || result.Stream == nil {
			cancel()
		} else {
			result.Stream = &cancelStream{InvocationStream: result.Stream, cancel: cancel}
		}
		return result, err
	}
	return s.invoke(ctx, caller, owned)
}
