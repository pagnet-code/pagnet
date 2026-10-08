package fabricnative

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"math"
	"sync/atomic"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// SourceReference is private encrypted association metadata, not authority.
// It contains no worker path/key and commits the actual original signed source.
// Every operation requires independently current caller/source authorization.
type SourceReference struct {
	Version        int              `json:"version"`
	Principal      fabric.Principal `json:"principal"`
	InvocationID   string           `json:"invocationId"`
	AdmissionSHA   [32]byte         `json:"admissionSha"`
	BindingSHA     [32]byte         `json:"bindingSha"`
	ReservationSHA [32]byte         `json:"reservationSha"`
}

func sourceSHA(value any) [32]byte { raw, _ := json.Marshal(value); return sha256.Sum256(raw) }
func referenceFor(c OriginalCheckpoint, r identity.NativeDispatchReservation) SourceReference {
	return SourceReference{1, c.Admission.OriginalCaller, c.Admission.InvocationID, sourceSHA(c.Admission), sourceSHA(c.OriginalBinding), sourceSHA(r)}
}
func (r SourceReference) valid() bool {
	return r.Version == 1 && r.Principal.Ref != "" && len(r.Principal.Ref) <= 4096 && r.Principal.Issuer != "" && len(r.Principal.Issuer) <= 4096 && fabric.ValidNamespacedName(r.Principal.Kind) && r.InvocationID != "" && len(r.InvocationID) <= 256 && r.AdmissionSHA != ([32]byte{}) && r.BindingSHA != ([32]byte{}) && r.ReservationSHA != ([32]byte{})
}

// RetainedSource owns only a delivery handle. It never creates a runtime,
// reserves an invocation, resubmits input or owns a shared worker connection.
// Close detaches delivery without stopping the original accepted operation.
type RetainedSource struct {
	adapter     *Adapter
	checkpoint  OriginalCheckpoint
	reservation identity.NativeDispatchReservation
	reference   SourceReference
	ownership   nativeauthority.Scope
	directory   string
	closed      atomic.Bool
}

func (s *RetainedSource) Reference() SourceReference {
	if s == nil {
		return SourceReference{}
	}
	return s.reference
}
func (s *RetainedSource) Close() error {
	if s != nil {
		s.closed.Store(true)
	}
	return nil
}

// RetainOriginal locates only an already worker-accepted source. Current policy
// and genuine private Outcome evidence are checked before exposing a reference.
func (a *Adapter) RetainOriginal(ctx context.Context, caller fabric.ExecutionContext, principal fabric.Principal, invocation string) (*RetainedSource, error) {
	if a == nil || ctx == nil || caller.VerifyAuthenticated(a.config.Authority.Identity().Namespace) != nil {
		return nil, adapterError(fabric.CodeUnauthenticated, "Current retained-source caller required")
	}
	checkpoint, _, err := a.config.Checkpoints.Load(ctx, principal, invocation)
	if err != nil {
		return nil, err
	}
	reservation, err := a.config.Authority.LookupNativeDispatch(ctx, a.config.Owner, checkpoint.Admission, checkpoint.OriginalBinding)
	if err != nil {
		return nil, err
	}
	scope, err := nativeauthority.NewLocalScope(a.config.Authority.Identity(), checkpoint.OriginalBinding)
	if err != nil {
		return nil, err
	}
	h, err := a.config.Workers.Refresh(ctx, caller, scope)
	if err != nil {
		return nil, err
	}
	if err = a.handle(ctx, h, scope); err != nil {
		return nil, err
	}
	var response sessionworker.LocalResponse
	err = a.read(ctx, caller, h, checkpoint, reservation, identity.NativeSourcePage, func(current context.Context) error {
		var e error
		response, e = h.Client.Call(current, sessionworker.LocalRequest{Type: "outcome", Sequence: reservation.Sequence})
		return e
	})
	if err != nil {
		return nil, err
	}
	o := response.Outcome
	if o == nil || o.LocalSource == nil || o.Sequence != reservation.Sequence || o.CommandID != reservation.CommandID || o.Kind != "prompt" || !equalNativeValue(o.LocalSource.Admission, checkpoint.Admission) || !equalNativeValue(o.LocalSource.Reservation, reservation) || !equalNativeValue(o.LocalSource.Binding, checkpoint.OriginalBinding) {
		return nil, adapterError(fabric.CodeTargetUnavailable, "Original accepted native source evidence unavailable")
	}
	return &RetainedSource{adapter: a, checkpoint: checkpoint, reservation: reservation, reference: referenceFor(checkpoint, reservation), ownership: scope, directory: h.Directory}, nil
}
func (a *Adapter) OpenRetainedSource(ctx context.Context, caller fabric.ExecutionContext, ref SourceReference) (*RetainedSource, error) {
	if !ref.valid() {
		return nil, adapterError(fabric.CodeInvalidInput, "Invalid original native source reference")
	}
	source, err := a.RetainOriginal(ctx, caller, ref.Principal, ref.InvocationID)
	if err != nil {
		return nil, err
	}
	if source.reference != ref {
		source.Close()
		return nil, adapterError(fabric.CodeUnauthenticated, "Original native source commitment differs")
	}
	return source, nil
}
func (s *RetainedSource) handle(ctx context.Context, caller fabric.ExecutionContext) (WorkerHandle, error) {
	if s == nil || s.closed.Load() || ctx == nil || ctx.Err() != nil {
		return WorkerHandle{}, adapterError(fabric.CodeTargetUnavailable, "Native delivery handle unavailable")
	}
	h, err := s.adapter.config.Workers.Refresh(ctx, caller, s.ownership)
	if err != nil {
		return WorkerHandle{}, err
	}
	if h.Directory != s.directory {
		return WorkerHandle{}, adapterError(fabric.CodeStaleReference, "Original native physical directory changed")
	}
	if err = s.adapter.handle(ctx, h, s.ownership); err != nil {
		return WorkerHandle{}, err
	}
	return h, nil
}

// SourcePage distinguishes an actual frame from readiness. The cipher digest is
// the original worker ACK commitment, not a hash of a transformed response.
type SourcePage struct {
	Frame        *fabric.InvocationFrame
	Cursor       int64
	CipherDigest string
	Floor        int64
	Readiness    *sessionworker.ReadinessToken
}

// Page reads at most one genuine original frame, never automatically ACKs it.
// The consumer must FULL-checkpoint its exact cursor BEFORE calling Ack.
func (s *RetainedSource) Page(ctx context.Context, caller fabric.ExecutionContext, cursor int64) (SourcePage, error) {
	if cursor < -1 || cursor == math.MaxInt64 {
		return SourcePage{}, adapterError(fabric.CodeInvalidInput, "Invalid native source cursor")
	}
	h, err := s.handle(ctx, caller)
	if err != nil {
		return SourcePage{}, err
	}
	var response sessionworker.LocalResponse
	err = s.adapter.read(ctx, caller, h, s.checkpoint, s.reservation, identity.NativeSourcePage, func(current context.Context) error {
		var e error
		response, e = h.Client.Call(current, sessionworker.LocalRequest{Type: "stream_page", Control: &nativeauthority.LocalControl{CurrentController: h.Current, CurrentBinding: h.Binding}, Sequence: s.reservation.Sequence, Cursor: cursor, Limit: 1})
		return e
	})
	if err != nil {
		if response.Code == "not_ready" && response.Readiness != nil {
			return SourcePage{Cursor: cursor, Readiness: response.Readiness}, nil
		}
		return SourcePage{}, err
	}
	page := response.Stream
	if page == nil || page.Floor != cursor || page.Source.Authority != s.ownership || !equalNativeValue(page.Source.Original.Admission, s.checkpoint.Admission) || !equalNativeValue(page.Source.Original.Reservation, s.reservation) || !equalNativeValue(page.Source.Original.Binding, s.checkpoint.OriginalBinding) {
		return SourcePage{}, adapterError(fabric.CodeTargetUnavailable, "Original source page/cursor unavailable or consumed")
	}
	ready := page.Readiness
	result := SourcePage{Cursor: cursor, Floor: page.Floor, Readiness: &ready}
	if len(page.Frames) == 0 {
		if page.Terminal {
			return SourcePage{}, adapterError(fabric.CodeTargetUnavailable, "Original terminal frame already consumed")
		}
		return result, nil
	}
	if len(page.Frames) != 1 || page.Frames[0].Cursor != cursor+1 {
		return SourcePage{}, adapterError(fabric.CodeProtocolError, "Original native frame sequence differs")
	}
	key := bytes.Clone(h.ControlKey)
	defer clear(key)
	frame, err := sessionworker.OpenLocalInvocationFrame(key, s.ownership, s.directory, page.Source, page.Frames[0])
	if err != nil {
		return SourcePage{}, adapterError(fabric.CodeProtocolError, "Original native frame authentication failed")
	}
	if frame.InvocationID != s.reference.InvocationID || frame.Sequence != uint64(cursor+1) {
		return SourcePage{}, adapterError(fabric.CodeProtocolError, "Original native invocation frame differs")
	}
	result.Frame = &frame
	result.Cursor = page.Frames[0].Cursor
	result.CipherDigest = page.Frames[0].Digest
	return result, nil
}

// PollActivation services only the existing accepted source's actual worker
// activation ticket. It does not admit/resend work. No plaintext model output
// or fabricated native origin is produced here.
func (s *RetainedSource) PollActivation(ctx context.Context, caller fabric.ExecutionContext) error {
	h, err := s.handle(ctx, caller)
	if err != nil {
		return err
	}
	// Recheck exact disclosure permission first; activation validates its own
	// existing original source ticket through the authority's genuine origin gate.
	if err = s.adapter.read(ctx, caller, h, s.checkpoint, s.reservation, identity.NativeSourcePage, func(context.Context) error { return nil }); err != nil {
		return err
	}
	return s.adapter.activation(ctx, h, s.reference)
}

// Wait is readiness-only, outside the SQL/source read transaction. Always call
// Page again afterward to freshly authorize any source content.
func (s *RetainedSource) Wait(ctx context.Context, caller fabric.ExecutionContext, token sessionworker.ReadinessToken) error {
	h, err := s.handle(ctx, caller)
	if err != nil {
		return err
	}
	if err = s.adapter.read(ctx, caller, h, s.checkpoint, s.reservation, identity.NativeSourcePage, func(context.Context) error { return nil }); err != nil {
		return err
	}
	_, err = h.Client.WaitReady(ctx, h.ControlKey, token)
	return err
}

// Ack FULL-checkpoints the consumer's exact cursor against the retained
// original journal. The digest must be the journal's own cipher digest for
// the ACKed frame (from Page); the journal verifies it against its retained
// frame chain (a re-ACK of the current floor against its floor digest is
// idempotent). On success it returns that journal-verified digest as the
// actuation evidence — never an unverified wire-claimed value.
func (s *RetainedSource) Ack(ctx context.Context, caller fabric.ExecutionContext, cursor int64, digest string) (string, error) {
	if cursor < 0 || cursor == math.MaxInt64 || len(digest) != 64 {
		return "", adapterError(fabric.CodeInvalidInput, "Invalid original native frame ACK")
	}
	h, err := s.handle(ctx, caller)
	if err != nil {
		return "", err
	}
	err = s.adapter.read(ctx, caller, h, s.checkpoint, s.reservation, identity.NativeSourceAck, func(current context.Context) error {
		_, e := h.Client.Call(current, sessionworker.LocalRequest{Type: "stream_ack", Control: &nativeauthority.LocalControl{CurrentController: h.Current, CurrentBinding: h.Binding}, Sequence: s.reservation.Sequence, Cursor: cursor, Digest: digest})
		return e
	})
	if err != nil {
		return "", err
	}
	return digest, nil
}

// RequestCancellation commits only a genuine worker FULL cancellation-intent
// ACK. It does not assert process reaping, business completion or a terminal
// frame. On success it returns the digest of the exact verified
// cancellation-intent wire artifact the worker committed — retained evidence
// for the stop, never a self-attested value.
func (s *RetainedSource) RequestCancellation(ctx context.Context, caller fabric.ExecutionContext) ([32]byte, error) {
	h, err := s.handle(ctx, caller)
	if err != nil {
		return [32]byte{}, err
	}
	binder, err := nativeauthority.NewInputBinder(h.InputBindingProfile, s.checkpoint.OriginalBinding.Worker.ProfileDigest)
	if err != nil {
		return [32]byte{}, err
	}
	controller, err := nativeauthority.NewLocalControllerForOwnership(s.adapter.config.Authority, s.adapter.config.Owner, h.Ownership, h.Binding, binder)
	if err != nil {
		return [32]byte{}, err
	}
	intent, err := controller.CancellationIntent(h.Current, s.checkpoint.OriginalBinding, s.checkpoint.Admission, s.reservation, s.checkpoint.Finalized)
	if err != nil {
		return [32]byte{}, err
	}
	var committed [32]byte
	err = s.adapter.config.Authority.FenceNativeCancellation(ctx, s.adapter.config.Owner, caller, h.Current, h.Binding, s.checkpoint.OriginalBinding, s.checkpoint.Admission, s.reservation, func(current context.Context) error {
		request := intent.Request()
		if _, e := h.Client.Call(current, sessionworker.LocalRequest{Type: "cancel", Intent: &request}); e != nil {
			return e
		}
		raw, e := json.Marshal(request)
		if e != nil {
			return adapterError(fabric.CodeProtocolError, "Original native cancellation intent encoding failed")
		}
		defer clear(raw)
		committed = sha256.Sum256(raw)
		return nil
	})
	if err != nil {
		return [32]byte{}, err
	}
	return committed, nil
}

// PrepareReferenceVerifier performs current caller/kernel checks before SQL.
// Its returned verifier consumes the exact existing source inside a consumer's
// same-root transaction, without IPC or nested registry calls.
func (s *RetainedSource) PrepareReferenceVerifier(ctx context.Context, caller fabric.ExecutionContext) (*identity.NativeSourceReadVerifier, error) {
	if s == nil || s.closed.Load() || ctx == nil {
		return nil, checkpointDenied()
	}
	h, err := s.adapter.config.Workers.Refresh(ctx, caller, s.ownership)
	if err != nil {
		return nil, err
	}
	// Shared fixture/resolver ownership differs; do not mutate borrowed handle keys.
	if h.Directory != s.directory {
		return nil, checkpointDenied()
	}
	return s.adapter.config.Authority.PrepareNativeSourceReadVerifier(ctx, caller, h.Current, h.Binding, s.checkpoint.OriginalBinding, s.checkpoint.Admission, s.reservation)
}
