package fabricnative

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// WorkerHandle comes only from trusted launch/adoption composition. Neither
// private paths, control keys nor executable profiles are application arguments.
// The resolver owns the shared IPC connection; streams never close it.
type WorkerHandle struct {
	InputBindingProfile string
	Current             identity.Controller
	Binding             identity.Binding
	Ownership           nativeauthority.Scope
	Directory           string
	ControlKey          []byte                     `json:"-"`
	Client              *sessionworker.LocalClient `json:"-"`
}
type WorkerResolver interface {
	Resolve(context.Context, fabric.ExecutionContext, fabric.EndpointDescriptor) (WorkerHandle, error)
	// Refresh adopts control/readback only, never resubmits a paid native effect.
	Refresh(context.Context, fabric.ExecutionContext, nativeauthority.Scope) (WorkerHandle, error)
}
type AdapterConfig struct {
	// CleanupCaller is protected operator authority for exact-source stop only.
	CleanupCaller         func(context.Context) (fabric.ExecutionContext, error)
	Authority             *identity.Authority
	Owner                 fabric.ExecutionContext
	Checkpoints           *Checkpoints
	ManagedPeers          *ManagedPeers
	Workers               WorkerResolver
	MaxWorkers            int
	MaxInvocationDuration time.Duration
	CleanupTimeout        time.Duration
}

// Adapter bridges genuine finalized node requests to the same-root local worker.
// Source acknowledgement is not native completion. No cloud authority is minted.
type Adapter struct {
	config AdapterConfig
	mu     sync.Mutex
	gates  map[nativeauthority.Scope]*sync.Mutex
	ready  map[nativeauthority.Scope]handleAdmission
}

func NewAdapter(c AdapterConfig) (*Adapter, error) {
	if c.Authority == nil || c.Checkpoints == nil || c.ManagedPeers == nil || c.Workers == nil || c.Owner.VerifyAuthenticated(c.Authority.Identity().Namespace) != nil || c.Owner.PrincipalView() != c.Authority.Identity().Owner {
		return nil, adapterError(fabric.CodeInvalidInput, "Native adapter trusted composition missing")
	}
	if c.MaxWorkers == 0 {
		c.MaxWorkers = 128
	}
	if c.MaxInvocationDuration == 0 {
		c.MaxInvocationDuration = 10 * time.Minute
	}
	if c.CleanupTimeout == 0 {
		c.CleanupTimeout = 5 * time.Second
	}
	if c.MaxWorkers < 1 || c.MaxWorkers > 4096 || c.MaxInvocationDuration <= 0 || c.MaxInvocationDuration > 24*time.Hour || c.CleanupTimeout <= 0 || c.CleanupTimeout > 5*time.Second {
		return nil, adapterError(fabric.CodeInvalidInput, "Native adapter budgets invalid")
	}
	if c.Checkpoints.authority.Identity().StoreID != c.Authority.Identity().StoreID || c.ManagedPeers.authority.Identity().StoreID != c.Authority.Identity().StoreID {
		return nil, adapterError(fabric.CodeInvalidInput, "Native adapter root differs")
	}
	return &Adapter{config: c, gates: make(map[nativeauthority.Scope]*sync.Mutex), ready: make(map[nativeauthority.Scope]handleAdmission)}, nil
}

type handleAdmission struct {
	Client              *sessionworker.LocalClient
	Lease               int64
	Directory           string
	Controller, Binding [32]byte
}

func handleAdmissionKey(h WorkerHandle) handleAdmission {
	current, _ := json.Marshal(h.Current)
	binding, _ := json.Marshal(h.Binding)
	return handleAdmission{h.Client, h.Client.Lease, h.Directory, sha256.Sum256(current), sha256.Sum256(binding)}
}
func adapterError(code fabric.ErrorCode, message string) error { return fabric.NewError(code, message) }
func equalNativeValue(a, b any) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
func (a *Adapter) handle(ctx context.Context, h WorkerHandle, expected nativeauthority.Scope) error {
	if h.Client == nil || len(h.ControlKey) != 32 || !filepath.IsAbs(h.Directory) || filepath.Clean(h.Directory) != h.Directory || h.Ownership.Validate() != nil || h.Ownership.Kind() != nativeauthority.Local || h.Current.Scope != h.Binding.Scope {
		return adapterError(fabric.CodeProtocolError, "Native worker handle invalid")
	}
	current, e := nativeauthority.NewLocalScope(a.config.Authority.Identity(), h.Binding)
	if e != nil || !h.Ownership.SamePhysical(current) || (expected.Kind() != nativeauthority.Kind("") && h.Ownership != expected) {
		return adapterError(fabric.CodeStaleReference, "Native physical ownership differs")
	}
	key := handleAdmissionKey(h)
	a.mu.Lock()
	known, exists := a.ready[h.Ownership]
	full := !exists && len(a.ready) >= a.config.MaxWorkers
	if !exists && !full {
		a.ready[h.Ownership] = handleAdmission{}
	}
	a.mu.Unlock()
	if exists && known == key {
		return nil
	}
	if full {
		return adapterError(fabric.CodeTargetUnavailable, "Native worker admission capacity unavailable")
	}
	if e = a.config.ManagedPeers.Register(ctx, h.Client, h.Ownership); e != nil {
		return e
	}
	e = a.config.Authority.FenceNativeControl(ctx, a.config.Owner, h.Current, h.Binding, func(c context.Context) error {
		_, err := h.Client.Call(c, sessionworker.LocalRequest{Type: "control", Control: &nativeauthority.LocalControl{CurrentController: h.Current, CurrentBinding: h.Binding}})
		return err
	})
	if e == nil {
		a.mu.Lock()
		a.ready[h.Ownership] = key
		a.mu.Unlock()
	}
	return e
}
func nativeAdmissionID(caller fabric.Principal, id string) string {
	return "invoke-" + checkpointID(caller, id)
}
func (a *Adapter) Invoke(ctx context.Context, caller fabric.ExecutionContext, endpoint fabric.EndpointDescriptor, request fabric.InvokeRequest) (fabric.InvocationStream, error) {
	if a == nil || ctx == nil {
		return nil, adapterError(fabric.CodeInvalidInput, "Native invocation missing")
	}
	authenticated, original, finalized, ok := node.FinalizedRequestFromContext(ctx)
	if !ok || authenticated.PrincipalView() != caller.PrincipalView() || !equalNativeValue(authenticated.ProvenanceView(), caller.ProvenanceView()) || caller.VerifyAuthenticated(a.config.Authority.Identity().Namespace) != nil || request.Validate() != nil {
		return nil, adapterError(fabric.CodeUnauthenticated, "Native invocation requires finalized node admission")
	}
	if _, e := caller.DecodeVerifiedEnvelope(original, a.config.Authority.Identity().Namespace); e != nil {
		return nil, e
	}
	var env fabric.Envelope
	if fabric.DecodeJSON(finalized, &env) != nil || env.Validate() != nil || env.Operation != fabric.OperationInvoke || env.Target == nil || *env.Target != request.Target || endpoint.Ref != env.Target.Endpoint() || !env.Target.IsOffer() && endpoint.Revision != env.ExpectedRevision || request.ExpectedRevision != env.ExpectedRevision || request.InvocationID != env.ID || request.IdempotencyKey != env.Context.IdempotencyKey || !bytes.Equal(request.Input, env.Payload) || !equalNativeValue(request.Deadline, env.Context.Deadline) {
		return nil, adapterError(fabric.CodeInvalidInput, "Native request differs from finalized dispatch")
	}
	checkpoint, restored, e := a.config.Checkpoints.Load(ctx, caller.PrincipalView(), env.ID)
	if e == nil {
		if !bytes.Equal(checkpoint.Original, original) || !bytes.Equal(checkpoint.Finalized, finalized) {
			return nil, adapterError(fabric.CodeStaleReference, "Original native invocation changed")
		}
		return a.recover(ctx, caller, restored, checkpoint)
	}
	var typed *fabric.Error
	if !errors.As(e, &typed) || typed.Code != fabric.CodeNotFound {
		return nil, e
	}
	h, e := a.config.Workers.Resolve(ctx, caller, endpoint)
	if e != nil {
		return nil, e
	}
	if e = a.handle(ctx, h, nativeauthority.Scope{}); e != nil {
		return nil, e
	}
	if h.Binding.Scope.Endpoint != endpoint.Ref || h.Binding.Scope.DescriptorRevision != endpoint.Revision {
		return nil, adapterError(fabric.CodeStaleReference, "Native descriptor changed")
	}
	id := nativeAdmissionID(caller.PrincipalView(), env.ID)
	source, e := a.config.Authority.Admit(ctx, a.config.Owner, h.Current, h.Binding, caller, original, finalized, id, id, id)
	if e != nil {
		return nil, e
	}
	checkpoint = OriginalCheckpoint{source, h.Binding, bytes.Clone(original), bytes.Clone(finalized)}
	if _, e = a.config.Checkpoints.Save(ctx, checkpoint); e != nil {
		return nil, e
	}
	binder, e := nativeauthority.NewInputBinder(h.InputBindingProfile, h.Binding.Worker.ProfileDigest)
	if e != nil {
		return nil, e
	}
	controller, e := nativeauthority.NewLocalControllerForOwnership(a.config.Authority, a.config.Owner, h.Ownership, h.Binding, binder)
	if e != nil {
		return nil, e
	}
	receipt, e := controller.AdmitIntent(ctx, h.Current, source, caller, original, finalized, func(c context.Context, v nativeauthority.VerifiedIntent) (identity.NativeIntentReceipt, error) {
		req := v.Request()
		response, err := h.Client.Call(c, sessionworker.LocalRequest{Type: "intent", Intent: &req})
		if err != nil {
			return identity.NativeIntentReceipt{}, err
		}
		if response.Receipt == nil {
			return identity.NativeIntentReceipt{}, adapterError(fabric.CodeProtocolError, "Native durable acknowledgement missing")
		}
		return *response.Receipt, nil
	})
	if e != nil {
		return nil, e
	} // Never automatically resend an ambiguous effect.
	reservation, e := a.config.Authority.LookupNativeDispatch(ctx, a.config.Owner, source, h.Binding)
	if e != nil {
		return nil, e
	}
	if receipt.CommandID != reservation.CommandID || receipt.Sequence != reservation.Sequence || receipt.OriginalAdmissionID != source.ID {
		return nil, adapterError(fabric.CodeProtocolError, "Native acknowledgement source differs")
	}
	return a.stream(ctx, caller, checkpoint, reservation, h, true), nil
}

// Recover restores original evidence only. It performs no admission/reservation
// or paid effect. Current caller authorization is required independently.
func (a *Adapter) Recover(ctx context.Context, caller fabric.ExecutionContext, principal fabric.Principal, invocation string) (fabric.InvocationStream, error) {
	if a == nil || ctx == nil || caller.VerifyAuthenticated(a.config.Authority.Identity().Namespace) != nil {
		return nil, adapterError(fabric.CodeUnauthenticated, "Native recovery caller unavailable")
	}
	checkpoint, originalCaller, e := a.config.Checkpoints.Load(ctx, principal, invocation)
	if e != nil {
		return nil, e
	}
	return a.recover(ctx, caller, originalCaller, checkpoint)
}
func (a *Adapter) recover(ctx context.Context, caller, originalCaller fabric.ExecutionContext, checkpoint OriginalCheckpoint) (fabric.InvocationStream, error) {
	_ = originalCaller // Load's real signature restoration is mandatory; no context reconstruction.
	scope, e := nativeauthority.NewLocalScope(a.config.Authority.Identity(), checkpoint.OriginalBinding)
	if e != nil {
		return nil, e
	}
	reservation, e := a.config.Authority.LookupNativeDispatch(ctx, a.config.Owner, checkpoint.Admission, checkpoint.OriginalBinding)
	if e != nil {
		var typed *fabric.Error
		if errors.As(e, &typed) && typed.Code == fabric.CodeNotFound {
			return nil, adapterError(fabric.CodeTargetUnavailable, "Native source checkpoint is committed before worker admission; explicit continuation is required")
		}
		return nil, e
	}
	h, e := a.config.Workers.Refresh(ctx, caller, scope)
	if e != nil {
		return nil, e
	}
	if e = a.handle(ctx, h, scope); e != nil {
		return nil, e
	}
	// Absence never authorizes a fresh resend. A reservation is not a worker ACK.
	var response sessionworker.LocalResponse
	e = a.read(ctx, caller, h, checkpoint, reservation, identity.NativeSourcePage, func(c context.Context) error {
		var err error
		response, err = h.Client.Call(c, sessionworker.LocalRequest{Type: "outcome", Sequence: reservation.Sequence})
		return err
	})
	if e != nil {
		return nil, e
	}
	if response.Outcome == nil || response.Outcome.LocalSource == nil || response.Outcome.Sequence != reservation.Sequence || response.Outcome.CommandID != reservation.CommandID || response.Outcome.Kind != "prompt" || !equalNativeValue(response.Outcome.LocalSource.Admission, checkpoint.Admission) || !equalNativeValue(response.Outcome.LocalSource.Reservation, reservation) || !equalNativeValue(response.Outcome.LocalSource.Binding, checkpoint.OriginalBinding) {
		return nil, adapterError(fabric.CodeTargetUnavailable, "Native acceptance evidence unavailable")
	}
	return a.stream(ctx, caller, checkpoint, reservation, h, false), nil
}
func (a *Adapter) read(ctx context.Context, caller fabric.ExecutionContext, h WorkerHandle, checkpoint OriginalCheckpoint, reservation identity.NativeDispatchReservation, operation identity.NativeSourceReadOperation, callback func(context.Context) error) error {
	return a.config.Authority.FenceNativeSourceRead(ctx, a.config.Owner, caller, h.Current, h.Binding, checkpoint.OriginalBinding, checkpoint.Admission, reservation, operation, callback)
}
func (a *Adapter) activation(ctx context.Context, h WorkerHandle, expected ...SourceReference) error {
	a.mu.Lock()
	gate := a.gates[h.Ownership]
	if gate == nil {
		if len(a.gates) >= a.config.MaxWorkers {
			a.mu.Unlock()
			return adapterError(fabric.CodeTargetUnavailable, "Native activation service capacity unavailable")
		}
		gate = &sync.Mutex{}
		a.gates[h.Ownership] = gate
	}
	a.mu.Unlock()
	gate.Lock()
	defer gate.Unlock()
	response, e := h.Client.Call(ctx, sessionworker.LocalRequest{Type: "activation_poll"})
	if e != nil {
		return e
	}
	ticket := response.Activation
	if ticket == nil {
		return nil
	}
	if ticket.Authority != h.Ownership || !equalNativeValue(ticket.CurrentController, h.Current) || !equalNativeValue(ticket.CurrentBinding, h.Binding) || ticket.NativeGeneration == "" {
		return adapterError(fabric.CodeStaleReference, "Native activation ticket authority changed")
	}
	if len(expected) > 1 {
		return adapterError(fabric.CodeInvalidInput, "Ambiguous native activation source")
	}
	if len(expected) == 1 {
		original := OriginalCheckpoint{Admission: ticket.OriginalSource.Admission, OriginalBinding: ticket.OriginalSource.Binding}
		if referenceFor(original, ticket.OriginalSource.Reservation) != expected[0] || ticket.SourceCommandID != ticket.OriginalSource.Reservation.CommandID {
			return adapterError(fabric.CodeTargetUnavailable, "Native activation ticket belongs to another original source")
		}
	}
	checkpoint, caller, e := a.config.Checkpoints.Load(ctx, ticket.OriginalSource.Admission.OriginalCaller, ticket.OriginalSource.Admission.InvocationID)
	if e == nil && !equalNativeValue(checkpoint.Admission, ticket.OriginalSource.Admission) {
		e = adapterError(fabric.CodeProtocolError, "Native activation original source changed")
	}
	var origin identity.Origin
	if e == nil {
		raw, _ := json.Marshal(struct{ Purpose, Command, Generation string }{"pagnet.native.adapter.origin.v1", ticket.SourceCommandID, ticket.NativeGeneration})
		hash := sha256.Sum256(raw)
		id := hex.EncodeToString(hash[:])
		if checkpoint.OriginalBinding.Scope == h.Binding.Scope {
			origin, e = a.config.Authority.RegisterOrigin(ctx, a.config.Owner, h.Current, h.Binding, checkpoint.Admission, caller, checkpoint.Original, checkpoint.Finalized, id, ticket.NativeGeneration)
		} else {
			origin, e = a.config.Authority.RegisterHistoricalOrigin(ctx, a.config.Owner, h.Current, h.Binding, checkpoint.OriginalBinding, checkpoint.Admission, caller, checkpoint.Original, checkpoint.Finalized, id, ticket.NativeGeneration)
		}
	}
	reply := sessionworker.LocalActivationOrigin{ID: ticket.ID, NativeGeneration: ticket.NativeGeneration}
	if e != nil {
		reply.Error = "Original native activation authorization unavailable"
	} else {
		reply.Origin = &origin
	}
	_, sendError := h.Client.Call(ctx, sessionworker.LocalRequest{Type: "activation_origin", ActivationOrigin: &reply})
	if e != nil {
		return e
	}
	return sendError
}

type nativeStream struct {
	adapter     *Adapter
	caller      fabric.ExecutionContext
	checkpoint  OriginalCheckpoint
	reservation identity.NativeDispatchReservation
	ownership   nativeauthority.Scope
	directory   string
	lifetime    context.Context
	cancel      context.CancelFunc
	nextMu      sync.Mutex
	mu          sync.Mutex
	closed      bool
	closeDone   chan struct{}
	closeError  error
	terminal    bool
	started     bool
	pending     *sessionworker.LocalInvocationCipherFrame
	cursor      int64
}

func (a *Adapter) stream(ctx context.Context, caller fabric.ExecutionContext, checkpoint OriginalCheckpoint, r identity.NativeDispatchReservation, h WorkerHandle, executionDeadline bool) *nativeStream {
	life, cancel := context.WithTimeout(ctx, a.config.MaxInvocationDuration)
	var env fabric.Envelope
	if executionDeadline && fabric.DecodeJSON(checkpoint.Finalized, &env) == nil && env.Context.Deadline != nil {
		limited, stop := context.WithDeadline(life, *env.Context.Deadline)
		previous := cancel
		life = limited
		cancel = func() { stop(); previous() }
	}
	stream := &nativeStream{adapter: a, caller: caller, checkpoint: checkpoint, reservation: r, ownership: h.Ownership, directory: h.Directory, lifetime: life, cancel: cancel, cursor: -1, closeDone: make(chan struct{})}
	context.AfterFunc(life, func() { _ = stream.Close() })
	return stream
}
func (s *nativeStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	s.nextMu.Lock()
	defer s.nextMu.Unlock()
	s.mu.Lock()
	closed, terminal := s.closed, s.terminal
	s.mu.Unlock()
	if closed {
		if !terminal {
			if errors.Is(s.lifetime.Err(), context.DeadlineExceeded) {
				return fabric.InvocationFrame{}, adapterError(fabric.CodeDeadlineExceeded, "Native invocation deadline elapsed; source effects require retained evidence")
			}
			// Close publishes closed before cancelling the owned lifetime. A
			// concurrent first pull in that interval is stopped, never normal EOF.
			return fabric.InvocationFrame{}, adapterError(fabric.CodeCancelled, "Native invocation was cancelled; source effects require retained evidence")
		}
		return fabric.InvocationFrame{}, io.EOF
	}
	if ctx == nil {
		return fabric.InvocationFrame{}, adapterError(fabric.CodeInvalidInput, "Native pull context missing")
	}
	if e := ctx.Err(); e != nil {
		_ = s.Close()
		return fabric.InvocationFrame{}, adapterError(fabric.CodeCancelled, "Native pull was cancelled; source effects require retained evidence")
	}
	life, cancel := context.WithCancel(s.lifetime)
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	defer cancel()
	fail := func(e error) (fabric.InvocationFrame, error) {
		_ = s.Close()
		if errors.Is(e, context.Canceled) {
			e = adapterError(fabric.CodeCancelled, "Native invocation was cancelled; source effects require retained evidence")
		} else if errors.Is(e, context.DeadlineExceeded) {
			e = adapterError(fabric.CodeDeadlineExceeded, "Native invocation deadline elapsed; source effects require retained evidence")
		}
		return fabric.InvocationFrame{}, e
	}
	for {
		if e := life.Err(); e != nil {
			return fail(e)
		}
		h, e := s.adapter.config.Workers.Refresh(life, s.caller, s.ownership)
		if e != nil {
			return fail(e)
		}
		if h.Directory != s.directory {
			return fail(adapterError(fabric.CodeStaleReference, "Native worker state directory changed"))
		}
		if e = s.adapter.handle(life, h, s.ownership); e != nil {
			return fail(e)
		}
		s.mu.Lock()
		ack := s.pending
		s.mu.Unlock()
		if ack != nil {
			e = s.adapter.read(life, s.caller, h, s.checkpoint, s.reservation, identity.NativeSourceAck, func(c context.Context) error {
				_, err := h.Client.Call(c, sessionworker.LocalRequest{Type: "stream_ack", Control: &nativeauthority.LocalControl{CurrentController: h.Current, CurrentBinding: h.Binding}, Sequence: s.reservation.Sequence, Cursor: ack.Cursor, Digest: ack.Digest})
				return err
			})
			if e != nil {
				return fail(e)
			}
			s.mu.Lock()
			s.cursor = ack.Cursor
			s.pending = nil
			s.mu.Unlock()
		}
		if terminal {
			s.cancel()
			return fabric.InvocationFrame{}, io.EOF
		}
		if !s.started {
			if e = s.adapter.activation(life, h); e != nil {
				return fail(e)
			}
		}
		var response sessionworker.LocalResponse
		e = s.adapter.read(life, s.caller, h, s.checkpoint, s.reservation, identity.NativeSourcePage, func(c context.Context) error {
			var err error
			response, err = h.Client.Call(c, sessionworker.LocalRequest{Type: "stream_page", Control: &nativeauthority.LocalControl{CurrentController: h.Current, CurrentBinding: h.Binding}, Sequence: s.reservation.Sequence, Cursor: s.cursor, Limit: 1})
			return err
		})
		if e != nil && response.Code != "not_ready" {
			return fail(e)
		}
		if e == nil {
			page := response.Stream
			if page == nil {
				return fail(adapterError(fabric.CodeProtocolError, "Native stream evidence missing"))
			}
			if page.Floor != s.cursor {
				return fail(adapterError(fabric.CodeUnsupported, "Native stream bytes were already consumed; a consumer cursor is required"))
			}
			if len(page.Frames) > 0 {
				if len(page.Frames) != 1 || page.Source.Authority != s.ownership || !equalNativeValue(page.Source.Original.Admission, s.checkpoint.Admission) || !equalNativeValue(page.Source.Original.Reservation, s.reservation) || page.Frames[0].Cursor != s.cursor+1 {
					return fail(adapterError(fabric.CodeProtocolError, "Native stream source or cursor differs"))
				}
				key := bytes.Clone(h.ControlKey)
				frame, err := sessionworker.OpenLocalInvocationFrame(key, s.ownership, s.directory, page.Source, page.Frames[0])
				clear(key)
				if err != nil {
					return fail(adapterError(fabric.CodeProtocolError, "Native stream authentication failed"))
				}
				if frame.Kind == fabric.FrameStart {
					s.started = true
				}
				sealed := page.Frames[0]
				s.mu.Lock()
				s.pending = &sealed
				s.mu.Unlock()
				if frame.Kind == fabric.FrameComplete || frame.Kind == fabric.FrameError {
					s.mu.Lock()
					s.terminal = true
					s.mu.Unlock()
				}
				return frame, nil
			}
			if page.Terminal {
				return fail(adapterError(fabric.CodeTargetUnavailable, "Native terminal evidence was already consumed"))
			}
		}
		// Ticket publication may have preceded the Page token after the first
		// poll. Check it once more before sleeping; subsequent publication changes
		// that captured token, so the auxiliary wait cannot miss readiness.
		if !s.started {
			if e = s.adapter.activation(life, h); e != nil {
				return fail(e)
			}
		}
		if response.Readiness == nil {
			return fail(adapterError(fabric.CodeProtocolError, "Native readiness token unavailable"))
		}
		if _, e = h.Client.WaitReady(life, h.ControlKey, *response.Readiness); e != nil {
			return fail(e)
		}

	}
}
func (s *nativeStream) Close() (result error) {
	s.mu.Lock()
	if s.closed {
		done := s.closeDone
		s.mu.Unlock()
		<-done
		s.mu.Lock()
		err := s.closeError
		s.mu.Unlock()
		return err
	}
	s.closed = true
	defer func() { s.mu.Lock(); s.closeError = result; close(s.closeDone); s.mu.Unlock() }()
	terminal := s.terminal
	ack := s.pending
	s.mu.Unlock()
	s.cancel()

	ctx, cancel := context.WithTimeout(context.Background(), s.adapter.config.CleanupTimeout)
	defer cancel()
	cleanupCaller := s.caller
	if !terminal && s.adapter.config.CleanupCaller != nil {
		var err error
		cleanupCaller, err = s.adapter.config.CleanupCaller(ctx)
		if err != nil {
			return err
		}
	}
	h, e := s.adapter.config.Workers.Refresh(ctx, cleanupCaller, s.ownership)
	if e != nil {
		return e
	}
	if h.Directory != s.directory {
		return adapterError(fabric.CodeStaleReference, "Native cancellation physical directory differs")
	}
	if e = s.adapter.handle(ctx, h, s.ownership); e != nil {
		return e
	}
	if terminal {
		if ack == nil {
			return nil
		}
		return s.adapter.read(ctx, s.caller, h, s.checkpoint, s.reservation, identity.NativeSourceAck, func(c context.Context) error {
			_, err := h.Client.Call(c, sessionworker.LocalRequest{Type: "stream_ack", Control: &nativeauthority.LocalControl{CurrentController: h.Current, CurrentBinding: h.Binding}, Sequence: s.reservation.Sequence, Cursor: ack.Cursor, Digest: ack.Digest})
			return err
		})
	}
	binder, e := nativeauthority.NewInputBinder(h.InputBindingProfile, s.checkpoint.OriginalBinding.Worker.ProfileDigest)
	if e != nil {
		return e
	}
	controller, e := nativeauthority.NewLocalControllerForOwnership(s.adapter.config.Authority, s.adapter.config.Owner, h.Ownership, h.Binding, binder)
	if e != nil {
		return e
	}
	intent, e := controller.CancellationIntent(h.Current, s.checkpoint.OriginalBinding, s.checkpoint.Admission, s.reservation, s.checkpoint.Finalized)
	if e != nil {
		return e
	}
	return s.adapter.config.Authority.FenceNativeCancellation(ctx, s.adapter.config.Owner, cleanupCaller, h.Current, h.Binding, s.checkpoint.OriginalBinding, s.checkpoint.Admission, s.reservation, func(c context.Context) error {
		request := intent.Request()
		_, err := h.Client.Call(c, sessionworker.LocalRequest{Type: "cancel", Intent: &request})
		return err
	})
}
