// Package fabricagent adapts owner-bound native agent invocations. It does not
// own a runtime or mint admissions: daemon composition supplies the genuine
// lifecycle implementation and its durable invocation/source association.
package fabricagent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
)

// Binding is private registry state. Instance selection may change between
// invocations, but never changes an admitted invocation's selected realization.
// Resolve must read the exact revision atomically, without launching a runtime.
type Binding struct {
	Ref          fabric.EndpointRef
	Revision     fabric.Revision
	DefinitionID string
	InstanceID   string
	BindingID    string
}

type BindingStore interface {
	Resolve(context.Context, fabric.EndpointRef, fabric.Revision) (Binding, error)
}

// Lifecycle is injected by the daemon. Begin must durably associate the exact
// caller, reference/revision, input, idempotency identity and original native
// admission before effects. It owns wake/resume; missing history cannot silently
// start a fresh conversation. It never manufactures a cloud or local authority.
// A transport failure cannot automatically repeat accepted work.
type Lifecycle interface {
	Begin(context.Context, fabric.ExecutionContext, Binding, fabric.InvokeRequest) (NativeInvocation, error)
}

// Receipt is the immutable durable association, not an acceptance fabricated
// from an enqueue ACK. IDs are private adapter data, never prompt decoration.
type Receipt struct {
	InvocationID        string
	Binding             Binding
	SourceCommandID     string
	SourceAdmissionID   string
	OwnershipGeneration string
	DispatchSequence    uint64
}

// Source identifies the genuine native realization and logical turn of this
// admission. It must be verified at original capture by the lifecycle boundary.
type Source struct {
	Receipt          Receipt
	OriginID         string
	NativeGeneration string
	NativeSessionID  string
	LogicalTurnID    string
}

type EventKind uint8

const (
	EventStarted EventKind = iota + 1
	EventAssistantContent
	EventReplyCommitted
	EventFailed
)

// Event content must be authenticated original assistant content, never PTY
// rendering, tool output, a controller-generated replay, or an idle inference.
// ReplyCommitted means the correlated delivery/result committed, not merely
// that a prompt was accepted or a runtime reported turn completion.
type Event struct {
	Kind        EventKind
	Source      Source
	ContentType string
	Data        []byte
	Error       *fabric.Error
}

// NativeInvocation owns source verification and bounded durable consumption.
// Next is pull-driven, cancellation-aware, and must deliver small authenticated
// chunks while a turn is running (not wait for a 64 KiB spool or EOF).
// Close releases the consumer and cancels only THIS invocation if cancellation
// is supported; it must not stop another turn or claim unknown effects undone.
// Accepted outcomes remain durably queryable after consumer/controller loss.
type NativeInvocation interface {
	Receipt() Receipt
	Next(context.Context) (Event, error)
	Close() error
}

type Adapter struct {
	bindings  BindingStore
	lifecycle Lifecycle
}

func New(bindings BindingStore, lifecycle Lifecycle) (*Adapter, error) {
	if bindings == nil || lifecycle == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Native agent composition is incomplete")
	}
	return &Adapter{bindings: bindings, lifecycle: lifecycle}, nil
}

// Invoke resolves exactly the remembered endpoint; it never discovers a
// replacement, searches for another replica after acceptance, or invokes on
// descriptor lookup. Authorization precedes this adapter in the Fabric engine.
func (a *Adapter) Invoke(ctx context.Context, caller fabric.ExecutionContext, descriptor fabric.EndpointDescriptor, request fabric.InvokeRequest) (fabric.InvocationStream, error) {
	if ctx == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Missing invocation context")
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	if err := caller.VerifyAuthenticated(caller.Audience()); err != nil {
		return nil, err
	}
	if caller.PrincipalView().Ref == "" || caller.Audience() == "" {
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "Missing authenticated caller")
	}
	if request.Target.IsOffer() || descriptor.Ref != request.Target || descriptor.Revision == "" || request.ExpectedRevision != "" && request.ExpectedRevision != descriptor.Revision {
		return nil, fabric.NewError(fabric.CodeStaleReference, "Native agent reference or revision changed")
	}
	binding, err := a.bindings.Resolve(ctx, request.Target, descriptor.Revision)
	if err != nil {
		return nil, err
	}
	if binding.Ref != request.Target || binding.Revision != descriptor.Revision || binding.DefinitionID == "" || binding.InstanceID == "" || binding.BindingID == "" {
		return nil, fabric.NewError(fabric.CodeStaleReference, "Native agent binding changed")
	}
	advertised := false
	for _, b := range descriptor.Bindings {
		if b.ID == binding.BindingID && b.Protocol == "pagnet.native-agent" {
			advertised = true
		}
	}
	if !advertised {
		return nil, fabric.NewError(fabric.CodeUnsupported, "Native agent binding is not advertised")
	}
	// Pin caller-owned bytes before asynchronous lifecycle admission/consumption.
	request.Input = append(json.RawMessage(nil), request.Input...)
	if request.Deadline != nil {
		deadline := *request.Deadline
		request.Deadline = &deadline
	}
	request.ExpectedRevision = binding.Revision
	lifetime, cancel := context.WithCancel(ctx)
	if request.Deadline != nil {
		var deadlineCancel context.CancelFunc
		lifetime, deadlineCancel = context.WithDeadline(lifetime, *request.Deadline)
		previous := cancel
		cancel = func() { deadlineCancel(); previous() }
	}
	if err := lifetime.Err(); err != nil {
		cancel()
		return nil, err
	}
	native, err := a.lifecycle.Begin(lifetime, caller, binding, request)
	if err != nil {
		cancel()
		return nil, err
	}
	if native == nil {
		cancel()
		return nil, fabric.NewError(fabric.CodeProtocolError, "Native lifecycle returned no admission")
	}
	receipt := native.Receipt()
	if !validReceipt(receipt) || receipt.Binding != binding || receipt.InvocationID != request.InvocationID {
		cancel()
		_ = native.Close()
		return nil, fabric.NewError(fabric.CodeProtocolError, "Native admission association changed")
	}
	stream := &invocationStream{native: native, receipt: receipt, lifetime: lifetime, cancel: cancel}
	checked, err := fabric.NewCheckedStream(lifetime, receipt.InvocationID, stream)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	return checked, nil
}

func validReceipt(r Receipt) bool {
	return r.InvocationID != "" && len(r.InvocationID) <= 256 && r.SourceCommandID != "" && r.SourceAdmissionID != "" && r.OwnershipGeneration != "" && r.DispatchSequence > 0
}

// No producer goroutine or unbounded in-memory stream buffer is introduced.
type invocationStream struct {
	native    NativeInvocation
	receipt   Receipt
	source    Source
	lifetime  context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	next      uint64
	terminal  bool
	closeOnce sync.Once
	closeErr  error
}

func (s *invocationStream) Close() error {
	s.cancel()
	s.closeOnce.Do(func() { s.closeErr = s.native.Close() })
	return s.closeErr
}
func (s *invocationStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal {
		return fabric.InvocationFrame{}, io.EOF
	}
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.lifetime, cancel)
	defer func() { stop(); cancel() }()
	if s.lifetime.Err() != nil {
		return fabric.InvocationFrame{}, s.lifetime.Err()
	}
	event, err := s.native.Next(call)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeProtocolError, "Native result ended without committed reply")
		}
		return fabric.InvocationFrame{}, err
	}
	if event.Source.Receipt != s.receipt || event.Source.OriginID == "" || event.Source.NativeGeneration == "" || event.Source.NativeSessionID == "" || event.Source.LogicalTurnID == "" {
		return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeProtocolError, "Native result source does not match admission")
	}
	if s.next == 0 {
		if event.Kind != EventStarted {
			return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeProtocolError, "Native result has no original start")
		}
		s.source = event.Source
	} else if event.Source != s.source {
		return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeProtocolError, "Native result realization changed")
	}
	if len(event.Data) > fabric.MaxFrameBytes {
		return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeProtocolError, "Native frame exceeds its bound")
	}
	if event.Error != nil {
		copy := *event.Error
		event.Error = &copy
	}
	frame := fabric.InvocationFrame{InvocationID: s.receipt.InvocationID, Sequence: s.next, ContentType: event.ContentType, Data: append([]byte(nil), event.Data...), Error: event.Error}
	switch event.Kind {
	case EventStarted:
		frame.Kind = fabric.FrameStart
	case EventAssistantContent:
		frame.Kind = fabric.FrameChunk
	case EventReplyCommitted:
		frame.Kind = fabric.FrameComplete
		s.terminal = true
	case EventFailed:
		frame.Kind = fabric.FrameError
		s.terminal = true
	default:
		return fabric.InvocationFrame{}, fabric.NewError(fabric.CodeProtocolError, "Unsupported native event")
	}
	s.next++
	return frame, nil
}

var _ fabric.EndpointAdapter = (*Adapter)(nil)
