package fabricagent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

// These are adapter-port conformance tests, not proof of native admission or
// offline execution. Real daemon composition must pass original worker gates.
type bindingFixture struct {
	binding Binding
	reads   int
}

func (b *bindingFixture) Resolve(_ context.Context, _ fabric.EndpointRef, _ fabric.Revision) (Binding, error) {
	b.reads++
	return b.binding, nil
}

type lifecycleFixture struct {
	native  *nativeFixture
	calls   int
	request fabric.InvokeRequest
}

func (l *lifecycleFixture) Begin(_ context.Context, _ fabric.ExecutionContext, _ Binding, r fabric.InvokeRequest) (NativeInvocation, error) {
	l.calls++
	l.request = r
	return l.native, nil
}

type nativeFixture struct {
	receipt Receipt
	events  []Event
	block   bool
	closed  chan struct{}
	once    sync.Once
}

func (n *nativeFixture) Receipt() Receipt { return n.receipt }
func (n *nativeFixture) Next(ctx context.Context) (Event, error) {
	if n.block {
		select {
		case <-ctx.Done():
			return Event{}, ctx.Err()
		case <-n.closed:
			return Event{}, context.Canceled
		}
	}
	if len(n.events) == 0 {
		return Event{}, io.EOF
	}
	e := n.events[0]
	n.events = n.events[1:]
	return e, nil
}
func (n *nativeFixture) Close() error { n.once.Do(func() { close(n.closed) }); return nil }
func adapterFixture(t *testing.T) (*Adapter, *bindingFixture, *lifecycleFixture, fabric.ExecutionContext, fabric.EndpointDescriptor, fabric.InvokeRequest, Source) {
	t.Helper()
	ref, err := fabric.NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{Ref: ref, Revision: "rev1", DefinitionID: "definition", InstanceID: "instance", BindingID: "native"}
	receipt := Receipt{InvocationID: "invocation", Binding: binding, SourceCommandID: "original-command", SourceAdmissionID: "original-admission", OwnershipGeneration: "owner", DispatchSequence: 4}
	source := Source{Receipt: receipt, OriginID: "origin", NativeGeneration: "generation", NativeSessionID: "conversation", LogicalTurnID: "turn4"}
	native := &nativeFixture{receipt: receipt, closed: make(chan struct{}), events: []Event{{Kind: EventStarted, Source: source}, {Kind: EventAssistantContent, Source: source, ContentType: "text/plain", Data: []byte("answer")}, {Kind: EventReplyCommitted, Source: source}}}
	b := &bindingFixture{binding: binding}
	l := &lifecycleFixture{native: native}
	adapter, err := New(b, l)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := fabric.NewAuthenticatedContext(fabric.Principal{Ref: "caller", Kind: "test.caller", Issuer: "fixture"}, "node", []byte("authenticated-fixture"))
	if err != nil {
		t.Fatal(err)
	}
	d := fabric.EndpointDescriptor{Ref: ref, Revision: "rev1", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "pagnet.native-agent", Streaming: true}}}
	r := fabric.InvokeRequest{InvocationID: "invocation", Target: ref, ExpectedRevision: "rev1", Input: json.RawMessage(`{"text":"ask"}`)}
	return adapter, b, l, caller, d, r, source
}
func TestExactAdmissionSourceAndCommittedReply(t *testing.T) {
	a, b, l, caller, d, r, _ := adapterFixture(t)
	stream, err := a.Invoke(context.Background(), caller, d, r)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if b.reads != 1 || l.calls != 1 {
		t.Fatal("admission repeated")
	}
	r.Input[2] = 'X'
	if string(l.request.Input) != `{"text":"ask"}` {
		t.Fatal("borrowed request changed after admission")
	}
	for i, kind := range []fabric.FrameKind{fabric.FrameStart, fabric.FrameChunk, fabric.FrameComplete} {
		f, err := stream.Next(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if f.Kind != kind || f.Sequence != uint64(i) || f.InvocationID != "invocation" {
			t.Fatalf("bad frame: %#v", f)
		}
	}
	if _, err := stream.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatal("no terminal EOF", err)
	}
}
func TestStaleNativeReferenceNeverBegins(t *testing.T) {
	for _, change := range []func(*bindingFixture, *fabric.EndpointDescriptor, *fabric.InvokeRequest){
		func(_ *bindingFixture, _ *fabric.EndpointDescriptor, r *fabric.InvokeRequest) {
			r.ExpectedRevision = "old"
		},
		func(b *bindingFixture, _ *fabric.EndpointDescriptor, _ *fabric.InvokeRequest) {
			b.binding.Revision = "changed"
		},
		func(_ *bindingFixture, d *fabric.EndpointDescriptor, _ *fabric.InvokeRequest) { d.Bindings = nil },
	} {
		a, b, l, c, d, r, _ := adapterFixture(t)
		change(b, &d, &r)
		if _, err := a.Invoke(context.Background(), c, d, r); err == nil {
			t.Fatal("stale binding accepted")
		}
		if l.calls != 0 {
			t.Fatal("stale resolution launched native lifecycle")
		}
	}
}
func TestNativeSourceDriftOrUncommittedEOFNeverCompletes(t *testing.T) {
	for _, change := range []func(*nativeFixture){
		func(n *nativeFixture) { n.events[1].Source.Receipt.SourceAdmissionID = "foreign" },
		func(n *nativeFixture) { n.events[1].Source.NativeSessionID = "different-conversation" },
		func(n *nativeFixture) { n.events = n.events[:2] },
		func(n *nativeFixture) { n.events[1].Data = make([]byte, fabric.MaxFrameBytes+1) },
	} {
		a, _, l, c, d, r, _ := adapterFixture(t)
		change(l.native)
		s, err := a.Invoke(context.Background(), c, d, r)
		if err != nil {
			t.Fatal(err)
		}
		for {
			f, err := s.Next(context.Background())
			if err != nil {
				if errors.Is(err, io.EOF) {
					t.Fatal("premature EOF treated as normal result")
				}
				break
			}
			if f.Kind == fabric.FrameComplete {
				t.Fatal("unproven result completed")
			}
		}
		select {
		case <-l.native.closed:
		default:
			t.Fatal("invalid source retained consumer")
		}
	}
}
func TestNativeCloseCancelsBlockedConsumption(t *testing.T) {
	a, _, l, c, d, r, _ := adapterFixture(t)
	l.native.block = true
	s, err := a.Invoke(context.Background(), c, d, r)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := s.Next(context.Background()); done <- err }()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancel returned a frame")
		}
	case <-time.After(time.Second):
		t.Fatal("close stranded blocked consumer")
	}
}

func TestNativeReceiptCannotSubstituteProtectedInvocation(t *testing.T) {
	a, _, l, c, d, r, _ := adapterFixture(t)
	l.native.receipt.InvocationID = "another-invocation"
	if _, err := a.Invoke(context.Background(), c, d, r); err == nil {
		t.Fatal("protected invocation identity replaced")
	}
	select {
	case <-l.native.closed:
	default:
		t.Fatal("foreign receipt consumer retained")
	}
}
func TestExpiredInvocationCannotBeginNativeEffects(t *testing.T) {
	a, _, l, c, d, r, _ := adapterFixture(t)
	deadline := time.Now().Add(-time.Second)
	r.Deadline = &deadline
	if _, err := a.Invoke(context.Background(), c, d, r); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wrong deadline result: %v", err)
	}
	if l.calls != 0 {
		t.Fatal("expired invocation entered native admission")
	}
}
