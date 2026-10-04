package mcpbridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
)

type fixtureFactory struct {
	key       ed25519.PrivateKey
	principal fabric.Principal
	calls     atomic.Int32
	last      Call
}

func (f *fixtureFactory) Build(_ context.Context, c Call) ([]byte, any, error) {
	f.calls.Add(1)
	f.last = c
	e := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "server-owned-call", Operation: c.Operation, Principal: f.principal, Source: f.principal.Ref, CreatedAt: time.Now().UTC(), Context: fabric.EnvelopeContext{Origin: f.principal.Ref}}
	switch c.Operation {
	case fabric.OperationDiscover:
		e.Payload, _ = json.Marshal(c.Discover)
	case fabric.OperationDescribe:
		e.Payload, _ = json.Marshal(c.Describe)
	case fabric.OperationInvoke:
		e.Target = &c.Invoke.Target
		e.ExpectedRevision = c.Invoke.ExpectedRevision
		e.Payload = bytes.Clone(c.Invoke.Input)
		e.Context.Deadline = c.Invoke.Deadline
		e.Context.IdempotencyKey = c.Invoke.IdempotencyKey
	}
	raw, _ := json.Marshal(e)
	return raw, ed25519.Sign(f.key, raw), nil
}

type fixtureAuth struct {
	public    ed25519.PublicKey
	principal fabric.Principal
}

func (a fixtureAuth) Authenticate(_ context.Context, r fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	sig, ok := r.PeerEvidence.([]byte)
	if !ok || !ed25519.Verify(a.public, r.ExactEnvelope, sig) {
		return fabric.ExecutionContext{}, errors.New("signature mismatch")
	}
	return fabric.NewAuthenticatedContext(a.principal, r.Audience, r.ExactEnvelope)
}

type fixtureBinder struct {
	factory *fixtureFactory
	key     string
	deny    bool
}

func (b *fixtureBinder) Bind(context.Context, *sdk.CallToolRequest) (BoundSession, error) {
	if b.deny {
		return BoundSession{}, errors.New("unbound requester")
	}
	return BoundSession{Key: b.key, Factory: b.factory}, nil
}

type fixtureDispatcher struct {
	calls  atomic.Int32
	last   fabric.InvokeRequest
	closed atomic.Int32
	block  bool
}

func (d *fixtureDispatcher) Invoke(_ context.Context, _ fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	d.calls.Add(1)
	d.last = r
	return &fixtureStream{id: r.InvocationID, closed: &d.closed, done: make(chan struct{}), block: d.block}, nil
}

type fixtureStream struct {
	id       string
	sequence uint64
	closed   *atomic.Int32
	once     sync.Once
	done     chan struct{}
	block    bool
}

func (s *fixtureStream) Next(ctx context.Context) (fabric.InvocationFrame, error) {
	f := fabric.InvocationFrame{InvocationID: s.id, Sequence: s.sequence}
	switch s.sequence {
	case 0:
		f.Kind = fabric.FrameStart
	case 1:
		if s.block {
			select {
			case <-s.done:
				return f, io.EOF
			case <-ctx.Done():
				return f, ctx.Err()
			}
		}
		f.Kind = fabric.FrameChunk
		f.Data = []byte(`{"n":9007199254740993123456789}`)
		f.ContentType = "application/json"
	case 2:
		f.Kind = fabric.FrameComplete
	default:
		return f, io.EOF
	}
	s.sequence++
	return f, nil
}
func (s *fixtureStream) Close() error {
	s.once.Do(func() { s.closed.Add(1); close(s.done) })
	return nil
}

type fixtureSearch struct{ calls atomic.Int32 }

func (s *fixtureSearch) Search(context.Context, fabric.DiscoverRequest) (fabric.DiscoverResult, error) {
	s.calls.Add(1)
	return fabric.DiscoverResult{Candidates: []fabric.Candidate{}, IndexRevision: "observed-1"}, nil
}
func newBridgeFixture(t *testing.T, version string) (*Bridge, *sdk.ClientSession, *fixtureBinder, *fixtureDispatcher, *fixtureSearch, fabric.EndpointRef) {
	t.Helper()
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	endpoint, _ := fabric.NewEndpointRef(public)
	offer, _ := endpoint.WithOfferID(bytes.Repeat([]byte{3}, 32))
	principal := fabric.Principal{Ref: "trusted-human", Issuer: "private-fixture", Kind: "pagnet.human"}
	factory := &fixtureFactory{key: key, principal: principal}
	binder := &fixtureBinder{factory: factory, key: "authenticated-principal-and-session"}
	dispatcher := &fixtureDispatcher{}
	search := &fixtureSearch{}
	service, err := node.New(node.Config{Audience: "fixture-node", Authenticator: fixtureAuth{public, principal}, Search: search, Dispatcher: dispatcher})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(t.Context(), Config{Service: service, BindSession: binder, ProtocolVersions: []string{version}})
	if err != nil {
		t.Fatal(err)
	}
	clientTransport, serverTransport := sdk.NewInMemoryTransports()
	ss, err := b.Server().Connect(t.Context(), serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Default client middleware remains ON to prove ordinary DEFER/flow-control
	// replies cannot accidentally ask the SDK to invoke a destructive handler again.
	client := sdk.NewClient(&sdk.Implementation{Name: "real-sdk-browser-fixture", Version: "1"}, nil)
	cs, err := client.Connect(t.Context(), clientTransport, &sdk.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Close(); _ = b.Close() })
	return b, cs, binder, dispatcher, search, offer
}
func callBridge(t *testing.T, c *sdk.ClientSession, name string, args any) *sdk.CallToolResult {
	t.Helper()
	r, err := c.CallTool(t.Context(), &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func pageResult(t *testing.T, r *sdk.CallToolResult) Page {
	t.Helper()
	if r.IsError {
		t.Fatalf("unexpected tool failure: %#v", r.Content)
	}
	text := r.Content[0].(*sdk.TextContent)
	var p Page
	if err := fabric.DecodeJSON([]byte(text.Text), &p); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestOfficialBridgeThreeToolsTrustedRoutingAndExactStreamRetry(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			_, client, binder, dispatch, search, offer := newBridgeFixture(t, version)
			tools, err := client.ListTools(t.Context(), nil)
			if err != nil || len(tools.Tools) != 3 {
				t.Fatal("bridge must expose exactly three tools", err)
			}
			r := callBridge(t, client, "discover", map[string]any{"query": "compute", "scope": map[string]any{}, "limit": 1})
			if r.IsError || dispatch.calls.Load() != 0 || search.calls.Load() != 1 {
				t.Fatal("discovery executed target")
			}
			poisoned := map[string]any{"target": offer.String(), "input": map[string]any{}, "principal": "administrator"}
			if !callBridge(t, client, "invoke", poisoned).IsError || dispatch.calls.Load() != 0 {
				t.Fatal("untrusted identity accepted")
			}
			p := pageResult(t, callBridge(t, client, "invoke", json.RawMessage(`{"target":"`+offer.String()+`","revision":"remembered","input":{"target":"malicious-inner-target","n":9007199254740993123456789}}`)))
			if p.Frames[0].Kind != fabric.FrameStart || !p.More || dispatch.calls.Load() != 1 || dispatch.last.Target != offer || dispatch.last.ExpectedRevision != "remembered" || !bytes.Contains(dispatch.last.Input, []byte("9007199254740993123456789")) {
				t.Fatal("trusted factory routing/payload changed")
			}
			control := map[string]any{"stream": map[string]any{"handle": p.Handle, "afterSequence": "0"}}
			next := pageResult(t, callBridge(t, client, "invoke", control))
			repeat := pageResult(t, callBridge(t, client, "invoke", control))
			a, _ := json.Marshal(next)
			z, _ := json.Marshal(repeat)
			if !bytes.Equal(a, z) || dispatch.calls.Load() != 1 || binder.factory.calls.Load() != 2 {
				t.Fatal("cursor retry repeated admission or changed immutable frame")
			}
			if string(next.Frames[0].Data) != `{"n":9007199254740993123456789}` {
				t.Fatal("stream JSON number changed")
			}
			final := pageResult(t, callBridge(t, client, "invoke", map[string]any{"stream": map[string]any{"handle": p.Handle, "afterSequence": "1"}}))
			if final.More || final.Frames[0].Kind != fabric.FrameComplete {
				t.Fatal("missing genuine terminal")
			}
			if !callBridge(t, client, "invoke", map[string]any{"target": offer.String(), "input": map[string]any{}, "stream": map[string]any{"handle": p.Handle, "afterSequence": "0"}}).IsError {
				t.Fatal("flow control selected a new target")
			}
		})
	}
}
func TestOfficialBridgeSessionBoundCancellationAndCapacityBeforeEffects(t *testing.T) {
	b, c, binder, d, _, offer := newBridgeFixture(t, "2025-11-25")
	d.block = true
	p := pageResult(t, callBridge(t, c, "invoke", map[string]any{"target": offer.String(), "input": map[string]any{}}))
	binder.key = "foreign-authenticated-session"
	if !callBridge(t, c, "invoke", map[string]any{"stream": map[string]any{"handle": p.Handle, "afterSequence": "0", "cancel": true}}).IsError {
		t.Fatal("foreign session canceled admitted stream")
	}
	if d.closed.Load() != 0 {
		t.Fatal("unauthorized control changed native stream")
	}
	binder.key = "authenticated-principal-and-session"
	cancelled := pageResult(t, callBridge(t, c, "invoke", map[string]any{"stream": map[string]any{"handle": p.Handle, "afterSequence": "0", "cancel": true}}))
	if len(cancelled.Frames) != 0 || cancelled.More || d.calls.Load() != 1 {
		t.Fatal("cancel fabricated terminal/admission")
	}
	if d.closed.Load() == 0 {
		t.Fatal("cancel did not close original stream")
	}
	b.config.Limits.MaxStreams = 1
	pageResult(t, callBridge(t, c, "invoke", map[string]any{"target": offer.String(), "input": map[string]any{}}))
	if !callBridge(t, c, "invoke", map[string]any{"target": offer.String(), "input": map[string]any{}}).IsError || d.calls.Load() != 2 {
		t.Fatal("capacity failed after destructive target dispatch")
	}
	b.CloseSession(binder.key)
	if len(b.streams) != 0 {
		t.Fatal("session close retained stream handles")
	}
}

func TestOfficialBridgeExpiryAuthenticationAndUnknownEOFDoNotInventCompletion(t *testing.T) {
	b, c, binder, d, _, offer := newBridgeFixture(t, "2026-07-28")
	binder.deny = true
	if !callBridge(t, c, "invoke", map[string]any{"target": offer.String(), "input": map[string]any{}}).IsError || d.calls.Load() != 0 {
		t.Fatal("unauthenticated tool invoked target")
	}
	binder.deny = false
	p := pageResult(t, callBridge(t, c, "invoke", map[string]any{"target": offer.String(), "input": map[string]any{}}))
	b.expire(time.Now().Add(time.Hour))
	if !callBridge(t, c, "invoke", map[string]any{"stream": map[string]any{"handle": p.Handle, "afterSequence": "0"}}).IsError {
		t.Fatal("expired handle restarted original invocation")
	}
	b.mu.Lock()
	remaining, retained := len(b.streams), b.bytes
	b.mu.Unlock()
	if remaining != 0 || retained != 0 || d.calls.Load() != 1 {
		t.Fatal("expiry leaked capacity or replayed target")
	}
	if !callBridge(t, c, "invoke", map[string]any{"input": map[string]any{}}).IsError || d.calls.Load() != 1 {
		t.Fatal("missing target inferred from input")
	}
}

type deferredExecutor struct{ calls atomic.Int32 }

func (e *deferredExecutor) Execute(context.Context, []byte, any) (node.Result, error) {
	e.calls.Add(1)
	return node.Result{DeferredID: "durably-committed-control", DeferredNotificationError: fabric.NewError(fabric.CodeTargetUnavailable, "Committed control notification unavailable")}, nil
}
func TestOfficialBridgeDeferredControlNeverTriggersSDKInputReplay(t *testing.T) {
	b, c, binder, _, _, offer := newBridgeFixture(t, "2026-07-28")
	executor := &deferredExecutor{}
	b.config.Service = executor
	result := callBridge(t, c, "invoke", map[string]any{"target": offer.String(), "input": map[string]any{}})
	if result.IsError || result.NeedsInput() || executor.calls.Load() != 1 || binder.factory.calls.Load() != 1 {
		t.Fatal("committed DEFER was turned into SDK retry")
	}
	var value struct {
		DeferredID        string        `json:"deferredId"`
		NotificationError *fabric.Error `json:"notificationError"`
	}
	if err := fabric.DecodeJSON([]byte(result.Content[0].(*sdk.TextContent).Text), &value); err != nil || value.DeferredID != "durably-committed-control" || value.NotificationError == nil {
		t.Fatal("committed control hidden by notification failure", err)
	}
}

// Simulate an admitted result racing session shutdown. Even an executor that
// returns its already-admitted stream after cancellation cannot leak a handle.
type heldExecutor struct {
	entered  chan struct{}
	canceled chan struct{}
	closed   atomic.Int32
	calls    atomic.Int32
}

func (e *heldExecutor) Execute(ctx context.Context, _ []byte, _ any) (node.Result, error) {
	e.calls.Add(1)
	close(e.entered)
	<-ctx.Done()
	close(e.canceled)
	return node.Result{Stream: &fixtureStream{id: "original-admitted-operation", closed: &e.closed, done: make(chan struct{})}}, nil
}
func TestOfficialSessionCloseFencesAdmissionBeforeHandlePublication(t *testing.T) {
	b, client, binder, _, _, target := newBridgeFixture(t, "2026-07-28")
	executor := &heldExecutor{entered: make(chan struct{}), canceled: make(chan struct{})}
	b.config.Service = executor
	finished := make(chan *sdk.CallToolResult, 1)
	failed := make(chan error, 1)
	go func() {
		r, err := client.CallTool(t.Context(), &sdk.CallToolParams{Name: "invoke", Arguments: map[string]any{"target": target.String(), "input": map[string]any{}}})
		if err != nil {
			failed <- err
			return
		}
		finished <- r
	}()
	select {
	case <-executor.entered:
	case <-time.After(time.Second):
		t.Fatal("admission did not begin")
	}
	b.CloseSession(binder.key)
	select {
	case err := <-failed:
		t.Fatal(err)
	case r := <-finished:
		if !r.IsError {
			t.Fatal("closed session received a new stream handle")
		}
	case <-time.After(time.Second):
		t.Fatal("session close stranded admission")
	}
	if executor.calls.Load() != 1 || executor.closed.Load() != 1 {
		t.Fatal("admission replayed or original stream leaked")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.streams) != 0 || len(b.pending) != 0 || b.reserved != 0 || b.bytes != 0 {
		t.Fatal("closed session retained admission resources")
	}
}

func TestToolErrorClampsCopiesAndValidatesPublicFields(t *testing.T) {
	original := &fabric.Error{Code: fabric.ErrorCode(string(bytes.Repeat([]byte("x"), 300))), Message: string(bytes.Repeat([]byte("m"), 4096)), Effect: "invented-success"}
	r := toolError(original)
	var body struct {
		Error *fabric.Error `json:"error"`
	}
	if err := json.Unmarshal([]byte(r.Content[0].(*sdk.TextContent).Text), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != fabric.CodeProtocolError || len(body.Error.Message) > 1024 || body.Error.Effect != fabric.EffectUnknown || len(original.Message) != 4096 || original.Effect != "invented-success" {
		t.Fatal("unbounded error or provider error mutated")
	}
	for _, effect := range []fabric.EffectState{fabric.EffectUnknown, fabric.EffectNotStarted, fabric.EffectCompleted} {
		r = toolError(&fabric.Error{Code: "provider.known_error", Message: "bounded", Effect: effect})
		if err := json.Unmarshal([]byte(r.Content[0].(*sdk.TextContent).Text), &body); err != nil || body.Error.Effect != effect {
			t.Fatal("valid effect evidence discarded")
		}
	}
}
