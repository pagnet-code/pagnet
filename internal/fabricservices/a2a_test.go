package fabricservices

import (
	"bytes"
	"context"
	"encoding/json"
	"iter"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/a2a"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func drainService(t *testing.T, s fabric.InvocationStream) ([]byte, fabric.FrameKind) {
	t.Helper()
	defer s.Close()
	var raw bytes.Buffer
	for n := 0; n < 32; n++ {
		f, e := s.Next(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		raw.Write(f.Data)
		if f.Kind == fabric.FrameComplete || f.Kind == fabric.FrameError {
			return raw.Bytes(), f.Kind
		}
	}
	t.Fatal("fixture stream not finite")
	return nil, ""
}
func TestActualA2ASameRootAssociationOriginalFramesAndRestart(t *testing.T) {
	p, scope, owner, dir := serviceFixture(t)
	d, e := p.store.GetEndpoint(t.Context(), scope.Endpoint, scope.ExpectedEndpointRevision)
	if e != nil {
		t.Fatal(e)
	}
	previous := d.Revision
	d.Revision = ""
	d.Kind = "service.a2a"
	d.Bindings = []fabric.BindingSummary{{ID: "a2a", Protocol: "a2a.jsonrpc", Version: string(sdk.Version), Streaming: true, Cancellation: true}}
	rev, e := p.store.Update(t.Context(), owner, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: previous})
	if e != nil {
		t.Fatal(e)
	}
	scope.ExpectedEndpointRevision = rev
	scope.BindingID = "a2a"
	d.Revision = rev
	var effects atomic.Int32
	executor := a2asrv.AgentExecutorFunc(func(_ context.Context, c *a2asrv.ExecutorContext) iter.Seq2[sdk.Event, error] {
		return func(yield func(sdk.Event, error) bool) {
			effects.Add(1)
			task := sdk.NewSubmittedTask(c, c.Message)
			if !yield(task, nil) {
				return
			}
			if !yield(sdk.NewArtifactEvent(task, sdk.NewDataPart(map[string]any{"large": uint64(9007199254740993)})), nil) {
				return
			}
			yield(sdk.NewStatusUpdateEvent(task, sdk.TaskStateCompleted, nil), nil)
		}
	})
	server := httptest.NewServer(a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(executor)))
	defer server.Close()
	selected := sdk.NewAgentInterface(server.URL, sdk.TransportProtocolJSONRPC)
	private := Profile{Protocol: "a2a.jsonrpc", Version: string(sdk.Version), CredentialSelector: "private-a2a-provider-selector", BindingDigest: [32]byte{63}, A2A: &A2AProfile{Card: &sdk.AgentCard{Name: "explicit-installed-private-agent", Version: "1", Capabilities: sdk.AgentCapabilities{Streaming: true}, SupportedInterfaces: []*sdk.AgentInterface{selected}}, Interface: *selected, AllowHTTP: true, Cancellation: true, Limits: a2a.Limits{MaxEventBytes: 64 << 10, MaxRequestBytes: 64 << 10, MaxStreamBytes: 16 << 20, Lifetime: time.Minute}}}
	if _, e = p.Install(t.Context(), scope, private); e != nil {
		t.Fatal(e)
	}
	ledger := invocationFixture(t, p)
	credentials := &credentialsFixture{digest: private.BindingDigest}
	gate := func(_ context.Context, c fabric.ExecutionContext, d fabric.EndpointDescriptor, r fabric.InvokeRequest) error {
		if c.PrincipalView() != p.root.Owner || d.Ref != scope.Endpoint || r.Target != scope.Endpoint {
			return denied()
		}
		return nil
	}
	connections, e := NewA2AConnections(p, ledger, credentials, gate, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer connections.Close()
	if e = connections.Connect(t.Context(), scope); e != nil {
		t.Fatal(e)
	}
	if effects.Load() != 0 {
		t.Fatal("setup executed provider")
	}
	adapter, _, e := connections.Resolve(t.Context(), scope)
	if e != nil {
		t.Fatal(e)
	}
	request := fabric.InvokeRequest{InvocationID: "original-a2a-send", Target: scope.Endpoint, ExpectedRevision: scope.ExpectedEndpointRevision, Input: json.RawMessage(`{"operation":"send","mode":"stream","parts":[{"data":{"large":9007199254740993}}]}`)}
	invoke := func(ctx context.Context, c fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
		return adapter.Invoke(ctx, c, d, r)
	}
	stream, e := executeServiceFixture(t.Context(), p, request, invoke)
	if e != nil {
		t.Fatal(e)
	}
	raw, terminal := drainService(t, stream)
	if terminal != fabric.FrameComplete || !bytes.Contains(raw, []byte("9007199254740993")) || effects.Load() != 1 {
		t.Fatal("actual events/association missing", terminal, string(raw), effects.Load())
	}
	get := request
	get.InvocationID = "owned-task-get"
	get.Input = json.RawMessage(`{"operation":"get","associationInvocation":"original-a2a-send"}`)
	getStream, e := executeServiceFixture(t.Context(), p, get, invoke)
	if e != nil {
		t.Fatal("retained task association unavailable", e)
	}
	_, getEnd := drainService(t, getStream)
	if getEnd != fabric.FrameComplete || effects.Load() != 1 {
		t.Fatal("get lost owned task or launched new task")
	}
	replay, e := executeServiceFixture(t.Context(), p, request, invoke)
	if e != nil {
		t.Fatal(e)
	}
	again, terminal := drainService(t, replay)
	if terminal != fabric.FrameComplete || !bytes.Equal(raw, again) || effects.Load() != 1 {
		t.Fatal("A2A replay repeated external effect")
	}
	if e = connections.Close(); e != nil {
		t.Fatal(e)
	}
	if e = p.store.Close(); e != nil {
		t.Fatal(e)
	}
	root, e := registry.Open(t.Context(), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	p, e = NewProfileStore(t.Context(), root, p.owner, p.protector)
	if e != nil {
		t.Fatal(e)
	}
	ledger, e = OpenInvocations(t.Context(), p, DefaultInvocationConfig(), servicePolicyFixture{p.root.Owner})
	if e != nil {
		t.Fatal(e)
	}
	connections, e = NewA2AConnections(p, ledger, credentials, gate, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer connections.Close()
	if e = connections.Connect(t.Context(), scope); e != nil {
		t.Fatal(e)
	}
	adapter, _, e = connections.Resolve(t.Context(), scope)
	if e != nil {
		t.Fatal(e)
	}
	replay, e = executeServiceFixture(t.Context(), p, request, invoke)
	if e != nil {
		t.Fatal(e)
	}
	again, _ = drainService(t, replay)
	if !bytes.Equal(raw, again) || effects.Load() != 1 {
		t.Fatal("restart reexecuted original effect")
	}
	credentials.changed.Store(true)
	request.InvocationID = "second-a2a-send"
	if s, e := executeServiceFixture(t.Context(), p, request, invoke); e == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("changed provider account authorized")
	}
	if effects.Load() != 1 {
		t.Fatal("changed-account effect")
	}
}
