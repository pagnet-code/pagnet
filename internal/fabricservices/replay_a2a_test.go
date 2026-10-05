package fabricservices

import (
	"bytes"
	"context"
	"encoding/json"
	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/a2a"
	"github.com/pagnet-code/pagnet/fabric/node"
	"iter"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestActualA2ASignedCrossIDAliasDoesNotResend(t *testing.T) {
	p, scope, owner, _ := serviceFixture(t)
	d, e := p.store.GetEndpoint(t.Context(), scope.Endpoint, scope.ExpectedEndpointRevision)
	if e != nil {
		t.Fatal(e)
	}
	previous := d.Revision
	d.Revision = ""
	d.Kind = "service.a2a"
	d.Bindings = []fabric.BindingSummary{{ID: "a2a", Protocol: "a2a.jsonrpc", Version: string(sdk.Version), Streaming: true, Cancellation: true, Idempotency: true}}
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
	policy := &aliasPolicyFixture{servicePolicyFixture: servicePolicyFixture{p.root.Owner}}
	ledger, e := BootstrapInvocations(t.Context(), p, DefaultInvocationConfig(), policy)
	if e != nil {
		t.Fatal(e)
	}
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
	request := fabric.InvokeRequest{InvocationID: "original-a2a-send", Target: scope.Endpoint, ExpectedRevision: scope.ExpectedEndpointRevision, IdempotencyKey: "same-a2a-send", Input: json.RawMessage(`{"operation":"send","mode":"stream","parts":[{"data":{"large":9007199254740993}}]}`)}
	invoke := func(ctx context.Context, c fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
		return adapter.Invoke(ctx, c, d, r)
	}
	execute := func(r fabric.InvokeRequest) node.Result {
		service, e := node.New(node.Config{Audience: p.root.Namespace, Authenticator: serviceAuthFixture{p.root.Owner}, Dispatcher: serviceDispatcherFixture(invoke), ReplayVerifier: ledger})
		if e != nil {
			t.Fatal(e)
		}
		env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: r.InvocationID, Operation: fabric.OperationInvoke, Principal: p.root.Owner, Source: p.root.Owner.Ref, Target: &r.Target, ExpectedRevision: r.ExpectedRevision, CreatedAt: time.Unix(1000, 0).UTC(), Payload: r.Input, Context: fabric.EnvelopeContext{Origin: p.root.Owner.Ref, IdempotencyKey: r.IdempotencyKey}}
		raw, _ := json.Marshal(env)
		result, e := service.Execute(t.Context(), raw, nil)
		if e != nil {
			t.Fatal(e)
		}
		return result
	}
	original := aliasDrain(t, execute(request))
	request.InvocationID = "fresh-a2a-request"
	result := execute(request)
	if result.Replay == nil || result.Replay.ExecutionID != original[0].InvocationID {
		t.Fatal("actual alias association absent")
	}
	replay := aliasDrain(t, result)
	first, _ := json.Marshal(original)
	second, _ := json.Marshal(replay)
	if !bytes.Equal(first, second) || effects.Load() != 1 {
		t.Fatal("actual original A2A source changed or resent", effects.Load())
	}
}
