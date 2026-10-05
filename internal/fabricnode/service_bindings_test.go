package fabricnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	a2asdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/pagnet-code/pagnet/fabric/adapters/a2a"
	"github.com/pagnet-code/pagnet/fabric/node"
	"iter"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

type serviceRouterCredentials struct{ digest [32]byte }

func (c serviceRouterCredentials) Resolve(context.Context, string) (fabricservices.Credentials, error) {
	return fabricservices.Credentials{BindingDigest: c.digest}, nil
}

type serviceRouterPolicy struct{ owner fabric.Principal }

func (p serviceRouterPolicy) AuthorizeTx(_ context.Context, _ *registry.AuthorityTx, c fabric.ExecutionContext, f fabricservices.InvocationFacts, _ string) error {
	if c.PrincipalView() != p.owner || f.Principal != p.owner {
		return fabric.NewError(fabric.CodeUnauthenticated, "fixture caller denied")
	}
	return nil
}
func TestActualRouterUsesOnceInstalledMCPAndNoResolveEffects(t *testing.T) {
	principal := fabric.Principal{Ref: "router.operator", Kind: "local.owner", Issuer: "fixture.root"}
	store, e := registry.Bootstrap(t.Context(), filepath.Join(t.TempDir(), "root"), principal)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	owner, e := fabric.NewAuthenticatedContext(principal, store.Namespace(), []byte("explicit fixture trusted owner"))
	if e != nil {
		t.Fatal(e)
	}
	ref, _ := fabric.NewEndpointRef(store.AuthorityIdentity().PublicKey)
	descriptor := fabric.EndpointDescriptor{Ref: ref, Kind: "service.mcp", Name: "Shared installed service", Description: "Tool service", Bindings: []fabric.BindingSummary{{ID: "mcp", Protocol: "mcp.tools", Version: "2026-07-28", Cancellation: true}}}
	rev, e := store.Register(t.Context(), owner, fabric.RegistryUpdate{Descriptor: descriptor})
	if e != nil {
		t.Fatal(e)
	}
	descriptor.Revision = rev
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: rev, BindingID: "mcp"}
	key, _ := durable.NewAESGCM(durable.KeyReference{ID: "router-owned-key", Version: "1"}, bytes.Repeat([]byte{38}, 32))
	profiles, e := fabricservices.NewProfileStore(t.Context(), store, func(context.Context) (fabric.ExecutionContext, error) { return owner, nil }, key)
	if e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int32
	official := sdk.NewServer(&sdk.Implementation{Name: "router-official", Version: "1"}, nil)
	official.AddTool(&sdk.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		calls.Add(1)
		return &sdk.CallToolResult{Content: []sdk.Content{}}, nil
	})
	server := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return official }, &sdk.StreamableHTTPOptions{Stateless: true}))
	defer server.Close()
	digest := sha256.Sum256([]byte("explicit selected provider account"))
	profile := fabricservices.Profile{Protocol: "mcp.tools", Version: "2026-07-28", CredentialSelector: "private installed provider", BindingDigest: digest, MCP: &fabricservices.MCPProfile{URL: server.URL, AllowHTTP: true, Limits: mcp.DefaultLimits}}
	if _, e = profiles.Install(t.Context(), scope, profile); e != nil {
		t.Fatal(e)
	}
	ledger, e := fabricservices.BootstrapInvocations(t.Context(), profiles, fabricservices.DefaultInvocationConfig(), serviceRouterPolicy{principal})
	if e != nil {
		t.Fatal(e)
	}
	connections, e := fabricservices.NewConnections(profiles, serviceRouterCredentials{digest}, ledger, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer connections.Close()
	provider, e := NewServiceBindingProvider(connections)
	if e != nil {
		t.Fatal(e)
	}
	router, e := NewRouter(map[BindingProtocol]BindingProvider{{"mcp.tools", "2026-07-28"}: provider})
	if e != nil {
		t.Fatal(e)
	}
	if e = connections.ConnectMCP(t.Context(), scope, true); e != nil {
		t.Fatal(e)
	}
	offers, _, e := store.ListOffers(t.Context(), ref, rev, "", 2)
	if e != nil || len(offers) != 1 {
		t.Fatal(e)
	}
	offer, e := store.GetOffer(t.Context(), offers[0].Ref, offers[0].Revision)
	if e != nil {
		t.Fatal(e)
	}
	selected, e := router.Select(t.Context(), owner, descriptor, &offer)
	if e != nil || selected.Adapter == nil || selected.Fingerprint == ([32]byte{}) || selected.BindingID != "mcp" || calls.Load() != 0 {
		t.Fatal("explicit selected SDK adapter unavailable or discovery executed effect", e)
	}
	if _, e = router.Select(t.Context(), owner, descriptor, nil); e == nil {
		t.Fatal("MCP endpoint target silently picked a tool")
	}
	if _, e = router.Select(t.Context(), fabric.ExecutionContext{}, descriptor, &offer); e == nil {
		t.Fatal("unauthenticated routing allowed")
	}
	foreign := offer
	foreign.BindingID = "not-installed"
	if _, e = router.Select(t.Context(), owner, descriptor, &foreign); e == nil {
		t.Fatal("foreign binding selected")
	}
	previous := descriptor.Revision
	descriptor.Revision = ""
	descriptor.Name = "Renewed service"
	if _, e = store.Update(t.Context(), owner, fabric.RegistryUpdate{Descriptor: descriptor, ExpectedRevision: previous}); e != nil {
		t.Fatal(e)
	}
	descriptor.Revision = previous
	if _, e = router.Select(t.Context(), owner, descriptor, &offer); e == nil {
		t.Fatal("stale descriptor exposed original connection")
	}
	if calls.Load() != 0 {
		t.Fatal("resolve/update invoked service")
	}
}

type serviceNodeAuthenticator struct{ owner fabric.Principal }

func (a serviceNodeAuthenticator) Authenticate(_ context.Context, r fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	var e fabric.Envelope
	if fabric.DecodeJSON(r.ExactEnvelope, &e) != nil || e.Principal != a.owner {
		return fabric.ExecutionContext{}, fabric.NewError(fabric.CodeUnauthenticated, "fixture caller denied")
	}
	return fabric.NewAuthenticatedContext(a.owner, r.Audience, r.ExactEnvelope)
}

type serviceNodeDirectDispatcher struct {
	router     *Router
	descriptor fabric.EndpointDescriptor
}

func (d serviceNodeDirectDispatcher) Invoke(ctx context.Context, c fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	selected, e := d.router.Select(ctx, c, d.descriptor, nil)
	if e != nil {
		return nil, e
	}
	return selected.Adapter.Invoke(ctx, c, d.descriptor, r)
}
func TestActualNamespacedA2ARouterDirectNodeInvocation(t *testing.T) {
	ownerPrincipal := fabric.Principal{Ref: "a2a-router.operator", Kind: "local.owner", Issuer: "fixture.root"}
	store, e := registry.Bootstrap(t.Context(), filepath.Join(t.TempDir(), "root"), ownerPrincipal)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	owner, _ := fabric.NewAuthenticatedContext(ownerPrincipal, store.Namespace(), []byte("explicit fixture owner"))
	ref, _ := fabric.NewEndpointRef(store.AuthorityIdentity().PublicKey)
	var effects atomic.Int32
	executor := a2asrv.AgentExecutorFunc(func(_ context.Context, c *a2asrv.ExecutorContext) iter.Seq2[a2asdk.Event, error] {
		return func(yield func(a2asdk.Event, error) bool) {
			effects.Add(1)
			task := a2asdk.NewSubmittedTask(c, c.Message)
			if !yield(task, nil) {
				return
			}
			yield(a2asdk.NewStatusUpdateEvent(task, a2asdk.TaskStateCompleted, nil), nil)
		}
	})
	server := httptest.NewServer(a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(executor)))
	defer server.Close()
	selected := a2asdk.NewAgentInterface(server.URL, a2asdk.TransportProtocolJSONRPC)
	descriptor := fabric.EndpointDescriptor{Ref: ref, Kind: "service.a2a", Name: "Installed exact A2A", Description: "Explicit SDK fixture", Bindings: []fabric.BindingSummary{{ID: "a2a", Protocol: "a2a.jsonrpc", Version: string(a2asdk.Version), Cancellation: true}}}
	rev, e := store.Register(t.Context(), owner, fabric.RegistryUpdate{Descriptor: descriptor})
	if e != nil {
		t.Fatal(e)
	}
	descriptor.Revision = rev
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: rev, BindingID: "a2a"}
	key, _ := durable.NewAESGCM(durable.KeyReference{ID: "a2a-router-key", Version: "1"}, bytes.Repeat([]byte{49}, 32))
	profiles, e := fabricservices.NewProfileStore(t.Context(), store, func(context.Context) (fabric.ExecutionContext, error) { return owner, nil }, key)
	if e != nil {
		t.Fatal(e)
	}
	digest := [32]byte{74}
	profile := fabricservices.Profile{Protocol: "a2a.jsonrpc", Version: string(a2asdk.Version), CredentialSelector: "private selected A2A", BindingDigest: digest, A2A: &fabricservices.A2AProfile{Card: &a2asdk.AgentCard{Name: "fixture", Version: "1", SupportedInterfaces: []*a2asdk.AgentInterface{selected}}, Interface: *selected, AllowHTTP: true, Cancellation: true, Limits: a2a.Limits{MaxEventBytes: 64 << 10, MaxRequestBytes: 64 << 10, MaxStreamBytes: 16 << 20, Lifetime: time.Minute}}}
	if _, e = profiles.Install(t.Context(), scope, profile); e != nil {
		t.Fatal(e)
	}
	ledger, e := fabricservices.BootstrapInvocations(t.Context(), profiles, fabricservices.DefaultInvocationConfig(), serviceRouterPolicy{ownerPrincipal})
	if e != nil {
		t.Fatal(e)
	}
	gate := func(_ context.Context, c fabric.ExecutionContext, d fabric.EndpointDescriptor, _ fabric.InvokeRequest) error {
		if c.PrincipalView() != ownerPrincipal || d.Ref != ref {
			return fabric.NewError(fabric.CodeUnauthenticated, "fixture disclosure denied")
		}
		return nil
	}
	connections, e := fabricservices.NewA2AConnections(profiles, ledger, serviceRouterCredentials{digest}, gate, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer connections.Close()
	if e = connections.Connect(t.Context(), scope); e != nil {
		t.Fatal(e)
	}
	provider, e := NewA2AServiceBindingProvider(connections)
	if e != nil {
		t.Fatal(e)
	}
	router, e := NewRouter(map[BindingProtocol]BindingProvider{{"a2a.jsonrpc", string(a2asdk.Version)}: provider})
	if e != nil {
		t.Fatal(e)
	}
	n, e := node.New(node.Config{Audience: store.Namespace(), Authenticator: serviceNodeAuthenticator{ownerPrincipal}, Dispatcher: serviceNodeDirectDispatcher{router, descriptor}})
	if e != nil {
		t.Fatal(e)
	}
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "actual-router-first", Operation: fabric.OperationInvoke, Principal: ownerPrincipal, Source: ownerPrincipal.Ref, Target: &ref, ExpectedRevision: rev, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"operation":"send","mode":"unary","parts":[{"text":"explicit original"}]}`), Context: fabric.EnvelopeContext{Origin: ownerPrincipal.Ref}}
	raw, _ := json.Marshal(env)
	for range 2 {
		out, e := n.Execute(t.Context(), raw, nil)
		if e != nil {
			t.Fatal(e)
		}
		terminal := fabric.FrameKind("")
		for range 16 {
			f, e := out.Stream.Next(t.Context())
			if e != nil {
				t.Fatal(e)
			}
			if f.Kind == fabric.FrameComplete || f.Kind == fabric.FrameError {
				terminal = f.Kind
				break
			}
		}
		out.Stream.Close()
		if terminal != fabric.FrameComplete {
			t.Fatal("real canonical A2A route failed", terminal)
		}
	}
	if effects.Load() != 1 {
		t.Fatal("direct Router replay repeated SDK effect", effects.Load())
	}
}
