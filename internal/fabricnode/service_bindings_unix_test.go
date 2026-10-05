//go:build linux || darwin

package fabricnode

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	adaptera2a "github.com/pagnet-code/pagnet/fabric/adapters/a2a"
	"iter"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

func TestKernelOwnerBoundaryActualSharedMCPService(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	private, err := os.MkdirTemp("", "pgn-service-boundary-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(private)
	dir, socket := filepath.Join(private, "domain"), filepath.Join(private, "fabric.sock")
	installed, err := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if err != nil {
		t.Fatal(err)
	}
	defer installed.Close()
	owner, err := installed.Operator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewLocalRuntime(ctx, installed.Store, LocalRuntimeConfig{Operator: installed, Native: NativeRuntimeConfig{Owner: owner, Protector: installed.Keys, Credentials: func(context.Context, []string) ([]string, error) { return nil, nil }, CleanupCaller: installed.Operator, Binary: executable, AuthorityDirectory: dir, SocketPath: socket, ControllerBootID: "service-boundary", MaxWorkers: 1, MaxStartupMetadataBytes: 1 << 20, StartupTimeout: 5 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	ref, _ := fabric.NewEndpointRef(installed.Store.AuthorityIdentity().PublicKey)
	revision, err := installed.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "service.mcp", Name: "Installed shared service", Bindings: []fabric.BindingSummary{{ID: "mcp", Protocol: "mcp.tools", Version: "2026-07-28", Cancellation: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "mcp"}
	var effects atomic.Int32
	official := sdk.NewServer(&sdk.Implementation{Name: "genuine-service", Version: "1"}, nil)
	official.AddTool(&sdk.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object","properties":{"number":{"type":"integer"}},"required":["number"]}`)}, func(_ context.Context, r *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		effects.Add(1)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: string(r.Params.Arguments)}}}, nil
	})
	server := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return official }, &sdk.StreamableHTTPOptions{Stateless: true}))
	defer server.Close()
	profiles, err := fabricservices.NewProfileStore(ctx, installed.Store, installed.Operator, installed.Keys)
	if err != nil {
		t.Fatal(err)
	}
	digest := [32]byte{91}
	_, err = profiles.Install(ctx, scope, fabricservices.Profile{Protocol: "mcp.tools", Version: "2026-07-28", CredentialSelector: "operator-selected private account", BindingDigest: digest, MCP: &fabricservices.MCPProfile{URL: server.URL, AllowHTTP: true, Limits: mcp.DefaultLimits}})
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := fabricservices.BootstrapInvocations(ctx, profiles, fabricservices.DefaultInvocationConfig(), runtime.Boundary)
	if err != nil {
		t.Fatal(err)
	}
	connections, err := fabricservices.NewConnections(profiles, serviceRouterCredentials{digest}, ledger, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer connections.Close()
	if err = connections.ConnectMCP(ctx, scope, true); err != nil {
		t.Fatal(err)
	}
	provider, err := NewServiceBindingProvider(connections)
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(map[BindingProtocol]BindingProvider{{Protocol: "mcp.tools", Version: "2026-07-28"}: provider})
	if err != nil {
		t.Fatal(err)
	}
	n, err := ComposeRetained(ctx, installed.Store, func(context.Context, *registry.Store, *search.Backend) (Ports, error) {
		p := runtime.Ports()
		p.Bindings = router
		return p, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	offers, _, err := installed.Store.ListOffers(ctx, ref, revision, "", 2)
	if err != nil || len(offers) != 1 {
		t.Fatal("actual shared catalog", err, len(offers))
	}
	factory, closeSession := runtimeOwnerSession(t, ctx, runtime.NativeRuntime, socket)
	defer closeSession()
	raw, proof, err := factory.Build(ctx, mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: offers[0].Ref, ExpectedRevision: offers[0].Revision, Input: json.RawMessage(`{"number":9007199254740993}`)}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := n.Service.Execute(ctx, raw, proof)
	if err != nil {
		t.Fatal(err)
	}
	var complete bool
	for !complete {
		frame, e := result.Stream.Next(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if frame.Kind == fabric.FrameError {
			t.Fatal(frame.Error)
		}
		complete = frame.Kind == fabric.FrameComplete
	}
	if err = result.Stream.Close(); err != nil {
		t.Fatal(err)
	}
	if effects.Load() != 1 {
		t.Fatal("wrong genuine SDK effects", effects.Load())
	}
	// A fabricated matching owner principal has no genuine local session stamp.
	static, _ := fabric.NewAuthenticatedContext(owner.PrincipalView(), installed.Store.Namespace(), raw)
	if static.VerifyAuthenticated(installed.Store.Namespace()) != nil {
		t.Fatal("fixture static principal malformed")
	}
	if _, err = n.Service.Execute(ctx, raw, nil); err == nil {
		t.Fatal("unauthenticated raw service invocation accepted")
	}
	closeSession()
	if _, _, err = factory.Build(ctx, mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: offers[0].Ref, ExpectedRevision: offers[0].Revision, Input: json.RawMessage(`{"number":2}`)}}); err == nil {
		t.Fatal("closed session minted a service invocation")
	}
	if effects.Load() != 1 {
		t.Fatal("disconnect replayed effect")
	}
}

func TestKernelOwnerBoundaryActualA2AOriginalAssociation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	private, e := os.MkdirTemp("", "pgn-a2a-boundary-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(private)
	dir, socket := filepath.Join(private, "domain"), filepath.Join(private, "fabric.sock")
	installed, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	defer installed.Close()
	owner, e := installed.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	runtime, e := NewLocalRuntime(ctx, installed.Store, LocalRuntimeConfig{Operator: installed, Native: NativeRuntimeConfig{Owner: owner, Protector: installed.Keys, Credentials: func(context.Context, []string) ([]string, error) { return nil, nil }, CleanupCaller: installed.Operator, Binary: executable, AuthorityDirectory: dir, SocketPath: socket, ControllerBootID: "a2a-service-boundary", MaxWorkers: 1, MaxStartupMetadataBytes: 1 << 20, StartupTimeout: 5 * time.Second}})
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close()
	ref, _ := fabric.NewEndpointRef(installed.Store.AuthorityIdentity().PublicKey)
	revision, e := installed.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "service.a2a", Name: "Shared A2A service", Bindings: []fabric.BindingSummary{{ID: "a2a", Protocol: "a2a.jsonrpc", Version: string(a2a.Version), Cancellation: true}}}})
	if e != nil {
		t.Fatal(e)
	}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "a2a"}
	var effects atomic.Int32
	executor := a2asrv.AgentExecutorFunc(func(_ context.Context, c *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			effects.Add(1)
			task := a2a.NewSubmittedTask(c, c.Message)
			if yield(task, nil) {
				yield(a2a.NewStatusUpdateEvent(task, a2a.TaskStateCompleted, nil), nil)
			}
		}
	})
	server := httptest.NewServer(a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(executor)))
	defer server.Close()
	selected := a2a.NewAgentInterface(server.URL, a2a.TransportProtocolJSONRPC)
	profiles, e := fabricservices.NewProfileStore(ctx, installed.Store, installed.Operator, installed.Keys)
	if e != nil {
		t.Fatal(e)
	}
	digest := [32]byte{98}
	_, e = profiles.Install(ctx, scope, fabricservices.Profile{Protocol: "a2a.jsonrpc", Version: string(a2a.Version), CredentialSelector: "private A2A account", BindingDigest: digest, A2A: &fabricservices.A2AProfile{Card: &a2a.AgentCard{Name: "actual", Version: "1", SupportedInterfaces: []*a2a.AgentInterface{selected}}, Interface: *selected, AllowHTTP: true, Cancellation: true, Limits: adaptera2a.Limits{MaxEventBytes: 64 << 10, MaxRequestBytes: 64 << 10, MaxStreamBytes: 16 << 20, Lifetime: time.Minute}}})
	if e != nil {
		t.Fatal(e)
	}
	ledger, e := fabricservices.BootstrapInvocations(ctx, profiles, fabricservices.DefaultInvocationConfig(), runtime.Boundary)
	if e != nil {
		t.Fatal(e)
	}
	gate := func(c context.Context, caller fabric.ExecutionContext, d fabric.EndpointDescriptor, _ fabric.InvokeRequest) error {
		return runtime.Boundary.WithCurrent(c, caller, d, func(context.Context) error { return nil })
	}
	connections, e := fabricservices.NewA2AConnections(profiles, ledger, serviceRouterCredentials{digest}, gate, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer connections.Close()
	if e = connections.Connect(ctx, scope); e != nil {
		t.Fatal(e)
	}
	provider, e := NewA2AServiceBindingProvider(connections)
	if e != nil {
		t.Fatal(e)
	}
	router, e := NewRouter(map[BindingProtocol]BindingProvider{{Protocol: "a2a.jsonrpc", Version: string(a2a.Version)}: provider})
	if e != nil {
		t.Fatal(e)
	}
	n, e := ComposeRetained(ctx, installed.Store, func(context.Context, *registry.Store, *search.Backend) (Ports, error) {
		p := runtime.Ports()
		p.Bindings = router
		return p, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer n.Close()
	factory, closeSession := runtimeOwnerSession(t, ctx, runtime.NativeRuntime, socket)
	defer closeSession()
	invoke := func(input json.RawMessage) (string, []byte) {
		t.Helper()
		raw, proof, e := factory.Build(ctx, mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: ref, ExpectedRevision: revision, Input: input}})
		if e != nil {
			t.Fatal(e)
		}
		var env fabric.Envelope
		if e = fabric.DecodeJSON(raw, &env); e != nil {
			t.Fatal(e)
		}
		out, e := n.Service.Execute(ctx, raw, proof)
		if e != nil {
			t.Fatal(e)
		}
		defer out.Stream.Close()
		var data bytes.Buffer
		for range 16 {
			f, e := out.Stream.Next(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if f.Kind == fabric.FrameError {
				t.Fatal(f.Error)
			}
			data.Write(f.Data)
			if f.Kind == fabric.FrameComplete {
				return env.ID, data.Bytes()
			}
		}
		t.Fatal("actual A2A stream had no terminal frame")
		return "", nil
	}
	original, _ := invoke(json.RawMessage(`{"operation":"send","mode":"unary","parts":[{"text":"owned original"}]}`))
	get, _ := json.Marshal(adaptera2a.Input{Operation: "get", AssociationInvocation: original})
	current, data := invoke(get)
	if current == original || len(data) == 0 || effects.Load() != 1 {
		t.Fatal("genuine new caller lost original association or repeated paid effect", effects.Load())
	}
}
