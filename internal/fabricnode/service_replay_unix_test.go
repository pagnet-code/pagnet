//go:build linux || darwin

package fabricnode

import (
	"context"
	"encoding/json"
	"errors"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestKernelOwnerActualSignedAliasOriginalFramesAndReadRevocation(t *testing.T) {
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
	revision, err := installed.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "service.mcp", Name: "Installed shared service", Bindings: []fabric.BindingSummary{{ID: "mcp", Protocol: "mcp.tools", Version: "2026-07-28", Cancellation: true, Idempotency: true}}}})
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
		p.ReplayVerifier = ledger
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
	call := mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: offers[0].Ref, ExpectedRevision: offers[0].Revision, Input: json.RawMessage(`{"number":9007199254740993}`), IdempotencyKey: "one-authenticated-operation"}}
	execute := func() node.Result {
		raw, proof, e := factory.Build(ctx, call)
		if e != nil {
			t.Fatal(e)
		}
		result, e := n.Service.Execute(ctx, raw, proof)
		if e != nil {
			t.Fatal(e)
		}
		return result
	}
	drain := func(result node.Result) []fabric.InvocationFrame {
		var frames []fabric.InvocationFrame
		defer result.Stream.Close()
		for {
			f, e := result.Stream.Next(ctx)
			if errors.Is(e, io.EOF) {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
			frames = append(frames, f)
		}
		return frames
	}
	original := drain(execute())
	alias := execute()
	if alias.Replay == nil || alias.Replay.RequestID == alias.Replay.ExecutionID || alias.Replay.ExecutionID != original[0].InvocationID {
		t.Fatal("missing real signed original association")
	}
	replay := drain(alias)
	a, _ := json.Marshal(original)
	b, _ := json.Marshal(replay)
	if string(a) != string(b) || effects.Load() != 1 {
		t.Fatal("real SDK effect duplicated or original source relabeled", effects.Load())
	}
	revoked := execute()
	closeSession()
	if _, e := revoked.Stream.Next(ctx); e == nil {
		t.Fatal("closed actual kernel session read original frame")
	}
	revoked.Stream.Close()
	if effects.Load() != 1 {
		t.Fatal("closed alias repeated external work")
	}
}
