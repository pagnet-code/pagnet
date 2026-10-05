//go:build linux || darwin

package fabricnode

import (
	"context"
	"encoding/json"
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
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

func TestActualServiceRuntimeSelectedStartupOutageIsolationNoPaidEffects(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	private, e := os.MkdirTemp("", "pgn-startup-service-")
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
	native, e := NewLocalRuntime(ctx, installed.Store, LocalRuntimeConfig{Operator: installed, Native: NativeRuntimeConfig{Owner: owner, Protector: installed.Keys, Credentials: func(context.Context, []string) ([]string, error) { return nil, nil }, CleanupCaller: installed.Operator, Binary: executable, AuthorityDirectory: dir, SocketPath: socket, ControllerBootID: "service-startup", MaxWorkers: 1, MaxStartupMetadataBytes: 1 << 20, StartupTimeout: 5 * time.Second}})
	if e != nil {
		t.Fatal(e)
	}
	defer native.Close()
	digest := [32]byte{117}
	config := ServiceRuntimeConfig{Credentials: serviceRouterCredentials{digest}, InvocationConfig: fabricservices.DefaultInvocationConfig(), MaxConnections: 2, SetupTimeout: time.Second, SetupConcurrency: 2}
	if _, e = NewServiceRuntime(ctx, installed, native.Boundary, config); e == nil {
		t.Fatal("missing service state auto-created")
	}
	if e = InitializeServiceState(ctx, installed, native.Boundary, config); e != nil {
		t.Fatal(e)
	}
	if e = InitializeServiceState(ctx, installed, native.Boundary, config); e == nil {
		t.Fatal("explicit repeated init reset replay fence")
	}
	runtime, e := NewServiceRuntime(ctx, installed, native.Boundary, config)
	if e != nil {
		t.Fatal(e)
	}
	var effects atomic.Int32
	server := func() *httptest.Server {
		official := sdk.NewServer(&sdk.Implementation{Name: "explicit startup service", Version: "1"}, nil)
		official.AddTool(&sdk.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			effects.Add(1)
			return &sdk.CallToolResult{Content: []sdk.Content{}}, nil
		})
		return httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return official }, &sdk.StreamableHTTPOptions{Stateless: true}))
	}
	healthy, offline := server(), server()
	defer healthy.Close()
	defer offline.Close()
	scopes := make([]registry.DescriptorBatchScope, 0, 2)
	for _, url := range []string{healthy.URL, offline.URL} {
		ref, _ := fabric.NewEndpointRef(installed.Store.AuthorityIdentity().PublicKey)
		revision, e := installed.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "service.mcp", Name: "Explicit selected startup service", Bindings: []fabric.BindingSummary{{ID: "mcp", Protocol: "mcp.tools", Version: "2026-07-28", Cancellation: true}}}})
		if e != nil {
			t.Fatal(e)
		}
		scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "mcp"}
		scopes = append(scopes, scope)
		if _, e = runtime.Profiles.Install(ctx, scope, fabricservices.Profile{Protocol: "mcp.tools", Version: "2026-07-28", CredentialSelector: "private startup account", BindingDigest: digest, MCP: &fabricservices.MCPProfile{URL: url, AllowHTTP: true, Limits: mcp.DefaultLimits}}); e != nil {
			t.Fatal(e)
		}
		if e = runtime.Connect(ctx, scope, true); e != nil {
			t.Fatal(e)
		}
	}
	choices, e := runtime.Startup.Selections(ctx)
	if e != nil || len(choices) != 2 {
		t.Fatal("operator connect failed to commit startup choices", e)
	}
	if effects.Load() != 0 {
		t.Fatal("connection/setup executed paid tools")
	}
	if e = runtime.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	offline.Close()
	restarted, e := NewServiceRuntime(ctx, installed, native.Boundary, config)
	if e != nil {
		t.Fatal("offline peer disabled local service composition", e)
	}
	defer restarted.Close()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		statuses := restarted.Status()
		done := len(statuses) == 2
		for _, status := range statuses {
			done = done && !status.Connecting
		}
		if done {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("bounded setup did not settle")
		case <-tick.C:
		}
	}
	statuses := restarted.Status()
	var online, failed int
	for _, s := range statuses {
		if s.Connected {
			online++
		} else if s.ErrorCode != "" {
			failed++
		}
	}
	if online != 1 || failed != 1 || effects.Load() != 0 {
		t.Fatal("outage isolation or no-effect guarantee failed", online, failed, effects.Load())
	}
	provider := restarted.Bindings()[BindingProtocol{Protocol: "mcp.tools", Version: "2026-07-28"}]
	d, e := installed.Store.GetEndpoint(ctx, scopes[1].Endpoint, scopes[1].ExpectedEndpointRevision)
	if e != nil {
		t.Fatal(e)
	}
	offers, _, e := installed.Store.ListOffers(ctx, d.Ref, d.Revision, "", 1)
	if e != nil || len(offers) != 1 {
		t.Fatal("retained failed-service catalog disappeared", e)
	}
	offer, e := installed.Store.GetOffer(ctx, offers[0].Ref, offers[0].Revision)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = provider.ResolveBinding(ctx, owner, d, d.Bindings[0], &offer); e == nil {
		t.Fatal("unconnected selected target silently routed elsewhere")
	}
	if effects.Load() != 0 {
		t.Fatal("resolve retried paid effect")
	}
	if e = restarted.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	if e = restarted.Connect(ctx, scopes[0], false); e == nil {
		t.Fatal("closed runtime opened another SDK connection")
	}
}
