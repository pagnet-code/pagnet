//go:build linux || darwin

package fabricnode

import (
	"bytes"
	"context"
	"encoding/json"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

func TestInstalledServiceConfigurationExplicitAtomicRestart(t *testing.T) {
	ctx := t.Context()
	private, e := os.MkdirTemp("", "pgn-services-config-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(private)
	dir := filepath.Join(private, "domain")
	i, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(filepath.Join(private, "node.sock"))})
	if e != nil {
		t.Fatal(e)
	}
	if e = i.Close(); e != nil {
		t.Fatal(e)
	}
	binary, _ := os.Executable()
	n, e := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary})
	if e != nil {
		t.Fatal(e)
	}
	originalRoot := n.Installation.Store.AuthorityIdentity()
	configBefore, e := os.ReadFile(filepath.Join(dir, "installation.json"))
	if e != nil {
		t.Fatal(e)
	}
	s, e := LoadInstalledServiceSettings(ctx, n.Installation)
	if e != nil || s != nil {
		t.Fatal("native-only state not intentionally empty", e)
	}
	if e = InitializeConfiguredServices(ctx, n.Installation, n.Runtime.Boundary, DefaultInstalledServiceSettings()); e != nil {
		t.Fatal(e)
	}
	s, e = LoadInstalledServiceSettings(ctx, n.Installation)
	if e != nil || s == nil || *s != DefaultInstalledServiceSettings() {
		t.Fatal("explicit settings not retained", e)
	}
	if e = InitializeConfiguredServices(ctx, n.Installation, n.Runtime.Boundary, DefaultInstalledServiceSettings()); e == nil {
		t.Fatal("existing replay state reset")
	}
	if e = n.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	published := make(chan error, 32)
	n, e = OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary, ObserveIndexPublication: func(more bool, e error) {
		if !more || e != nil {
			select {
			case published <- e:
			default:
			}
		}
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer n.CloseContext(ctx)
	if n.Services == nil || n.Installation.Store.AuthorityIdentity().StoreID != originalRoot.StoreID {
		t.Fatal("restart didn't use original configured installation")
	}
	configAfter, e := os.ReadFile(filepath.Join(dir, "installation.json"))
	if e != nil || !bytes.Equal(configBefore, configAfter) {
		t.Fatal("immutable installation pin rewritten", e)
	}
	creds, e := n.Services.config.Credentials.Resolve(ctx, "none")
	if e != nil || len(creds.MCP.Headers) != 0 || creds.BindingDigest != fabricservices.CredentialFreeAccountDigest() {
		t.Fatal("credential-free selection changed", e)
	}
	// Actual explicit credential-free SDK endpoint: ambient tokens are never sent.
	t.Setenv("MCP_TOKEN", "ambient-secret")
	var effects atomic.Int32
	official := sdk.NewServer(&sdk.Implementation{Name: "credential-free", Version: "1"}, nil)
	official.AddTool(&sdk.Tool{Name: "free", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		effects.Add(1)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "explicit-none-result"}}}, nil
	})
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return official }, &sdk.StreamableHTTPOptions{Stateless: true})
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("ambient credential disclosed")
		}
		handler.ServeHTTP(w, r)
	}))
	defer func() { n.CloseContext(ctx); remote.Close() }()
	owner, e := n.Installation.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	ref, _ := fabric.NewEndpointRef(originalRoot.PublicKey)
	revision, e := n.Installation.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "service.mcp", Name: "Explicit no-credential endpoint", Description: "credentialfreemarker", Bindings: []fabric.BindingSummary{{ID: "mcp", Protocol: "mcp.tools", Version: "2026-07-28", Cancellation: true}}}})
	if e != nil {
		t.Fatal(e)
	}
	scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "mcp"}
	_, e = n.Services.Profiles.Install(ctx, scope, fabricservices.Profile{Protocol: "mcp.tools", Version: "2026-07-28", CredentialSelector: "none", BindingDigest: fabricservices.CredentialFreeAccountDigest(), MCP: &fabricservices.MCPProfile{URL: remote.URL, AllowHTTP: true, Limits: mcp.DefaultLimits}})
	if e != nil {
		t.Fatal(e)
	}
	if e = n.Services.Connect(ctx, scope, true); e != nil {
		t.Fatal(e)
	}
	if effects.Load() != 0 {
		t.Fatal("service setup ran a paid operation")
	}
	client, e := fabricclient.Dial(ctx, filepath.Join(private, "node.sock"), fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	for {
		select {
		case e = <-published:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("credential-free real catalog not published")
		}
		raw := installedServiceCall(t, ctx, client, fabric.OperationDiscover, map[string]any{"query": "credentialfreemarker", "limit": 10})
		var found fabric.DiscoverResult
		if json.Unmarshal(raw, &found) != nil {
			t.Fatal(string(raw))
		}
		if len(found.Candidates) > 0 {
			break
		}
	}
	offers, _, e := n.Installation.Store.ListOffers(ctx, ref, revision, "", 1)
	if e != nil || len(offers) != 1 {
		t.Fatal(e)
	}
	page := installedNativePage(t, ctx, client, map[string]any{"target": offers[0].Ref.String(), "revision": offers[0].Revision, "input": json.RawMessage(`{}`)})
	var output bytes.Buffer
	complete := false
	for {
		for _, f := range page.Frames {
			if f.Kind == fabric.FrameError {
				t.Fatal(f.Error)
			}
			output.Write(f.Data)
			complete = complete || f.Kind == fabric.FrameComplete
		}
		if complete {
			break
		}
		if !page.More || page.Handle == "" || len(page.Frames) == 0 {
			t.Fatal("real credential-free stream did not complete")
		}
		last := page.Frames[len(page.Frames)-1].Sequence
		page = installedNativePage(t, ctx, client, map[string]any{"stream": map[string]any{"handle": page.Handle, "afterSequence": strconv.FormatUint(last, 10)}})
	}
	if !complete || !bytes.Contains(output.Bytes(), []byte("explicit-none-result")) || effects.Load() != 1 {
		t.Fatal("genuine none-selected invocation unavailable", string(output.Bytes()), effects.Load())
	}

}

func TestInstalledServicePartialStateFailsClosedAndInitializationRollsBack(t *testing.T) {
	ctx := t.Context()
	private, e := os.MkdirTemp("", "pgn-services-partial-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(private)
	dir := filepath.Join(private, "domain")
	i, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(filepath.Join(private, "node.sock"))})
	if e != nil {
		t.Fatal(e)
	}
	i.Close()
	binary, _ := os.Executable()
	n, e := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary})
	if e != nil {
		t.Fatal(e)
	}
	owner, e := n.Installation.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	key := registry.AuthorityKey{Kind: registry.AuthorityServiceInvocation, ID: "startup/header"}
	e = n.Installation.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{MaxOperations: 2, Timeout: time.Second}, func(tx *registry.AuthorityTx) error {
		_, e := tx.CAS(key, 0, []byte(`{"invalid":"partial"}`), false)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = LoadInstalledServiceSettings(ctx, n.Installation); e == nil {
		t.Fatal("partial state treated disabled")
	}
	if e = InitializeConfiguredServices(ctx, n.Installation, n.Runtime.Boundary, DefaultInstalledServiceSettings()); e == nil {
		t.Fatal("partial state reset")
	}
	e = n.Installation.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{MaxOperations: 3, Timeout: time.Second}, func(tx *registry.AuthorityTx) error {
		for _, k := range []registry.AuthorityKey{fabricservices.InstalledServiceConfigurationKey(), {Kind: registry.AuthorityServiceInvocation, ID: "configuration"}} {
			if _, e := tx.Get(k); !authorityMissing(e) {
				t.Fatalf("failed FULL init partially wrote %v: %v", k, e)
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	n.CloseContext(ctx)
	if reopened, e := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary}); e == nil {
		reopened.Close()
		t.Fatal("partial infrastructure served")
	}
	i, e = localinstallation.Load(ctx, dir, registry.DefaultOptions())
	if e != nil {
		t.Fatal("constructor leaked root writer", e)
	}
	i.Close()
}

func TestInstalledServiceProviderSelectionNeverFallsBack(t *testing.T) {
	s := DefaultInstalledServiceSettings()
	s.ProviderSelector = "operator.private"
	c, e := selectedInstalledServiceConfig(&s, InstalledConfig{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Credentials.Resolve(context.Background(), "none"); e == nil {
		t.Fatal("missing named provider became credential free")
	}
	override := DefaultInstalledServiceConfig(fabricservices.CredentialFreeProvider{})
	override.MaxConnections--
	if _, e = selectedInstalledServiceConfig(&s, InstalledConfig{Services: &override}); e == nil {
		t.Fatal("retained quota overridden")
	}
	if _, e = selectedInstalledServiceConfig(nil, InstalledConfig{Services: &override}); e == nil {
		t.Fatal("missing state implicitly configured")
	}
}
