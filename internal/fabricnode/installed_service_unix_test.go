//go:build linux || darwin

package fabricnode

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/fabricnative"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func installedServiceCall(t *testing.T, ctx context.Context, c *fabricclient.Client, op fabric.Operation, args any) json.RawMessage {
	t.Helper()
	raw, e := json.Marshal(args)
	if e != nil {
		t.Fatal(e)
	}
	result, e := c.Call(ctx, op, raw)
	if e != nil || result == nil || result.IsError || len(result.Content) != 1 {
		if result != nil && len(result.Content) == 1 {
			t.Fatal("actual installed service call", e, result.Content[0].(*sdk.TextContent).Text)
		}
		t.Fatal("actual installed service call", e)
	}
	return json.RawMessage(result.Content[0].(*sdk.TextContent).Text)
}
func TestActualInstalledServiceSocketSharedCatalogRestartAndOfflineIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	private, e := os.MkdirTemp("", "pgn-installed-services-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(private)
	dir, socket := filepath.Join(private, "domain"), filepath.Join(private, "node.sock")
	initial, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	root := initial.Store.AuthorityIdentity()
	if e = initial.Close(); e != nil {
		t.Fatal(e)
	}
	binDir, workspace := filepath.Join(private, "bin"), filepath.Join(private, "workspace")
	for _, d := range []string{binDir, workspace} {
		if e = os.Mkdir(d, 0700); e != nil {
			t.Fatal(e)
		}
	}
	binary, nativeBinary := filepath.Join(binDir, "pagnet"), filepath.Join(binDir, "fake-native")
	rootDir, _ := filepath.Abs("../..")
	for _, b := range []struct{ path, pkg string }{{binary, "./cmd/pagnet"}, {nativeBinary, "./cmd/pagnet-fake-runtime"}} {
		cmd := exec.CommandContext(ctx, "go", "build", "-o", b.path, b.pkg)
		cmd.Dir = rootDir
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatal("actual binary build", e, string(out))
		}
	}
	setup, e := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary})
	if e != nil {
		t.Fatal(e)
	}
	defer setup.CloseContext(ctx)
	digest := [32]byte{131}
	config := DefaultInstalledServiceConfig(serviceRouterCredentials{digest})
	config.MaxConnections = 2
	config.SetupTimeout = time.Second
	config.SetupConcurrency = 2
	if e = InitializeServiceState(ctx, setup.Installation, setup.Runtime.Boundary, config); e != nil {
		t.Fatal(e)
	}
	serviceSetup, e := NewServiceRuntime(ctx, setup.Installation, setup.Runtime.Boundary, config)
	if e != nil {
		t.Fatal(e)
	}
	defer serviceSetup.CloseContext(ctx)
	var effects atomic.Int32
	server := func() *httptest.Server {
		official := sdk.NewServer(&sdk.Implementation{Name: "installed official SDK service", Version: "1"}, nil)
		official.AddTool(&sdk.Tool{Name: "echo", Description: "Echo an exact integer", InputSchema: json.RawMessage(`{"type":"object","properties":{"number":{"type":"integer"}},"required":["number"]}`)}, func(_ context.Context, r *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			effects.Add(1)
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: string(r.Params.Arguments)}}}, nil
		})
		return httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return official }, &sdk.StreamableHTTPOptions{Stateless: true}))
	}
	healthy, offline := server(), server()
	defer healthy.Close()
	defer offline.Close()
	owner, e := setup.Installation.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	scopes := make([]registry.DescriptorBatchScope, 0, 2)
	for _, url := range []string{healthy.URL, offline.URL} {
		ref, _ := fabric.NewEndpointRef(root.PublicKey)
		revision, e := setup.Installation.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "service.mcp", Name: "Operator customer support", Description: "installedservicemarker", Bindings: []fabric.BindingSummary{{ID: "mcp", Protocol: "mcp.tools", Version: "2026-07-28", Cancellation: true}}}})
		if e != nil {
			t.Fatal(e)
		}
		scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "mcp"}
		scopes = append(scopes, scope)
		if _, e = serviceSetup.Profiles.Install(ctx, scope, fabricservices.Profile{Protocol: "mcp.tools", Version: "2026-07-28", CredentialSelector: "private configured SDK account", BindingDigest: digest, MCP: &fabricservices.MCPProfile{URL: url, AllowHTTP: true, Limits: mcp.DefaultLimits}}); e != nil {
			t.Fatal(e)
		}
		if e = serviceSetup.Connect(ctx, scope, true); e != nil {
			t.Fatal(e)
		}
	}
	nativeRef, _ := fabric.NewEndpointRef(root.PublicKey)
	nativeRevision, e := setup.Node.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: nativeRef, Kind: "agent.local", Name: "Native alongside services", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if e != nil {
		t.Fatal(e)
	}
	nativeScope := identity.Scope{Endpoint: nativeRef, DescriptorRevision: nativeRevision, BindingID: "native"}
	controller, e := setup.Runtime.Authority.AcquireController(ctx, owner, nativeScope, 0, "shared-service-native", "shared-native-request")
	if e != nil {
		t.Fatal(e)
	}
	spec := sessionworker.NativeSpec{Kind: "local", Runtime: domain.RuntimeFakePersistent, Binary: nativeBinary, MCPExecutable: binary, Workspace: workspace, LocalAuthorityDirectory: dir, LocalFabricSocket: socket, Env: []string{"PATH=/usr/bin:/bin", "HOME=" + workspace}}
	fp, _ := hex.DecodeString(sessionworker.LocalNativeProfileFingerprint(spec))
	worker := identity.WorkerBinding{WorkerID: "shared-native-worker", StateDirectoryID: "shared-native-state", OwnershipGeneration: "shared-native-physical", ActualRuntime: string(spec.Runtime)}
	copy(worker.ProfileDigest[:], fp)
	binding, e := setup.Runtime.Authority.BindWorker(ctx, owner, controller, 0, worker)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = setup.Runtime.Profiles.Put(ctx, registry.DescriptorBatchScope{Endpoint: nativeRef, ExpectedEndpointRevision: nativeRevision, BindingID: "native"}, fabricnative.Profile{Native: spec, Worker: binding.Worker, Directory: filepath.Join(private, "worker")}); e != nil {
		t.Fatal(e)
	}
	if e = serviceSetup.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	if e = setup.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	offline.Close()
	product, e := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary, Services: &config})
	if e != nil {
		t.Fatal("offline service disabled installed local node", e)
	}
	defer product.CloseContext(ctx)
	if product.Services == nil || product.Node.Store != product.Installation.Store || product.Node.Store.AuthorityIdentity().StoreID != root.StoreID {
		t.Fatal("service composition substituted retained Store")
	}
	until := time.NewTimer(5 * time.Second)
	defer until.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		statuses := product.Services.Status()
		ready := len(statuses) == 2
		for _, s := range statuses {
			ready = ready && !s.Connecting
		}
		if ready {
			break
		}
		select {
		case <-until.C:
			t.Fatal("startup connection work did not settle")
		case <-tick.C:
		}
	}
	if _, e = product.Node.Synchronize(ctx, 16); e != nil {
		t.Fatal(e)
	}
	client, e := fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	discovery := installedServiceCall(t, ctx, client, fabric.OperationDiscover, map[string]any{"query": "installedservicemarker", "limit": 10})
	var found fabric.DiscoverResult
	if e = json.Unmarshal(discovery, &found); e != nil || len(found.Candidates) < 2 {
		t.Fatal("service catalog unavailable over genuine installed socket", e, string(discovery))
	}
	offers, _, e := product.Node.Store.ListOffers(ctx, scopes[0].Endpoint, scopes[0].ExpectedEndpointRevision, "", 1)
	if e != nil || len(offers) != 1 {
		t.Fatal(e)
	}
	description := installedServiceCall(t, ctx, client, fabric.OperationDescribe, map[string]any{"selections": []map[string]any{{"ref": offers[0].Ref.String(), "expectedRevision": offers[0].Revision}}})
	if !bytes.Contains(description, []byte("inputSchema")) {
		t.Fatal("real offer schema not described")
	}
	page := installedNativePage(t, ctx, client, map[string]any{"target": offers[0].Ref.String(), "revision": offers[0].Revision, "input": json.RawMessage(`{"number":9007199254740993}`)})
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
			t.Fatal("SDK stream did not complete")
		}
		last := page.Frames[len(page.Frames)-1].Sequence
		page = installedNativePage(t, ctx, client, map[string]any{"stream": map[string]any{"handle": page.Handle, "afterSequence": strconv.FormatUint(last, 10)}})
	}
	if !strings.Contains(output.String(), "9007199254740993") || effects.Load() != 1 {
		t.Fatal("actual SDK precision/effect count", effects.Load(), output.Len())
	}
	failed, _, e := product.Node.Store.ListOffers(ctx, scopes[1].Endpoint, scopes[1].ExpectedEndpointRevision, "", 1)
	if e != nil || len(failed) != 1 {
		t.Fatal(e)
	}
	args, _ := json.Marshal(map[string]any{"target": failed[0].Ref.String(), "revision": failed[0].Revision, "input": json.RawMessage(`{"number":1}`)})
	result, e := client.Call(ctx, fabric.OperationInvoke, args)
	if e != nil || !result.IsError {
		t.Fatal("offline target silently selected another binding", e)
	}
	if effects.Load() != 1 {
		t.Fatal("offline attempt ran a paid effect")
	}
	if output := installedNativeOutput(t, ctx, client, nativeRef, nativeRevision, "let shared alive"); output != "[fake-persist local-native] let shared = alive" {
		t.Fatal("offline service disabled genuine native execution", len(output))
	}
	descriptor, e := product.Node.Store.GetEndpoint(ctx, nativeRef, nativeRevision)
	if e != nil {
		t.Fatal(e)
	}
	currentOwner, e := product.Installation.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	handle, e := product.Runtime.Resolver.Resolve(ctx, currentOwner, descriptor)
	if e != nil {
		t.Fatal(e)
	}
	process, e := handle.Client.OwnerProcess()
	if e != nil {
		t.Fatal(e)
	}
	child, _ := os.FindProcess(process.PID)
	defer child.Signal(os.Interrupt)

	if e = client.Close(); e != nil {
		t.Fatal(e)
	}
	if e = product.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	// Another real restart owns exactly the same catalog/receipts and native ports.
	reopened, e := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary, Services: &config})
	if e != nil {
		t.Fatal(e)
	}
	if reopened.Node.Store.AuthorityIdentity().StoreID != root.StoreID || reopened.Runtime == nil || reopened.Services == nil {
		t.Fatal("restart changed root or lost native composition")
	}
	if e = reopened.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	if effects.Load() != 1 {
		t.Fatal("restart retried original paid invocation")
	}
}
func TestInstalledServiceMissingInfrastructureDoesNotBootstrapOrLeakWriter(t *testing.T) {
	ctx := t.Context()
	private, e := os.MkdirTemp("", "pgn-service-missing-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(private)
	dir, socket := filepath.Join(private, "domain"), filepath.Join(private, "node.sock")
	initial, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	root := initial.Store.AuthorityIdentity()
	if e = initial.Close(); e != nil {
		t.Fatal(e)
	}
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	config := DefaultInstalledServiceConfig(serviceRouterCredentials{[32]byte{171}})
	if n, e := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary, Services: &config}); e == nil {
		n.Close()
		t.Fatal("missing service replay state regenerated")
	}
	nativeOnly, e := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary})
	if e != nil {
		t.Fatal("failed constructor leaked sole writer/key", e)
	}
	defer nativeOnly.Close()
	if nativeOnly.Services != nil || nativeOnly.Installation.Store.AuthorityIdentity().StoreID != root.StoreID {
		t.Fatal("native-only startup changed installation")
	}
	if e = InitializeServiceState(ctx, nativeOnly.Installation, nativeOnly.Runtime.Boundary, config); e != nil {
		t.Fatal("failed open partially created service infrastructure", e)
	}
}
