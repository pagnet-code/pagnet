//go:build linux || darwin

package fabricnode

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/fabricnative"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func installedNativePage(t *testing.T, ctx context.Context, c *fabricclient.Client, args any) mcpbridge.Page {
	t.Helper()
	raw, _ := json.Marshal(args)
	result, e := c.Call(ctx, fabric.OperationInvoke, raw)
	if e != nil || result.IsError || len(result.Content) != 1 {
		if result != nil && len(result.Content) == 1 {
			t.Fatal("genuine installed MCP invoke", e, result.Content[0].(*sdk.TextContent).Text)
		}
		t.Fatal("genuine installed MCP invoke", e)
	}
	var page mcpbridge.Page
	if e = json.Unmarshal([]byte(result.Content[0].(*sdk.TextContent).Text), &page); e != nil {
		t.Fatal(e)
	}
	return page
}
func installedNativeOutput(t *testing.T, ctx context.Context, c *fabricclient.Client, ref fabric.EndpointRef, rev fabric.Revision, input string) string {
	t.Helper()
	return installedNativeOutputAt(t, ctx, c, ref, rev, input, time.Now().UTC().Add(30*time.Second), nil)
}
func installedNativeOutputAt(t *testing.T, ctx context.Context, c *fabricclient.Client, ref fabric.EndpointRef, rev fabric.Revision, input string, deadline time.Time, invocation *string) string {
	t.Helper()
	page := installedNativePage(t, ctx, c, map[string]any{"target": ref.String(), "revision": rev, "input": map[string]string{"input": input}, "deadline": deadline.Format(time.RFC3339Nano)})
	if invocation != nil && len(page.Frames) > 0 {
		*invocation = page.Frames[0].InvocationID
	}
	var output bytes.Buffer
	for {
		for _, frame := range page.Frames {
			switch frame.Kind {
			case fabric.FrameChunk:
				output.Write(frame.Data)
			case fabric.FrameError:
				t.Fatal("actual native source failed", frame.Error)
			case fabric.FrameComplete:
				return output.String()
			}
		}
		if !page.More || len(page.Frames) == 0 || page.Handle == "" {
			t.Fatal("incomplete genuine native page")
		}
		page = installedNativePage(t, ctx, c, map[string]any{"stream": map[string]any{"handle": page.Handle, "afterSequence": strconv.FormatUint(page.Frames[len(page.Frames)-1].Sequence, 10)}})
	}
}
func TestActualInstalledNativeMCPInvokeRetainedHistoryAndProductRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	private, e := os.MkdirTemp("", "pgn-installed-native-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(private)
	binDir := filepath.Join(private, "bin")
	if e = os.Mkdir(binDir, 0700); e != nil {
		t.Fatal(e)
	}
	binary, native := filepath.Join(binDir, "pagnet"), filepath.Join(binDir, "native")
	rootDir, _ := filepath.Abs("../..")
	for _, b := range []struct{ path, pkg string }{{binary, "./cmd/pagnet"}, {native, "./cmd/pagnet-fake-runtime"}} {
		cmd := exec.CommandContext(ctx, "go", "build", "-o", b.path, b.pkg)
		cmd.Dir = rootDir
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("build %v %s", e, out)
		}
	}
	dir, workspace, socket := filepath.Join(private, "domain"), filepath.Join(private, "workspace"), filepath.Join(private, "fabric.sock")
	if e = os.Mkdir(workspace, 0700); e != nil {
		t.Fatal(e)
	}
	initial, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	root := initial.Store.AuthorityIdentity()
	if e = initial.Close(); e != nil {
		t.Fatal(e)
	}
	product, e := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary})
	if e != nil {
		t.Fatal(e)
	}
	defer func() { product.CloseContext(ctx) }()
	owner, e := product.Installation.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	ref, _ := fabric.NewEndpointRef(root.PublicKey)
	rev, e := product.Node.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "agent.local", Name: "Installed native", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if e != nil {
		t.Fatal(e)
	}
	scope := identity.Scope{Endpoint: ref, DescriptorRevision: rev, BindingID: "native"}
	controller, e := product.Runtime.Authority.AcquireController(ctx, owner, scope, 0, "installed-controller", "installed-request")
	if e != nil {
		t.Fatal(e)
	}
	spec := sessionworker.NativeSpec{Kind: "local", Runtime: domain.RuntimeFakePersistent, Binary: native, MCPExecutable: binary, Workspace: workspace, LocalAuthorityDirectory: dir, LocalFabricSocket: socket, Env: []string{"PATH=/usr/bin:/bin", "HOME=" + workspace}}
	fingerprint, _ := hex.DecodeString(sessionworker.LocalNativeProfileFingerprint(spec))
	worker := identity.WorkerBinding{WorkerID: "product-worker", StateDirectoryID: "product-state", OwnershipGeneration: "product-physical", ActualRuntime: string(spec.Runtime)}
	copy(worker.ProfileDigest[:], fingerprint)
	binding, e := product.Runtime.Authority.BindWorker(ctx, owner, controller, 0, worker)
	if e != nil {
		t.Fatal(e)
	}
	_, e = product.Runtime.Profiles.Put(ctx, registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: rev, BindingID: "native"}, fabricnative.Profile{Native: spec, Worker: binding.Worker, Directory: filepath.Join(private, "worker")})
	if e != nil {
		t.Fatal(e)
	}
	client, e := fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	originalDeadline := time.Now().UTC().Add(2 * time.Second)
	var originalInvocation string
	if out := installedNativeOutputAt(t, ctx, client, ref, rev, "let retained once", originalDeadline, &originalInvocation); out != "[fake-persist local-native] let retained = once" {
		t.Fatal("first actual native output differs", len(out))
	}
	descriptor, e := product.Node.Store.GetEndpoint(ctx, ref, rev)
	if e != nil {
		t.Fatal(e)
	}
	handle, e := product.Runtime.Resolver.Resolve(ctx, owner, descriptor)
	if e != nil {
		t.Fatal(e)
	}
	before, e := handle.Client.Call(ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if e != nil || before.Snapshot == nil || before.Snapshot.PID == 0 {
		t.Fatal("actual source absent", e)
	}
	process, e := handle.Client.OwnerProcess()
	if e != nil {
		t.Fatal(e)
	}
	child, _ := os.FindProcess(process.PID)
	defer child.Signal(os.Interrupt)
	timer := time.NewTimer(time.Until(originalDeadline.Add(10 * time.Millisecond)))
	select {
	case <-timer.C:
	case <-ctx.Done():
		timer.Stop()
		t.Fatal(ctx.Err())
	}
	if time.Now().Before(originalDeadline) {
		t.Fatal("original paid deadline not actually expired")
	}
	if e = client.Close(); e != nil {
		t.Fatal(e)
	}
	if e = product.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	product, e = OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary})
	if e != nil {
		t.Fatal("actual product reopen/adopt", e)
	}
	if product.Node.Store.AuthorityIdentity().StoreID != root.StoreID {
		t.Fatal("product root replaced")
	}
	client, e = fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if out := installedNativeOutput(t, ctx, client, ref, rev, "print retained"); out != "[fake-persist local-native] print retained: once" {
		t.Fatal("actual native history lost on product restart", len(out))
	}
	saved, restored, e := product.Runtime.Checkpoints.Load(ctx, root.Owner, originalInvocation)
	if e != nil || restored.PrincipalView() != root.Owner || len(saved.Original) == 0 {
		t.Fatal("expired original checkpoint did not restore authentic history", e)
	}
	owner, e = product.Installation.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	handle, e = product.Runtime.Resolver.Resolve(ctx, owner, descriptor)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = product.Runtime.Authority.Admit(ctx, owner, handle.Current, handle.Binding, restored, saved.Original, saved.Finalized, "expired-fresh-attempt", "attempt", "replay"); e == nil {
		t.Fatal("expired original history authorized fresh paid admission")
	}
	after, e := handle.Client.Call(ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if e != nil || after.Snapshot == nil || after.Snapshot.PID != before.Snapshot.PID || after.Snapshot.NativeSessionID != before.Snapshot.NativeSessionID {
		t.Fatal("reopen fabricated new source", e)
	}
}
