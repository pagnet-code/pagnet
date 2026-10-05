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
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/fabricnative"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func TestActualLocalBoundaryInstallationPeerInvokeAndDisconnectCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	private, e := os.MkdirTemp("", "pagnet-boundary-")
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
	dir, socket, workspace := filepath.Join(private, "domain"), filepath.Join(private, "fabric.sock"), filepath.Join(private, "workspace")
	if e = os.Mkdir(workspace, 0700); e != nil {
		t.Fatal(e)
	}
	installed, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	defer installed.Close()
	owner, e := installed.Operator(ctx)
	if e != nil {
		t.Fatal(e)
	}
	c := LocalRuntimeConfig{Operator: installed, Native: NativeRuntimeConfig{Owner: owner, Protector: installed.Keys, Credentials: func(context.Context, []string) ([]string, error) { return nil, nil }, CleanupCaller: installed.Operator, Binary: binary, AuthorityDirectory: dir, SocketPath: socket, ControllerBootID: "actual-local-boundary", MaxWorkers: 4, MaxStartupMetadataBytes: 1 << 20, StartupTimeout: 10 * time.Second}}
	runtime, e := NewLocalRuntime(ctx, installed.Store, c)
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close()
	n, e := ComposeRetained(ctx, installed.Store, func(context.Context, *registry.Store, *search.Backend) (Ports, error) { return runtime.Ports(), nil })
	if e != nil {
		t.Fatal(e)
	}
	defer n.Close()
	principal := owner.PrincipalView()
	static, _ := fabric.NewAuthenticatedContext(principal, installed.Store.Namespace(), []byte("static setup"))
	if runtime.Boundary.WithCurrentOwner(ctx, static, func(context.Context) error { t.Fatal("static current owner"); return nil }) == nil {
		t.Fatal("historical principal promoted to operator")
	}
	ref, _ := fabric.NewEndpointRef(installed.Store.AuthorityIdentity().PublicKey)
	rev, e := installed.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "agent.local", Name: "Actual local source", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if e != nil {
		t.Fatal(e)
	}
	scope := identity.Scope{Endpoint: ref, DescriptorRevision: rev, BindingID: "native"}
	controller, e := runtime.Authority.AcquireController(ctx, owner, scope, 0, "controller", "request")
	if e != nil {
		t.Fatal(e)
	}
	spec := sessionworker.NativeSpec{Kind: "local", Runtime: domain.RuntimeFakePersistent, Binary: native, MCPExecutable: binary, Workspace: workspace, LocalAuthorityDirectory: dir, LocalFabricSocket: socket, Env: []string{"PATH=/usr/bin:/bin", "HOME=" + workspace, "PAGNET_FAKE_INTERACTION=permission"}}
	fingerprint, _ := hex.DecodeString(sessionworker.LocalNativeProfileFingerprint(spec))
	worker := identity.WorkerBinding{WorkerID: "actual-worker", StateDirectoryID: "actual-state", OwnershipGeneration: "actual-physical", ActualRuntime: string(spec.Runtime)}
	copy(worker.ProfileDigest[:], fingerprint)
	binding, e := runtime.Authority.BindWorker(ctx, owner, controller, 0, worker)
	if e != nil {
		t.Fatal(e)
	}
	_, e = runtime.Profiles.Put(ctx, registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: rev, BindingID: "native"}, fabricnative.Profile{Native: spec, Worker: binding.Worker, Directory: filepath.Join(private, "worker")})
	if e != nil {
		t.Fatal(e)
	}
	factory, closeSession := runtimeOwnerSession(t, ctx, runtime.NativeRuntime, socket)
	defer closeSession()
	deadline := time.Now().UTC().Add(30 * time.Second)
	original, proof, e := factory.Build(ctx, mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: ref, ExpectedRevision: rev, Input: json.RawMessage(`{"input":"let actual once"}`), Deadline: &deadline}})
	if e != nil {
		t.Fatal(e)
	}
	result, e := n.Service.Execute(ctx, original, proof)
	if e != nil {
		t.Fatal("actual protected boundary invoke", e)
	}
	var output bytes.Buffer
	for {
		frame, e := result.Stream.Next(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if frame.Kind == fabric.FrameError {
			t.Fatal(frame.Error)
		}
		if frame.Kind == fabric.FrameChunk {
			output.Write(frame.Data)
		}
		if frame.Kind == fabric.FrameComplete {
			break
		}
	}
	if output.String() != "[fake-persist local-native] let actual = once" {
		t.Fatal("actual bytes changed", output.Len())
	}
	if e = result.Stream.Close(); e != nil {
		t.Fatal(e)
	}
	descriptor, e := installed.Store.GetEndpoint(ctx, ref, rev)
	if e != nil {
		t.Fatal(e)
	}
	handle, e := runtime.Resolver.Resolve(ctx, owner, descriptor)
	if e != nil {
		t.Fatal(e)
	}
	process, e := handle.Client.OwnerProcess()
	if e != nil {
		t.Fatal(e)
	}
	child, _ := os.FindProcess(process.PID)
	defer child.Signal(os.Interrupt)
	deadline = time.Now().UTC().Add(2 * time.Second)
	original, proof, e = factory.Build(ctx, mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: ref, ExpectedRevision: rev, Input: json.RawMessage(`{"input":"permission_check secret"}`), Deadline: &deadline}})
	if e != nil {
		t.Fatal(e)
	}
	result, e = n.Service.Execute(ctx, original, proof)
	if e != nil {
		t.Fatal(e)
	}
	frame, e := result.Stream.Next(ctx)
	if e != nil || frame.Kind != fabric.FrameStart {
		t.Fatal("actual approval source did not start", e, frame.Kind)
	}
	// Explicit Session.Close revokes the actual peer association. Cleanup may use
	// ONLY the protected installation stop capability, not read/ACK promotion.
	timer := time.NewTimer(time.Until(deadline.Add(10 * time.Millisecond)))
	select {
	case <-timer.C:
	case <-ctx.Done():
		timer.Stop()
		t.Fatal(ctx.Err())
	}
	closeSession()
	if e = result.Stream.Close(); e != nil {
		t.Fatal("disconnected exact-source cleanup", e)
	}
	snapshot, e := handle.Client.Call(ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if e != nil || snapshot.Snapshot == nil || snapshot.Snapshot.PID != 0 {
		t.Fatal("exact approval-held native process did not join", e)
	}
}
