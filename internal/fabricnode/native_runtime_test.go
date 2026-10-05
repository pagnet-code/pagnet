//go:build linux || darwin

package fabricnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricnative"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// Explicit test operator policy; production composition has no default grants.
type nativeRuntimePolicy struct{ principal fabric.Principal }

func (p nativeRuntimePolicy) WithCurrent(ctx context.Context, c fabric.ExecutionContext, _ fabric.EndpointDescriptor, n func(context.Context) error) error {
	if c.PrincipalView() != p.principal {
		return fabric.NewError(fabric.CodeUnauthenticated, "caller denied")
	}
	return n(ctx)
}
func (p nativeRuntimePolicy) WithCurrentOwner(ctx context.Context, c fabric.ExecutionContext, n func(context.Context) error) error {
	if c.PrincipalView() != p.principal {
		return fabric.NewError(fabric.CodeUnauthenticated, "owner denied")
	}
	return n(ctx)
}
func (p nativeRuntimePolicy) WithAdmission(_ context.Context, f identity.AdmissionFacts, n func(identity.Witness) error) error {
	return n(identity.Witness{Version: "node.fixture.v1", FinalizedDigest: f.FinalizedDigest, Value: json.RawMessage(`{}`)})
}
func (p nativeRuntimePolicy) WithNativeControl(_ context.Context, f identity.NativeControlFacts, n func() error) error {
	if f.Owner != p.principal {
		return fabric.NewError(fabric.CodeUnauthenticated, "control denied")
	}
	return n()
}
func (p nativeRuntimePolicy) WithNativeSourceRead(_ context.Context, f identity.NativeSourceReadFacts, n func() error) error {
	if f.Caller != p.principal || f.Caller != f.Admission.OriginalCaller {
		return fabric.NewError(fabric.CodeUnauthenticated, "source denied")
	}
	return n()
}
func (p nativeRuntimePolicy) WithNativeCancellation(_ context.Context, f identity.NativeCancellationFacts, n func() error) error {
	if f.Caller != p.principal || f.Caller != f.Admission.OriginalCaller {
		return fabric.NewError(fabric.CodeUnauthenticated, "cancel denied")
	}
	return n()
}
func (p nativeRuntimePolicy) WithHistoricalNativeOrigin(_ context.Context, f identity.HistoricalNativeOriginFacts, n func(identity.Witness) error) error {
	return n(identity.Witness{Version: "node.history.v1", FinalizedDigest: f.Original.FinalizedDigest, Value: json.RawMessage(`{}`)})
}

type nativeRuntimeAdmission struct{ principal fabric.Principal }

func (p nativeRuntimeAdmission) WithDispatch(ctx context.Context, c fabric.ExecutionContext, original, final []byte, d fabric.EndpointDescriptor, _ *fabric.OfferDescriptor, s dispatch.Selection, n func(context.Context) (fabric.InvocationStream, error)) (fabric.InvocationStream, error) {
	if c.PrincipalView() != p.principal || c.VerifyAuthenticated(d.Ref.Domain()) != nil || len(original) == 0 || len(final) == 0 || s.BindingID != "native" {
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "dispatch denied")
	}
	return n(ctx)
}
func runtimeOwnerSession(t *testing.T, ctx context.Context, r *NativeRuntime, socket string) (*fabricauth.Session, func()) {
	t.Helper()
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(socket, 0600); e != nil {
		t.Fatal(e)
	}
	client, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	server, e := listener.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	factory, e := r.Authenticator.BindOwner(ctx, server)
	if e != nil {
		t.Fatal("kernel owner", e)
	}
	return factory, func() { factory.Close(); server.Close(); client.Close(); listener.Close() }
}
func TestNativeRuntimeActualNodeOriginalCaptureRestartAndMissingWorker(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	private, e := os.MkdirTemp("", "pgn-native-node-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(private)
	rootDir, _ := filepath.Abs("../..")
	binDir := filepath.Join(private, "bin")
	if e = os.Mkdir(binDir, 0700); e != nil {
		t.Fatal(e)
	}
	binary, native := filepath.Join(binDir, "pagnet"), filepath.Join(binDir, "native")
	for _, b := range []struct{ path, pkg string }{{binary, "./cmd/pagnet"}, {native, "./cmd/pagnet-fake-runtime"}} {
		cmd := exec.CommandContext(ctx, "go", "build", "-o", b.path, b.pkg)
		cmd.Dir = rootDir
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("build: %v %s", e, out)
		}
	}
	dir, socket, workspace := filepath.Join(private, "domain"), filepath.Join(private, "fabric.sock"), filepath.Join(private, "workspace")
	if e = os.Mkdir(workspace, 0700); e != nil {
		t.Fatal(e)
	}
	principal := fabric.Principal{Ref: "local:native-node-owner", Kind: "local.owner", Issuer: "native-node.fixture"}
	bootstrap, e := registry.Bootstrap(ctx, dir, principal)
	if e != nil {
		t.Fatal(e)
	}
	retained := bootstrap.AuthorityIdentity()
	bootstrap.Close()
	// Only the fixture setup supplies this capability; no constructor mints one.
	owner, e := fabric.NewAuthenticatedContext(principal, retained.Namespace, []byte("trusted fixture operator setup"))
	if e != nil {
		t.Fatal(e)
	}
	secret := sha256.Sum256([]byte("operator supplied stable key"))
	protector, e := durable.NewAESGCM(durable.KeyReference{ID: "operator-key", Version: "1"}, secret[:])
	if e != nil {
		t.Fatal(e)
	}
	policy := nativeRuntimePolicy{principal}
	credentials := &atomic.Int64{}
	c := NativeRuntimeConfig{Owner: owner, Fence: policy, Protector: protector, Admission: nativeRuntimeAdmission{principal}, Policy: policy, StartupPolicy: policy, Credentials: func(context.Context, []string) ([]string, error) { credentials.Add(1); return nil, nil }, Binary: binary, AuthorityDirectory: dir, SocketPath: socket, ControllerBootID: "native-node-A", MaxWorkers: 4, MaxStartupMetadataBytes: 1 << 20, StartupTimeout: 10 * time.Second}
	var runtime *NativeRuntime
	config := Config{Directory: dir, Compose: func(ctx context.Context, s *registry.Store, _ *search.Backend) (Ports, error) {
		var err error
		runtime, err = NewNativeRuntime(ctx, s, c)
		if err != nil {
			return Ports{}, err
		}
		return runtime.Ports(), nil
	}}
	n, e := Open(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	defer n.Close()
	if !runtime.Authenticator.SupportsManaged() {
		t.Fatal("managed classification missing")
	}

	for _, mode := range []string{"missing-admission", "missing-current-policy", "missing-credentials", "foreign-owner", "socket-inside-authority", "substituted-authority-directory"} {
		bad := c
		switch mode {
		case "missing-admission":
			bad.Admission = nil
		case "missing-current-policy":
			bad.Policy = nil
		case "missing-credentials":
			bad.Credentials = nil
		case "foreign-owner":
			bad.Owner, e = fabric.NewAuthenticatedContext(fabric.Principal{Ref: "local:foreign", Kind: "local.owner", Issuer: "native-node.fixture"}, retained.Namespace, []byte("foreign fixture"))
			if e != nil {
				t.Fatal(e)
			}
		case "socket-inside-authority":
			bad.SocketPath = filepath.Join(dir, "unsafe.sock")
		case "substituted-authority-directory":
			bad.AuthorityDirectory = filepath.Join(private, "unprotected-root")
		}
		denied, err := NewNativeRuntime(ctx, n.Store, bad)
		if err == nil || denied != nil {
			if denied != nil {
				denied.Close()
			}
			t.Fatal("unsafe composition accepted", mode)
		}
		if _, err := n.Store.CurrentAuthorityIdentity(ctx); err != nil {
			t.Fatal("denied constructor closed caller's store", mode, err)
		}
	}
	ref, _ := fabric.NewEndpointRef(retained.PublicKey)
	revision, e := n.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "agent.local", Name: "Original native", Description: "Actual original capture", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if e != nil {
		t.Fatal(e)
	}
	scope := identity.Scope{Endpoint: ref, DescriptorRevision: revision, BindingID: "native"}
	controller, e := runtime.Authority.AcquireController(ctx, owner, scope, 0, "installed-controller", "installed-request")
	if e != nil {
		t.Fatal(e)
	}
	spec := sessionworker.NativeSpec{Kind: "local", Runtime: domain.RuntimeFakePersistent, Binary: native, MCPExecutable: binary, Workspace: workspace, LocalAuthorityDirectory: dir, LocalFabricSocket: socket, Env: []string{"PATH=/usr/bin:/bin", "HOME=" + workspace}}
	raw, e := hex.DecodeString(sessionworker.LocalNativeProfileFingerprint(spec))
	if e != nil {
		t.Fatal(e)
	}
	worker := identity.WorkerBinding{WorkerID: "real-worker", StateDirectoryID: "real-state", OwnershipGeneration: "real-physical-A", ActualRuntime: string(spec.Runtime)}
	copy(worker.ProfileDigest[:], raw)
	binding, e := runtime.Authority.BindWorker(ctx, owner, controller, 0, worker)
	if e != nil {
		t.Fatal(e)
	}
	directory := filepath.Join(private, "original-worker")
	_, e = runtime.Profiles.Put(ctx, registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "native"}, fabricnative.Profile{Native: spec, Worker: binding.Worker, Directory: directory})
	if e != nil {
		t.Fatal(e)
	}
	factory, closeSession := runtimeOwnerSession(t, ctx, runtime, socket)
	defer closeSession()
	deadline := time.Now().UTC().Add(30 * time.Second)
	exact, evidence, e := factory.Build(ctx, mcpbridge.Call{Operation: fabric.OperationInvoke, Invoke: &fabric.InvokeRequest{Target: ref, ExpectedRevision: revision, Input: json.RawMessage(`{"input":"let actual once"}`), Deadline: &deadline}})
	if e != nil {
		t.Fatal(e)
	}
	result, e := n.Service.Execute(ctx, exact, evidence)
	if e != nil {
		t.Fatal("real invocation", e)
	}
	var output bytes.Buffer
	for {
		f, e := result.Stream.Next(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if f.Kind == fabric.FrameError {
			t.Fatal(f.Error)
		}
		if f.Kind == fabric.FrameChunk {
			output.Write(f.Data)
		}
		if f.Kind == fabric.FrameComplete {
			break
		}
	}
	if output.String() != "[fake-persist local-native] let actual = once" {
		t.Fatal("original output differs", output.Len())
	}
	if e = result.Stream.Close(); e != nil {
		t.Fatal(e)
	}
	d, e := n.Store.GetEndpoint(ctx, ref, revision)
	if e != nil {
		t.Fatal(e)
	}
	original, e := runtime.Resolver.Resolve(ctx, owner, d)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(original.ControlKey)
	physical, e := original.Client.OwnerProcess()
	if e != nil {
		t.Fatal(e)
	}
	child, _ := os.FindProcess(physical.PID)
	defer child.Signal(os.Interrupt)
	before, e := original.Client.Call(ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if e != nil || before.Snapshot == nil || before.Snapshot.PID == 0 || before.Snapshot.NativeSessionID == "" {
		t.Fatal("no genuine native session", e)
	}
	var envelope fabric.Envelope
	if e = fabric.DecodeJSON(exact, &envelope); e != nil {
		t.Fatal(e)
	}
	saved, _, e := runtime.Checkpoints.Load(ctx, principal, envelope.ID)
	if e != nil || !bytes.Equal(saved.Original, exact) {
		t.Fatal("source checkpoint changed", e)
	}
	if e = runtime.CloseContext(ctx); e != nil {
		t.Fatal("runtime shutdown did not join", e)
	}
	if _, _, e = factory.Build(ctx, mcpbridge.Call{Operation: fabric.OperationDiscover, Discover: &fabric.DiscoverRequest{Query: "native", Limit: 1}}); e == nil {
		t.Fatal("closed runtime still authenticated owner")
	}
	closeSession()
	if e = n.Close(); e != nil {
		t.Fatal(e)
	}
	c.ControllerBootID = "native-node-B"
	reopened, e := Open(ctx, config)
	if e != nil {
		t.Fatal("adoption", e)
	}
	defer reopened.Close()
	if runtime.Authority.Identity().StoreID != retained.StoreID {
		t.Fatal("root replaced")
	}
	adopted, e := runtime.Resolver.Resolve(ctx, owner, d)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(adopted.ControlKey)
	actual, e := adopted.Client.OwnerProcess()
	if e != nil || actual != physical || adopted.Directory != directory || adopted.Ownership != original.Ownership {
		t.Fatal("original worker replaced", e)
	}
	after, e := adopted.Client.Call(ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if e != nil || after.Snapshot == nil || after.Snapshot.NativeSessionID != before.Snapshot.NativeSessionID || after.Snapshot.PID != before.Snapshot.PID {
		t.Fatal("native session changed", e)
	}
	saved, _, e = runtime.Checkpoints.Load(ctx, principal, envelope.ID)
	if e != nil || !bytes.Equal(saved.Original, exact) {
		t.Fatal("source lost on restart", e)
	}
	if runtime.Peers.ValidateOwner(ctx, actual) == nil {
		t.Fatal("worker accepted as owner")
	}
	if credentials.Load() != 1 {
		t.Fatal("restart replayed credential/launch")
	}
	if e = reopened.Close(); e != nil {
		t.Fatal(e)
	}
	if e = child.Signal(os.Interrupt); e != nil {
		t.Fatal(e)
	}
	// Kernel birth check only; no fabricated native completion/state mutation.
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		if live, err := localpeer.ReadProcess(physical.PID); err != nil || live.Start != physical.Start {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if live, err := localpeer.ReadProcess(physical.PID); err == nil && live.Start == physical.Start {
		t.Fatal("original worker still live")
	}
	c.ControllerBootID = "native-node-C"
	runtime = nil
	missing, e := Open(ctx, config)
	if e == nil || missing != nil || runtime != nil {
		if missing != nil {
			missing.Close()
		}
		t.Fatal("missing worker exposed authentication")
	}
	verify, e := registry.Open(ctx, dir)
	if e != nil {
		t.Fatal("failed startup retained writer", e)
	}
	defer verify.Close()
	if verify.AuthorityIdentity().StoreID != retained.StoreID {
		t.Fatal("failed recovery regenerated root")
	}
}
