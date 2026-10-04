//go:build linux || darwin

package fabricnative

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
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

type managedFixtureFence struct{}

func (managedFixtureFence) WithAdmission(_ context.Context, f identity.AdmissionFacts, next func(identity.Witness) error) error {
	return next(identity.Witness{Version: "managed.actual-owner.v1", FinalizedDigest: f.FinalizedDigest, Value: json.RawMessage(`{}`)})
}
func (managedFixtureFence) WithNativeControl(_ context.Context, f identity.NativeControlFacts, next func() error) error {
	if f.Owner.Ref != "spiffe://managed/owner" || f.Owner.Issuer != "managed.fixture" {
		return fabric.NewError(fabric.CodeUnauthenticated, "fixture owner differs")
	}
	return next()
}

// This fixture crosses the actual process/IPC/parser boundary. Source identity,
// native PID, SID, nonce and generation are obtained from the real owned worker,
// never pre-seeded as assertions or replaced with the physical worker generation.
func TestActualManagedWorkerCurrentOriginAndRestartRegistration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "pgn-managed-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	binDir := filepath.Join(dir, "bin")
	workspace := filepath.Join(dir, "workspace")
	state := filepath.Join(dir, "worker")
	for _, p := range []string{binDir, workspace} {
		if err = os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(binDir, "pagnet")
	native := filepath.Join(binDir, "native")
	for _, build := range []struct{ path, pkg string }{{binary, "./cmd/pagnet"}, {native, "./cmd/pagnet-fake-runtime"}} {
		cmd := exec.CommandContext(ctx, "go", "build", "-o", build.path, build.pkg)
		cmd.Dir = root
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("real binary build: %v %s", e, b)
		}
	}
	principal := fabric.Principal{Ref: "spiffe://managed/owner", Kind: "local.owner", Issuer: "managed.fixture"}
	registryDir := filepath.Join(dir, "domain")
	store, err := registry.Bootstrap(ctx, registryDir, principal)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	owner, err := fabric.NewAuthenticatedContext(principal, store.Namespace(), []byte("trusted managed owner setup"))
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := fabric.NewEndpointRef(store.AuthorityIdentity().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rev, err := store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: endpoint, Kind: "agent.local", Name: "Actual offline native", Description: "Actual fixture", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := identity.New(store, managedFixtureFence{})
	if err != nil {
		t.Fatal(err)
	}
	bindingScope := identity.Scope{Endpoint: endpoint, DescriptorRevision: rev, BindingID: "native"}
	A, err := authority.AcquireController(ctx, owner, bindingScope, 0, "managed-request-A", "managed-A")
	if err != nil {
		t.Fatal(err)
	}
	spec := sessionworker.NativeSpec{Kind: "local", Runtime: domain.RuntimeFakePersistent, Binary: native, MCPExecutable: binary, Workspace: workspace, LocalAuthorityDirectory: registryDir, LocalFabricSocket: filepath.Join(dir, "fabric.sock"), Env: []string{"PATH=/usr/bin:/bin", "HOME=" + workspace}}
	profile, err := hex.DecodeString(sessionworker.LocalNativeProfileFingerprint(spec))
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], profile)
	worker := identity.WorkerBinding{WorkerID: "actual-managed-worker", StateDirectoryID: "actual-managed-state", OwnershipGeneration: "physical-ownership-A", ActualRuntime: string(spec.Runtime), ProfileDigest: digest}
	binding, err := authority.BindWorker(ctx, owner, A, 0, worker)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := nativeauthority.NewLocalScope(authority.Identity(), binding)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{73}, 32)
	if err = sessionworker.PrepareLocalBootstrap(state, sessionworker.LocalBootstrap{Protocol: sessionworker.LocalProtocol, Authority: scope, Native: spec}, key); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, sessionworker.Subcommand, "--state", state)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + workspace}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Signal(os.Interrupt); _ = cmd.Wait() }()
	socket, err := sessionworker.SocketPath(state)
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err = os.Lstat(socket); err == nil {
			break
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	client, err := sessionworker.DialLocal(ctx, state, scope, key, "managed-A")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { client.Close() }()
	peers, err := NewManagedPeers(store, authority, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err = peers.Register(ctx, client, scope); err != nil {
		t.Fatal(err)
	}
	kernel, err := client.OwnerProcess()
	if err != nil || kernel.PID != cmd.Process.Pid {
		t.Fatal("actual worker process", err)
	}
	if peers.ValidateOwner(ctx, kernel) == nil {
		t.Fatal("registered prelaunch worker became root owner")
	}
	if _, err = peers.ResolveManaged(ctx, fabrichost.ManagedSelector{Endpoint: endpoint, WorkerID: worker.WorkerID, Generation: worker.OwnershipGeneration}); err == nil {
		t.Fatal("physical ownership generation became native activation")
	}
	deadline := time.Now().UTC().Add(time.Minute)
	envelope := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "managed-native-original", Operation: fabric.OperationInvoke, Principal: principal, Source: principal.Ref, Target: &endpoint, ExpectedRevision: rev, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"input":"let actual once"}`), Context: fabric.EnvelopeContext{Origin: principal.Ref, Deadline: &deadline}}
	original, _ := json.Marshal(envelope)
	caller, err := fabric.NewAuthenticatedContext(principal, store.Namespace(), original)
	if err != nil {
		t.Fatal(err)
	}
	source, err := authority.Admit(ctx, owner, A, binding, caller, original, original, "managed-source-A", "attempt", "replay")
	if err != nil {
		t.Fatal(err)
	}
	controller, err := nativeauthority.NewLocalController(authority, owner, binding, nativeauthority.JSONPromptBinder{ProfileDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	_, err = controller.AdmitIntent(ctx, A, source, caller, original, original, func(c context.Context, i nativeauthority.VerifiedIntent) (identity.NativeIntentReceipt, error) {
		request := i.Request()
		r, e := client.Call(c, sessionworker.LocalRequest{Type: "intent", Intent: &request})
		if r.Receipt != nil {
			return *r.Receipt, e
		}
		return identity.NativeIntentReceipt{}, e
	})
	if err != nil {
		t.Fatal(err)
	}
	var ticket *sessionworker.LocalActivationRequest
	for ticket == nil {
		r, e := client.Call(ctx, sessionworker.LocalRequest{Type: "activation_poll"})
		if e != nil {
			t.Fatal(e)
		}
		ticket = r.Activation
		if ticket == nil {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	origin, err := authority.RegisterOrigin(ctx, owner, A, binding, source, caller, original, original, "actual-managed-origin", ticket.NativeGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Call(ctx, sessionworker.LocalRequest{Type: "activation_origin", ActivationOrigin: &sessionworker.LocalActivationOrigin{ID: ticket.ID, NativeGeneration: ticket.NativeGeneration, Origin: &origin}}); err != nil {
		t.Fatal(err)
	}
	var snapshot *sessionworker.LocalNativeSnapshot
	for {
		r, e := client.Call(ctx, sessionworker.LocalRequest{Type: "snapshot"})
		if e != nil {
			t.Fatal(e)
		}
		snapshot = r.Snapshot
		if snapshot != nil && snapshot.PID > 1 && !snapshot.IdentityPending && snapshot.NativeSessionID != "" && snapshot.ActivationNonce != "" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	nativeProcess, err := localpeer.ReadProcess(snapshot.PID)
	if err != nil {
		t.Fatal(err)
	}
	if peers.ValidateOwner(ctx, nativeProcess) == nil {
		t.Fatal("actual native descendant downgraded to owner")
	}
	selector := fabrichost.ManagedSelector{Endpoint: endpoint, WorkerID: worker.WorkerID, Generation: snapshot.NativeGeneration}
	ownershipSpoof := selector
	ownershipSpoof.Generation = worker.OwnershipGeneration
	if _, err = peers.ResolveManaged(ctx, ownershipSpoof); err == nil {
		t.Fatal("physical ownership generation accepted as live native selector")
	}
	activation, err := peers.ResolveManaged(ctx, selector)
	if err != nil {
		t.Fatal("actual native-generation selector rejected", err)
	}
	peer := fabricauth.ManagedPeer{Process: nativeProcess, Activation: activation, Root: store.AuthorityIdentity()}
	got, err := peers.ValidateManaged(ctx, peer)
	if err != nil || got.Ref != endpoint.String() || got == principal {
		t.Fatal("native identity became owner or failed", err)
	}
	for _, alter := range []func(*fabricauth.Activation){func(a *fabricauth.Activation) { a.Nonce = "stale" }, func(a *fabricauth.Activation) { a.NativeGeneration = "stale" }, func(a *fabricauth.Activation) { a.NativeSessionID = "stale" }} {
		bad := peer
		alter(&bad.Activation)
		if _, err = peers.ValidateManaged(ctx, bad); err == nil {
			t.Fatal("stale native source authenticated")
		}
	}
	// Simulate daemon restart: only genuine surviving worker IPC/kernel evidence
	// is re-registered, under a higher lease, before any owner listener is opened.
	fresh, err := sessionworker.DialLocal(ctx, state, scope, key, "managed-B")
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	client = fresh
	restarted, err := NewManagedPeers(store, authority, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.Register(ctx, client, scope); err != nil {
		t.Fatal(err)
	}
	if restarted.ValidateOwner(ctx, nativeProcess) == nil {
		t.Fatal("restart lost native descendant deny")
	}
	if _, err = restarted.ResolveManaged(ctx, selector); err != nil {
		t.Fatal("surviving genuine native source lost on adoption", err)
	}
	descriptor, err := store.GetEndpoint(ctx, endpoint, rev)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Name = "Renamed"
	descriptor.Revision = ""
	revB, err := store.Update(ctx, owner, fabric.RegistryUpdate{Descriptor: descriptor, ExpectedRevision: rev})
	if err != nil {
		t.Fatal(err)
	}
	scopeB := bindingScope
	scopeB.DescriptorRevision = revB
	B, err := authority.AcquireController(ctx, owner, scopeB, A.Epoch(), "managed-request-B", "managed-B")
	if err != nil {
		t.Fatal(err)
	}
	bindingB, err := authority.RenewWorkerBinding(ctx, owner, B, binding)
	if err != nil {
		t.Fatal(err)
	}
	control := nativeauthority.LocalControl{CurrentBinding: bindingB, CurrentController: B}
	if err = authority.FenceNativeControl(ctx, owner, B, bindingB, func(c context.Context) error {
		_, e := client.Call(c, sessionworker.LocalRequest{Type: "control", Control: &control})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	renamed, err := restarted.ResolveManaged(ctx, selector)
	if err != nil || renamed.Scope != activation.Scope || renamed.NativeGeneration != activation.NativeGeneration {
		t.Fatal("rename rewrote physical native identity", err)
	}
	if _, err = restarted.ValidateManaged(ctx, peer); err != nil {
		t.Fatal("same genuine source invalid after rename", err)
	}
	if _, err = authority.RetireOrigin(ctx, owner, origin, "actual source retired"); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.ResolveManaged(ctx, selector); err == nil {
		t.Fatal("retired origin authenticated")
	}
	if _, err = restarted.ValidateManaged(ctx, peer); err == nil {
		t.Fatal("retired peer authenticated")
	}
	if restarted.ValidateOwner(ctx, nativeProcess) == nil {
		t.Fatal("retirement downgraded surviving native to owner")
	}
}
