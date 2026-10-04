//go:build linux || darwin

package fabricnative

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

type adapterFixtureFence struct {
	managedFixtureFence
	controls, reads *atomic.Int64
}

func (p adapterFixtureFence) WithNativeSourceRead(_ context.Context, f identity.NativeSourceReadFacts, next func() error) error {
	if p.reads != nil {
		p.reads.Add(1)
	}
	if f.Caller != f.Admission.OriginalCaller || f.Caller.Ref != "spiffe://managed/owner" || f.Caller.Issuer != "managed.fixture" {
		return fabric.NewError(fabric.CodeUnauthenticated, "fixture source caller differs")
	}
	return next()
}
func (adapterFixtureFence) WithNativeCancellation(_ context.Context, f identity.NativeCancellationFacts, next func() error) error {
	if f.Caller != f.Admission.OriginalCaller {
		return fabric.NewError(fabric.CodeUnauthenticated, "fixture cancel caller differs")
	}
	return next()
}
func (adapterFixtureFence) WithHistoricalNativeOrigin(_ context.Context, f identity.HistoricalNativeOriginFacts, next func(identity.Witness) error) error {
	return next(identity.Witness{Version: "fixture.history.v1", FinalizedDigest: f.Original.FinalizedDigest, Value: json.RawMessage(`{}`)})
}

func (p adapterFixtureFence) WithNativeControl(ctx context.Context, f identity.NativeControlFacts, next func() error) error {
	if p.controls != nil {
		p.controls.Add(1)
	}
	return p.managedFixtureFence.WithNativeControl(ctx, f, next)
}

type adapterResolver struct{ handle WorkerHandle }

func (r *adapterResolver) Resolve(_ context.Context, _ fabric.ExecutionContext, e fabric.EndpointDescriptor) (WorkerHandle, error) {
	if e.Ref != r.handle.Binding.Scope.Endpoint {
		return WorkerHandle{}, errors.New("fixture target differs")
	}
	return r.handle, nil
}
func (r *adapterResolver) Refresh(_ context.Context, _ fabric.ExecutionContext, s nativeauthority.Scope) (WorkerHandle, error) {
	if s != r.handle.Ownership {
		return WorkerHandle{}, errors.New("fixture ownership differs")
	}
	return r.handle, nil
}

type adapterRig struct {
	adapter         *Adapter
	resolver        *adapterResolver
	store           *registry.Store
	authority       *identity.Authority
	owner           fabric.ExecutionContext
	endpoint        fabric.EndpointDescriptor
	workspace       string
	ctx             context.Context
	controls, reads *atomic.Int64
}

func actualAdapterRig(t *testing.T, pressure ...bool) *adapterRig {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "pgn-managed-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
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
	t.Cleanup(func() { _ = store.Close() })
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
	controls, reads := &atomic.Int64{}, &atomic.Int64{}
	authority, err := identity.New(store, adapterFixtureFence{controls: controls, reads: reads})
	if err != nil {
		t.Fatal(err)
	}
	bindingScope := identity.Scope{Endpoint: endpoint, DescriptorRevision: rev, BindingID: "native"}
	A, err := authority.AcquireController(ctx, owner, bindingScope, 0, "managed-request-A", "managed-A")
	if err != nil {
		t.Fatal(err)
	}
	spec := sessionworker.NativeSpec{Kind: "local", Runtime: domain.RuntimeFakePersistent, Binary: native, MCPExecutable: binary, Workspace: workspace, LocalAuthorityDirectory: registryDir, LocalFabricSocket: filepath.Join(dir, "fabric.sock"), Env: []string{"PATH=/usr/bin:/bin", "HOME=" + workspace}}
	if len(pressure) > 0 && pressure[0] {
		spec.Env = append(spec.Env, "PAGNET_FAKE_FULL_OUTPUT=1", "PAGNET_FAKE_OUTPUT_CHUNK_BYTES=8")
	}
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
	t.Cleanup(func() { _ = cmd.Process.Signal(os.Interrupt); _ = cmd.Wait() })
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
	t.Cleanup(func() { _ = client.Close() })
	peers, err := NewManagedPeers(store, authority, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err = peers.Register(ctx, client, scope); err != nil {
		t.Fatal(err)
	}

	protectorKey := sha256.Sum256([]byte("actual adapter protected checkpoint key"))
	protector, e := durable.NewAESGCM(durable.KeyReference{ID: "adapter-fixture", Version: "1"}, protectorKey[:])
	if e != nil {
		t.Fatal(e)
	}
	checkpoints, e := NewCheckpoints(store, authority, owner, protector)
	if e != nil {
		t.Fatal(e)
	}
	resolver := &adapterResolver{WorkerHandle{Current: A, Binding: binding, Ownership: scope, Directory: state, ControlKey: key, Client: client}}
	adapter, e := NewAdapter(AdapterConfig{Authority: authority, Owner: owner, Checkpoints: checkpoints, ManagedPeers: peers, Workers: resolver})
	if e != nil {
		t.Fatal(e)
	}
	descriptor, e := store.GetEndpoint(ctx, endpoint, rev)
	if e != nil {
		t.Fatal(e)
	}
	return &adapterRig{adapter, resolver, store, authority, owner, descriptor, workspace, ctx, controls, reads}
}

type adapterAuthenticator struct{ principal fabric.Principal }

func (a adapterAuthenticator) Authenticate(_ context.Context, r fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	if r.PeerEvidence != "actual trusted fixture owner" {
		return fabric.ExecutionContext{}, errors.New("unverified fixture peer")
	}
	return fabric.NewAuthenticatedContext(a.principal, r.Audience, r.ExactEnvelope)
}

type adapterDispatcher struct {
	adapter *Adapter
	store   *registry.Store
}

func (d adapterDispatcher) Invoke(ctx context.Context, caller fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	e, err := d.store.GetEndpoint(ctx, r.Target, r.ExpectedRevision)
	if err != nil {
		return nil, err
	}
	return d.adapter.Invoke(ctx, caller, e, r)
}
func (r *adapterRig) execute(t *testing.T, id, input string, contexts ...context.Context) (node.Result, []byte, error) {
	t.Helper()
	deadline := time.Now().UTC().Add(30 * time.Second)
	principal := r.owner.PrincipalView()
	target := r.endpoint.Ref
	payload, _ := json.Marshal(struct {
		Input string `json:"input"`
	}{input})
	envelope := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: id, Operation: fabric.OperationInvoke, Principal: principal, Source: principal.Ref, Target: &target, ExpectedRevision: r.endpoint.Revision, CreatedAt: time.Now().UTC(), Payload: payload, Context: fabric.EnvelopeContext{Origin: principal.Ref, Deadline: &deadline}}
	exact, _ := json.Marshal(envelope)
	exact = append(exact, '\n')
	service, e := node.New(node.Config{Audience: r.store.Namespace(), Authenticator: adapterAuthenticator{principal}, Dispatcher: adapterDispatcher{r.adapter, r.store}})
	if e != nil {
		t.Fatal(e)
	}
	callCtx := r.ctx
	if len(contexts) > 0 {
		callCtx = contexts[0]
	}
	result, e := service.Execute(callCtx, exact, "actual trusted fixture owner")
	return result, exact, e
}
func TestActualNativeAdapterNodeCheckpointPullCompletionAndNoReplay(t *testing.T) {
	r := actualAdapterRig(t)
	result, exact, e := r.execute(t, "actual-adapter-original", "let adapter once")
	if e != nil {
		t.Fatal(e)
	}
	if result.Stream == nil {
		t.Fatal("No genuine source stream")
	}
	saved, _, e := r.adapter.config.Checkpoints.Load(r.ctx, r.owner.PrincipalView(), "actual-adapter-original")
	if e != nil || !bytes.Equal(saved.Original, exact) {
		t.Fatal("Original exact caller bytes were not checkpointed before ACK", e)
	}
	response, e := r.resolver.handle.Client.Call(r.ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if e != nil || response.Snapshot == nil || response.Snapshot.PID != 0 {
		t.Fatal("Native effect started before real origin", e)
	}
	var output bytes.Buffer
	started, completed := false, false
	for {
		frame, err := result.Stream.Next(r.ctx)
		if err != nil {
			t.Fatal("genuine parser stream", err)
		}
		switch frame.Kind {
		case fabric.FrameStart:
			started = true
		case fabric.FrameChunk:
			output.Write(frame.Data)
		case fabric.FrameError:
			t.Fatal("Native terminal failure", frame.Error)
		case fabric.FrameComplete:
			completed = true
		}
		if completed {
			break
		}
	}
	if !started || output.String() != "[fake-persist local-native] let adapter = once" {
		t.Fatal("Original parser output differs", output.Len(), started)
	}
	if e = result.Stream.Close(); e != nil {
		t.Fatal("Terminal exact ACK", e)
	}
	if r.controls.Load() != 1 || r.reads.Load() < 4 {
		t.Fatal("Repeated control admission or cached source permission", r.controls.Load(), r.reads.Load())
	}
	reservation, e := r.authority.LookupNativeDispatch(r.ctx, r.owner, saved.Admission, saved.OriginalBinding)
	if e != nil {
		t.Fatal(e)
	}
	page, e := r.resolver.handle.Client.Call(r.ctx, sessionworker.LocalRequest{Type: "stream_page", Control: &nativeauthority.LocalControl{CurrentController: r.resolver.handle.Current, CurrentBinding: r.resolver.handle.Binding}, Sequence: reservation.Sequence, Cursor: 2, Limit: 1})
	if e == nil && page.Stream != nil && page.Stream.Floor < 2 {
		t.Fatal("Terminal delivery was not ACKed")
	}
	recovered, e := r.adapter.Recover(r.ctx, r.owner, r.owner.PrincipalView(), "actual-adapter-original")
	if e != nil {
		t.Fatal("Source reconciliation", e)
	}
	if _, e = recovered.Next(r.ctx); e == nil || e == io.EOF {
		t.Fatal("Consumed stream silently replayed", e)
	}
	// Actual effect counter remains one despite retained-source reconciliation.
	response, e = r.resolver.handle.Client.Call(r.ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if e != nil || response.Snapshot == nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(r.resolver.handle.Directory, "native-state", "sessions", r.resolver.handle.Ownership.WorkerID(), "session.json"))
	if e != nil {
		t.Fatal(e)
	}
	var session struct {
		Turns int `json:"turns"`
	}
	if json.Unmarshal(raw, &session) != nil || session.Turns != 1 {
		t.Fatal("Native effect repeated", session.Turns)
	}
}
func TestNativeAdapterRejectsDirectContextBeforeAnyProvision(t *testing.T) {
	r := actualAdapterRig(t)
	request := fabric.InvokeRequest{InvocationID: "forged", Target: r.endpoint.Ref, ExpectedRevision: r.endpoint.Revision, Input: json.RawMessage(`{"input":"never"}`)}
	if _, e := r.adapter.Invoke(r.ctx, r.owner, r.endpoint, request); e == nil {
		t.Fatal("Caller assertions bypassed finalized node capability")
	}
	response, e := r.resolver.handle.Client.Call(r.ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if e != nil || response.Snapshot.PID != 0 {
		t.Fatal("Effect before private node admission", e)
	}
}

func TestActualNativeAdapterPrelaunchRestartCurrentBAcrossRename(t *testing.T) {
	r := actualAdapterRig(t)
	result, exact, e := r.execute(t, "adapter-recovery-original", "let recovered original-A")
	if e != nil {
		t.Fatal(e)
	}
	old := r.resolver.handle
	saved, _, e := r.adapter.config.Checkpoints.Load(r.ctx, r.owner.PrincipalView(), "adapter-recovery-original")
	if e != nil || !bytes.Equal(saved.Original, exact) {
		t.Fatal(e)
	}
	d := r.endpoint
	d.Name = "Renamed while source A was accepted"
	d.Revision = ""
	rev, e := r.store.Update(r.ctx, r.owner, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: r.endpoint.Revision})
	if e != nil {
		t.Fatal(e)
	}
	scope := old.Binding.Scope
	scope.DescriptorRevision = rev
	B, e := r.authority.AcquireController(r.ctx, r.owner, scope, old.Current.Epoch(), "adapter-currentB", "adapter-B")
	if e != nil {
		t.Fatal(e)
	}
	bindingB, e := r.authority.RenewWorkerBinding(r.ctx, r.owner, B, old.Binding)
	if e != nil {
		t.Fatal(e)
	}
	clientB, e := sessionworker.DialLocal(r.ctx, old.Directory, old.Ownership, old.ControlKey, "adapter-B")
	if e != nil {
		t.Fatal(e)
	}
	defer clientB.Close()
	r.resolver.handle = WorkerHandle{Current: B, Binding: bindingB, Ownership: old.Ownership, Directory: old.Directory, ControlKey: old.ControlKey, Client: clientB}
	restarted, e := NewAdapter(r.adapter.config)
	if e != nil {
		t.Fatal(e)
	}
	recovered, e := restarted.Recover(r.ctx, r.owner, r.owner.PrincipalView(), "adapter-recovery-original")
	if e != nil {
		t.Fatal(e)
	}
	var output bytes.Buffer
	for {
		frame, err := recovered.Next(r.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Kind == fabric.FrameChunk {
			output.Write(frame.Data)
		}
		if frame.Kind == fabric.FrameError {
			t.Fatal(frame.Error)
		}
		if frame.Kind == fabric.FrameComplete {
			break
		}
	}
	if output.String() != "[fake-persist local-native] let recovered = original-A" {
		t.Fatal("Recovered output differs", output.Len())
	}
	if e = recovered.Close(); e != nil {
		t.Fatal(e)
	}
	snapshot, e := clientB.Call(r.ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if e != nil || snapshot.Snapshot == nil || snapshot.Snapshot.Origin == nil {
		t.Fatal(e)
	}
	var origin identity.Origin
	if fabric.DecodeJSON(snapshot.Snapshot.Origin, &origin) != nil {
		t.Fatal("Malformed actual origin")
	}
	if origin.Scope != saved.Admission.Scope || origin.OriginalControllerEpoch != old.Current.Epoch() || origin.RegisteredControllerEpoch != B.Epoch() {
		t.Fatal("Original A source was rewritten")
	}
	_ = result.Stream.Close() // Abandoned original caller cannot schedule another effect.
	raw, e := os.ReadFile(filepath.Join(old.Directory, "native-state", "sessions", old.Ownership.WorkerID(), "session.json"))
	if e != nil {
		t.Fatal(e)
	}
	var session struct {
		Turns int `json:"turns"`
	}
	if json.Unmarshal(raw, &session) != nil || session.Turns != 1 {
		t.Fatal("Restart repeated paid turn", session.Turns)
	}
}

func TestActualNativeAdapterCloseStopsExactSourceWithoutCompletion(t *testing.T) {
	r := actualAdapterRig(t, true)
	result, _, e := r.execute(t, "adapter-cancel-source", strings.Repeat("genuine paid output ", 2048))
	if e != nil {
		t.Fatal(e)
	}
	frame, e := result.Stream.Next(r.ctx)
	if e != nil || frame.Kind != fabric.FrameStart {
		t.Fatal("No genuine native source start", e)
	}
	snapshot, e := r.resolver.handle.Client.Call(r.ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if e != nil || snapshot.Snapshot == nil || snapshot.Snapshot.PID <= 1 {
		t.Fatal("No actual native owner", e)
	}
	if e = result.Stream.Close(); e != nil {
		t.Fatal("Exact source cancellation rejected", e)
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		response, err := r.resolver.handle.Client.Call(r.ctx, sessionworker.LocalRequest{Type: "snapshot"})
		if err != nil {
			t.Fatal(err)
		}
		if response.Snapshot != nil && response.Snapshot.PID == 0 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("Native stop did not join actual source")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if _, e = result.Stream.Next(r.ctx); e == nil {
		t.Fatal("Closed stream fabricated result", e)
	}
}

func TestActualNativeAdapterCallerCancellationStopsOwnedSource(t *testing.T) {
	r := actualAdapterRig(t, true)
	callerCtx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	result, _, e := r.execute(t, "adapter-caller-cancel", strings.Repeat("genuine paid output ", 2048), callerCtx)
	if e != nil {
		t.Fatal(e)
	}
	frame, e := result.Stream.Next(r.ctx)
	if e != nil || frame.Kind != fabric.FrameStart {
		t.Fatal("No actual native Start", e)
	}
	cancel() // No Next or explicit Close is required to propagate caller lifetime.
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		response, e := r.resolver.handle.Client.Call(r.ctx, sessionworker.LocalRequest{Type: "snapshot"})
		if e != nil {
			t.Fatal(e)
		}
		if response.Snapshot != nil && response.Snapshot.PID == 0 {
			break
		}
		select {
		case <-timer.C:
			t.Fatal("Caller cancellation did not join original source")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if _, e = result.Stream.Next(r.ctx); e == nil {
		t.Fatal("Cancelled source fabricated completion")
	}
}

func TestActualNativeAdapterPrecancelledPullStopsPrelaunchWithoutEffect(t *testing.T) {
	r := actualAdapterRig(t)
	result, _, e := r.execute(t, "adapter-pre-cancelled", "let never native-effect")
	if e != nil {
		t.Fatal(e)
	}
	recovered, e := r.adapter.Recover(r.ctx, r.owner, r.owner.PrincipalView(), "adapter-pre-cancelled")
	if e != nil {
		t.Fatal(e)
	}
	cancelled, cancel := context.WithCancel(r.ctx)
	cancel()
	frame, e := recovered.Next(cancelled)
	var structured *fabric.Error
	if e == nil || frame.Kind == fabric.FrameComplete || !errors.As(e, &structured) || structured.Code != fabric.CodeCancelled || structured.Effect == fabric.EffectCompleted {
		t.Fatal("Pre-cancelled pull fabricated completion", e)
	}
	snapshot, e := r.resolver.handle.Client.Call(r.ctx, sessionworker.LocalRequest{Type: "snapshot"})
	if e != nil || snapshot.Snapshot == nil || snapshot.Snapshot.PID != 0 {
		t.Fatal("Pre-cancelled source launched native effect", e)
	}
	_ = result.Stream.Close()
}
