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
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

type resolverFixtureFence struct{ checkpointFence }

func (resolverFixtureFence) WithNativeControl(_ context.Context, f identity.NativeControlFacts, next func() error) error {
	if f.Owner.Ref != "spiffe://checkpoint/owner" {
		return checkpointDenied()
	}
	return next()
}
func (resolverFixtureFence) WithNativeSourceRead(_ context.Context, f identity.NativeSourceReadFacts, next func() error) error {
	if f.Caller != f.Admission.OriginalCaller {
		return checkpointDenied()
	}
	return next()
}
func (resolverFixtureFence) WithNativeCancellation(_ context.Context, f identity.NativeCancellationFacts, next func() error) error {
	if f.Caller != f.Admission.OriginalCaller {
		return checkpointDenied()
	}
	return next()
}
func (resolverFixtureFence) WithHistoricalNativeOrigin(_ context.Context, f identity.HistoricalNativeOriginFacts, next func(identity.Witness) error) error {
	return next(identity.Witness{Version: "actual.fixture.history.v1", FinalizedDigest: f.Original.FinalizedDigest, Value: json.RawMessage(`{}`)})
}

type resolverFixturePolicy struct {
	denied atomic.Bool
	owner  fabric.Principal
}

func (p *resolverFixturePolicy) WithCurrent(ctx context.Context, caller fabric.ExecutionContext, _ fabric.EndpointDescriptor, next func(context.Context) error) error {
	if p.denied.Load() || caller.PrincipalView() != p.owner {
		return checkpointDenied()
	}
	return next(ctx)
}

func TestActualResolverNodeInvocationRenameRestartAndCancellation(t *testing.T) {
	c, original, authorityDir := checkpointFixture(t, registry.DefaultOptions())
	a, err := identity.New(c.store, resolverFixtureFence{})
	if err != nil {
		t.Fatal(err)
	}
	c.authority = a
	dir, err := os.MkdirTemp("", "pgn-resolver-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	root, _ := filepath.Abs("../..")
	binDir := filepath.Join(dir, "bin")
	if err = os.MkdirAll(binDir, 0700); err != nil {
		t.Fatal(err)
	}
	binary, native := filepath.Join(binDir, "pagnet"), filepath.Join(binDir, "native")
	for _, b := range []struct{ path, pkg string }{{binary, "./cmd/pagnet"}, {native, "./cmd/pagnet-fake-runtime"}} {
		cmd := exec.CommandContext(t.Context(), "go", "build", "-o", b.path, b.pkg)
		cmd.Dir = root
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("actual build: %v %s", err, output)
		}
	}
	launch, peers := launcherBinding(t, c, original, binary, dir, authorityDir, "resolver-original")
	launch.Native.Binary = native
	current, binding, err := a.CurrentNativeState(t.Context(), c.owner, original.OriginalBinding.Scope)
	if err != nil {
		t.Fatal(err)
	}
	profileDigest, _ := hex.DecodeString(sessionworker.LocalNativeProfileFingerprint(launch.Native))
	copy(binding.Worker.ProfileDigest[:], profileDigest)
	binding, err = a.BindWorker(t.Context(), c.owner, current, binding.Proof.Revision, binding.Worker)
	if err != nil {
		t.Fatal(err)
	}
	launch.Ownership, err = nativeauthority.NewLocalScope(a.Identity(), binding)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := NewProfileStore(t.Context(), c.store, c.owner, c.protector)
	if err != nil {
		t.Fatal(err)
	}
	scope := registry.DescriptorBatchScope{Endpoint: binding.Scope.Endpoint, ExpectedEndpointRevision: binding.Scope.DescriptorRevision, BindingID: binding.Scope.BindingID}
	_, err = profiles.Put(t.Context(), scope, Profile{Native: launch.Native, Worker: binding.Worker, Directory: launch.Directory})
	if err != nil {
		t.Fatal(err)
	}
	launcher, err := NewLauncher(LauncherConfig{c, peers, binary, authorityDir, 10 * time.Second, 4})
	if err != nil {
		t.Fatal(err)
	}
	defer launcher.Close()
	credentials := &atomic.Int64{}
	policy := &resolverFixturePolicy{owner: c.owner.PrincipalView()}
	config := ResolverConfig{Authority: a, Owner: c.owner, Profiles: profiles, Launcher: launcher, ControllerBootID: "actual-resolver-boot-A", MaxWorkers: 4, Credentials: func(_ context.Context, names []string) ([]string, error) {
		credentials.Add(1)
		if len(names) != 1 || names[0] != "ACME_SESSION_CREDENTIAL" {
			return nil, checkpointDenied()
		}
		return launch.RuntimeEnvironment, nil
	}, Policy: policy}
	resolver, err := NewResolver(config)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	adapter, err := NewAdapter(AdapterConfig{Authority: a, Owner: c.owner, Checkpoints: c, ManagedPeers: peers, Workers: resolver})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := c.store.GetEndpoint(t.Context(), scope.Endpoint, scope.ExpectedEndpointRevision)
	if err != nil {
		t.Fatal(err)
	}
	rig := &adapterRig{adapter: adapter, store: c.store, authority: a, owner: c.owner, endpoint: descriptor, ctx: t.Context()}
	result, _, err := rig.execute(t, "resolver-genuine-original", "let adapter once")
	if err != nil {
		t.Fatal(err)
	}
	handle, err := resolver.Resolve(t.Context(), c.owner, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(handle.ControlKey)
	process, err := handle.Client.OwnerProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		child, _ := os.FindProcess(process.PID)
		_ = child.Signal(os.Interrupt)
		launcher.mu.Lock()
		reaped := launcher.processes[launch.Directory]
		launcher.mu.Unlock()
		if reaped != nil {
			select {
			case <-reaped.done:
			case <-time.After(5 * time.Second):
				_ = child.Kill()
				<-reaped.done
			}
		}
	}()
	var output bytes.Buffer
	for {
		frame, err := result.Stream.Next(t.Context())
		if err != nil {
			o, oe := handle.Client.Call(t.Context(), sessionworker.LocalRequest{Type: "outcome", Sequence: 1})
			if o.Outcome != nil {
				t.Logf("original outcome state=%s query=%v", o.Outcome.State, oe)
			}

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
	if output.String() != "[fake-persist local-native] let adapter = once" {
		t.Fatal("genuine original output differs", output.Len())
	}
	if err = result.Stream.Close(); err != nil {
		t.Fatal(err)
	}
	if credentials.Load() != 1 {
		t.Fatal("credential provider called for already retained worker")
	}
	repeated, err := resolver.Resolve(t.Context(), c.owner, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(repeated.ControlKey)
	if repeated.Current.Epoch() != handle.Current.Epoch() || repeated.Client != handle.Client {
		t.Fatal("healthy read renewed controller or IPC")
	}
	previous := descriptor.Revision
	descriptor.Revision = ""
	descriptor.Name = "Renamed original runtime"
	revision, err := c.store.Update(t.Context(), c.owner, fabric.RegistryUpdate{Descriptor: descriptor, ExpectedRevision: previous})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err = c.store.GetEndpoint(t.Context(), scope.Endpoint, revision)
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := resolver.Resolve(t.Context(), c.owner, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(renamed.ControlKey)
	if renamed.Ownership != handle.Ownership || renamed.Binding.Worker != handle.Binding.Worker || renamed.Current.Epoch() <= handle.Current.Epoch() {
		t.Fatal("rename replaced original physical authority")
	}
	// Retained binding configuration is immutable; a current CAS cannot
	// relocate the original worker by substituting private configuration.
	currentProfileScope := registry.DescriptorBatchScope{Endpoint: descriptor.Ref, ExpectedEndpointRevision: descriptor.Revision, BindingID: binding.Scope.BindingID, ExpectedProjectionRevision: 1}
	moved := Profile{Native: launch.Native, Worker: binding.Worker, Directory: filepath.Join(dir, "substituted-worker")}
	if _, err = profiles.Put(t.Context(), currentProfileScope, moved); err == nil {
		t.Fatal("physical profile relocated within immutable binding")
	}
	if _, err = os.Stat(moved.Directory); !os.IsNotExist(err) {
		t.Fatal("substituted directory was prepared")
	}
	rig.endpoint = descriptor
	cancelled, _, err := rig.execute(t, "resolver-real-cancel", "later native instruction")
	if err != nil {
		t.Fatal(err)
	}
	if err = cancelled.Stream.Close(); err != nil {
		t.Fatal("genuine source cancellation", err)
	}
	policy.denied.Store(true)
	if _, err = resolver.Refresh(t.Context(), c.owner, handle.Ownership); err == nil {
		t.Fatal("retained proof bypassed current caller policy")
	}
	policy.denied.Store(false)
	if err = resolver.Close(); err != nil {
		t.Fatal(err)
	}
	if err = c.store.Close(); err != nil {
		t.Fatal(err)
	}
	retained, err := registry.Open(t.Context(), authorityDir)
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	nextAuthority, err := identity.New(retained, resolverFixtureFence{})
	if err != nil {
		t.Fatal(err)
	}
	nextCheckpoints, err := NewCheckpoints(retained, nextAuthority, c.owner, c.protector)
	if err != nil {
		t.Fatal(err)
	}
	nextPeers, err := NewManagedPeers(retained, nextAuthority, c.owner)
	if err != nil {
		t.Fatal(err)
	}
	nextProfiles, err := NewProfileStore(t.Context(), retained, c.owner, c.protector)
	if err != nil {
		t.Fatal(err)
	}
	nextLauncher, err := NewLauncher(LauncherConfig{nextCheckpoints, nextPeers, binary, authorityDir, 10 * time.Second, 4})
	if err != nil {
		t.Fatal(err)
	}
	config.Authority = nextAuthority
	config.Profiles = nextProfiles
	config.Launcher = nextLauncher
	config.ControllerBootID = "actual-resolver-boot-B"
	recovered, err := NewResolver(config)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	adopted, err := recovered.Refresh(t.Context(), c.owner, handle.Ownership)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(adopted.ControlKey)
	fresh, err := adopted.Client.OwnerProcess()
	if err != nil || fresh.PID != process.PID || fresh.Start != process.Start || adopted.Ownership != handle.Ownership || adopted.Current.Epoch() <= renamed.Current.Epoch() {
		t.Fatal("restart did not adopt exact original worker", err)
	}
	if credentials.Load() != 1 {
		t.Fatal("restart reacquired or persisted provider credential")
	}
}

func TestResolverAmbiguousClaimNeverLaunchesOrReacquiresCredentials(t *testing.T) {
	for _, differentDirectory := range []bool{false, true} {
		name := "missing-original"
		if differentDirectory {
			name = "signed-directory-mismatch"
		}
		t.Run(name, func(t *testing.T) {

			c, value, authorityDir := checkpointFixture(t, registry.DefaultOptions())
			dir, err := os.MkdirTemp("", "pgn-resolver-unknown-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			launch, peers := launcherBinding(t, c, value, "/bin/true", dir, authorityDir, "ambiguous-original")
			local, _ := launch.Ownership.Local()
			_, binding, err := c.authority.CurrentNativeState(t.Context(), c.owner, identity.Scope{Endpoint: local.Endpoint, DescriptorRevision: local.DescriptorRevision, BindingID: local.BindingID})
			if err != nil {
				t.Fatal(err)
			}
			profiles, err := NewProfileStore(t.Context(), c.store, c.owner, c.protector)
			if err != nil {
				t.Fatal(err)
			}
			_, err = profiles.Put(t.Context(), registry.DescriptorBatchScope{Endpoint: local.Endpoint, ExpectedEndpointRevision: local.DescriptorRevision, BindingID: local.BindingID}, Profile{launch.Native, binding.Worker, launch.Directory})
			if err != nil {
				t.Fatal(err)
			}
			// A FULL launch claim exists but no original startup evidence is available.
			claimDirectory := launch.Directory
			if differentDirectory {
				claimDirectory = filepath.Join(dir, "original-claimed-location")
			}
			if _, err = c.BeginLaunch(t.Context(), launch.Ownership, "unknown-accepted-start", claimDirectory); err != nil {
				t.Fatal(err)
			}
			launcher, err := NewLauncher(LauncherConfig{c, peers, "/bin/true", authorityDir, time.Second, 1})
			if err != nil {
				t.Fatal(err)
			}
			var credentials atomic.Int64
			resolver, err := NewResolver(ResolverConfig{Authority: c.authority, Owner: c.owner, Profiles: profiles, Launcher: launcher, ControllerBootID: "unknown-controller", MaxWorkers: 1, Credentials: func(context.Context, []string) ([]string, error) { credentials.Add(1); return nil, nil }, Policy: &resolverFixturePolicy{owner: c.owner.PrincipalView()}})
			if err != nil {
				t.Fatal(err)
			}
			defer resolver.Close()
			d, err := c.store.GetEndpoint(t.Context(), local.Endpoint, local.DescriptorRevision)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = resolver.Resolve(t.Context(), c.owner, d); err == nil {
				t.Fatal("unknown claim authorized replacement")
			}
			if _, err = resolver.Refresh(t.Context(), c.owner, launch.Ownership); err == nil {
				t.Fatal("refresh invented original worker")
			}
			if credentials.Load() != 0 {
				t.Fatal("unknown retained claim acquired credentials")
			}
			if _, err = os.Stat(launch.Directory); !os.IsNotExist(err) {
				t.Fatal("unknown startup created bootstrap")
			}
			if len(launcher.processes) != 0 {
				t.Fatal("unknown original claim spawned")
			}

		})
	}
}

type heldResolverPolicy struct{ entered chan struct{} }

func (p heldResolverPolicy) WithCurrent(ctx context.Context, _ fabric.ExecutionContext, _ fabric.EndpointDescriptor, _ func(context.Context) error) error {
	close(p.entered)
	<-ctx.Done()
	return ctx.Err()
}
func TestResolverCloseJoinsCurrentPolicyBeforeRegistryShutdown(t *testing.T) {
	c, value, authorityDir := checkpointFixture(t, registry.DefaultOptions())
	peers, err := NewManagedPeers(c.store, c.authority, c.owner)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := NewProfileStore(t.Context(), c.store, c.owner, c.protector)
	if err != nil {
		t.Fatal(err)
	}
	launcher, err := NewLauncher(LauncherConfig{c, peers, "/bin/true", authorityDir, time.Second, 1})
	if err != nil {
		t.Fatal(err)
	}
	policy := heldResolverPolicy{entered: make(chan struct{})}
	resolver, err := NewResolver(ResolverConfig{Authority: c.authority, Owner: c.owner, Profiles: profiles, Launcher: launcher, ControllerBootID: "close-boundary", MaxWorkers: 1, Credentials: func(context.Context, []string) ([]string, error) {
		t.Error("cancelled policy requested credentials")
		return nil, nil
	}, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.store.GetEndpoint(t.Context(), value.OriginalBinding.Scope.Endpoint, value.OriginalBinding.Scope.DescriptorRevision)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := resolver.Resolve(t.Context(), c.owner, d); result <- err }()
	select {
	case <-policy.entered:
	case <-time.After(time.Second):
		t.Fatal("policy not entered")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err = resolver.CloseContext(ctx); err != nil {
		t.Fatal("genuine policy join", err)
	}
	if err = <-result; err != context.Canceled {
		t.Fatal("resolution was not canceled", err)
	}
	if _, err = resolver.Resolve(t.Context(), c.owner, d); err == nil {
		t.Fatal("closed resolver accepted current work")
	}
}

type resolverPolicyFunc func(context.Context, fabric.ExecutionContext, fabric.EndpointDescriptor, func(context.Context) error) error

func (f resolverPolicyFunc) WithCurrent(ctx context.Context, c fabric.ExecutionContext, d fabric.EndpointDescriptor, next func(context.Context) error) error {
	return f(ctx, c, d, next)
}
func TestResolverPolicyCannotSwallowSkipRepeatOrEscapeAdmission(t *testing.T) {
	for _, mode := range []string{"skip", "swallow-profile-error", "repeat", "escape"} {
		t.Run(mode, func(t *testing.T) {
			c, value, authorityDir := checkpointFixture(t, registry.DefaultOptions())
			peers, err := NewManagedPeers(c.store, c.authority, c.owner)
			if err != nil {
				t.Fatal(err)
			}
			profiles, err := NewProfileStore(t.Context(), c.store, c.owner, c.protector)
			if err != nil {
				t.Fatal(err)
			}
			launcher, err := NewLauncher(LauncherConfig{c, peers, "/bin/true", authorityDir, time.Second, 1})
			if err != nil {
				t.Fatal(err)
			}
			var escaped func(context.Context) error
			var calls atomic.Int64
			policy := resolverPolicyFunc(func(ctx context.Context, _ fabric.ExecutionContext, _ fabric.EndpointDescriptor, next func(context.Context) error) error {
				switch mode {
				case "skip":
					return nil
				case "escape":
					escaped = next
					return nil
				case "swallow-profile-error":
					_ = next(ctx)
					return nil
				case "repeat":
					_ = next(ctx)
					_ = next(ctx)
					return nil
				}
				return checkpointDenied()
			})
			resolver, err := NewResolver(ResolverConfig{Authority: c.authority, Owner: c.owner, Profiles: profiles, Launcher: launcher, ControllerBootID: "policy-check", MaxWorkers: 1, Credentials: func(context.Context, []string) ([]string, error) { calls.Add(1); return nil, nil }, Policy: policy})
			if err != nil {
				t.Fatal(err)
			}
			d, err := c.store.GetEndpoint(t.Context(), value.OriginalBinding.Scope.Endpoint, value.OriginalBinding.Scope.DescriptorRevision)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := resolver.Resolve(t.Context(), c.owner, d)
			if err == nil || handle.Client != nil || len(handle.ControlKey) != 0 {
				t.Fatal("invalid policy manufactured admission")
			}
			if err = resolver.CloseContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			if escaped != nil && escaped(t.Context()) == nil {
				t.Fatal("late callback accessed released resolver entry")
			}
			if calls.Load() != 0 || len(launcher.processes) != 0 {
				t.Fatal("invalid policy reached credentials or process")
			}
		})
	}
}
func TestOnceCurrentPolicyPreservesFailureAndRejectsRepeatedSuccessfulCallback(t *testing.T) {
	var steps atomic.Int64
	for _, mode := range []string{"repeated-success", "swallowed-step-failure"} {
		t.Run(mode, func(t *testing.T) {
			steps.Store(0)
			err := onceCurrentPolicy(t.Context(), func(next func(context.Context) error) error {
				_ = next(t.Context())
				if mode == "repeated-success" {
					_ = next(t.Context())
				}
				return nil
			}, func(context.Context) error {
				steps.Add(1)
				if mode == "swallowed-step-failure" {
					return checkpointDenied()
				}
				return nil
			})
			if err == nil || steps.Load() != 1 {
				t.Fatal("policy violated once-only step admission", steps.Load(), err)
			}
		})
	}
}
