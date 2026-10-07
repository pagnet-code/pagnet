//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"errors"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func nativeRegistryFixture(t *testing.T) (*NativeWorkerRegistry, sessionworker.Scope, sessionworker.NativeSpec) {
	t.Helper()
	root, err := os.MkdirTemp("", "pgn-reg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(root, strings.Repeat("long-owner-state-", 8))
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	r, err := OpenNativeWorkerRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	s := sessionworker.Scope{ServerURL: "https://example.test", TenantID: domain.NewID().String(), AccountID: domain.NewID().String(), HostID: domain.NewID().String(), InstanceID: domain.NewID().String(), Generation: domain.NewID().String()}
	spec := sessionworker.NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: "/bin/true", MCPExecutable: "/bin/true", Workspace: t.TempDir(), Kind: "worker", TenantID: s.TenantID, NetworkTenantID: s.TenantID, NetworkID: domain.NewID().String(), Env: []string{"TEST_SECRET=never-persist"}}
	return r, s, spec
}
func TestNativeWorkerRegistryDurableOriginalAuthority(t *testing.T) {
	r, s, spec := nativeRegistryFixture(t)
	record, err := r.Reserve(s, spec, "original", "")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Owns(s.InstanceID) || record.Dir != r.Dir(s) || len(record.Spec.Env) != 0 {
		t.Fatal("original authority or secret isolation missing")
	}
	reopened, err := OpenNativeWorkerRegistry(filepath.Dir(r.root))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, err := reopened.Lookup(s.InstanceID)
	if err != nil || loaded.Scope != s || loaded.ProfileFingerprint != record.ProfileFingerprint {
		t.Fatal("durable discovery failed", err)
	}
	wrong := s
	wrong.Generation = domain.NewID().String()
	if _, err := r.Reserve(wrong, spec, "original", ""); err == nil {
		t.Fatal("original generation replaced")
	}
	changed := spec
	changed.Model = "replacement"
	if _, err := r.Reserve(s, changed, "original", ""); err == nil {
		t.Fatal("original profile replaced")
	}
	ownership := transport.NativeWorkerOwnership{ID: domain.NewID().String(), OriginalAdmissionID: domain.NewID().String(), InstanceID: s.InstanceID, OwnershipGeneration: s.Generation, Runtime: string(spec.Runtime), Profile: "original", ProfileFingerprint: record.ProfileFingerprint, State: "active"}
	if err := r.BindOwnership(record, ownership); err != nil {
		t.Fatal(err)
	}
	if err := r.BindOwnership(record, ownership); err != nil {
		t.Fatal("identical receipt not idempotent", err)
	}
	advanced := ownership
	advanced.LastDispatchSequence = 4
	advanced.RetiredFloor = 2
	if err := r.BindOwnership(record, advanced); err != nil {
		t.Fatal("fresh server receipt rejected", err)
	}
	if err := r.BindOwnership(record, ownership); err == nil {
		t.Fatal("server receipt regression accepted")
	}
	changedAdmission := advanced
	changedAdmission.OriginalAdmissionID = domain.NewID().String()
	if err := r.BindOwnership(record, changedAdmission); err == nil {
		t.Fatal("original admission mutated")
	}
	ownership.ID = domain.NewID().String()
	if err := r.BindOwnership(record, ownership); err == nil {
		t.Fatal("original ownership mutated")
	}
	rows, err := r.List()
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(r.root, "registry.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("never-persist")) {
		t.Fatal("runtime secret persisted")
	}
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(filepath.Dir(r.root), link); err != nil {
		t.Fatal(err)
	}
	if bad, err := OpenNativeWorkerRegistry(link); err == nil {
		bad.Close()
		t.Fatal("symlinked namespace accepted")
	}
}
func TestNativeWorkerDetachedLaunchAndAuthenticatedAdoption(t *testing.T) {
	if root := os.Getenv("PAGNET_REGISTRY_CHILD_STATE"); root != "" {
		registry, err := OpenNativeWorkerRegistry(root)
		if err != nil {
			os.Exit(10)
		}
		record, err := registry.Lookup(os.Getenv("PAGNET_REGISTRY_CHILD_INSTANCE"))
		if err != nil {
			os.Exit(11)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := EnsureNativeWorker(ctx, registry, record, os.Getenv("PAGNET_REGISTRY_CHILD_BINARY"), []string{"TEST_SECRET=never-persist"}, ""); err != nil {
			os.Exit(12)
		}
		os.Exit(0) // original launching controller exits; worker must survive
	}

	r, s, spec := nativeRegistryFixture(t)
	binary := filepath.Join(t.TempDir(), "pagnet")
	build := exec.Command("go", "build", "-o", binary, "./cmd/pagnet")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "GOWORK=off")
	if err := build.Run(); err != nil {
		t.Fatal("worker build failed", err)
	}
	record, err := r.Reserve(s, spec, "", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	launcher := exec.Command(os.Args[0], "-test.run=^TestNativeWorkerDetachedLaunchAndAuthenticatedAdoption$")
	launcher.Env = append(os.Environ(), "PAGNET_REGISTRY_CHILD_STATE="+filepath.Dir(r.root), "PAGNET_REGISTRY_CHILD_INSTANCE="+s.InstanceID, "PAGNET_REGISTRY_CHILD_BINARY="+binary)
	if err := launcher.Run(); err != nil {
		t.Fatal("original launch controller failed", err)
	}
	b, key, err := sessionworker.LoadControllerBootstrap(record.Dir, s)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	a, err := sessionworker.DialOwnerController(ctx, record.Dir, s, key, "controller-A")
	if err != nil {
		t.Fatal(err)
	}
	originalBuild := a.WorkerBuild
	guard, err := NewHostedOwnerGuard(func(context.Context, localpeer.ProcessSnapshot) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	// Classification is taken from the actual mutually authenticated detached
	// owner socket, before any native child. This fixture starts no paid turn.
	if err = guard.Register(&NativeWorkerProxy{controller: a, scope: s}); err != nil {
		t.Fatal("genuine original worker owner fence", err)
	}
	hostedDaemon := &Daemon{Config: Config{HostedOwnerGuard: guard}, nativeRegistry: r}
	if err = hostedDaemon.HostedOwnerGuardReady(ctx, guard); err != nil {
		t.Fatal("actual detached owner not ready", err)
	}
	workerRoot, err := a.OwnerProcess()
	if err != nil || guard.Validate(ctx, workerRoot) == nil {
		t.Fatal("real detached worker entered owner mode", err)
	}
	// Lifecycle cleanup signals only the mutually authenticated worker through
	// its original bootstrap process identity (PID inspected via private socket).
	socket, err := sessionworker.SocketPath(record.Dir)
	if err != nil || len(socket) >= 104 {
		t.Fatal("original endpoint not bounded", err)
	}
	peer, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	workerPID, _, err := localpeer.Owner(peer)
	_ = peer.Close()
	if err != nil || workerPID <= 0 {
		t.Fatal("worker peer proof unavailable", err)
	}
	t.Cleanup(func() { _ = syscall.Kill(workerPID, syscall.SIGTERM) })
	pgid, err := syscall.Getpgid(workerPID)
	if err != nil || pgid != workerPID {
		t.Fatal("worker did not own detached process group", err)
	}
	if b.Native.Env != nil {
		t.Fatal("credential environment persisted in bootstrap")
	}
	if _, err := a.Call(ctx, sessionworker.Request{Type: "snapshot"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err = hostedDaemon.HostedOwnerGuardReady(ctx, guard); err != nil || guard.Validate(ctx, workerRoot) == nil {
		t.Fatal("controller disconnect released original live worker fence", err)
	}
	cancel() // controller lifetime cancellation must not terminate detached owner
	fresh, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	reopened, err := OpenNativeWorkerRegistry(filepath.Dir(r.root))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered, err := reopened.Lookup(s.InstanceID)
	if err != nil || recovered.LaunchState != "launched" {
		t.Fatal("launch state not durable", err)
	}
	if err := EnsureNativeWorker(fresh, reopened, recovered, binary, spec.Env, ""); err != nil {
		t.Fatal(err)
	}
	replacement, err := sessionworker.DialOwnerController(fresh, recovered.Dir, s, key, "controller-B")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	nextPeer, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	nextPID, _, err := localpeer.Owner(nextPeer)
	_ = nextPeer.Close()
	if err != nil || nextPID != workerPID {
		t.Fatal("controller replacement relaunched original worker", err)
	}
	if replacement.WorkerBuild != originalBuild {
		t.Fatal("original worker silently replaced")
	}
	if _, err := replacement.Call(fresh, sessionworker.Request{Type: "snapshot"}); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), key...)
	bad[0] ^= 1
	if foreign, err := sessionworker.DialOwnerController(fresh, recovered.Dir, s, bad, "wrong-key"); err == nil {
		foreign.Close()
		t.Fatal("unauthenticated adoption accepted")
	}
	if _, err := replacement.Call(fresh, sessionworker.Request{Type: "snapshot"}); err != nil {
		t.Fatal("failed authentication evicted owner", err)
	}
}

func TestNativeWorkerCanceledEnvironmentPipeClearsOnlyAfterWriter(t *testing.T) {
	r, s, spec := nativeRegistryFixture(t)
	binary := filepath.Join(t.TempDir(), "stalled-private-worker")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexec sleep 0.3\n"), 0700); err != nil {
		t.Fatal(err)
	}
	record, err := r.Reserve(s, spec, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// This subprocess never reads fd3. A frame larger than pipe capacity leaves
	// the writer genuinely blocked when cancellation clears private memory.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err = EnsureNativeWorker(ctx, r, record, binary, []string{"PRIVATE_FIXTURE=" + strings.Repeat("s", 120<<10)}, "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("stalled private pipe did not cancel safely", err)
	}
	loaded, err := r.Lookup(s.InstanceID)
	if err != nil || loaded.LaunchState != "launched" {
		t.Fatal("cancellation made original owner replaceable", err)
	}
	// The synthetic child exits naturally; the helper never kills uncertain PIDs.
	time.Sleep(320 * time.Millisecond)
}

// TestNativeWorkerFabricSideportInPrivatePipe pins the sideport pair's
// placement in the env-fd pipe payload (bootstrap.Native.Env source): it
// reaches the detached worker exactly when the daemon has the fused
// node's sideport socket configured. The pair is a pagnet-internal
// injection appended AFTER the ChildEnv filter — it never travels through
// the operator runtime-env pairs (ValidateExtraEnv rejects the PAGNET_*
// key except this one documented exception), so the daemon config, not the
// runtime env, decides its presence.
func TestNativeWorkerFabricSideportInPrivatePipe(t *testing.T) {
	const sideport = "/h/.pagnet/run/fabric/local.sock"
	for _, tc := range []struct {
		name   string
		socket string
	}{
		{"sideport set", sideport},
		{"sideport unset", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, s, spec := nativeRegistryFixture(t)
			marker := filepath.Join(t.TempDir(), "pipe-payload")
			binary := filepath.Join(t.TempDir(), "sideport-probe")
			// The probe dumps the private env-fd payload and exits. It never
			// creates the readiness socket, so EnsureNativeWorker is expected
			// to time out AFTER the payload has crossed the pipe.
			if err := os.WriteFile(binary, []byte("#!/bin/sh\ncat < /dev/fd/3 > "+marker+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			record, err := r.Reserve(s, spec, "", "")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			if err := EnsureNativeWorker(ctx, r, record, binary, spec.Env, tc.socket); err == nil {
				t.Fatal("readiness wait succeeded although the probe never creates a socket")
			}
			data, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal("probe did not capture the pipe payload", err)
			}
			present := bytes.Contains(data, []byte("PAGNET_FABRIC_SIDEPORT="+sideport))
			if tc.socket == "" {
				if present {
					t.Fatal("sideport pair rendered into the pipe payload without a configured socket")
				}
			} else if !present {
				t.Fatalf("pipe payload lacks the sideport pair: %s", data)
			}
		})
	}
}

func TestNativeWorkerRegistryAcceptsSafeParentWithoutChangingPermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0755, 0777} {
		parent := t.TempDir()
		if err := os.Chmod(parent, mode); err != nil {
			t.Fatal(err)
		}
		registry, err := OpenNativeWorkerRegistry(parent)
		if mode == 0777 {
			if err == nil {
				registry.Close()
				t.Fatal("writable daemon state parent accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal("safe existing daemon parent refused", err)
		}
		defer registry.Close()
		info, err := os.Stat(parent)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("daemon parent permissions silently changed", err)
		}
		child, err := os.Stat(registry.root)
		if err != nil || child.Mode().Perm() != 0700 {
			t.Fatal("private registry child not protected", err)
		}
	}
}

func TestLegacyForgetCannotDiscardOriginalOwnedInstance(t *testing.T) {
	registry, scope, spec := nativeRegistryFixture(t)
	if _, err := registry.Reserve(scope, spec, "original", ""); err != nil {
		t.Fatal(err)
	}
	d := newTestDaemon(t)
	d.nativeRegistry = registry
	if err := d.state.UpsertInstance(InstanceRow{InstanceID: scope.InstanceID, AgentName: "original"}); err != nil {
		t.Fatal(err)
	}
	if err := d.doForget(nil, scope.InstanceID); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
		t.Fatal("legacy forget crossed owned retirement", err)
	}
	if _, ok, err := d.state.GetInstance(scope.InstanceID); err != nil || !ok {
		t.Fatal("owned source state lost", err)
	}
	if !registry.Owns(scope.InstanceID) {
		t.Fatal("original registry lost")
	}
}
