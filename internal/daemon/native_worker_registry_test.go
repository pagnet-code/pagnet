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
		if err := EnsureNativeWorker(ctx, registry, record, os.Getenv("PAGNET_REGISTRY_CHILD_BINARY"), []string{"TEST_SECRET=never-persist"}); err != nil {
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
	// Lifecycle cleanup signals only the mutually authenticated worker through
	// its original bootstrap process identity (PID inspected via private socket).
	peer, err := net.Dial("unix", filepath.Join(record.Dir, "controller.sock"))
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
	if err := EnsureNativeWorker(fresh, reopened, recovered, binary, spec.Env); err != nil {
		t.Fatal(err)
	}
	replacement, err := sessionworker.DialOwnerController(fresh, recovered.Dir, s, key, "controller-B")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	nextPeer, err := net.Dial("unix", filepath.Join(recovered.Dir, "controller.sock"))
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
	err = EnsureNativeWorker(ctx, r, record, binary, []string{"PRIVATE_FIXTURE=" + strings.Repeat("s", 120<<10)})
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
