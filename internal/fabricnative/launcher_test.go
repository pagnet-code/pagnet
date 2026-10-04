//go:build linux || darwin

package fabricnative

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func launcherBinding(t *testing.T, c *Checkpoints, value OriginalCheckpoint, binary, dir, authorityDir, worker string, runtimeOverride ...domain.RuntimeName) (LaunchSpec, *ManagedPeers) {
	t.Helper()
	workspace := filepath.Join(dir, "workspace")
	if e := os.MkdirAll(workspace, 0700); e != nil {
		t.Fatal(e)
	}
	spec := sessionworker.NativeSpec{Kind: "local", Runtime: domain.RuntimeFakePersistent, Binary: "/bin/true", MCPExecutable: binary, Workspace: workspace, LocalAuthorityDirectory: authorityDir, LocalFabricSocket: filepath.Join(dir, "fabric.sock"), Env: []string{"PATH=/usr/bin:/bin", "HOME=" + workspace}, CredentialEnvKeys: []string{"ACME_SESSION_CREDENTIAL"}}
	if len(runtimeOverride) > 0 {
		spec.Runtime = runtimeOverride[0]
	}
	raw, e := hex.DecodeString(sessionworker.LocalNativeProfileFingerprint(spec))
	if e != nil {
		t.Fatal(e)
	}
	var digest [32]byte
	copy(digest[:], raw)
	current, _, e := c.authority.CurrentNativeState(t.Context(), c.owner, value.OriginalBinding.Scope)
	if e != nil {
		t.Fatal(e)
	}
	binding, e := c.authority.BindWorker(t.Context(), c.owner, current, 1, identity.WorkerBinding{WorkerID: worker, StateDirectoryID: "private-" + worker, OwnershipGeneration: "generation-" + worker, ActualRuntime: string(spec.Runtime), ProfileDigest: digest})
	if e != nil {
		t.Fatal(e)
	}
	scope, e := nativeauthority.NewLocalScope(c.authority.Identity(), binding)
	if e != nil {
		t.Fatal(e)
	}
	peers, e := NewManagedPeers(c.store, c.authority, c.owner)
	if e != nil {
		t.Fatal(e)
	}
	key := sha256.Sum256([]byte("private controller fixture key"))
	return LaunchSpec{Directory: filepath.Join(dir, "worker"), Ownership: scope, Native: spec, ControlKey: key[:], RuntimeEnvironment: []string{"ACME_SESSION_CREDENTIAL=pipe-only-credential-marker"}, Attempt: "original-launch", ControllerID: "controller-original"}, peers
}
func TestActualDetachedLauncherAdoptsSameOriginalWorkerWithoutNativeEffectOrCredentialPersistence(t *testing.T) {
	c, value, authorityDir := checkpointFixture(t, registry.DefaultOptions())
	root, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	dir, e := os.MkdirTemp("", "pgn-launcher-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	binary := filepath.Join(dir, "pagnet")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/pagnet")
	build.Dir = root
	if output, e := build.CombinedOutput(); e != nil {
		t.Fatalf("actual CLI build failed: %v %s", e, output)
	}
	t.Run("actual-worker-startup-failure", func(t *testing.T) {
		failedCheckpoints, original, failedAuthority := checkpointFixture(t, registry.DefaultOptions())
		failedDir := filepath.Join(dir, "failed-startup")
		if e := os.Mkdir(failedDir, 0700); e != nil {
			t.Fatal(e)
		}
		failed, failedPeers := launcherBinding(t, failedCheckpoints, original, binary, failedDir, failedAuthority, "unsupported-worker", domain.RuntimeName("unsupported-fixture-runtime"))
		actual, e := NewLauncher(LauncherConfig{failedCheckpoints, failedPeers, binary, failedAuthority, 5 * time.Second, 2})
		if e != nil {
			t.Fatal(e)
		}
		defer actual.Close()
		if _, e = actual.Launch(t.Context(), failed); e == nil {
			t.Fatal("actual SDK accepted unsupported runtime startup")
		}
		if _, e = actual.Launch(t.Context(), failed); e == nil {
			t.Fatal("failed actual worker claim silently relaunched")
		}
		actual.mu.Lock()
		reaped := actual.processes[failed.Directory]
		actual.mu.Unlock()
		if reaped == nil {
			t.Fatal("actual child was not launched")
		}
		select {
		case <-reaped.done:
			if reaped.result() == nil {
				t.Fatal("actual unsupported startup did not fail")
			}
		case <-time.After(time.Second):
			t.Fatal("failed child was not reaped")
		}
	})
	s, peers := launcherBinding(t, c, value, binary, dir, authorityDir, "original-worker")
	config := LauncherConfig{c, peers, binary, authorityDir, 10 * time.Second, 8}
	launcher, e := NewLauncher(config)
	if e != nil {
		t.Fatal(e)
	}
	worker, e := launcher.Launch(t.Context(), s)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		process, _ := os.FindProcess(worker.Process.PID)
		process.Signal(os.Interrupt)
		launcher.mu.Lock()
		p := launcher.processes[s.Directory]
		launcher.mu.Unlock()
		if p != nil {
			select {
			case <-p.done:
			case <-time.After(5 * time.Second):
				process.Kill()
				<-p.done
			}
		}
	}()
	response, e := worker.Client.Call(t.Context(), sessionworker.LocalRequest{Type: "snapshot"})
	if e != nil || response.Snapshot == nil || response.Snapshot.PID != 0 || response.Snapshot.NativeSessionID != "" {
		t.Fatal("launch manufactured native effect", e)
	}
	if peers.ValidateOwner(t.Context(), worker.Process) == nil {
		t.Fatal("new worker accepted as owner")
	}
	e = filepath.WalkDir(s.Directory, func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.IsDir() || entry.Type()&os.ModeSocket != 0 {
			return nil
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if bytes.Contains(raw, []byte("pipe-only-credential-marker")) {
			t.Fatal("provider credential persisted", filepath.Base(path))
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = launcher.Launch(t.Context(), s); e == nil {
		t.Fatal("existing claim relaunched paid ownership")
	}
	original := worker.Process
	if e = launcher.Close(); e != nil {
		t.Fatal(e)
	}
	// A new controller owns no child process handle; only actual authenticated
	// private IPC + retained kernel birth may adopt the original owner.
	if e = c.store.Close(); e != nil {
		t.Fatal(e)
	}
	retainedRoot, e := registry.Open(t.Context(), authorityDir)
	if e != nil {
		t.Fatal(e)
	}
	defer retainedRoot.Close()
	retainedAuthority, e := identity.New(retainedRoot, checkpointFence{})
	if e != nil {
		t.Fatal(e)
	}
	retainedCheckpoints, e := NewCheckpoints(retainedRoot, retainedAuthority, c.owner, c.protector)
	if e != nil {
		t.Fatal(e)
	}
	config.Checkpoints = retainedCheckpoints
	freshPeers, e := NewManagedPeers(retainedRoot, retainedAuthority, c.owner)
	if e != nil {
		t.Fatal(e)
	}
	config.Peers = freshPeers
	recovered, e := NewLauncher(config)
	if e != nil {
		t.Fatal(e)
	}
	defer recovered.Close()
	adopted, e := recovered.Adopt(t.Context(), s.Directory, s.Ownership, "controller-recovered")
	if e != nil {
		t.Fatal(e)
	}
	if adopted.Process.PID != original.PID || adopted.Process.UID != original.UID || adopted.Process.Start != original.Start {
		t.Fatal("controller adoption replaced original worker")
	}
	if _, e = localpeer.ReadProcess(original.PID); e != nil {
		t.Fatal("controller close killed original worker", e)
	}
	if freshPeers.ValidateOwner(t.Context(), adopted.Process) == nil {
		t.Fatal("adopted worker downgraded to owner")
	}
	if _, e = recovered.Launch(t.Context(), s); e == nil {
		t.Fatal("recovered claim emitted another process")
	}
	wrong := s
	wrong.Directory = filepath.Join(dir, "missing-worker")
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, e = recovered.Adopt(ctx, wrong.Directory, wrong.Ownership, "absent"); e == nil {
		t.Fatal("missing original identity silently recreated")
	}
	if _, e = os.Stat(wrong.Directory); !os.IsNotExist(e) {
		t.Fatal("adoption created replacement bootstrap")
	}

	// Capability readers race real controller replacement and closure. Each
	// owned copy must be the complete original key or absent after revocation.
	var readers sync.WaitGroup
	stopCopies := make(chan struct{})
	badCopy := make(chan bool, 1)
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stopCopies:
					return
				default:
				}
				key := adopted.KeyCopy()
				if len(key) != 0 && !bytes.Equal(key, s.ControlKey) {
					select {
					case badCopy <- true:
					default:
					}
				}
				clear(key)
			}
		}()
	}
	replacement, replaceErr := recovered.Adopt(t.Context(), s.Directory, s.Ownership, "controller-replaced")
	if replaceErr == nil {
		replaceErr = recovered.Close()
	}
	close(stopCopies)
	readers.Wait()
	if replaceErr != nil {
		t.Fatal(replaceErr)
	}
	select {
	case <-badCopy:
		t.Fatal("concurrent capability copy observed wiped bytes")
	default:
	}
	if len(adopted.KeyCopy()) != 0 || len(replacement.KeyCopy()) != 0 {
		t.Fatal("closed capability retained")
	}
}
func TestLauncherRejectsEnvironmentBeforeClaimAndCancelledAttemptNeverRelaunches(t *testing.T) {
	c, value, authorityDir := checkpointFixture(t, registry.DefaultOptions())
	dir, e := os.MkdirTemp("", "pgn-no-launch-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	s, peers := launcherBinding(t, c, value, "/bin/true", dir, authorityDir, "invalid-worker")
	l, e := NewLauncher(LauncherConfig{c, peers, "/bin/true", authorityDir, time.Second, 2})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	bad := s
	bad.RuntimeEnvironment = []string{"PATH=/unapproved/profile"}
	if _, e = l.Launch(t.Context(), bad); e == nil {
		t.Fatal("profile changed through credential pipe")
	}
	if _, e = os.Stat(s.Directory); !os.IsNotExist(e) {
		t.Fatal("invalid environment created bootstrap")
	}
	// Successful claim consumes a ticket even if its supplied callback is canceled.
	ticket, e := c.BeginLaunch(t.Context(), s.Ownership, s.Attempt)
	if e != nil {
		t.Fatal("invalid env consumed durable claim", e)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if ticket.Run(cancelled, func(context.Context) error { t.Fatal("cancelled ticket spawned"); return nil }) == nil {
		t.Fatal("canceled claim accepted")
	}
	if _, e = l.Launch(t.Context(), s); e == nil {
		t.Fatal("cancelled FULL claim was retried automatically")
	}
}
func TestActualFailedSpawnKeepsClaimAndNeverAutomaticallyRecreatesWorker(t *testing.T) {
	c, value, authorityDir := checkpointFixture(t, registry.DefaultOptions())
	dir, e := os.MkdirTemp("", "pgn-spawn-failure-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	binary := filepath.Join(dir, "executable")
	if e = os.WriteFile(binary, []byte("not an executable format"), 0700); e != nil {
		t.Fatal(e)
	}
	s, peers := launcherBinding(t, c, value, binary, dir, authorityDir, "failed-worker")
	l, e := NewLauncher(LauncherConfig{c, peers, binary, authorityDir, time.Second, 2})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	if _, e = l.Launch(t.Context(), s); e == nil {
		t.Fatal("invalid executable succeeded")
	}
	if _, e = l.Launch(t.Context(), s); e == nil {
		t.Fatal("failed spawn claim reset")
	}
	if _, e = l.Adopt(t.Context(), s.Directory, s.Ownership, "recover-failure"); e == nil {
		t.Fatal("absent original worker adopted")
	}
}

func TestActualCancellationAfterSpawnPreservesOriginalWorkerForAuthenticatedAdoption(t *testing.T) {
	c, value, authorityDir := checkpointFixture(t, registry.DefaultOptions())
	dir, e := os.MkdirTemp("", "pgn-launch-cancel-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	root, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(dir, "pagnet")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/pagnet")
	build.Dir = root
	if output, e := build.CombinedOutput(); e != nil {
		t.Fatalf("actual CLI build failed: %v %s", e, output)
	}
	barrier := filepath.Join(dir, "start.fifo")
	marker := filepath.Join(dir, "original-started")
	if e = syscall.Mkfifo(barrier, 0600); e != nil {
		t.Fatal(e)
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	wrapper := filepath.Join(dir, "owned-pagnet")
	script := "#!/bin/sh\nif [ \"$1\" = session-worker ]; then\n printf ready > " + quote(marker) + "\n read permit < " + quote(barrier) + "\nfi\nexec " + quote(binary) + " \"$@\"\n"
	if e = os.WriteFile(wrapper, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	s, peers := launcherBinding(t, c, value, wrapper, dir, authorityDir, "cancel-original")
	l, e := NewLauncher(LauncherConfig{c, peers, wrapper, authorityDir, 10 * time.Second, 2})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, e := l.Launch(ctx, s); result <- e }()
	startup, stop := context.WithTimeout(t.Context(), 10*time.Second)
	defer stop()
	var original localpeer.ProcessSnapshot
	for original.PID == 0 {
		peers.guard.mu.RLock()
		for _, process := range peers.guard.roots {
			original = process
		}
		peers.guard.mu.RUnlock()
		if original.PID != 0 {
			if _, e = os.Stat(marker); e == nil {
				break
			}
			original = localpeer.ProcessSnapshot{}
		}
		select {
		case <-startup.Done():
			t.Fatal("actual worker did not reach controlled startup boundary")
		case <-time.After(5 * time.Millisecond):
		}
	}
	defer func() {
		process, _ := os.FindProcess(original.PID)
		process.Signal(os.Interrupt)
		l.mu.Lock()
		p := l.processes[s.Directory]
		l.mu.Unlock()
		if p != nil {
			select {
			case <-p.done:
			case <-time.After(3 * time.Second):
				process.Kill()
				<-p.done
			}
		}
	}()
	cancel()
	select {
	case e = <-result:
		if !errors.Is(e, context.Canceled) {
			t.Fatal("cancellation not reported", e)
		}
	case <-startup.Done():
		t.Fatal("launch did not observe cancellation")
	}
	if _, e = localpeer.ReadProcess(original.PID); e != nil {
		t.Fatal("caller cancellation killed detached original", e)
	}
	if peers.ValidateOwner(t.Context(), original) == nil {
		t.Fatal("pending private IPC worker became owner")
	}
	permit, e := os.OpenFile(barrier, os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, e = permit.Write([]byte("continue\n"))
	permit.Close()
	if e != nil {
		t.Fatal(e)
	}
	adopted, e := l.Adopt(t.Context(), s.Directory, s.Ownership, "post-cancellation-controller")
	if e != nil {
		t.Fatal(e)
	}
	if adopted.Process.PID != original.PID || adopted.Process.Start != original.Start {
		t.Fatal("adoption replaced canceled launch")
	}
	snapshot, e := adopted.Client.Call(t.Context(), sessionworker.LocalRequest{Type: "snapshot"})
	if e != nil || snapshot.Snapshot == nil || snapshot.Snapshot.PID != 0 {
		t.Fatal("canceled startup replayed native effect", e)
	}
	if _, e = l.Launch(t.Context(), s); e == nil {
		t.Fatal("canceled launch claim allowed replacement")
	}
}
