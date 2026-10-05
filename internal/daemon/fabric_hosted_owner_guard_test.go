//go:build linux || darwin

package daemon

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/pagnet-code/pagnet/internal/localpeer"
)

func TestHostedOwnerGuardActualKernelIncarnationAndChainedLocalGuard(t *testing.T) {
	if _, err := NewHostedOwnerGuard(nil); err == nil {
		t.Fatal("hosted guard replaced mandatory local managed guard")
	}
	called := 0
	localDenied := errors.New("local native owner denied")
	guard, err := NewHostedOwnerGuard(func(context.Context, localpeer.ProcessSnapshot) error {
		called++
		return localDenied
	})
	if err != nil {
		t.Fatal(err)
	}
	// This isolated fixture owns a genuine separate process. Production register
	// obtains this exact kernel incarnation from authenticated Controller IPC.
	worker := exec.CommandContext(t.Context(), "sleep", "30")
	if err = worker.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = worker.Process.Kill(); _ = worker.Wait() }()
	root, err := localpeer.ReadProcess(worker.Process.Pid)
	if err != nil || guard.register(root) != nil {
		t.Fatal("actual original worker incarnation", err)
	}
	if err = guard.Validate(t.Context(), root); err == nil || called != 0 {
		t.Fatal("managed process entered owner mode or bypassed its fence", err, called)
	}
	peer, err := localpeer.ReadProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err = guard.Validate(t.Context(), peer); !errors.Is(err, localDenied) || called != 1 {
		t.Fatal("unrelated same-UID peer skipped existing local guard", err, called)
	}
	forged := root
	forged.Start++
	if guard.Validate(t.Context(), forged) == nil || guard.register(forged) == nil {
		t.Fatal("guessed or replaced process incarnation accepted")
	}
	// A stale registration from another incarnation cannot blacklist a genuine
	// current user process merely because the OS recycled its PID.
	guard.mu.Lock()
	stale := peer
	stale.Start--
	guard.roots[peer.PID] = stale
	guard.mu.Unlock()
	if err = guard.Validate(t.Context(), peer); !errors.Is(err, localDenied) || called != 2 {
		t.Fatal("stale PID registration became permanent user blacklist", err, called)
	}
}

func TestHostedOwnerReadinessCannotSkipUnknownLaunchingOriginalWorker(t *testing.T) {
	registry, scope, spec := nativeRegistryFixture(t)
	if _, err := registry.Reserve(scope, spec, "", ""); err != nil {
		t.Fatal(err)
	}
	guard, err := NewHostedOwnerGuard(func(context.Context, localpeer.ProcessSnapshot) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	host := &Daemon{Config: Config{HostedOwnerGuard: guard}, nativeRegistry: registry}
	if err = host.HostedOwnerGuardReady(t.Context(), guard); err != nil {
		t.Fatal("unlaunched reserved profile incorrectly needs a process", err)
	}
	// State-only negative fixture: no process/admission is invented here. A
	// launching crash or old record may NEVER be interpreted as a safe operator.
	for _, state := range []string{"launching", "launched"} {
		if _, err = registry.db.Exec(`UPDATE native_workers SET launch_state=? WHERE instance_id=?`, state, scope.InstanceID); err != nil {
			t.Fatal(err)
		}
		if host.HostedOwnerGuardReady(t.Context(), guard) == nil {
			t.Fatal("unknown original worker skipped startup fence", state)
		}
	}
	other, _ := NewHostedOwnerGuard(func(context.Context, localpeer.ProcessSnapshot) error { return nil })
	if host.HostedOwnerGuardReady(t.Context(), other) == nil {
		t.Fatal("different guard accepted without daemon registration hook")
	}
}
