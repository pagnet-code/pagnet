//go:build linux || darwin

package sessionworker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// setWatchInterval shortens the watchdog interval for a test and restores
// the package default afterwards.
func setWatchInterval(t *testing.T, d time.Duration) {
	t.Helper()
	old := stateDirWatchInterval
	stateDirWatchInterval = d
	t.Cleanup(func() { stateDirWatchInterval = old })
}

func TestStateDirGone(t *testing.T) {
	// Real Lstat on a path under an existing dir that does not exist:
	// strict ENOENT must classify as gone.
	if _, err := os.Lstat(filepath.Join(t.TempDir(), "absent")); !stateDirGone(err) {
		t.Fatalf("strict ENOENT from a real Lstat must classify as gone: %v", err)
	}
	if stateDirGone(nil) {
		t.Fatal("nil error must not classify as gone")
	}
	if stateDirGone(errors.New("denied")) {
		t.Fatal("non-ENOENT error must not classify as gone")
	}
	if os.Geteuid() == 0 {
		t.Skipf("running as root; EACCES cannot be produced")
	}
	// A 0000-mode parent makes Lstat return EACCES (not ENOENT): a
	// permission error must not classify as gone.
	locked := t.TempDir()
	if err := os.Mkdir(filepath.Join(locked, "inner"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0700) })
	if _, err := os.Lstat(filepath.Join(locked, "inner")); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("expected EACCES under 0000-mode parent, got %v", err)
	} else if stateDirGone(err) {
		t.Fatalf("EACCES must not classify as gone: %v", err)
	}
}

func TestStateDirWatchdogCancelsOnDeletion(t *testing.T) {
	setWatchInterval(t, 10*time.Millisecond)
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stateDirWatchdog(ctx, dir, cancel)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not retire after its state dir disappeared")
	}
}

func TestStateDirWatchdogDoesNotCancelWhileDirExists(t *testing.T) {
	setWatchInterval(t, 10*time.Millisecond)
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stateDirWatchdog(ctx, dir, cancel)
	time.Sleep(300 * time.Millisecond) // ~30 polls while the dir exists
	if err := ctx.Err(); err != nil {
		t.Fatalf("worker retired while its state dir still exists: %v", err)
	}
}

func TestStateDirWatchdogDoesNotCancelOnNonENOENT(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skipf("running as root; EACCES cannot be produced")
	}
	setWatchInterval(t, 10*time.Millisecond)
	locked := t.TempDir()
	target := filepath.Join(locked, "worker-state") // never created
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0700) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stateDirWatchdog(ctx, target, cancel)
	time.Sleep(300 * time.Millisecond) // ~30 polls of EACCES
	if err := ctx.Err(); err != nil {
		t.Fatalf("worker retired on non-ENOENT (EACCES) stat result: %v", err)
	}
}
