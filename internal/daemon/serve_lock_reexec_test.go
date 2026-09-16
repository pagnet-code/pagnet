//go:build unix

// Regression test for the serve-lock re-exec window (P0 follow-up):
// performAutoUpdate re-execs in place (syscall.Exec, same PID). Go opens
// every file with O_CLOEXEC, so a closure-held lock fd would be closed
// at exec and the flock silently released — a second `pagnet serve`
// could take the state dir in the window before the new image
// re-acquires. The fix carries the lock fd across the exec (CLOEXEC
// cleared + PAGNET_SERVE_LOCK_FD) and re-adopts it in acquireServeLock,
// so the lock is NEVER released.
//
// The test drives a REAL re-exec of the test binary itself:
//
//   - TestServeLockReexecChildRole (image 1): acquires the lock fresh,
//     writes the `acquired` marker (its PID), prepares the exec exactly
//     as production does (the same serveLockExecEnv helper
//     performAutoUpdate uses), and re-execs into the adopt role.
//   - TestServeLockReexecAdoptRole (image 2, SAME PID): acquireServeLock
//     MUST take the adoption path (a fresh acquire would fail with
//     EWOULDBLOCK — the lock is still held by the carried fd). It then
//     spawns an ordinary CLOEXEC canary child (plain `sleep 3600`, no
//     special FD handling) and exits WITHOUT an explicit release: the
//     lock must be dropped by process exit (fd close), not by LOCK_UN —
//     an explicit LOCK_UN would release the lock even if the canary
//     inherited the fd, making the canary check vacuous.
//   - TestServeLockSurvivesReexec (orchestrator, this process): probes
//     the lock every 2ms for the child's entire lifetime — a FREE lock
//     before adoption is proven is the bug — verifies adopted PID ==
//     acquired PID (same-PID continuation through exec), and then, with
//     the child-role process dead but the canary still alive, acquires
//     the lock: it MUST succeed (the canary did not inherit the lock
//     fd). If a regression drops the CLOEXEC re-set in the adopt path,
//     the canary inherits the fd, the lock survives the adopt role's
//     exit, and this acquire fails.
package daemon

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// reexecStateDirEnv carries the state dir into the re-exec'd images.
const reexecStateDirEnv = "PAGNET_REEXEC_STATE_DIR"

// discardLog is a no-op logger for the minimal Daemon values the role
// tests construct (they never log on the success path).
func discardLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

// probeServeLock attempts a non-blocking exclusive flock on the lock
// file (open + Flock LOCK_EX|LOCK_NB + close). It reports whether the
// lock was FREE (true = the probe acquired it).
func probeServeLock(dir string) (bool, error) {
	f, err := os.OpenFile(filepath.Join(dir, "serve.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return false, nil // locked (EWOULDBLOCK) or other error: not free
	}
	return true, nil
}

// TestServeLockSurvivesReexec is the orchestrator (see the file comment
// for the full scenario).
func TestServeLockSurvivesReexec(t *testing.T) {
	dir := t.TempDir()
	// Scrub the carried-fd env so the outer environment cannot interfere.
	os.Unsetenv(serveLockFDEnv)
	t.Cleanup(func() { os.Unsetenv(serveLockFDEnv) })

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=TestServeLockReexecChildRole", "-test.count=1")
	cmd.Env = append(os.Environ(), reexecStateDirEnv+"="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	// Bounded: kill the child on timeout. waited flips once the test
	// body consumes the result; the cleanup must then NOT wait on done
	// again (the buffered value is gone — waiting on it would hang the
	// whole test binary).
	waited := false
	deadline := time.Now().Add(30 * time.Second)
	t.Cleanup(func() {
		if waited {
			return
		}
		_ = cmd.Process.Kill()
		<-done
	})

	// 1. Wait for the child to acquire the lock (the marker is written
	//    AFTER the acquire and holds the child's PID).
	var acquiredPID int
	for {
		if time.Now().After(deadline) {
			t.Fatal("timeout: the child never acquired the serve lock")
		}
		if b, err := os.ReadFile(filepath.Join(dir, "acquired")); err == nil {
			acquiredPID, _ = strconv.Atoi(strings.TrimSpace(string(b)))
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if acquiredPID == 0 {
		t.Fatal("acquired marker holds no pid")
	}

	// 2. Probe the lock every 2ms for the child's ENTIRE remaining
	//    lifetime. In the fixed design the lock is held from the
	//    child's acquire until its process EXIT (released only by fd
	//    close at exit), so a FREE lock before adoption is proven means
	//    the re-exec released it — the bug. A free lock after adoption
	//    is only the child having already exited (the probe is late).
	// The probe stops on stopProbe (closed by the test body after it
	// consumes done, or by the cleanup on failure paths). The probe must
	// NOT receive from done itself: a non-blocking select would consume
	// the buffered Wait result and starve the test body's receive.
	var stopProbeOnce sync.Once
	stopProbe := make(chan struct{})
	stopProbeNow := func() { stopProbeOnce.Do(func() { close(stopProbe) }) }
	t.Cleanup(stopProbeNow)
	adoptedPath := filepath.Join(dir, "adopted")
	probeDone := make(chan struct{})
	// probeFail lets the test body abort immediately when the probe
	// catches the lock free before adoption (t.Error alone cannot stop
	// the test — without this it would wait out the full deadline).
	probeFail := make(chan struct{}, 1)
	go func() {
		defer close(probeDone)
		for {
			select {
			case <-stopProbe:
				return
			default:
			}
			free, err := probeServeLock(dir)
			if err != nil {
				t.Errorf("probe: %v", err)
				return
			}
			if free {
				if _, aerr := os.Stat(adoptedPath); aerr != nil {
					t.Error("serve lock was FREE before adoption — the re-exec released it (the window is open)")
					select {
					case probeFail <- struct{}{}:
					default:
					}
				}
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	// 3. Wait for the adopt marker (written by the post-exec image after
	//    successful adoption; holds the post-exec PID). Abort immediately
	//    if the probe caught the lock free before adoption.
	var adoptedPID int
	adopted := false
	for !adopted {
		select {
		case <-probeFail:
			t.Fatal("the re-exec released the serve lock before adoption (probe) — aborting")
		case <-time.After(5 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("timeout: the post-exec image never adopted the serve lock")
		}
		if b, err := os.ReadFile(adoptedPath); err == nil {
			adoptedPID, _ = strconv.Atoi(strings.TrimSpace(string(b)))
			adopted = true
		}
	}
	if adoptedPID != acquiredPID {
		t.Fatalf("adopted pid %d != acquired pid %d (exec must continue the same process)", adoptedPID, acquiredPID)
	}

	// 4. Wait for the child to exit (its fd close releases the lock).
	// The test body is the SOLE consumer of done (see stopProbe above).
	err = <-done
	waited = true
	stopProbeNow()
	if err != nil {
		t.Fatalf("child exited with an error: %v", err)
	}
	<-probeDone

	// 5. CLOEXEC canary: the adopt role spawned an ordinary child before
	//    exiting. The child-role process is now DEAD; the canary is
	//    still alive. Acquiring the lock must SUCCEED — if the canary
	//    had inherited the lock fd (CLOEXEC re-set missing), the lock
	//    would still be held and this acquire would fail.
	var canaryPID int
	if b, err := os.ReadFile(filepath.Join(dir, "canary")); err == nil {
		canaryPID, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	if canaryPID == 0 {
		t.Fatal("canary marker missing (the adopt role died before spawning the canary)")
	}
	t.Cleanup(func() { _ = syscall.Kill(canaryPID, syscall.SIGKILL) })
	if err := syscall.Kill(canaryPID, 0); err != nil {
		t.Fatalf("canary %d not alive after the child exit (fixture broken)", canaryPID)
	}
	release, err := (&Daemon{Config: Config{StateDir: dir}, Log: discardLog()}).acquireServeLock()
	if err != nil {
		t.Fatalf("post-exit acquire failed while the canary holds no lock fd — the canary INHERITED the lock fd (CLOEXEC re-set missing): %v", err)
	}
	_ = syscall.Kill(canaryPID, syscall.SIGKILL)
	release()
}

// TestServeLockReexecChildRole is image 1 of the re-exec test (see the
// file comment). It runs only when selected by name with
// PAGNET_REEXEC_STATE_DIR set.
func TestServeLockReexecChildRole(t *testing.T) {
	dir := os.Getenv(reexecStateDirEnv)
	if dir == "" {
		t.Skip("re-exec role: only runs when selected by name with " + reexecStateDirEnv)
	}
	d := &Daemon{Config: Config{StateDir: dir}, Log: discardLog()}
	release, err := d.acquireServeLock()
	if err != nil {
		t.Fatalf("child acquireServeLock: %v", err)
	}
	defer release()
	if err := os.WriteFile(filepath.Join(dir, "acquired"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}
	// Prepare the exec exactly as production does (performAutoUpdate):
	// the same helper clears CLOEXEC on the lock fd and returns the env
	// var that carries it.
	envVar, err := d.serveLockExecEnv()
	if err != nil {
		t.Fatalf("serveLockExecEnv: %v", err)
	}
	if envVar == "" {
		t.Fatal("serveLockExecEnv returned no env var while the lock is held")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Re-exec into the adopt role (same PID). The env carries the state
	// dir (inherited) + the lock fd.
	if err := syscall.Exec(exe,
		[]string{exe, "-test.run=TestServeLockReexecAdoptRole", "-test.count=1"},
		append(os.Environ(), envVar)); err != nil {
		t.Fatalf("exec returned (it should not): %v", err)
	}
}

// TestServeLockReexecAdoptRole is image 2 (same PID, post-exec) of the
// re-exec test (see the file comment). It runs only when selected by
// name with PAGNET_REEXEC_STATE_DIR set.
func TestServeLockReexecAdoptRole(t *testing.T) {
	dir := os.Getenv(reexecStateDirEnv)
	if dir == "" {
		t.Skip("re-exec role: only runs when selected by name with " + reexecStateDirEnv)
	}
	d := &Daemon{Config: Config{StateDir: dir}, Log: discardLog()}
	// This MUST take the adoption path: the lock is still held by the
	// carried fd, so a fresh acquire on a second open file description
	// would fail with EWOULDBLOCK.
	if _, err := d.acquireServeLock(); err != nil {
		t.Fatalf("adopt acquireServeLock: %v", err)
	}
	// The adoption unsets the env var. If the carried fd was LOST at
	// exec, the adoption would have fallen back to a fresh acquire on
	// the now-free lock — which succeeds and leaves the env var set.
	// This assertion is what makes that failure DETERMINISTIC.
	if v := os.Getenv(serveLockFDEnv); v != "" {
		t.Fatalf("%s still set (value %q) — the carried fd was lost at exec", serveLockFDEnv, v)
	}
	// CLOEXEC canary: an ordinary child with NO special FD handling. If
	// the adopt path failed to re-set CLOEXEC, this child inherits the
	// lock fd and the lock survives this process's exit — the
	// orchestrator's post-exit acquire then fails.
	canary := exec.Command("sleep", "3600")
	if err := canary.Start(); err != nil {
		t.Fatalf("canary start: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "canary"), []byte(strconv.Itoa(canary.Process.Pid)), 0o644); err != nil {
		t.Fatal(err)
	}
	// Announce successful adoption (post-exec PID).
	if err := os.WriteFile(filepath.Join(dir, "adopted"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}
	// Deliberately NO explicit release: the lock must be dropped by the
	// process EXIT (fd close), not by LOCK_UN — otherwise the canary
	// check would be vacuous (LOCK_UN releases the lock even if the
	// canary inherited the fd).
}
