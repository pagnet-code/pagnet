//go:build unix

package daemon

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// acquireServeLock takes an exclusive advisory lock on
// <StateDir>/serve.lock (external audit F-006) and returns a release
// function. The lock is held for the daemon's lifetime; closing the fd
// (on release or process exit) drops the flock. A second daemon with the
// same state dir gets EWOULDBLOCK and must refuse to start.
//
// Re-exec adoption: when the environment carries a lock fd from a
// re-exec'd image (serveLockFDEnv), it is adopted instead of freshly
// acquired — the flock is held by the open file description, so the
// lock was never released and no second daemon can have taken the state
// dir in between.
func (d *Daemon) acquireServeLock() (func(), error) {
	path := filepath.Join(d.StateDir, "serve.lock")

	if v := os.Getenv(serveLockFDEnv); v != "" {
		if release, ok := d.adoptServeLock(path, v); ok {
			d.Log.Info("adopted serve lock across re-exec")
			return release, nil
		}
		// Stale/foreign fd: fall through to the normal fresh acquire.
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("serve lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another pagnet daemon is already running (state dir %s is locked): %w", d.StateDir, err)
	}
	d.serveLockFile = f
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// adoptServeLock re-adopts the serve lock carried across a re-exec. The
// carried fd is verified to be exactly the lock file (fstat dev+ino vs
// the path — a reused fd number or a stale env from an unrelated
// process must not be adopted) and the lock is re-asserted on the same
// open file description (a re-flock succeeds only for the current
// holder). On any mismatch the fd is closed and false is returned (the
// caller does a fresh acquire).
//
// CLOEXEC is re-set IMMEDIATELY after the identity check, before the
// verifying flock: from that point on the fd can never leak into a
// spawned process (runtime children, MCP bridges, git/update helpers).
// If it leaked, the lock would survive this daemon's exit — a
// descendant still holding the descriptor keeps the flock — and the
// state dir would be permanently locked.
func (d *Daemon) adoptServeLock(path, fdStr string) (func(), bool) {
	fd, err := strconv.Atoi(fdStr)
	if err != nil || fd <= 0 {
		return nil, false
	}
	f := os.NewFile(uintptr(fd), "serve.lock")
	// Verify the fd is actually our lock file (fstat on the fd vs the
	// path): a closed/reused fd number must not be adopted.
	fdFi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, false
	}
	pathFi, err := os.Stat(path)
	if err != nil {
		_ = f.Close()
		return nil, false
	}
	fdSt, ok1 := fdFi.Sys().(*syscall.Stat_t)
	pathSt, ok2 := pathFi.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 || fdSt.Dev != pathSt.Dev || fdSt.Ino != pathSt.Ino {
		_ = f.Close()
		return nil, false
	}
	// Re-arm CLOEXEC NOW (before the verifying flock): the fd must not
	// leak into processes this daemon spawns; only a deliberate
	// re-exec carries it (serveLockExecEnv clears it again).
	if _, err := unix.FcntlInt(f.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		_ = f.Close()
		return nil, false
	}
	// Prove we hold the lock: a re-flock on the same open file
	// description succeeds only for the current holder.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, false
	}
	os.Unsetenv(serveLockFDEnv)
	d.serveLockFile = f
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, true
}

// serveLockExecEnv prepares the serve lock to survive an auto-update
// re-exec and returns the env var that carries the fd to the new image
// ("" when the daemon holds no serve lock). The flock is held by the
// open file description, not the process: Go opens every file with
// O_CLOEXEC, so without clearing the flag the fd would be closed at
// exec and the lock silently released — opening a window in which a
// second `pagnet serve` can take over the state dir. The adopt path
// re-sets CLOEXEC immediately, so the carried fd cannot leak into
// spawned processes of the new image.
func (d *Daemon) serveLockExecEnv() (string, error) {
	if d.serveLockFile == nil {
		return "", nil
	}
	if _, err := unix.FcntlInt(d.serveLockFile.Fd(), unix.F_SETFD, 0); err != nil {
		return "", fmt.Errorf("clear CLOEXEC on serve lock fd: %w", err)
	}
	return serveLockFDEnv + "=" + strconv.FormatInt(int64(d.serveLockFile.Fd()), 10), nil
}

func readDiskFree(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	// Bsize is int64 on Linux but uint32 on Darwin — normalize explicitly
	// so the daemon cross-compiles (make release).
	return int64(st.Bavail) * int64(st.Bsize), nil
}

func reexecDaemon(path string, args, env []string) error { return syscall.Exec(path, args, env) }

func hostPlatformError() error { return nil }
