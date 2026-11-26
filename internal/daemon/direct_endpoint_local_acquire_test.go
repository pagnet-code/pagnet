//go:build linux || darwin

package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Cancel deterministically at the check following a successful acquisition.
type directEndpointCancelAfterCheck struct {
	context.Context
	checks int
	after  int
}

func (c *directEndpointCancelAfterCheck) Err() error {
	c.checks++
	after := c.after
	if after == 0 {
		after = 1
	}
	if c.checks > after {
		return context.Canceled
	}
	return nil
}

func TestDirectEndpointLocalAcquireMutex(t *testing.T) {
	var mu sync.Mutex
	var rw sync.RWMutex
	for _, tc := range []struct {
		name    string
		hold    func()
		release func()
		try     func(context.Context) (func(), error)
	}{
		{"mutex", mu.Lock, mu.Unlock, func(ctx context.Context) (func(), error) { return directEndpointTryLock(ctx, &mu) }},
		{"read mutex", rw.Lock, rw.Unlock, func(ctx context.Context) (func(), error) { return directEndpointTryRLock(ctx, &rw) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.hold()
			unlock, err := tc.try(context.Background())
			tc.release()
			if unlock != nil || err != errDirectEndpointLocalBusy {
				t.Fatalf("held lock: unlock=%v err=%v", unlock != nil, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			for _, ctx := range []context.Context{ctx, &directEndpointCancelAfterCheck{Context: context.Background()}} {
				if unlock, err := tc.try(ctx); unlock != nil || !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled acquisition: unlock=%v err=%v", unlock != nil, err)
				}
			}
			unlock, err = tc.try(context.Background())
			if err != nil {
				t.Fatalf("cancellation leaked lock: %v", err)
			}
			unlock()
			tc.hold()
			tc.release()
		})
	}
}

func TestDirectEndpointLocalAcquireFlockChild(t *testing.T) {
	path := os.Getenv("PAGNET_TEST_LOCAL_FLOCK")
	if path == "" {
		return
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	fmt.Println("locked")
	_, _ = bufio.NewReader(os.Stdin).ReadByte()
}

func directEndpointHoldChildFlock(t *testing.T, path string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDirectEndpointLocalAcquireFlockChild$")
	cmd.Env = append(os.Environ(), "PAGNET_TEST_LOCAL_FLOCK="+path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		err := cmd.Wait()
		cancel()
		if err != nil {
			t.Errorf("flock child: %v", err)
		}
	})
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("flock child readiness: %q %v", line, err)
	}
}

func TestDirectEndpointLocalAcquireFlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{ctx, &directEndpointCancelAfterCheck{Context: context.Background()}} {
		if unlock, err := directEndpointTryFlock(ctx, file); unlock != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled flock: unlock=%v err=%v", unlock != nil, err)
		}
	}
	other, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	unlock, err := directEndpointTryFlock(context.Background(), other)
	if err != nil {
		t.Fatalf("cancellation leaked flock: %v", err)
	}
	unlock()
	directEndpointHoldChildFlock(t, path)
	if unlock, err := directEndpointTryFlock(context.Background(), file); unlock != nil || err != errDirectEndpointLocalBusy {
		t.Fatalf("held flock: unlock=%v err=%v", unlock != nil, err)
	}
}

func TestDirectEndpointLocalAcquireFiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		try  func(context.Context, *os.File) (*os.File, error)
	}{
		{"registry.custody.lock", directEndpointTryNativeRegistryCustodyLock},
		{"holder.lock", func(ctx context.Context, dir *os.File) (*os.File, error) {
			return directEndpointTryNativeShareHolderLockMode(ctx, dir, true)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, kind := range []string{"safe", "symlink", "hardlink", "mode", "fifo"} {
				t.Run(kind, func(t *testing.T) {
					dir := t.TempDir()
					root, err := os.Open(dir)
					if err != nil {
						t.Fatal(err)
					}
					defer root.Close()
					path := filepath.Join(dir, tc.name)
					sentinel := filepath.Join(dir, "sentinel")
					if err := os.WriteFile(sentinel, []byte("unchanged"), 0600); err != nil {
						t.Fatal(err)
					}
					switch kind {
					case "safe":
						err = os.WriteFile(path, nil, 0600)
					case "symlink":
						err = os.Symlink(sentinel, path)
					case "hardlink":
						err = os.Link(sentinel, path)
					case "mode":
						err = os.WriteFile(path, nil, 0644)
					case "fifo":
						err = unix.Mkfifo(path, 0600)
					}
					if err != nil {
						t.Fatal(err)
					}
					before, _ := os.ReadDir("/proc/self/fd")
					for i := 0; i < 8; i++ {
						lock, err := tc.try(context.Background(), root)
						if kind == "safe" {
							if err != nil {
								t.Fatal(err)
							}
							lock.Close()
						} else if err == nil || lock != nil {
							t.Fatal("unsafe lock accepted")
						}
					}
					after, _ := os.ReadDir("/proc/self/fd")
					if len(before) != len(after) {
						t.Fatalf("descriptor leak: %d -> %d", len(before), len(after))
					}
					if data, err := os.ReadFile(sentinel); err != nil || string(data) != "unchanged" {
						t.Fatal("sentinel modified")
					}
					if kind != "safe" {
						return
					}
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					if lock, err := tc.try(ctx, root); lock != nil || !errors.Is(err, context.Canceled) {
						t.Fatalf("canceled file lock: %v", err)
					}
					for _, after := range []int{2, 3} {
						ctx := &directEndpointCancelAfterCheck{Context: context.Background(), after: after}
						if lock, err := tc.try(ctx, root); lock != nil || !errors.Is(err, context.Canceled) {
							t.Fatalf("cancellation after acquisition: %v", err)
						}
						lock, err := tc.try(context.Background(), root)
						if err != nil {
							t.Fatalf("cancellation leaked file lock: %v", err)
						}
						lock.Close()
					}
					directEndpointHoldChildFlock(t, path)
					before, _ = os.ReadDir("/proc/self/fd")
					for i := 0; i < 8; i++ {
						if lock, err := tc.try(context.Background(), root); lock != nil || err != errDirectEndpointLocalBusy {
							t.Fatalf("held file lock: %v", err)
						}
					}
					after, _ = os.ReadDir("/proc/self/fd")
					if len(before) != len(after) {
						t.Fatalf("busy descriptor leak: %d -> %d", len(before), len(after))
					}
				})
			}
		})
	}
}

func TestDirectEndpointLocalAcquireHolderExisting(t *testing.T) {
	dir := t.TempDir()
	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if lock, err := directEndpointTryNativeShareHolderLockMode(context.Background(), root, false); lock != nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing existing lock: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "holder.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("existing-only acquisition created lock")
	}
	lock, err := directEndpointTryNativeShareHolderLockMode(context.Background(), root, true)
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
	lock, err = directEndpointTryNativeShareHolderLockMode(context.Background(), root, false)
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
}
