//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package textbridge

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestLockProfilePolicyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	unlock, err := LockProfilePolicy(ctx, textBridgePrivateTestDir(t))
	if unlock != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled lock: %v", err)
	}
}

func TestLockProfilePolicyContention(t *testing.T) {
	root := textBridgePrivateTestDir(t)
	unlock, err := LockProfilePolicy(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if other, err := LockProfilePolicy(ctx, root); other != nil || !errors.Is(err, context.DeadlineExceeded) {
		if other != nil {
			other()
		}
		t.Fatalf("contended lock: %v", err)
	}
	unlock()
	unlock()
	other, err := LockProfilePolicy(context.Background(), root)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	other()
}

func TestLockProfilePolicyWaitsForRelease(t *testing.T) {
	root := textBridgePrivateTestDir(t)
	unlock, err := LockProfilePolicy(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		other, err := LockProfilePolicy(ctx, root)
		if other != nil {
			other()
		}
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("waiter returned before release: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	unlock()
	if err := <-result; err != nil {
		t.Fatalf("waiter did not acquire released lock: %v", err)
	}
}

func TestLockProfilePolicySeparateRunLock(t *testing.T) {
	root := textBridgePrivateTestDir(t)
	unlockRun, err := LockProfile(root)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockRun()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unlockPolicy, err := LockProfilePolicy(ctx, root)
	if err != nil {
		t.Fatalf("run.lock blocked policy.lock: %v", err)
	}
	unlockPolicy()
}

func TestLockProfilePolicyPrivate(t *testing.T) {
	for _, kind := range []string{"public file", "symlink file", "directory file", "symlink directory", "public directory"} {
		t.Run(kind, func(t *testing.T) {
			root := textBridgePrivateTestDir(t)
			path := filepath.Join(root, "policy.lock")
			var err error
			switch kind {
			case "public file":
				err = os.WriteFile(path, nil, 0644)
			case "symlink file":
				err = os.Symlink(filepath.Join(root, "target"), path)
			case "directory file":
				err = os.Mkdir(path, 0700)
			case "symlink directory":
				link := filepath.Join(root, "link")
				err = os.Symlink(root, link)
				root = link
			case "public directory":
				err = os.Chmod(root, 0755)
			}
			if err != nil {
				t.Fatal(err)
			}
			if unlock, err := LockProfilePolicy(context.Background(), root); err == nil {
				unlock()
				t.Fatal("accepted insecure policy lock")
			}
		})
	}
}

func TestLockProfilePolicySubprocess(t *testing.T) {
	if root := os.Getenv("TEXTBRIDGE_POLICY_LOCK_TEST_DIR"); root != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		unlock, err := LockProfilePolicy(ctx, root)
		if unlock != nil {
			unlock()
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("subprocess acquired contended lock: %v", err)
		}
		return
	}
	root := textBridgePrivateTestDir(t)
	unlock, err := LockProfilePolicy(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLockProfilePolicySubprocess$")
	cmd.Env = append(os.Environ(), "TEXTBRIDGE_POLICY_LOCK_TEST_DIR="+root)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("subprocess lock test: %v\n%s", err, output)
	}
}
