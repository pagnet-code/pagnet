//go:build linux || darwin

package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func nativeWorkerReadinessFixture(t *testing.T) (*NativeWorkerRegistry, NativeWorkerRecord, string) {
	t.Helper()
	r, scope, spec := nativeRegistryFixture(t)
	record, err := r.Reserve(scope, spec, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.prepare(record); err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.Exec(`UPDATE native_workers SET launch_state='launched' WHERE instance_id=?`, scope.InstanceID); err != nil {
		t.Fatal(err)
	}
	path, err := sessionworker.SocketPath(record.Dir)
	if err != nil {
		t.Fatal(err)
	}
	return r, record, path
}

func nativeWorkerReadinessSocket(t *testing.T, path string) {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
}

func TestNativeWorkerReadinessWaitsForPrivateSocket(t *testing.T) {
	r, record, path := nativeWorkerReadinessFixture(t)
	nativeWorkerReadinessSocket(t, path)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ready := make(chan error, 1)
	go func() { ready <- EnsureNativeWorker(ctx, r, record, "/bin/true", nil, "") }()
	select {
	case err := <-ready:
		t.Fatalf("readiness completed before socket became private: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := <-ready; err != nil {
		t.Fatalf("private socket did not become ready: %v", err)
	}
}

func TestNativeWorkerReadinessNonPrivateSocketTimeout(t *testing.T) {
	for _, cancellation := range []bool{false, true} {
		name := "readiness deadline"
		if cancellation {
			name = "context deadline"
		}
		t.Run(name, func(t *testing.T) {
			r, record, path := nativeWorkerReadinessFixture(t)
			nativeWorkerReadinessSocket(t, path)
			ctx := context.Background()
			if cancellation {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
			}
			err := EnsureNativeWorker(ctx, r, record, "/bin/true", nil, "")
			if cancellation {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("expected context deadline, got %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "original native worker unavailable") {
				t.Fatalf("expected readiness deadline, got %v", err)
			}
			info, err := os.Lstat(path)
			if err != nil || info.Mode().Perm() != 0755 {
				t.Fatalf("controller changed non-private socket: %v, %v", info, err)
			}
		})
	}
}

func TestNativeWorkerReadinessRejectsInvalidPaths(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		name := "regular file"
		if symlink {
			name = "symlink to private socket"
		}
		t.Run(name, func(t *testing.T) {
			r, record, path := nativeWorkerReadinessFixture(t)
			if symlink {
				target := filepath.Join(filepath.Dir(path), "target.sock")
				nativeWorkerReadinessSocket(t, target)
				if err := os.Chmod(target, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := EnsureNativeWorker(ctx, r, record, "/bin/true", nil, ""); err == nil || !strings.Contains(err.Error(), "not a private socket") {
				t.Fatalf("invalid path was not rejected immediately: %v", err)
			}
		})
	}
}

func TestNativeWorkerPreflightPreservesReservedAndLaunchedOwners(t *testing.T) {
	r, scope, spec := nativeRegistryFixture(t)
	dir := t.TempDir()
	spec.Binary = filepath.Join(dir, "qwen")
	if err := os.WriteFile(spec.Binary, []byte("#!/usr/bin/env node\n"), 0700); err != nil {
		t.Fatal(err)
	}
	record, err := r.Reserve(scope, spec, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureNativeWorker(context.Background(), r, record, "/bin/true", []string{"PATH=" + dir}, ""); err != agentruntime.ErrExecutableUnavailable {
		t.Fatalf("missing interpreter: %v", err)
	}
	current, err := r.Lookup(scope.InstanceID)
	if err != nil || current.LaunchState != "reserved" {
		t.Fatalf("failed preflight consumed original launch: %s, %v", current.LaunchState, err)
	}
	if _, err := os.Stat(record.Dir); !os.IsNotExist(err) {
		t.Fatal("failed preflight created worker bootstrap")
	}
	if err := r.prepare(record); err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.Exec(`UPDATE native_workers SET launch_state='launched' WHERE instance_id=?`, scope.InstanceID); err != nil {
		t.Fatal(err)
	}
	path, err := sessionworker.SocketPath(record.Dir)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureNativeWorker(context.Background(), r, record, "/bin/true", []string{"PATH=" + dir}, ""); err != nil {
		t.Fatalf("already launched owner rejected by interpreter preflight: %v", err)
	}
}
