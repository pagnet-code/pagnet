//go:build linux || darwin

package daemon

import (
	"context"
	"errors"
	"io"
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

// The wrapper selects this test in a fresh process without passing controller
// environment variables through the worker's intentionally minimal environment.
func TestNativeWorkerReadinessHelperProcess(t *testing.T) {
	separator := -1
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 {
		return
	}
	args := os.Args[separator+1:]
	if len(args) != 6 || args[1] != sessionworker.Subcommand || args[2] != "--state" || args[4] != "--env-fd" {
		os.Exit(24)
	}
	if args[0] == "exit-before-env" {
		_, _ = os.Stderr.WriteString("private fixture must never appear in diagnostics")
		os.Exit(22)
	}
	pipe := os.NewFile(3, "private-env")
	if _, err := io.Copy(io.Discard, pipe); err != nil {
		os.Exit(25)
	}
	_ = pipe.Close()
	if args[0] == "exit" {
		_, _ = os.Stderr.WriteString("private fixture must never appear in diagnostics")
		os.Exit(23)
	}
	delay := 5250 * time.Millisecond
	if args[0] == "cancel" {
		delay = 400 * time.Millisecond
	}
	time.Sleep(delay)
	path, err := sessionworker.SocketPath(args[3])
	if err != nil {
		os.Exit(26)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		os.Exit(27)
	}
	if err := os.Chmod(path, 0600); err != nil {
		os.Exit(28)
	}
	for {
		if _, err := os.Stat(filepath.Join(args[3], "helper-stop")); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = listener.Close()
	_ = os.WriteFile(filepath.Join(args[3], "helper-exited"), nil, 0600)
	os.Exit(0)
}

func nativeWorkerReadinessProcessFixture(t *testing.T, mode string) (*NativeWorkerRegistry, NativeWorkerRecord, string) {
	t.Helper()
	r, scope, spec := nativeRegistryFixture(t)
	record, err := r.Reserve(scope, spec, "", "")
	if err != nil {
		t.Fatal(err)
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "readiness-helper")
	quotedBinary := "'" + strings.ReplaceAll(testBinary, "'", "'\"'\"'") + "'"
	script := "#!/bin/sh\nexec " + quotedBinary + " -test.run=^TestNativeWorkerReadinessHelperProcess$ -- " + mode + " \"$@\"\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(mode, "exit") {
		t.Cleanup(func() {
			if err := os.WriteFile(filepath.Join(record.Dir, "helper-stop"), nil, 0600); err != nil {
				t.Error(err)
				return
			}
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(filepath.Join(record.Dir, "helper-exited")); err == nil {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Error("readiness helper did not exit")
		})
	}
	return r, record, binary
}

func TestNativeWorkerReadinessNewProcessSlowStartup(t *testing.T) {
	r, record, binary := nativeWorkerReadinessProcessFixture(t, "slow")
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	started := time.Now()
	if err := EnsureNativeWorker(ctx, r, record, binary, nil, ""); err != nil {
		t.Fatalf("slow original worker failed readiness: %v", err)
	}
	if time.Since(started) < 5*time.Second {
		t.Fatal("helper became ready before exercising the former readiness deadline")
	}
}

func TestNativeWorkerReadinessNewProcessEarlyExit(t *testing.T) {
	for mode, code := range map[string]string{"exit": "23", "exit-before-env": "22"} {
		t.Run(mode, func(t *testing.T) {
			r, record, binary := nativeWorkerReadinessProcessFixture(t, mode)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			started := time.Now()
			runtimeEnv := []string(nil)
			if mode == "exit-before-env" {
				// Exceed pipe capacity so the write observes the child closing fd3.
				runtimeEnv = []string{"PRIVATE_FIXTURE=" + strings.Repeat("s", 120<<10)}
			}
			err := EnsureNativeWorker(ctx, r, record, binary, runtimeEnv, "")
			if !errors.Is(err, errNativeWorkerReadinessUnavailable) || !strings.Contains(err.Error(), "exit code "+code) {
				t.Fatalf("missing safe child exit diagnostic: %v", err)
			}
			connection := NewNativeObservationConnection(record.Scope.ServerURL, record.Scope.HostID, "boot", nil)
			d := &Daemon{nativeRegistry: r}
			d.recordNativeWorkerReadinessFailure(connection, record, err)
			if got := d.nativeWorkerAvailability(nil, connection, record, time.Now()); got != "unavailable" {
				t.Fatalf("exited owner availability = %s", got)
			}
			if strings.Contains(err.Error(), "private fixture") {
				t.Fatal("worker stderr escaped into diagnostics")
			}
			if time.Since(started) >= 5*time.Second {
				t.Fatal("child exit waited for readiness deadline")
			}
			current, err := r.Lookup(record.Scope.InstanceID)
			if err != nil || current.LaunchState != "launched" {
				t.Fatalf("child exit made original launch retryable: %s, %v", current.LaunchState, err)
			}
			probe, stop := context.WithTimeout(t.Context(), 80*time.Millisecond)
			defer stop()
			if err := EnsureNativeWorker(probe, r, record, binary, nil, ""); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("consumed owner was relaunched: %v", err)
			}
		})
	}
}

func TestNativeWorkerReadinessCancellationLeavesNewProcessAlive(t *testing.T) {
	r, record, binary := nativeWorkerReadinessProcessFixture(t, "cancel")
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := EnsureNativeWorker(ctx, r, record, binary, nil, ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("readiness did not cancel: %v", err)
	}
	probe, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	if err := EnsureNativeWorker(probe, r, record, "/does-not-exist", nil, ""); err != nil {
		t.Fatalf("original worker did not survive cancellation: %v", err)
	}
}
