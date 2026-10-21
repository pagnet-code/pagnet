//go:build linux || darwin

package daemon

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

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
