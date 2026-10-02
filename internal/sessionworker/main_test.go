//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

func TestFailedNativeListenerCannotAdvertiseWholeOwnership(t *testing.T) {
	const childEnvironment = "PAGNET_TEST_FAILED_WORKER_BRIDGE"
	if state := os.Getenv(childEnvironment); state != "" {
		os.Exit(RunMain([]string{"--state", state}, "test-worker"))
	}
	dir, err := os.MkdirTemp("", "pgn-bridge-fail-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	key := bytes.Repeat([]byte{1}, 32)
	bootstrap := Bootstrap{Protocol: Protocol, Scope: testScope(), Native: NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: "/bin/true", MCPExecutable: "/bin/true", Workspace: dir, NetworkID: "network", Kind: "worker", TenantID: "tenant", NetworkTenantID: "tenant"}}
	if err := PrepareBootstrap(dir, bootstrap, key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "native.sock"), []byte("not a socket"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFailedNativeListenerCannotAdvertiseWholeOwnership$")
	cmd.Env = append(os.Environ(), childEnvironment+"="+dir)
	var logs bytes.Buffer
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("failed bridge startup succeeded")
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("worker remained available after required bridge startup failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if controller, err := DialOwnerController(ctx, dir, bootstrap.Scope, key, "test-controller"); err == nil {
		_ = controller.Close()
		t.Fatal("whole ownership authenticated without native listener")
	}
	if _, err := os.Lstat(filepath.Join(dir, "controller.sock")); !os.IsNotExist(err) {
		t.Fatalf("controller socket advertised before bridge readiness: %v", err)
	}
}
