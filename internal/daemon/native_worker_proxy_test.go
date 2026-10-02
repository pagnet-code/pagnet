//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeWorkerProxyReconnectsExistingWorkerWithoutBootstrapMutation(t *testing.T) {
	const childEnv = "PAGNET_TEST_PROXY_WORKER"
	if dir := os.Getenv(childEnv); dir != "" {
		os.Exit(sessionworker.RunMain([]string{"--state", dir}, "original-worker"))
	}
	dir, err := os.MkdirTemp("", "pgn-proxy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	scope := sessionworker.Scope{ServerURL: "https://example.test", TenantID: domain.NewID().String(), AccountID: domain.NewID().String(), HostID: domain.NewID().String(), InstanceID: domain.NewID().String(), Generation: domain.NewID().String()}
	b := sessionworker.Bootstrap{Protocol: sessionworker.Protocol, Scope: scope, Native: sessionworker.NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: "/bin/true", MCPExecutable: "/bin/true", Workspace: dir, Kind: "worker", NetworkID: domain.NewID().String(), NetworkTenantID: scope.TenantID, TenantID: scope.TenantID}}
	key := bytes.Repeat([]byte{5}, 32)
	if err := sessionworker.PrepareBootstrap(dir, b, key); err != nil {
		t.Fatal(err)
	}
	manifestBefore, err := os.ReadFile(filepath.Join(dir, "bootstrap.json"))
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestNativeWorkerProxyReconnectsExistingWorkerWithoutBootstrapMutation$")
	child.Env = append(os.Environ(), childEnv+"="+dir)
	var stderr bytes.Buffer
	child.Stderr = &stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	workerPID := child.Process.Pid
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "controller.sock")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("original worker did not publish authenticated socket")
		}
		time.Sleep(5 * time.Millisecond)
	}
	connection := func(admit bool) *NativeObservationConnection {
		boot, runner := domain.NewID().String(), domain.NewID().String()
		c := NewNativeObservationConnection(scope.ServerURL, scope.HostID, boot, func(context.Context, string, any) error {
			t.Error("idle worker manufactured remote effect")
			return nil
		})
		if admit {
			if err := c.Admit(transport.HostSessionPayload{TenantID: scope.TenantID, AccountID: scope.AccountID, OwnershipScope: "personal", NativeAdmissionID: domain.NewID().String(), HostID: scope.HostID, BootID: boot, RunnerID: runner, RunnerEpoch: time.Now().UTC(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(c.Close)
		return c
	}
	remoteA := connection(true)
	a, err := AttachNativeWorker(t.Context(), remoteA, dir, scope, "controller-A")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err := a.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if a.controller.WorkerBuild != "original-worker" {
		t.Fatal("controller replaced worker build")
	}
	for _, forbidden := range []string{"intent", "bridge_result", "admission", "activation_origin"} {
		if _, err := a.SourceCall(t.Context(), sessionworker.Request{Type: forbidden}); err == nil {
			t.Fatal("source journal lane accepted a native effect", forbidden)
		}
	}
	// No fresh server admission must fail BEFORE acquiring another local lease.
	if unavailable, err := AttachNativeWorker(t.Context(), connection(false), dir, scope, "offline"); err == nil {
		_ = unavailable.Close()
		t.Fatal("offline controller attached")
	}
	if _, err := a.Snapshot(t.Context()); err != nil {
		t.Fatal("offline attempt evicted live controller", err)
	}
	wrong := scope
	wrong.AccountID = domain.NewID().String()
	if foreign, err := AttachNativeWorker(t.Context(), remoteA, dir, wrong, "foreign"); err == nil {
		_ = foreign.Close()
		t.Fatal("foreign account attached")
	}
	if _, err := a.Snapshot(t.Context()); err != nil {
		t.Fatal("foreign attempt evicted live controller", err)
	}
	remoteA.Close()
	select {
	case <-a.done:
	case <-time.After(time.Second):
		t.Fatal("remote disconnect retained local controller admission")
	}
	if _, err := a.Snapshot(t.Context()); err == nil {
		t.Fatal("disconnected controller read inspection")
	}
	// The controller-free interval does not stop or relaunch the worker.
	remoteB := connection(true)
	replacement, err := AttachNativeWorker(t.Context(), remoteB, dir, scope, "controller-B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = replacement.Close() })
	if replacement.controller.Lease <= a.controller.Lease || replacement.controller.WorkerBuild != "original-worker" {
		t.Fatal("replacement lost worker ownership/fence")
	}
	if err := replacement.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if child.Process.Pid != workerPID {
		t.Fatal("worker process identity changed")
	}
	manifestAfter, err := os.ReadFile(filepath.Join(dir, "bootstrap.json"))
	if err != nil || !bytes.Equal(manifestBefore, manifestAfter) {
		t.Fatal("reconnect changed immutable bootstrap", err)
	}
	keyAfter, err := os.ReadFile(filepath.Join(dir, "control.key"))
	defer clear(keyAfter)
	if err != nil || !bytes.Equal(key, keyAfter) {
		t.Fatal("reconnect changed original control key", err)
	}
}
