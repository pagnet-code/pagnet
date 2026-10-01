//go:build darwin

package daemon

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The helper is an actual child process; no peer PID or credentials are mocked.
func TestDarwinBridgePeerProcessHelper(t *testing.T) {
	path := os.Getenv("PAGNET_PEER_TEST_SOCKET")
	if path == "" {
		return
	}
	if os.Getenv("PAGNET_PEER_TEST_PARENT") == "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDarwinBridgePeerProcessHelper$")
		cmd.Env = append(os.Environ(), "PAGNET_PEER_TEST_PARENT=0")
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		return
	}
	c, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err = io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
}

func TestDarwinBridgeKernelDescendantAndSibling(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "pagnet-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "bridge.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDarwinBridgePeerProcessHelper$")
	cmd.Env = append(os.Environ(), "PAGNET_PEER_TEST_SOCKET="+path, "PAGNET_PEER_TEST_PARENT=1")
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err = io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{}
	if err = d.verifyBridgePeer(conn, cmd.Process.Pid); err != nil {
		t.Fatalf("real grandchild rejected: %v", err)
	}
	// A second live child is a sibling, never an ancestor of the connected peer.
	sibling := exec.Command("/bin/sleep", "10")
	if err = sibling.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sibling.Process.Kill(); _ = sibling.Wait() }()
	if err = d.verifyBridgePeer(conn, sibling.Process.Pid); err == nil {
		t.Fatal("accepted unrelated same-UID root")
	}
	if err = d.verifyBridgePeer(conn, 0); err == nil {
		t.Fatal("accepted absent runtime root")
	}
	_, _ = conn.Write([]byte{1})
}

func TestDarwinBridgeTreeRejectsUnrelatedNonceHolder(t *testing.T) {
	// Darwin Unix socket paths are limited to 104 bytes; its default TMPDIR
	// plus this test name exceeds that limit before any authentication runs.
	t.Setenv("TMPDIR", "/tmp")
	d, _ := newBridgeE2EDaemon(t)
	instanceID := launchFakeEndpoint(t, d, "worker")
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatal("missing instance")
	}
	c := bridgeDial(t, d.bridgePath)
	response := c.authFull(t, instanceID, row.NetworkID, d.currentBridgeNonce(instanceID), "worker")
	assertBridgeError(t, response, "peer process verification failed")
}
