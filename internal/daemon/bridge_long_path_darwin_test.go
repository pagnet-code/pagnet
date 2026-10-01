//go:build darwin

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinLongStateBridgeAddressAndCleanup(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "p-state-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	state := filepath.Join(root, strings.Repeat("s", 100), strings.Repeat("t", 100))
	d, err := New(Config{StateDir: state}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if len(d.bridgePath) >= 104 || strings.HasPrefix(d.bridgePath, state) {
		t.Fatalf("not a short private address: %q", d.bridgePath)
	}
	if err = d.startBridgeSocket(); err != nil {
		t.Fatal(err)
	}
	defer d.stopBridgeSocket()
	response := bridgeDial(t, d.bridgePath).authFull(t, "unknown", "", "", "worker")
	assertBridgeError(t, response, "unknown instance")
	config := d.mcpConfig(&InstanceRow{InstanceID: "unknown"})
	if !strings.Contains(config, d.bridgePath) {
		t.Fatalf("MCP config does not discover listener address: %s", config)
	}
	if err = d.startBridgeSocket(); err == nil {
		t.Fatal("duplicate listener was not refused")
	}
	d.stopBridgeSocket()
	if _, err = os.Lstat(d.bridgePath); !os.IsNotExist(err) {
		t.Fatalf("socket not removed: %v", err)
	}
	if _, err = os.Stat(filepath.Join(state, "daemon.sqlite")); err != nil {
		t.Fatal("state file lost during socket cleanup")
	}
}
