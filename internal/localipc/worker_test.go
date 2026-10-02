//go:build unix

package localipc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkerEndpointsStableSeparateAndPrivate(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "pw-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	state := filepath.Join(root, strings.Repeat("long-account-path-", 8))
	if err := os.MkdirAll(state, 0700); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(root, "ipc")
	controller, err := shortNamedSocketPath(state, private, "controller.sock", "worker-controller", 104)
	if err != nil {
		t.Fatal(err)
	}
	native, err := shortNamedSocketPath(state, private, "native.sock", "worker-native", 104)
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := shortBridgeSocketPath(state, private, 104)
	if err != nil {
		t.Fatal(err)
	}
	if controller == native || controller == bridge || native == bridge || len(controller) >= 104 || len(native) >= 104 {
		t.Fatal("endpoint domain collision or oversized address")
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(state, alias); err != nil {
		t.Fatal(err)
	}
	same, err := shortNamedSocketPath(alias, private, "controller.sock", "worker-controller", 104)
	if err != nil || same != controller {
		t.Fatal("controller alias changed original address", err)
	}
	info, err := os.Lstat(private)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("namespace not private", err)
	}
	if err := os.Chmod(private, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := shortNamedSocketPath(state, private, "native.sock", "worker-native", 104); err == nil {
		t.Fatal("public namespace accepted")
	}
	if err := os.Remove(private); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, private); err != nil {
		t.Fatal(err)
	}
	if _, err := shortNamedSocketPath(state, private, "native.sock", "worker-native", 104); err == nil {
		t.Fatal("symlink namespace accepted")
	}
	if _, err := OwnedWorkerSocketPath(state, "../foreign.sock"); err == nil {
		t.Fatal("unknown endpoint accepted")
	}
}

func TestWorkerShortEndpointPreserved(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "pw-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	path, err := WorkerSocketPath(root)
	canonical, canonicalErr := filepath.EvalSymlinks(root)
	if err != nil || canonicalErr != nil || path != filepath.Join(canonical, "controller.sock") {
		t.Fatal("existing short worker endpoint changed", err)
	}
}
