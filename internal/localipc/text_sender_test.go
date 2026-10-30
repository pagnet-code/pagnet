//go:build linux || darwin

package localipc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTextSenderSocketPathUsesDistinctDomain(t *testing.T) {
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	direct, err := TextSenderSocketPath(state)
	if err != nil {
		t.Fatal(err)
	}
	if direct != filepath.Join(state, TextSenderSocketName) {
		t.Fatal("short sender path changed", direct)
	}
	long := filepath.Join(state, strings.Repeat("x", 90))
	if err := os.Mkdir(long, 0700); err != nil {
		t.Fatal(err)
	}
	sender, err := TextSenderSocketPath(long)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := WorkerSocketPath(long)
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := shortBridgeSocketPath(long, filepath.Dir(sender), 104)
	if err != nil {
		t.Fatal(err)
	}
	if sender == worker || sender == bridge || len(sender) >= 104 {
		t.Fatal("sender long socket domain collided", sender, worker, bridge)
	}
}
