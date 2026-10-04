//go:build linux || darwin

package fabricnative

import (
	"context"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/pagnet-code/pagnet/internal/localpeer"
)

func TestOwnerGuardActualKernelChild(t *testing.T) {
	if os.Getenv("PAGNET_TEST_OWNER_GUARD_CHILD") == "1" {
		_, _ = os.Stdout.Write([]byte("ready"))
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestOwnerGuardActualKernelChild$")
	cmd.Env = append(os.Environ(), "PAGNET_TEST_OWNER_GUARD_CHILD=1")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close(); _ = cmd.Wait() }()
	ready := make([]byte, 5)
	if _, err = io.ReadFull(out, ready); err != nil || string(ready) != "ready" {
		t.Fatalf("actual child start: %q %v", ready, err)
	}
	root, err := localpeer.ReadProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := localpeer.ReadProcess(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if peer.Parent != root.PID {
		t.Fatal("fixture is not genuine kernel child")
	}
	g := NewOwnerGuard()
	if err = g.Register(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	if g.Validate(context.Background(), peer) == nil {
		t.Fatal("actual managed child authenticated as root owner")
	}
}
