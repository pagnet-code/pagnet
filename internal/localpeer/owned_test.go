//go:build linux || darwin

package localpeer

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The connecting peer is a real subprocess, so kernel credentials and the
// actual descendant tree are exercised rather than trusted peer declarations.
func TestOwnedNativeDescendant(t *testing.T) {
	if os.Getenv("PAGNET_LOCALPEER_CHILD") == "1" {
		c, err := net.Dial("unix", os.Getenv("PAGNET_LOCALPEER_SOCKET"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		b := make([]byte, 1)
		if _, err = c.Read(b); err != nil {
			t.Fatal(err)
		}
		return
	}
	dir, err := os.MkdirTemp("", "pgn-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedNativeDescendant$")
	cmd.Env = append(os.Environ(), "PAGNET_LOCALPEER_CHILD=1", "PAGNET_LOCALPEER_SOCKET="+path)
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	c, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	root, err := ReadProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	marker := strconv.FormatInt(root.Start, 10)
	if err = VerifyOwned(c, os.Getpid(), marker); err != nil {
		t.Fatalf("actual native descendant rejected: %v", err)
	}
	if err = VerifyOwned(c, os.Getpid(), ""); err == nil {
		t.Fatal("missing captured birth marker accepted")
	}
	if err = VerifyOwned(c, os.Getpid(), fmt.Sprint(root.Start+1)); err == nil {
		t.Fatal("different activation birth marker accepted")
	}
	// A process cannot authenticate as the generation of an unrelated sibling.
	sibling := exec.Command("sleep", "30")
	if err = sibling.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sibling.Process.Kill(); _ = sibling.Wait() }()
	siblingRoot, err := ReadProcess(sibling.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyOwned(c, sibling.Process.Pid, strconv.FormatInt(siblingRoot.Start, 10)); err == nil {
		t.Fatal("unrelated native root accepted")
	}
	_, _ = c.Write([]byte{1})
}
