//go:build darwin

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/internal/localipc"
)

func TestDarwinUpdateDiscoversLongStateBridge(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "p-update-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	state := filepath.Join(root, strings.Repeat("s", 100))
	if err = os.MkdirAll(state, 0700); err != nil {
		t.Fatal(err)
	}
	path, err := localipc.BridgeSocketPath(state)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("error\n"))
	}()
	if !daemonRunning(state) {
		t.Fatal("running daemon undiscovered under long state path")
	}
	listener.Close()
	<-done
	if daemonRunning(state) {
		t.Fatal("closed daemon still reported online")
	}
}
