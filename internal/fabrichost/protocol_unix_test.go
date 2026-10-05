//go:build linux || darwin

package fabrichost

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

func TestProtocolRegistryRejectsServerAliasesBeforeExposure(t *testing.T) {
	config, _ := fixture(t)
	config.Protocols = map[string]VerifiedSessionServer{AdminProtocol: config.Server}
	if h, err := Start(t.Context(), config); err == nil {
		h.CloseContext(t.Context())
		t.Fatal("same server exposed under two protocol authorities")
	}
	if _, err := os.Lstat(config.SocketPath); !os.IsNotExist(err) {
		t.Fatal("rejected protocol registry created socket")
	}
}

func TestExplicitProtocolDialRejectsWrongReadyWithoutFallback(t *testing.T) {
	config, _ := fixture(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.SocketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = os.Chmod(config.SocketPath, 0600); err != nil {
		t.Fatal(err)
	}
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		conn, e := listener.AcceptUnix()
		if e != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 8192)
		conn.Read(buf)
		conn.Write([]byte("{\"type\":\"fabric.ready\",\"protocol\":\"fabric.mcp\"}\n"))
	}()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if conn, _, err := DialProtocol(ctx, config.SocketPath, Authentication{Type: "fabric.auth", Mode: "owner"}, AdminProtocol); err == nil {
		conn.Close()
		t.Fatal("MCP acknowledgement accepted for admin")
	}
	select {
	case <-ended:
	case <-ctx.Done():
		t.Fatal("selected protocol handshake did not close")
	}
}
