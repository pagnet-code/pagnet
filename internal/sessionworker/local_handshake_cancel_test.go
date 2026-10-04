//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalHandshakeHonorsCallerLifetime(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			f := newLocalAuthorityFixture(t)
			dir := t.TempDir()
			path, err := SocketPath(dir)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Clean(path), Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithCancel(t.Context())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 100*time.Millisecond)
			}
			defer cancel()
			done := make(chan error, 1)
			go func() {
				c, e := DialLocal(ctx, dir, f.scope, bytes.Repeat([]byte{42}, 32), "real-stalled-handshake")
				if c != nil {
					c.Close()
				}
				done <- e
			}()
			conn, err := listener.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			// A genuine Unix peer accepts but never sends the server handshake.
			// Caller cancellation must close the blocked read, not wait five seconds.
			if !deadline {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("stalled handshake authenticated")
				}
			case <-time.After(time.Second):
				t.Fatal("handshake ignored caller lifetime")
			}
		})
	}
}
