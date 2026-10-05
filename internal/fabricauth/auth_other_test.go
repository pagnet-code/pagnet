//go:build !linux && !darwin

package fabricauth

import (
	"context"
	"net"
	"testing"
)

func TestUnsupportedKernelPeerFailsClosed(t *testing.T) {
	if _, e := peer(context.Background(), &net.UnixConn{}, "/private/socket"); e == nil {
		t.Fatal("unsupported platform accepted kernel peer")
	}
}
