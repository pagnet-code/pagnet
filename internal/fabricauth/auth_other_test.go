//go:build !linux && !darwin

package fabricauth

import (
	"net"
	"testing"
)

func TestUnsupportedKernelPeerFailsClosed(t *testing.T) {
	if _, e := peer(&net.UnixConn{}, "/private/socket"); e == nil {
		t.Fatal("unsupported platform accepted kernel peer")
	}
}
