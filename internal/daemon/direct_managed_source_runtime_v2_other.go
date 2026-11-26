//go:build !linux && !darwin

package daemon

import (
	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/transport"
)

func (*Daemon) initDirectManagedSourceV2()       {}
func (*Daemon) directManagedSourceV2Ready() bool { return false }
func (*Daemon) directManagedSourceV2Handlers(*websocket.Conn, *NativeObservationConnection) ([]func(transport.Envelope) bool, func()) {
	return nil, nil
}

func directManagedSourceV2ServerOrigin(string) string { return "" }
