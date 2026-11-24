//go:build !linux && !darwin

package daemon

import (
	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/transport"
)

// The managed source credential lane uses the local publication authority
// fence, which is currently available only on Linux and macOS.
type directManagedSourceCredentialExecutor interface {
	ready() bool
}

func (d *Daemon) directManagedSourceCredentialReady() bool { return false }

type directManagedSourceCredentialConnection struct{}

func newDirectManagedSourceCredentialConnection(_ *Daemon, _ *websocket.Conn, _ *NativeObservationConnection) *directManagedSourceCredentialConnection {
	return &directManagedSourceCredentialConnection{}
}

func (*directManagedSourceCredentialConnection) close() {}

func (*directManagedSourceCredentialConnection) handle(_ transport.Envelope) bool { return false }
