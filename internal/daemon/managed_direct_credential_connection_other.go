//go:build !linux && !darwin

package daemon

import (
	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/transport"
)

type managedDirectCredentialExecutor interface{ ready() bool }
type managedDirectCredentialConnection struct{}
type managedDirectCredentialNegotiation struct {
	socket  *websocket.Conn
	native  *NativeObservationConnection
	session transport.HostSessionPayload
}

func (*managedDirectCredentialNegotiation) valid() bool { return false }
func newManagedDirectCredentialConnection(*Daemon, *websocket.Conn, *NativeObservationConnection, *managedDirectCredentialNegotiation) *managedDirectCredentialConnection {
	return nil
}
func (*managedDirectCredentialConnection) close() {}
func (*managedDirectCredentialConnection) handle(env transport.Envelope) bool {
	return env.Type == transport.MsgManagedDirectCredential
}
