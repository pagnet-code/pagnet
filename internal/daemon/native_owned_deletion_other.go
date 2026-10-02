//go:build !linux && !darwin

package daemon

import (
	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/transport"
)

func (d *Daemon) doNativeForget(*websocket.Conn, transport.ForgetInstancePayload) error {
	return errNativeWorkerPlatform
}
func (d *Daemon) confirmNativeForgotten(*websocket.Conn, transport.NativeInstanceForgottenPayload) error {
	return errNativeWorkerPlatform
}
