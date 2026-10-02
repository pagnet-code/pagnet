package daemon

import (
	"context"
	"encoding/json"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/transport"
)

// nativeConnection binds all admission and source messages to one socket.
// Ordinary daemon send may select a newer socket; native provenance cannot.
func (d *Daemon) nativeConnection(conn *websocket.Conn) *NativeObservationConnection {
	return NewNativeObservationConnection(d.ServerURL, d.HostID, d.bootID, func(ctx context.Context, typ string, payload any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		env, err := transport.NewEnvelope(typ, payload)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(env)
		if err != nil {
			return err
		}
		return d.write(conn, raw)
	})
}

// HandleEnvelope is called only by this socket's read loop. Replies never
// select a replacement controller, and malformed admission closes this lane.
func (c *NativeObservationConnection) HandleEnvelope(env transport.Envelope) (handled bool, err error) {
	switch env.Type {
	case transport.MsgHostSession:
		var p transport.HostSessionPayload
		if err = env.DecodePayload(&p); err == nil {
			err = c.Admit(p)
		}
	case transport.MsgNativeOriginRegistered:
		var p transport.NativeOriginRegisteredPayload
		if err = env.DecodePayload(&p); err == nil {
			c.OriginRegistered(p)
		}
	case transport.MsgNativeOriginSessionConfirmed:
		var p transport.NativeOriginSessionConfirmedPayload
		if err = env.DecodePayload(&p); err == nil {
			c.SessionConfirmed(p)
		}
	case transport.MsgNativeOwnershipRegistered, transport.MsgNativeOwnershipRetired:
		var p transport.NativeOwnershipRegisteredPayload
		if err = env.DecodePayload(&p); err == nil {
			c.OwnershipDisposition(p)
		}
	case transport.MsgNativeContentStaged, transport.MsgNativeContentRejected:
		var p transport.NativeContentStagedPayload
		if err = env.DecodePayload(&p); err == nil {
			// A rejection cannot masquerade as successfully staged content.
			if env.Type == transport.MsgNativeContentRejected && p.PublicError == "" {
				err = ErrNativeObservationConflict
			} else {
				c.NativeContentDisposition(p)
			}
		}
	case transport.MsgNativeObservationReceipt, transport.MsgNativeObservationRejected:
		var p transport.NativeObservationReceiptPayload
		if err = env.DecodePayload(&p); err == nil {
			c.NativeWorkerObservationDisposition(env.Type, p)
		}
	default:
		return false, nil
	}
	if err != nil {
		c.Close()
	}
	return true, err
}
