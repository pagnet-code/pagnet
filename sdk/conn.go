package sdk

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/pagnet-code/pagnet/transport"
)

// conn is one live WebSocket session to the control plane. The supervisor
// creates one per (re)connect; readLoop routes envelopes, heartbeat sends
// liveness reports. dead is closed exactly once when the session ends.
type conn struct {
	ws     *websocket.Conn
	c      *Client
	authOK chan transport.EndpointAuthOKPayload
	dead   chan struct{}
	sendMu sync.Mutex
}

// send writes one envelope (serialized: one concurrent writer).
func (pc *conn) send(msgType string, payload any) error {
	env, err := transport.NewEnvelope(msgType, payload)
	if err != nil {
		return err
	}
	pc.sendMu.Lock()
	defer pc.sendMu.Unlock()
	return pc.ws.WriteJSON(env)
}

// readLoop reads envelopes until the connection dies, then closes dead.
//
// Routing:
//   - auth_ok / heartbeat_ack / crypto_* / upgrade_required: handled inline
//     (control plane; fast, non-blocking).
//   - deliveries (message/event/invocation): enqueued to the dispatcher.
//     The send BLOCKS when the dispatcher's handler slots are saturated —
//     that is the backpressure path (north-star §119): the WebSocket buffer
//     fills, the control plane stops live dispatch, and the delivery stays
//     pending in the DB (at-least-once; nothing is dropped).
func (pc *conn) readLoop() {
	defer close(pc.dead)
	for {
		var env transport.Envelope
		if err := pc.ws.ReadJSON(&env); err != nil {
			return
		}
		if env.Type == transport.MsgUpgradeRequired {
			var p transport.UpgradeRequiredPayload
			if err := env.DecodePayload(&p); err == nil {
				pc.c.firstErr(fmt.Errorf("sdk: %s (server requires protocol %d)", p.Message, p.Required))
			}
			return
		}
		if !env.IsVersionSupported() {
			pc.c.firstErr(fmt.Errorf("sdk: unsupported protocol version %d from server", env.ProtocolVersion))
			return
		}
		switch env.Type {
		case transport.MsgEndpointAuthOK:
			var p transport.EndpointAuthOKPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			select {
			case pc.authOK <- p:
			default:
			}
		case transport.MsgEndpointHeartbeatAck:
			// liveness only
		case MsgEndpointCryptoKeyPackage:
			var p EndpointCryptoKeyPackagePayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			if err := pc.c.handleCryptoKeyPackage(p); err != nil {
				pc.c.firstErr(fmt.Errorf("sdk: crypto enrollment (key package): %w", err))
			}
		case MsgEndpointCryptoChallenge:
			var p EndpointCryptoChallengePayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			if err := pc.c.handleCryptoChallenge(p); err != nil {
				pc.c.firstErr(fmt.Errorf("sdk: crypto enrollment (challenge): %w", err))
			}
		case transport.MsgEndpointMessageDeliver,
			transport.MsgEndpointEventDeliver,
			transport.MsgEndpointInvocationDispatch:
			select {
			case pc.c.dispatchQueue <- env:
			case <-pc.c.closeCh:
				return
			}
		default:
			// Unknown type: ignore (forward compatibility — the server may
			// add types the SDK does not act on).
		}
	}
}

// heartbeat sends endpoint.heartbeat {inflight} every heartbeatInterval
// until the session ends. The cadence is the client's captured interval
// (immutable for the client's lifetime — no data race with tests that
// shorten the package-level default).
func (pc *conn) heartbeat() {
	t := time.NewTicker(pc.c.heartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			inflight := int(atomic.LoadInt64(&pc.c.inflightCount))
			_ = pc.send(transport.MsgEndpointHeartbeat, transport.EndpointHeartbeatPayload{Inflight: inflight})
		case <-pc.dead:
			return
		case <-pc.c.closeCh:
			return
		}
	}
}

// dispatcher consumes the delivery queue and runs handlers under the
// backpressure semaphore. It is Client-level (one instance, survives
// reconnects) so in-flight work is never lost to a connection drop.
func (c *Client) dispatcher() {
	defer c.wg.Done()
	for {
		select {
		case <-c.closeCh:
			return
		case env := <-c.dispatchQueue:
			// Acquire a handler slot. When all handlerSlotCap slots are
			// busy this BLOCKS: the queue backs up, the read loop stops,
			// the WebSocket buffer fills, and the control plane stops live
			// dispatch (the delivery stays pending in the DB).
			select {
			case c.sem <- struct{}{}:
			case <-c.closeCh:
				return
			}
			atomic.AddInt64(&c.inflightCount, 1)
			go func(env transport.Envelope) {
				defer func() {
					<-c.sem
					atomic.AddInt64(&c.inflightCount, -1)
				}()
				c.handleDelivery(env)
			}(env)
		}
	}
}

// handleDelivery routes one delivery envelope to its handler. Handler
// PANICS are contained inside each handler (recovered) and treated as a
// handler failure per that delivery's ack semantics — never a process
// crash from untrusted peer content.
func (c *Client) handleDelivery(env transport.Envelope) {
	switch env.Type {
	case transport.MsgEndpointMessageDeliver:
		c.handleMessageDeliver(env)
	case transport.MsgEndpointEventDeliver:
		c.handleEventDeliver(env)
	case transport.MsgEndpointInvocationDispatch:
		c.handleInvocationDispatch(env)
	}
}
