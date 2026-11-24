package daemon

import (
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/transport"
)

const managedEndpointPrepareQueueLimit = 8

type managedEndpointPrepareExecutor interface {
	ready() bool
	verifyPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.ManagedEndpointPrepareCommand) error
	prepare(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.ManagedEndpointPrepareCommand) ([]byte, error)
}

func (d *Daemon) managedEndpointPrepareReady() bool {
	return d.ManagedEndpointPrepareEnabled && d.managedEndpointPrepare != nil && d.managedEndpointPrepare.ready()
}

type managedEndpointPrepareAttempt struct {
	request transport.ManagedEndpointPrepareCommand
	session transport.HostSessionPayload
}

// This bounded lane never sends commands through generic worker persistence.
type managedEndpointPrepareConnection struct {
	d        *Daemon
	socket   *websocket.Conn
	native   *NativeObservationConnection
	executor managedEndpointPrepareExecutor
	endpoint string
	mu       sync.Mutex
	stopped  bool
	pending  int
	queue    chan managedEndpointPrepareAttempt
	done     chan struct{}
}

func newManagedEndpointPrepareConnection(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection) *managedEndpointPrepareConnection {
	c := &managedEndpointPrepareConnection{d: d, socket: socket, native: native, executor: d.managedEndpointPrepare, endpoint: native.serverURL, queue: make(chan managedEndpointPrepareAttempt, managedEndpointPrepareQueueLimit), done: make(chan struct{})}
	// Readiness may recover after a transient registry timeout. Keep a consumer
	// available for every configured executor; admission still checks readiness.
	if c.executor != nil {
		go c.run()
	}
	return c
}

func (c *managedEndpointPrepareConnection) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.stopped = true
		close(c.done)
	}
}

func (c *managedEndpointPrepareConnection) active(session transport.HostSessionPayload) bool {
	c.d.connMu.Lock()
	defer c.d.connMu.Unlock()
	if c.d.curConn != c.socket || c.d.nativeConn != c.native {
		return false
	}
	select {
	case <-c.done:
		return false
	default:
	}
	current, err := c.native.AuthenticatedNativeHostSession()
	return err == nil && reflect.DeepEqual(current, session)
}

func (c *managedEndpointPrepareConnection) handle(env transport.Envelope) bool {
	if env.Type != transport.MsgManagedEndpointPrepare {
		return false
	}
	request, err := transport.DecodeManagedEndpointPrepareCommand(env.Payload)
	if err != nil {
		return true
	}
	session, err := c.native.AuthenticatedNativeHostSession()
	count := 0
	for _, feature := range session.ProtocolFeatures {
		if feature == transport.ManagedEndpointPrepareProtocol {
			count++
		}
	}
	if err != nil || count != 1 || !c.native.offeredManagedEndpointPrepare || !c.d.managedEndpointPrepareReady() || !c.active(session) {
		c.ack(managedPrepareFailure(request), session, request)
		return true
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return true
	}
	if c.pending >= managedEndpointPrepareQueueLimit {
		c.mu.Unlock()
		c.close()
		_ = c.socket.Close()
		return true
	}
	// Keep retries in order, including changed transcripts with the same ID. The
	// durable executor reuses exact results and rejects changed replays.
	c.pending++
	c.queue <- managedEndpointPrepareAttempt{request: request, session: session}
	c.mu.Unlock()
	return true
}

func (c *managedEndpointPrepareConnection) run() {
	for {
		select {
		case <-c.done:
			return
		case a := <-c.queue:
			if c.active(a.session) {
				result, err := c.executor.prepare(context.Background(), c.socket, c.native, a.session, c.endpoint, a.request)
				if err == nil {
					c.ack(result, a.session, a.request)
				} else {
					c.ack(managedPrepareFailure(a.request), a.session, a.request)
				}
			}
			c.mu.Lock()
			c.pending--
			c.mu.Unlock()
		}
	}
}

// No generic send/ACK helper: those may retarget and/or persist command results.
func managedPrepareFailure(request transport.ManagedEndpointPrepareCommand) []byte {
	raw, _ := (transport.ManagedEndpointPrepareFailureACK{ProtocolVersion: transport.ManagedEndpointPrepareProtocol, CommandID: request.CommandID, Error: transport.ManagedEndpointPrepareFailure}).CanonicalBytes()
	return raw
}

func (c *managedEndpointPrepareConnection) ack(payload []byte, session transport.HostSessionPayload, command transport.ManagedEndpointPrepareCommand) {
	env, err := transport.NewEnvelope(transport.MsgCommandAck, json.RawMessage(payload))
	if err != nil {
		return
	}
	defer clear(env.Payload)
	raw, err := json.Marshal(env)
	if err != nil {
		return
	}
	defer clear(raw)
	// Serialize before checking ownership so a writer waiting behind another
	// frame cannot reply after supersession. Keep ownership fenced through write.
	c.d.writeMu.Lock()
	if _, err := transport.DecodeManagedEndpointPrepareACK(payload, command); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := c.executor.verifyPublication(ctx, c.socket, c.native, session, c.endpoint, command)
		cancel()
		if err != nil {
			c.d.writeMu.Unlock()
			return
		}

	}
	c.d.connMu.Lock()
	c.native.mu.Lock()
	if c.d.curConn != c.socket || c.d.nativeConn != c.native || c.native.session == nil || !reflect.DeepEqual(*c.native.session, session) {
		c.native.mu.Unlock()
		c.d.connMu.Unlock()
		c.d.writeMu.Unlock()
		return
	}
	select {
	case <-c.done:
		c.native.mu.Unlock()
		c.d.connMu.Unlock()
		c.d.writeMu.Unlock()
		return
	default:
	}
	_ = c.socket.SetWriteDeadline(time.Now().Add(c.d.writeTimeout))
	err = c.socket.WriteMessage(websocket.TextMessage, raw)
	c.native.mu.Unlock()
	c.d.connMu.Unlock()
	c.d.writeMu.Unlock()
	if err != nil {
		c.d.invalidateCurrentConnection(c.socket)
	}
}
