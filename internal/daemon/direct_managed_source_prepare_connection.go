package daemon

import (
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

const directManagedSourcePrepareQueueLimit = 8

type directManagedSourcePrepareExecutor interface {
	ready() bool
	verifyPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourcePrepareCommand) (*nativeWorkerPublicationToken, error)
	prepare(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourcePrepareCommand) ([]byte, error)
}

func (d *Daemon) directManagedSourcePrepareReady() bool {
	return d.DirectManagedSourcePrepareEnabled && d.directManagedSourcePrepare != nil && d.directManagedSourcePrepare.ready()
}

type directManagedSourcePrepareAttempt struct {
	request transport.DirectManagedSourcePrepareCommand
	session transport.HostSessionPayload
}

// This bounded lane never sends commands through generic worker persistence.
type directManagedSourcePrepareConnection struct {
	d        *Daemon
	socket   *websocket.Conn
	native   *NativeObservationConnection
	executor directManagedSourcePrepareExecutor
	endpoint string
	mu       sync.Mutex
	stopped  bool
	pending  int
	queue    chan directManagedSourcePrepareAttempt
	done     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
}

func newDirectManagedSourcePrepareConnection(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection) *directManagedSourcePrepareConnection {
	ctx, cancel := context.WithCancel(context.Background())
	c := &directManagedSourcePrepareConnection{ctx: ctx, cancel: cancel, d: d, socket: socket, native: native, executor: d.directManagedSourcePrepare, endpoint: native.serverURL, queue: make(chan directManagedSourcePrepareAttempt, directManagedSourcePrepareQueueLimit), done: make(chan struct{})}
	// Readiness may recover after a transient registry timeout. Keep a consumer
	// available for every configured executor; admission still checks readiness.
	if c.executor != nil {
		go c.run()
	}
	return c
}

func (c *directManagedSourcePrepareConnection) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.stopped = true
		close(c.done)
		c.cancel()
	}
}

func (c *directManagedSourcePrepareConnection) active(session transport.HostSessionPayload) bool {
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

func (c *directManagedSourcePrepareConnection) handle(env transport.Envelope) bool {
	if env.Type != transport.MsgDirectManagedSourcePrepare {
		return false
	}
	request, err := transport.DecodeDirectManagedSourcePrepareCommand(env.Payload)
	if err != nil {
		return true
	}
	session, err := c.native.AuthenticatedNativeHostSession()
	count := 0
	for _, feature := range session.ProtocolFeatures {
		if feature == transport.DirectManagedSourcePrepareProtocol {
			count++
		}
	}
	if err != nil || count != 1 || !c.native.offeredDirectManagedSourcePrepare || !c.d.directManagedSourcePrepareReady() || !c.active(session) {
		c.ack(directManagedSourcePrepareFailure(request), session, request)
		return true
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return true
	}
	if c.pending >= directManagedSourcePrepareQueueLimit {
		c.mu.Unlock()
		c.close()
		_ = c.socket.Close()
		return true
	}
	// Keep retries in order, including changed transcripts with the same ID. The
	// durable executor reuses exact results and rejects changed replays.
	c.pending++
	c.queue <- directManagedSourcePrepareAttempt{request: request, session: session}
	c.mu.Unlock()
	return true
}

func (c *directManagedSourcePrepareConnection) run() {
	for {
		select {
		case <-c.done:
			return
		case a := <-c.queue:
			if c.d.directManagedSourcePrepareReady() && c.active(a.session) {
				result, err := c.executor.prepare(c.ctx, c.socket, c.native, a.session, c.endpoint, a.request)
				if err == nil {
					c.ack(result, a.session, a.request)
				} else {
					c.ack(directManagedSourcePrepareFailure(a.request), a.session, a.request)
				}
				clear(result)
			}
			c.mu.Lock()
			c.pending--
			c.mu.Unlock()
		}
	}
}

// No generic send/ACK helper: those may retarget and/or persist command results.
func directManagedSourcePrepareFailure(request transport.DirectManagedSourcePrepareCommand) []byte {
	raw, _ := (transport.DirectManagedSourcePrepareFailureACK{ProtocolVersion: transport.DirectManagedSourcePrepareProtocol, CommandID: request.CommandID, Error: transport.DirectManagedSourcePrepareFailure}).CanonicalBytes()
	return raw
}

func (c *directManagedSourcePrepareConnection) ack(payload []byte, session transport.HostSessionPayload, command transport.DirectManagedSourcePrepareCommand) {
	_, ackErr := transport.DecodeDirectManagedSourcePrepareACK(payload, command)
	errorCode := ""
	if ackErr != nil {
		if _, err := transport.DecodeDirectManagedSourcePrepareFailureACK(payload, command.CommandID); err != nil {
			return
		}
		errorCode = transport.DirectManagedSourcePrepareFailure
	}
	env, err := transport.NewEnvelope(transport.MsgCommandAck, struct {
		CommandID domain.ID       `json:"commandId"`
		Error     string          `json:"error"`
		Result    json.RawMessage `json:"result"`
	}{CommandID: command.CommandID, Error: errorCode, Result: json.RawMessage(payload)})
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
	if ackErr == nil {
		if !c.d.directManagedSourcePrepareReady() {
			c.d.writeMu.Unlock()
			return
		}
		ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
		token, verifyErr := c.executor.verifyPublication(ctx, c.socket, c.native, session, c.endpoint, command)
		cancel()
		if verifyErr != nil {
			c.d.writeMu.Unlock()
			return
		}
		wrote := false
		err = c.d.publishNativeWorker(token, ManagedEndpointPrepareScope{Socket: c.socket, Connection: c.native, Session: session}, c.done, command.Subject.ExpiresAt, func(deadline time.Time) error {
			wrote = true
			if err := c.socket.SetWriteDeadline(deadline); err != nil {
				return err
			}
			return c.socket.WriteMessage(websocket.TextMessage, raw)
		})
		c.d.writeMu.Unlock()
		if wrote && err != nil {
			c.d.invalidateCurrentConnection(c.socket)
		}
		return
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
	case <-c.native.closed:
		c.native.mu.Unlock()
		c.d.connMu.Unlock()
		c.d.writeMu.Unlock()
		return
	case <-c.done:
		c.native.mu.Unlock()
		c.d.connMu.Unlock()
		c.d.writeMu.Unlock()
		return
	default:
	}
	err = c.socket.SetWriteDeadline(time.Now().Add(c.d.writeTimeout))
	if err == nil {
		err = c.socket.WriteMessage(websocket.TextMessage, raw)
	}
	c.native.mu.Unlock()
	c.d.connMu.Unlock()
	c.d.writeMu.Unlock()
	if err != nil {
		c.d.invalidateCurrentConnection(c.socket)
	}
}
