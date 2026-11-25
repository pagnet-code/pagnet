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

const directManagedSourcePrepareQueueLimitV2 = 8

type directManagedSourcePrepareExecutorV2 interface {
	ready() bool
	verifyPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourcePrepareCommandV2) (*nativeWorkerPublicationToken, error)
	prepare(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourcePrepareCommandV2) ([]byte, error)
}

func (d *Daemon) directManagedSourcePrepareReadyV2() bool {
	return d.directManagedSourcePrepareV2 != nil && d.directManagedSourcePrepareV2.ready()
}

type directManagedSourcePrepareAttemptV2 struct {
	request transport.DirectManagedSourcePrepareCommandV2
	session transport.HostSessionPayload
}

// This bounded lane never sends commands through generic worker persistence.
type directManagedSourcePrepareConnectionV2 struct {
	d           *Daemon
	socket      *websocket.Conn
	native      *NativeObservationConnection
	executor    directManagedSourcePrepareExecutorV2
	endpoint    string
	negotiation *directManagedSourcePrepareNegotiationV2
	mu          sync.Mutex
	stopped     bool
	pending     int
	queue       chan directManagedSourcePrepareAttemptV2
	done        chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
}

func newDirectManagedSourcePrepareConnectionV2(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection, negotiation *directManagedSourcePrepareNegotiationV2) *directManagedSourcePrepareConnectionV2 {
	if negotiation == nil || negotiation.native != native || negotiation.socket != socket || !negotiation.valid() {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &directManagedSourcePrepareConnectionV2{ctx: ctx, cancel: cancel, d: d, negotiation: negotiation, socket: socket, native: native, executor: d.directManagedSourcePrepareV2, endpoint: native.serverURL, queue: make(chan directManagedSourcePrepareAttemptV2, directManagedSourcePrepareQueueLimitV2), done: make(chan struct{})}
	// Readiness may recover after a transient registry timeout. Keep a consumer
	// available for every configured executor; admission still checks readiness.
	if c.executor != nil {
		go c.run()
	}
	return c
}

func (c *directManagedSourcePrepareConnectionV2) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.stopped = true
		close(c.done)
		c.cancel()
	}
}

func (c *directManagedSourcePrepareConnectionV2) active(session transport.HostSessionPayload) bool {
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

func (c *directManagedSourcePrepareConnectionV2) handle(env transport.Envelope) bool {
	if env.Type != transport.MsgDirectManagedSourcePrepareV2 {
		return false
	}
	request, err := transport.DecodeDirectManagedSourcePrepareCommandV2(env.Payload)
	if err != nil {
		return true
	}
	session, err := c.native.AuthenticatedNativeHostSession()
	count := 0
	for _, feature := range session.ProtocolFeatures {
		if feature == transport.DirectManagedSourcePrepareProtocolV2 {
			count++
		}
	}
	if err != nil || count != 1 || !c.negotiation.valid() || !c.d.directManagedSourcePrepareReadyV2() || !c.active(session) {
		c.ack(directManagedSourcePrepareFailureV2(request), session, request)
		return true
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return true
	}
	if c.pending >= directManagedSourcePrepareQueueLimitV2 {
		c.mu.Unlock()
		c.close()
		_ = c.socket.Close()
		return true
	}
	// Keep retries in order, including changed transcripts with the same ID. The
	// durable executor reuses exact results and rejects changed replays.
	c.pending++
	c.queue <- directManagedSourcePrepareAttemptV2{request: request, session: session}
	c.mu.Unlock()
	return true
}

func (c *directManagedSourcePrepareConnectionV2) run() {
	for {
		select {
		case <-c.done:
			return
		case a := <-c.queue:
			if c.d.directManagedSourcePrepareReadyV2() && c.active(a.session) {
				result, err := c.executor.prepare(c.ctx, c.socket, c.native, a.session, c.endpoint, a.request)
				if err == nil {
					c.ack(result, a.session, a.request)
				} else {
					c.ack(directManagedSourcePrepareFailureV2(a.request), a.session, a.request)
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
func directManagedSourcePrepareFailureV2(request transport.DirectManagedSourcePrepareCommandV2) []byte {
	raw, _ := (transport.DirectManagedSourcePrepareFailureACKV2{ProtocolVersion: transport.DirectManagedSourcePrepareProtocolV2, CommandID: request.CommandID, Error: transport.DirectManagedSourcePrepareFailureV2}).CanonicalBytes()
	return raw
}

func (c *directManagedSourcePrepareConnectionV2) ack(payload []byte, session transport.HostSessionPayload, command transport.DirectManagedSourcePrepareCommandV2) {
	_, ackErr := transport.DecodeDirectManagedSourcePrepareACKV2(payload, command)
	errorCode := ""
	if ackErr != nil {
		if _, err := transport.DecodeDirectManagedSourcePrepareFailureACKV2(payload, command.CommandID); err != nil {
			return
		}
		errorCode = transport.DirectManagedSourcePrepareFailureV2
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
		if !c.d.directManagedSourcePrepareReadyV2() {
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
		err = c.d.publishNativeWorker(token, ManagedEndpointPrepareScope{Socket: c.socket, Connection: c.native, Session: session}, c.done, command.Subject.EnrollmentExpiresAt, func(deadline time.Time) error {
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

// The authenticated handshake captures this socket and session negotiation.
type directManagedSourcePrepareNegotiationV2 struct {
	socket  *websocket.Conn
	native  *NativeObservationConnection
	session transport.HostSessionPayload
}

func (n *directManagedSourcePrepareNegotiationV2) valid() bool {
	if n == nil || n.socket == nil || n.native == nil {
		return false
	}
	session, err := n.native.AuthenticatedNativeHostSession()
	if err != nil || !reflect.DeepEqual(session, n.session) {
		return false
	}
	count := 0
	for _, feature := range session.ProtocolFeatures {
		if feature == transport.DirectManagedSourcePrepareProtocolV2 {
			count++
		}
	}
	return count == 1
}
