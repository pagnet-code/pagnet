package daemon

import (
	"encoding/json"
	"reflect"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

const nativeShareSourcePrepareQueueLimit = 8
const nativeShareSourcePrepareError = "native share source prepare unavailable"

type nativeShareSourcePrepareExecutor interface {
	nativeShareSourcePrepareReady() bool
	Prepare(string, transport.HostSessionPayload, transport.NativeShareSourcePreparePayload) (transport.NativeShareSourcePreparedPayload, error)
}

type nativeShareSourcePrepareAttempt struct {
	request transport.NativeShareSourcePreparePayload
	session transport.HostSessionPayload
}

// This bounded lane never sends commands through generic worker persistence.
type nativeShareSourcePrepareConnection struct {
	d        *Daemon
	socket   *websocket.Conn
	native   *NativeObservationConnection
	executor nativeShareSourcePrepareExecutor
	endpoint string
	mu       sync.Mutex
	stopped  bool
	pending  int
	queue    chan nativeShareSourcePrepareAttempt
	done     chan struct{}
}

func newNativeShareSourcePrepareConnection(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection) *nativeShareSourcePrepareConnection {
	c := &nativeShareSourcePrepareConnection{d: d, socket: socket, native: native, executor: d.nativeSourcePrepare, endpoint: native.serverURL, queue: make(chan nativeShareSourcePrepareAttempt, nativeShareSourcePrepareQueueLimit), done: make(chan struct{})}
	if c.executor != nil && c.executor.nativeShareSourcePrepareReady() {
		go c.run()
	}
	return c
}

func (c *nativeShareSourcePrepareConnection) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.stopped = true
		close(c.done)
	}
}

func (c *nativeShareSourcePrepareConnection) active(session transport.HostSessionPayload) bool {
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

func (c *nativeShareSourcePrepareConnection) handle(env transport.Envelope) bool {
	if env.Type != transport.MsgNativeShareSourcePrepare {
		return false
	}
	request, err := transport.DecodeNativeShareSourcePreparePayload(env.Payload)
	if err != nil {
		return true
	}
	session, err := c.native.AuthenticatedNativeHostSession()
	count := 0
	for _, feature := range session.ProtocolFeatures {
		if feature == transport.NativeShareSourceEnrollmentProtocol {
			count++
		}
	}
	if err != nil || count != 1 || c.executor == nil || !c.executor.nativeShareSourcePrepareReady() || !c.active(session) {
		c.ack(request.CommandID, nil, session)
		return true
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return true
	}
	if c.pending >= nativeShareSourcePrepareQueueLimit {
		c.mu.Unlock()
		c.ack(request.CommandID, nil, session)
		return true
	}
	// Keep retries in order, including changed transcripts with the same ID. The
	// durable executor reuses exact results and rejects changed replays.
	c.pending++
	c.queue <- nativeShareSourcePrepareAttempt{request: request, session: session}
	c.mu.Unlock()
	return true
}

func (c *nativeShareSourcePrepareConnection) run() {
	for {
		select {
		case <-c.done:
			return
		case a := <-c.queue:
			if c.active(a.session) {
				result, err := c.executor.Prepare(c.endpoint, a.session, a.request)
				if err == nil {
					c.ack(a.request.CommandID, result, a.session)
				} else {
					c.ack(a.request.CommandID, nil, a.session)
				}
			}
			c.mu.Lock()
			c.pending--
			c.mu.Unlock()
		}
	}
}

// No generic send/ACK helper: those may retarget and/or persist command results.
func (c *nativeShareSourcePrepareConnection) ack(id domain.ID, result any, session transport.HostSessionPayload) {
	payload := struct {
		CommandID domain.ID `json:"commandId"`
		Error     string    `json:"error,omitempty"`
		Result    any       `json:"result,omitempty"`
	}{CommandID: id, Result: result}
	if result == nil {
		payload.Error = nativeShareSourcePrepareError
	}
	env, err := transport.NewEnvelope(transport.MsgCommandAck, payload)
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
