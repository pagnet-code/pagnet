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

const nativeShareSourceProveQueueLimit = 8
const nativeShareSourceProveError = "native share source prove unavailable"

type nativeShareSourceProveExecutor interface {
	nativeShareSourceProveReady() bool
	Prove(string, transport.HostSessionPayload, transport.NativeShareSourceProvePayload) (transport.NativeShareSourceProvedPayload, error)
}

type nativeShareSourceProveAttempt struct {
	request transport.NativeShareSourceProvePayload
	session transport.HostSessionPayload
}

// This bounded lane never sends commands through generic worker persistence.
type nativeShareSourceProveConnection struct {
	d        *Daemon
	socket   *websocket.Conn
	native   *NativeObservationConnection
	executor nativeShareSourceProveExecutor
	endpoint string
	mu       sync.Mutex
	stopped  bool
	pending  int
	queue    chan nativeShareSourceProveAttempt
	done     chan struct{}
}

func newNativeShareSourceProveConnection(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection) *nativeShareSourceProveConnection {
	c := &nativeShareSourceProveConnection{d: d, socket: socket, native: native, executor: d.nativeSourceProve, endpoint: native.serverURL, queue: make(chan nativeShareSourceProveAttempt, nativeShareSourceProveQueueLimit), done: make(chan struct{})}
	// Readiness may recover after a transient registry timeout. Keep a consumer
	// available for every configured executor; admission still checks readiness.
	if c.executor != nil {
		go c.run()
	}
	return c
}

func (c *nativeShareSourceProveConnection) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.stopped = true
		close(c.done)
	}
}

func (c *nativeShareSourceProveConnection) active(session transport.HostSessionPayload) bool {
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

func (c *nativeShareSourceProveConnection) handle(env transport.Envelope) bool {
	if env.Type != transport.MsgNativeShareSourceProve {
		return false
	}
	request, err := transport.DecodeNativeShareSourceProvePayload(env.Payload)
	if err != nil {
		return true
	}
	session, err := c.native.AuthenticatedNativeHostSession()
	count := 0
	for _, feature := range session.ProtocolFeatures {
		if feature == transport.NativeShareSourceProveProtocol {
			count++
		}
	}
	if err != nil || count != 1 || c.executor == nil || !c.executor.nativeShareSourceProveReady() || !c.active(session) {
		c.ack(request.CommandID, nil, session)
		return true
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return true
	}
	if c.pending >= nativeShareSourceProveQueueLimit {
		c.mu.Unlock()
		c.ack(request.CommandID, nil, session)
		return true
	}
	// Keep retries in order, including changed transcripts with the same ID. The
	// durable executor reuses exact results and rejects changed replays.
	c.pending++
	c.queue <- nativeShareSourceProveAttempt{request: request, session: session}
	c.mu.Unlock()
	return true
}

func (c *nativeShareSourceProveConnection) run() {
	for {
		select {
		case <-c.done:
			return
		case a := <-c.queue:
			if c.active(a.session) {
				result, err := c.executor.Prove(c.endpoint, a.session, a.request)
				if err == nil {
					c.ack(a.request.CommandID, result, a.session)
					clear(result.Challenge)
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
func (c *nativeShareSourceProveConnection) ack(id domain.ID, result any, session transport.HostSessionPayload) {
	payload := struct {
		CommandID domain.ID `json:"commandId"`
		Error     string    `json:"error,omitempty"`
		Result    any       `json:"result,omitempty"`
	}{CommandID: id, Result: result}
	if result == nil {
		payload.Error = nativeShareSourceProveError
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
