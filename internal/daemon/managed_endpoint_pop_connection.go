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

const managedEndpointPoPQueueLimit = 8

type managedEndpointPoPExecutor interface {
	ready() bool
	verifyPoPPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.ManagedEndpointPoPChallenge) error
	confirmPoP(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.ManagedEndpointPoPChallenge) ([]byte, error)
}

func (d *Daemon) managedEndpointPoPReady() bool {
	return d.ManagedEndpointPoPEnabled && d.managedEndpointPrepareReady() && d.managedEndpointPoP != nil && d.managedEndpointPoP.ready()
}

type managedEndpointPoPAttempt struct {
	request transport.ManagedEndpointPoPChallenge
	session transport.HostSessionPayload
}

// This bounded lane never sends commands through generic worker persistence.
type managedEndpointPoPConnection struct {
	d        *Daemon
	socket   *websocket.Conn
	native   *NativeObservationConnection
	executor managedEndpointPoPExecutor
	endpoint string
	mu       sync.Mutex
	stopped  bool
	pending  int
	queue    chan managedEndpointPoPAttempt
	done     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
}

func newManagedEndpointPoPConnection(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection) *managedEndpointPoPConnection {
	ctx, cancel := context.WithCancel(context.Background())
	c := &managedEndpointPoPConnection{ctx: ctx, cancel: cancel, d: d, socket: socket, native: native, executor: d.managedEndpointPoP, endpoint: native.serverURL, queue: make(chan managedEndpointPoPAttempt, managedEndpointPoPQueueLimit), done: make(chan struct{})}
	// Readiness may recover after a transient registry timeout. Keep a consumer
	// available for every configured executor; admission still checks readiness.
	if c.executor != nil {
		go c.run()
	}
	return c
}

func (c *managedEndpointPoPConnection) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.stopped = true
		close(c.done)
		c.cancel()
	}
}

func (c *managedEndpointPoPConnection) active(session transport.HostSessionPayload) bool {
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

func (c *managedEndpointPoPConnection) handle(env transport.Envelope) bool {
	if env.Type != transport.MsgManagedEndpointPoP {
		return false
	}
	request, err := transport.DecodeManagedEndpointPoPChallenge(env.Payload)
	if err != nil {
		return true
	}
	session, err := c.native.AuthenticatedNativeHostSession()
	count := 0
	prepareCount := 0
	for _, feature := range session.ProtocolFeatures {
		if feature == transport.ManagedEndpointPrepareProtocol {
			prepareCount++
		}
		if feature == transport.ManagedEndpointPoPProtocol {
			count++
		}
	}
	if err != nil || count != 1 || prepareCount != 1 || !c.native.offeredManagedEndpointPrepare || !c.native.offeredManagedEndpointPoP || !c.d.managedEndpointPoPReady() || !c.active(session) {
		c.ack(managedPoPFailure(request), session, request)
		return true
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return true
	}
	if c.pending >= managedEndpointPoPQueueLimit {
		c.mu.Unlock()
		c.close()
		_ = c.socket.Close()
		return true
	}
	// Keep retries in order, including changed transcripts with the same ID. The
	// durable executor reuses exact results and rejects changed replays.
	c.pending++
	c.queue <- managedEndpointPoPAttempt{request: request, session: session}
	c.mu.Unlock()
	return true
}

func (c *managedEndpointPoPConnection) run() {
	for {
		select {
		case <-c.done:
			return
		case a := <-c.queue:
			if c.d.managedEndpointPoPReady() && c.active(a.session) {
				result, err := c.executor.confirmPoP(c.ctx, c.socket, c.native, a.session, c.endpoint, a.request)
				if err == nil {
					c.ack(result, a.session, a.request)
				} else {
					c.ack(managedPoPFailure(a.request), a.session, a.request)
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
func managedPoPFailure(request transport.ManagedEndpointPoPChallenge) []byte {
	raw, _ := (transport.ManagedEndpointPoPFailureACK{ProtocolVersion: transport.ManagedEndpointPoPProtocol, ChallengeID: request.ChallengeID, Error: transport.ManagedEndpointPoPFailure}).CanonicalBytes()
	return raw
}

func (c *managedEndpointPoPConnection) ack(payload []byte, session transport.HostSessionPayload, command transport.ManagedEndpointPoPChallenge) {
	success := false
	ackError := transport.ManagedEndpointPoPFailure
	if proof, err := transport.DecodeManagedEndpointPoPProof(payload); err == nil && proof.ChallengeID == command.ChallengeID {
		success = true
		ackError = ""
	} else if _, err := transport.DecodeManagedEndpointPoPFailureACK(payload, command.ChallengeID); err != nil {
		return
	}
	outer := struct {
		CommandID domain.ID       `json:"commandId"`
		Error     string          `json:"error"`
		Result    json.RawMessage `json:"result"`
	}{command.ChallengeID, ackError, json.RawMessage(payload)}
	env, err := transport.NewEnvelope(transport.MsgCommandAck, outer)
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
	if success {
		if !c.d.managedEndpointPoPReady() {
			c.d.writeMu.Unlock()
			return
		}
		ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
		err := c.executor.verifyPoPPublication(ctx, c.socket, c.native, session, c.endpoint, command)
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
