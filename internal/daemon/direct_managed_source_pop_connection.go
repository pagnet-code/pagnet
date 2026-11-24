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

const directManagedSourcePoPQueueLimit = 8

type directManagedSourcePoPExecutor interface {
	ready() bool
	verifyPoPPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourcePoPChallenge) (*nativeWorkerPublicationToken, error)
	confirmPoP(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourcePoPChallenge) ([]byte, error)
}

func (d *Daemon) directManagedSourcePoPReady() bool {
	return d.DirectManagedSourcePoPEnabled && d.directManagedSourcePrepareReady() && d.directManagedSourcePoP != nil && d.directManagedSourcePoP.ready()
}

type directManagedSourcePoPAttempt struct {
	request transport.DirectManagedSourcePoPChallenge
	session transport.HostSessionPayload
}

// This bounded lane never sends commands through generic worker persistence.
type directManagedSourcePoPConnection struct {
	d        *Daemon
	socket   *websocket.Conn
	native   *NativeObservationConnection
	executor directManagedSourcePoPExecutor
	endpoint string
	mu       sync.Mutex
	stopped  bool
	pending  int
	queue    chan directManagedSourcePoPAttempt
	done     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
}

func newDirectManagedSourcePoPConnection(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection) *directManagedSourcePoPConnection {
	ctx, cancel := context.WithCancel(context.Background())
	c := &directManagedSourcePoPConnection{ctx: ctx, cancel: cancel, d: d, socket: socket, native: native, executor: d.directManagedSourcePoP, endpoint: native.serverURL, queue: make(chan directManagedSourcePoPAttempt, directManagedSourcePoPQueueLimit), done: make(chan struct{})}
	// Readiness may recover after a transient registry timeout. Keep a consumer
	// available for every configured executor; admission still checks readiness.
	if c.executor != nil {
		go c.run()
	}
	return c
}

func (c *directManagedSourcePoPConnection) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.stopped = true
		close(c.done)
		c.cancel()
	}
}

func (c *directManagedSourcePoPConnection) active(session transport.HostSessionPayload) bool {
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

func (c *directManagedSourcePoPConnection) handle(env transport.Envelope) bool {
	if env.Type != transport.MsgDirectManagedSourcePoP {
		return false
	}
	request, err := transport.DecodeDirectManagedSourcePoPChallenge(env.Payload)
	if err != nil {
		return true
	}
	session, err := c.native.AuthenticatedNativeHostSession()
	count := 0
	prepareCount := 0
	for _, feature := range session.ProtocolFeatures {
		if feature == transport.DirectManagedSourcePrepareProtocol {
			prepareCount++
		}
		if feature == transport.DirectManagedSourcePoPProtocol {
			count++
		}
	}
	if err != nil || count != 1 || prepareCount != 1 || !c.native.offeredDirectManagedSourcePrepare || !c.native.offeredDirectManagedSourcePoP || !c.d.directManagedSourcePoPReady() || !c.active(session) {
		c.ack(directManagedSourcePoPFailure(request), session, request)
		return true
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return true
	}
	if c.pending >= directManagedSourcePoPQueueLimit {
		c.mu.Unlock()
		c.close()
		_ = c.socket.Close()
		return true
	}
	// Keep retries in order, including changed transcripts with the same ID. The
	// durable executor reuses exact results and rejects changed replays.
	c.pending++
	c.queue <- directManagedSourcePoPAttempt{request: request, session: session}
	c.mu.Unlock()
	return true
}

func (c *directManagedSourcePoPConnection) run() {
	for {
		select {
		case <-c.done:
			return
		case a := <-c.queue:
			if c.d.directManagedSourcePoPReady() && c.active(a.session) {
				result, err := c.executor.confirmPoP(c.ctx, c.socket, c.native, a.session, c.endpoint, a.request)
				if err == nil {
					c.ack(result, a.session, a.request)
				} else {
					c.ack(directManagedSourcePoPFailure(a.request), a.session, a.request)
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
func directManagedSourcePoPFailure(request transport.DirectManagedSourcePoPChallenge) []byte {
	raw, _ := (transport.DirectManagedSourcePoPFailureACK{ProtocolVersion: transport.DirectManagedSourcePoPProtocol, ChallengeID: request.ChallengeID, Error: transport.DirectManagedSourcePoPFailure}).CanonicalBytes()
	return raw
}

func (c *directManagedSourcePoPConnection) ack(payload []byte, session transport.HostSessionPayload, command transport.DirectManagedSourcePoPChallenge) {
	success := false
	ackError := transport.DirectManagedSourcePoPFailure
	if proof, err := transport.DecodeDirectManagedSourcePoPProof(payload); err == nil && proof.ChallengeID == command.ChallengeID {
		success = true
		ackError = ""
	} else if _, err := transport.DecodeDirectManagedSourcePoPFailureACK(payload, command.ChallengeID); err != nil {
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
		if !c.d.directManagedSourcePoPReady() {
			c.d.writeMu.Unlock()
			return
		}
		ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
		token, verifyErr := c.executor.verifyPoPPublication(ctx, c.socket, c.native, session, c.endpoint, command)
		cancel()
		if verifyErr != nil {
			c.d.writeMu.Unlock()
			return
		}
		expires := command.ExpiresAt
		if command.Prepare.Subject.ExpiresAt.Before(expires) {
			expires = command.Prepare.Subject.ExpiresAt
		}
		wrote := false
		err = c.d.publishNativeWorker(token, ManagedEndpointPrepareScope{Socket: c.socket, Connection: c.native, Session: session}, c.done, expires, func(deadline time.Time) error {
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
