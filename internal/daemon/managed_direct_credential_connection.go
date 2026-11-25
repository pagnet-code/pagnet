//go:build linux || darwin

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

const managedDirectCredentialQueueLimit = 8

type managedDirectCredentialExecutor interface {
	ready() bool
	installCredential(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.ManagedDirectCredentialIssue, *directManagedSourceCredentialPublicationLane) ([]byte, error)
	verifyCredentialPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.ManagedDirectCredentialIssue) (*nativeWorkerPublicationToken, error)
	publishCredentialACK(context.Context, *nativeWorkerPublicationToken, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.ManagedDirectCredentialIssue, *directManagedSourceCredentialPublicationLane, []byte, func() error) error
}

type managedDirectCredentialAttempt struct {
	request transport.ManagedDirectCredentialIssue
	session transport.HostSessionPayload
}

// This bounded lane never sends commands through generic worker persistence.
type managedDirectCredentialConnection struct {
	d           *Daemon
	socket      *websocket.Conn
	native      *NativeObservationConnection
	executor    managedDirectCredentialExecutor
	endpoint    string
	mu          sync.Mutex
	stopped     bool
	pending     int
	queue       chan managedDirectCredentialAttempt
	done        chan struct{}
	publication *directManagedSourceCredentialPublicationLane
	negotiation *managedDirectCredentialNegotiation
	ctx         context.Context
	cancel      context.CancelFunc
}

func newManagedDirectCredentialConnection(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection, negotiation *managedDirectCredentialNegotiation) *managedDirectCredentialConnection {
	if negotiation == nil || negotiation.socket != socket || negotiation.native != native || !negotiation.valid() {
		return nil
	}
	captured := *negotiation
	captured.session.ProtocolFeatures = append([]string(nil), negotiation.session.ProtocolFeatures...)
	negotiation = &captured
	ctx, cancel := context.WithCancel(context.Background())
	c := &managedDirectCredentialConnection{ctx: ctx, cancel: cancel, negotiation: negotiation, d: d, socket: socket, native: native, executor: d.managedDirectCredential, endpoint: native.serverURL, queue: make(chan managedDirectCredentialAttempt, managedDirectCredentialQueueLimit), done: make(chan struct{}), publication: newDirectManagedSourceCredentialPublicationLane()}
	// Readiness may recover after a transient registry timeout. Keep a consumer
	// available for every configured executor; admission still checks readiness.
	if c.executor != nil {
		go c.run()
	}
	return c
}

func (c *managedDirectCredentialConnection) close() {
	if c == nil {
		return
	}
	c.publication.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.stopped = true
		close(c.done)
		c.cancel()
		for {
			select {
			case <-c.queue:
				c.pending--
			default:
				return
			}
		}
	}
}

func (c *managedDirectCredentialConnection) active(session transport.HostSessionPayload) bool {
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

func (c *managedDirectCredentialConnection) handle(env transport.Envelope) bool {
	if env.Type != transport.MsgManagedDirectCredential {
		return false
	}
	if c == nil {
		return true
	}
	request, err := transport.DecodeManagedDirectCredentialIssue(env.Payload)
	if err != nil {
		return true
	}
	session, err := c.native.AuthenticatedNativeHostSession()
	if err != nil || !c.negotiation.valid() || !reflect.DeepEqual(c.negotiation.session, session) || !c.d.managedDirectCredentialReady() || !c.active(session) {
		c.close()
		_ = c.socket.Close()
		return true
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return true
	}
	if c.pending >= managedDirectCredentialQueueLimit {
		c.mu.Unlock()
		c.close()
		_ = c.socket.Close()
		return true
	}
	// Keep retries in order, including changed transcripts with the same ID. The
	// durable executor reuses exact results and rejects changed replays.
	c.pending++
	select {
	case c.queue <- managedDirectCredentialAttempt{request: request, session: session}:
		c.mu.Unlock()
	default:
		c.pending--
		c.mu.Unlock()
		c.close()
		_ = c.socket.Close()
	}
	return true
}

func (c *managedDirectCredentialConnection) run() {
	for {
		select {
		case <-c.done:
			return
		case a := <-c.queue:
			if c.d.managedDirectCredentialReady() && c.active(a.session) {
				result, err := c.executor.installCredential(c.ctx, c.socket, c.native, a.session, c.endpoint, a.request, c.publication)
				if err == nil {
					c.ack(result, a.session, a.request)
				} else {
					c.close()
					_ = c.socket.Close()
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

func (c *managedDirectCredentialConnection) ack(payload []byte, session transport.HostSessionPayload, command transport.ManagedDirectCredentialIssue) {
	// The store has no durable terminal failure state. Only retained installed
	// success may be acknowledged; every other outcome remains retryable.
	ack, decodeErr := transport.DecodeManagedDirectCredentialACK(payload)
	if decodeErr != nil || ack.CredentialID != command.CredentialID {
		c.close()
		_ = c.socket.Close()
		return
	}
	outer := struct {
		CommandID domain.ID       `json:"commandId"`
		Error     string          `json:"error"`
		Result    json.RawMessage `json:"result"`
	}{command.CredentialID, "", json.RawMessage(payload)}
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
	// Preverification is advisory. Locked publication rechecks exact authority
	// after the writer is acquired, without any blocking verifier or readiness call.
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()
	token, err := c.executor.verifyCredentialPublication(ctx, c.socket, c.native, session, c.endpoint, command)
	if err != nil {
		c.close()
		_ = c.socket.Close()
		return
	}
	c.d.writeMu.Lock()
	defer c.d.writeMu.Unlock()
	err = c.executor.publishCredentialACK(ctx, token, c.socket, c.native, session, c.endpoint, command, c.publication, payload, func() error {
		deadline := time.Now().Add(c.d.writeTimeout)
		if c.d.writeTimeout <= 0 {
			deadline = time.Now().Add(10 * time.Second)
		}
		if command.InstallExpiresAt.Before(deadline) {
			deadline = command.InstallExpiresAt
		}
		if err := c.socket.SetWriteDeadline(deadline); err != nil {
			return err
		}
		return c.socket.WriteMessage(websocket.TextMessage, raw)
	})
	if err != nil {
		c.close()
		_ = c.socket.Close()
	}
}

// The authenticated handshake captures this complete suite negotiation.
type managedDirectCredentialNegotiation struct {
	socket  *websocket.Conn
	native  *NativeObservationConnection
	session transport.HostSessionPayload
}

func (n *managedDirectCredentialNegotiation) valid() bool {
	if n == nil || n.socket == nil || n.native == nil || !n.native.offeredManagedEndpointPrepare || !n.native.offeredManagedEndpointPoP || !n.native.offeredManagedDirectCredential {
		return false
	}
	session, err := n.native.AuthenticatedNativeHostSession()
	if err != nil || !reflect.DeepEqual(session, n.session) {
		return false
	}
	for _, required := range []string{transport.ManagedEndpointPrepareProtocol, transport.ManagedEndpointPoPProtocol, transport.ManagedDirectCredentialProtocol} {
		count := 0
		for _, feature := range session.ProtocolFeatures {
			if feature == required {
				count++
			}
		}
		if count != 1 {
			return false
		}
	}
	return true
}
