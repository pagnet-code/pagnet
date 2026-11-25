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

const directManagedSourceCredentialQueueLimitV2 = 8

type directManagedSourceCredentialExecutorV2 interface {
	ready() bool
	installCredential(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourceCredentialIssueV2, *directManagedSourceCredentialPublicationLane) ([]byte, error)
	verifyCredentialPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourceCredentialIssueV2) (*nativeWorkerPublicationToken, error)
	publishCredentialACK(context.Context, *nativeWorkerPublicationToken, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourceCredentialIssueV2, *directManagedSourceCredentialPublicationLane, []byte, func() error) error
}

func (d *Daemon) directManagedSourceCredentialReadyV2() bool {
	return d.directManagedSourcePoPReadyV2() && d.directManagedSourceCredentialV2 != nil && d.directManagedSourceCredentialV2.ready()
}

type directManagedSourceCredentialAttemptV2 struct {
	request transport.DirectManagedSourceCredentialIssueV2
	session transport.HostSessionPayload
}

// This bounded lane never sends commands through generic worker persistence.
type directManagedSourceCredentialConnectionV2 struct {
	d           *Daemon
	socket      *websocket.Conn
	native      *NativeObservationConnection
	executor    directManagedSourceCredentialExecutorV2
	endpoint    string
	mu          sync.Mutex
	stopped     bool
	pending     int
	queue       chan directManagedSourceCredentialAttemptV2
	done        chan struct{}
	publication *directManagedSourceCredentialPublicationLane
	negotiation *directManagedSourceCredentialNegotiationV2
	ctx         context.Context
	cancel      context.CancelFunc
}

func newDirectManagedSourceCredentialConnectionV2(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection, negotiation *directManagedSourceCredentialNegotiationV2) *directManagedSourceCredentialConnectionV2 {
	if negotiation == nil || negotiation.socket != socket || negotiation.native != native || !negotiation.valid() {
		return nil
	}
	captured := *negotiation
	captured.session.ProtocolFeatures = append([]string(nil), negotiation.session.ProtocolFeatures...)
	negotiation = &captured
	ctx, cancel := context.WithCancel(context.Background())
	c := &directManagedSourceCredentialConnectionV2{ctx: ctx, cancel: cancel, negotiation: negotiation, d: d, socket: socket, native: native, executor: d.directManagedSourceCredentialV2, endpoint: native.serverURL, queue: make(chan directManagedSourceCredentialAttemptV2, directManagedSourceCredentialQueueLimitV2), done: make(chan struct{}), publication: newDirectManagedSourceCredentialPublicationLane()}
	// Readiness may recover after a transient registry timeout. Keep a consumer
	// available for every configured executor; admission still checks readiness.
	if c.executor != nil {
		go c.run()
	}
	return c
}

func (c *directManagedSourceCredentialConnectionV2) close() {
	c.publication.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.stopped = true
		close(c.done)
		c.cancel()
	}
}

func (c *directManagedSourceCredentialConnectionV2) active(session transport.HostSessionPayload) bool {
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

func (c *directManagedSourceCredentialConnectionV2) handle(env transport.Envelope) bool {
	if env.Type != transport.MsgDirectManagedSourceCredentialV2 {
		return false
	}
	request, err := transport.DecodeDirectManagedSourceCredentialIssueV2(env.Payload)
	if err != nil {
		return true
	}
	session, err := c.native.AuthenticatedNativeHostSession()
	if err != nil || !c.negotiation.valid() || !reflect.DeepEqual(c.negotiation.session, session) || !c.d.directManagedSourceCredentialReadyV2() || !c.active(session) {
		c.close()
		_ = c.socket.Close()
		return true
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return true
	}
	if c.pending >= directManagedSourceCredentialQueueLimitV2 {
		c.mu.Unlock()
		c.close()
		_ = c.socket.Close()
		return true
	}
	// Keep retries in order, including changed transcripts with the same ID. The
	// durable executor reuses exact results and rejects changed replays.
	c.pending++
	c.queue <- directManagedSourceCredentialAttemptV2{request: request, session: session}
	c.mu.Unlock()
	return true
}

func (c *directManagedSourceCredentialConnectionV2) run() {
	for {
		select {
		case <-c.done:
			return
		case a := <-c.queue:
			if c.d.directManagedSourceCredentialReadyV2() && c.active(a.session) {
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

func (c *directManagedSourceCredentialConnectionV2) ack(payload []byte, session transport.HostSessionPayload, command transport.DirectManagedSourceCredentialIssueV2) {
	// The store has no durable terminal failure state. Only retained installed
	// success may be acknowledged; every other outcome remains retryable.
	ack, decodeErr := transport.DecodeDirectManagedSourceCredentialACKV2(payload)
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

// Only future authenticated handshake integration may capture this full suite.
// No startup, dispatch or V1 fallback is installed by this constructor.
type directManagedSourceCredentialNegotiationV2 struct {
	socket  *websocket.Conn
	native  *NativeObservationConnection
	session transport.HostSessionPayload
}

func (n *directManagedSourceCredentialNegotiationV2) valid() bool {
	if n == nil || n.socket == nil || n.native == nil {
		return false
	}
	session, err := n.native.AuthenticatedNativeHostSession()
	if err != nil || !reflect.DeepEqual(session, n.session) {
		return false
	}
	for _, required := range []string{transport.DirectManagedSourcePrepareProtocolV2, transport.DirectManagedSourcePoPProtocolV2, transport.DirectManagedSourceCredentialProtocolV2} {
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
