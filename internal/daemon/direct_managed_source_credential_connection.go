package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

const directManagedSourceCredentialQueueLimit = 8

type directManagedSourceCredentialExecutor interface {
	ready() bool
	installCredential(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourceCredentialIssue, *directManagedSourceCredentialPublicationLane) ([]byte, error)
	publishCredentialACK(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourceCredentialIssue, *directManagedSourceCredentialPublicationLane, []byte, func() error) error
}

func (d *Daemon) directManagedSourceCredentialReady() bool {
	return d.DirectManagedSourceCredentialEnabled && d.directManagedSourcePoPReady() && d.directManagedSourceCredential != nil && d.directManagedSourceCredential.ready()
}

type directManagedSourceCredentialAttempt struct {
	request transport.DirectManagedSourceCredentialIssue
	session transport.HostSessionPayload
}

// This bounded lane never sends commands through generic worker persistence.
type directManagedSourceCredentialConnection struct {
	d           *Daemon
	socket      *websocket.Conn
	native      *NativeObservationConnection
	executor    directManagedSourceCredentialExecutor
	endpoint    string
	mu          sync.Mutex
	stopped     bool
	pending     int
	queue       chan directManagedSourceCredentialAttempt
	done        chan struct{}
	publication *directManagedSourceCredentialPublicationLane
	ctx         context.Context
	cancel      context.CancelFunc
}

func newDirectManagedSourceCredentialConnection(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection) *directManagedSourceCredentialConnection {
	ctx, cancel := context.WithCancel(context.Background())
	c := &directManagedSourceCredentialConnection{ctx: ctx, cancel: cancel, d: d, socket: socket, native: native, executor: d.directManagedSourceCredential, endpoint: native.serverURL, queue: make(chan directManagedSourceCredentialAttempt, directManagedSourceCredentialQueueLimit), done: make(chan struct{}), publication: newDirectManagedSourceCredentialPublicationLane()}
	// Readiness may recover after a transient registry timeout. Keep a consumer
	// available for every configured executor; admission still checks readiness.
	if c.executor != nil {
		go c.run()
	}
	return c
}

func (c *directManagedSourceCredentialConnection) close() {
	c.publication.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.stopped = true
		close(c.done)
		c.cancel()
	}
}

func (c *directManagedSourceCredentialConnection) active(session transport.HostSessionPayload) bool {
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

func (c *directManagedSourceCredentialConnection) handle(env transport.Envelope) bool {
	if env.Type != transport.MsgDirectManagedSourceCredential {
		return false
	}
	request, err := transport.DecodeDirectManagedSourceCredentialIssue(env.Payload)
	if err != nil {
		return true
	}
	session, err := c.native.AuthenticatedNativeHostSession()
	if err != nil || !c.negotiated(session) || !c.d.directManagedSourceCredentialReady() || !c.active(session) {
		c.close()
		_ = c.socket.Close()
		return true
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return true
	}
	if c.pending >= directManagedSourceCredentialQueueLimit {
		c.mu.Unlock()
		c.close()
		_ = c.socket.Close()
		return true
	}
	// Keep retries in order, including changed transcripts with the same ID. The
	// durable executor reuses exact results and rejects changed replays.
	c.pending++
	c.queue <- directManagedSourceCredentialAttempt{request: request, session: session}
	c.mu.Unlock()
	return true
}

func (c *directManagedSourceCredentialConnection) run() {
	for {
		select {
		case <-c.done:
			return
		case a := <-c.queue:
			if c.d.directManagedSourceCredentialReady() && c.active(a.session) {
				result, err := c.executor.installCredential(c.ctx, c.socket, c.native, a.session, c.endpoint, a.request, c.publication)
				if err == nil {
					c.ack(result, a.session, a.request)
				} else {
					if errors.Is(err, ErrManagedEndpointPrepareRejected) || errors.Is(err, errDirectManagedSourceKey) {
						c.ack(directManagedSourceCredentialFailure(a.request), a.session, a.request)
					} else {
						c.close()
						_ = c.socket.Close()
					}
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
func directManagedSourceCredentialFailure(request transport.DirectManagedSourceCredentialIssue) []byte {
	raw, _ := (transport.DirectManagedSourceCredentialFailureACK{ProtocolVersion: transport.DirectManagedSourceCredentialProtocol, CredentialID: request.CredentialID, Error: transport.DirectManagedSourceCredentialInstallFailure}).CanonicalBytes()
	return raw
}

func (c *directManagedSourceCredentialConnection) ack(payload []byte, session transport.HostSessionPayload, command transport.DirectManagedSourceCredentialIssue) {
	ackError := transport.DirectManagedSourceCredentialInstallFailure
	if ack, err := transport.DecodeDirectManagedSourceCredentialACK(payload); err == nil && ack.CredentialID == command.CredentialID {
		ackError = ""
	} else if failure, err := transport.DecodeDirectManagedSourceCredentialFailureACK(payload); err != nil || failure.CredentialID != command.CredentialID {
		return
	}
	outer := struct {
		CommandID domain.ID       `json:"commandId"`
		Error     string          `json:"error"`
		Result    json.RawMessage `json:"result"`
	}{command.CredentialID, ackError, json.RawMessage(payload)}
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
	defer c.d.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()
	err = c.executor.publishCredentialACK(ctx, c.socket, c.native, session, c.endpoint, command, c.publication, payload, func() error {
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

func (c *directManagedSourceCredentialConnection) negotiated(session transport.HostSessionPayload) bool {
	if !c.native.offeredDirectManagedSourcePrepare || !c.native.offeredDirectManagedSourcePoP || c.native.offeredDirectManagedSourceCredential != transport.DirectManagedSourceCredentialProtocol {
		return false
	}
	for _, required := range []string{transport.DirectManagedSourcePrepareProtocol, transport.DirectManagedSourcePoPProtocol, transport.DirectManagedSourceCredentialProtocol} {
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
