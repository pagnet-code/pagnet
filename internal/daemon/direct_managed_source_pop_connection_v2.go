package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

const directManagedSourcePoPQueueLimitV2 = 8

type directManagedSourcePoPExecutorV2 interface {
	ready() bool
	verifyPoPPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourcePoPChallengeV2) (*nativeWorkerPublicationToken, error)
	confirmPoP(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourcePoPChallengeV2) ([]byte, error)
}

func (d *Daemon) directManagedSourcePoPReadyV2() bool {
	return d.directManagedSourcePrepareReadyV2() && d.directManagedSourcePoPV2 != nil && d.directManagedSourcePoPV2.ready()
}

type directManagedSourcePoPAttemptV2 struct {
	request transport.DirectManagedSourcePoPChallengeV2
	session transport.HostSessionPayload
}

// This bounded lane never sends commands through generic worker persistence.
type directManagedSourcePoPConnectionV2 struct {
	d           *Daemon
	socket      *websocket.Conn
	native      *NativeObservationConnection
	executor    directManagedSourcePoPExecutorV2
	endpoint    string
	negotiation *directManagedSourcePoPNegotiationV2
	mu          sync.Mutex
	stopped     bool
	pending     int
	queue       chan directManagedSourcePoPAttemptV2
	done        chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
}

func newDirectManagedSourcePoPConnectionV2(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection, negotiation *directManagedSourcePoPNegotiationV2) *directManagedSourcePoPConnectionV2 {
	if negotiation == nil || negotiation.native != native || negotiation.socket != socket || !negotiation.valid() {
		return nil
	}
	captured := *negotiation
	captured.session.ProtocolFeatures = append([]string(nil), negotiation.session.ProtocolFeatures...)
	negotiation = &captured
	ctx, cancel := context.WithCancel(context.Background())
	c := &directManagedSourcePoPConnectionV2{ctx: ctx, cancel: cancel, d: d, negotiation: negotiation, socket: socket, native: native, executor: d.directManagedSourcePoPV2, endpoint: native.serverURL, queue: make(chan directManagedSourcePoPAttemptV2, directManagedSourcePoPQueueLimitV2), done: make(chan struct{})}
	// Readiness may recover after a transient registry timeout. Keep a consumer
	// available for every configured executor; admission still checks readiness.
	if c.executor != nil {
		go c.run()
	}
	return c
}

func (c *directManagedSourcePoPConnectionV2) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.stopped = true
		close(c.done)
		c.cancel()
	}
}

func (c *directManagedSourcePoPConnectionV2) active(session transport.HostSessionPayload) bool {
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

func (c *directManagedSourcePoPConnectionV2) handle(env transport.Envelope) bool {
	if env.Type != transport.MsgDirectManagedSourcePoPV2 {
		return false
	}
	request, err := transport.DecodeDirectManagedSourcePoPChallengeV2(env.Payload)
	if err != nil {
		return true
	}
	session, err := c.native.AuthenticatedNativeHostSession()
	count := 0
	prepareCount := 0
	for _, feature := range session.ProtocolFeatures {
		if feature == transport.DirectManagedSourcePrepareProtocolV2 {
			prepareCount++
		}
		if feature == transport.DirectManagedSourcePoPProtocolV2 {
			count++
		}
	}
	if err != nil || count != 1 || prepareCount != 1 || !c.negotiation.valid() || !c.d.directManagedSourcePoPReadyV2() || !c.active(session) {
		c.ack(directManagedSourcePoPFailureV2(request), session, request)
		return true
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return true
	}
	if c.pending >= directManagedSourcePoPQueueLimitV2 {
		c.mu.Unlock()
		c.close()
		_ = c.socket.Close()
		return true
	}
	// Keep retries in order, including changed transcripts with the same ID. The
	// durable executor reuses exact results and rejects changed replays.
	c.pending++
	c.queue <- directManagedSourcePoPAttemptV2{request: request, session: session}
	c.mu.Unlock()
	return true
}

func (c *directManagedSourcePoPConnectionV2) run() {
	for {
		select {
		case <-c.done:
			return
		case a := <-c.queue:
			if c.d.directManagedSourcePoPReadyV2() && c.active(a.session) {
				result, err := c.executor.confirmPoP(c.ctx, c.socket, c.native, a.session, c.endpoint, a.request)
				if err == nil {
					c.ack(result, a.session, a.request)
				} else {
					c.ack(directManagedSourcePoPFailureV2(a.request), a.session, a.request)
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
func directManagedSourcePoPFailureV2(request transport.DirectManagedSourcePoPChallengeV2) []byte {
	raw, _ := (transport.DirectManagedSourcePoPFailureACKV2{ProtocolVersion: transport.DirectManagedSourcePoPProtocolV2, ChallengeID: request.ChallengeID, Error: transport.DirectManagedSourcePoPFailureV2}).CanonicalBytes()
	return raw
}

func (c *directManagedSourcePoPConnectionV2) ack(payload []byte, session transport.HostSessionPayload, command transport.DirectManagedSourcePoPChallengeV2) {
	challenge, err := command.CanonicalBytes()
	if err != nil {
		return
	}
	digest := sha256.Sum256(append([]byte("pagnet/direct-managed-source-host-custody-pop/transcript/v2/"), challenge...))
	success := false
	ackError := transport.DirectManagedSourcePoPFailureV2
	if proof, err := transport.DecodeDirectManagedSourcePoPProofV2(payload); err == nil && proof.ChallengeID == command.ChallengeID && proof.TranscriptHash == hex.EncodeToString(digest[:]) {
		success = true
		ackError = ""
	} else if _, err := transport.DecodeDirectManagedSourcePoPFailureACKV2(payload, command.ChallengeID); err != nil {
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
		if !c.d.directManagedSourcePoPReadyV2() {
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
		if command.Prepare.Subject.EnrollmentExpiresAt.Before(expires) {
			expires = command.Prepare.Subject.EnrollmentExpiresAt
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

// Only future authenticated handshake integration may capture this negotiation.
// There is deliberately no V1 conversion or startup/dispatch path.
type directManagedSourcePoPNegotiationV2 struct {
	socket  *websocket.Conn
	native  *NativeObservationConnection
	session transport.HostSessionPayload
}

func (n *directManagedSourcePoPNegotiationV2) valid() bool {
	if n == nil || n.socket == nil || n.native == nil {
		return false
	}
	session, err := n.native.AuthenticatedNativeHostSession()
	if err != nil || !reflect.DeepEqual(session, n.session) {
		return false
	}
	prepare, pop := 0, 0
	for _, feature := range session.ProtocolFeatures {
		if feature == transport.DirectManagedSourcePrepareProtocolV2 {
			prepare++
		}
		if feature == transport.DirectManagedSourcePoPProtocolV2 {
			pop++
		}
	}
	return prepare == 1 && pop == 1
}
