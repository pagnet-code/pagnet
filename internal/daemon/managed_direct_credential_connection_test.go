//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

type managedCredentialLaneExecutor struct {
	available bool
	install   func(transport.ManagedDirectCredentialIssue) ([]byte, error)
	started   chan transport.ManagedDirectCredentialIssue
	canceled  chan struct{}
	release   chan struct{}
	finished  chan struct{}
	result    []byte
	err       error
}

func (e *managedCredentialLaneExecutor) ready() bool { return e.available }
func (e *managedCredentialLaneExecutor) installCredential(ctx context.Context, _ *websocket.Conn, _ *NativeObservationConnection, _ transport.HostSessionPayload, _ string, issue transport.ManagedDirectCredentialIssue, _ *directManagedSourceCredentialPublicationLane) ([]byte, error) {
	e.started <- issue
	if e.install != nil {
		return e.install(issue)
	}
	if e.finished != nil {
		defer close(e.finished)
	}
	if e.canceled != nil {
		<-ctx.Done()
		close(e.canceled)
		return nil, ctx.Err()
	}
	if e.release != nil {
		<-e.release
	}
	return append([]byte(nil), e.result...), e.err
}
func (e *managedCredentialLaneExecutor) verifyCredentialPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.ManagedDirectCredentialIssue) (*nativeWorkerPublicationToken, error) {
	return nil, nil
}
func (e *managedCredentialLaneExecutor) publishCredentialACK(ctx context.Context, _ *nativeWorkerPublicationToken, _ *websocket.Conn, _ *NativeObservationConnection, _ transport.HostSessionPayload, _ string, _ transport.ManagedDirectCredentialIssue, lane *directManagedSourceCredentialPublicationLane, _ []byte, write func() error) error {
	lane.mu.Lock()
	defer lane.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-lane.done:
		return context.Canceled
	default:
		return write()
	}
}

func managedCredentialLaneFixture(t *testing.T) (*Daemon, *managedDirectCredentialConnection, *websocket.Conn, *managedCredentialLaneExecutor, transport.ManagedDirectCredentialIssue) {
	t.Helper()
	keys, issue, session, _ := managedCredentialStoreFixture(t)
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.ManagedEndpointPrepareProtocol, transport.ManagedEndpointPoPProtocol, transport.ManagedDirectCredentialProtocol}
	result, err := keys.InstallCredential(issue, "https://example.test", session, managedCredentialScopeOK, managedCredentialFenceOK)
	if err != nil {
		t.Fatal(err)
	}
	socket, peer := nativeBindingSocketPair(t)
	native := NewNativeObservationConnection("https://example.test", session.HostID, session.BootID, nil)
	native.offeredManagedEndpointPrepare = true
	native.offeredManagedEndpointPoP = true
	native.offeredManagedDirectCredential = true
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	executor := &managedCredentialLaneExecutor{available: true, started: make(chan transport.ManagedDirectCredentialIssue, 16), result: result}
	d := &Daemon{Config: Config{ServerURL: "https://example.test", ManagedEndpointPrepareEnabled: true, ManagedEndpointPoPEnabled: true, ManagedDirectCredentialEnabled: true}, managedEndpointPrepare: &managedPrepareLaneExecutor{available: true}, managedEndpointPoP: &managedPoPLaneExecutor{available: true}, managedDirectCredential: executor, curConn: socket, nativeConn: native, writeTimeout: time.Second}
	lane := newManagedDirectCredentialConnection(d, socket, native, &managedDirectCredentialNegotiation{socket: socket, native: native, session: session})
	t.Cleanup(lane.close)
	return d, lane, peer, executor, issue
}

func TestManagedCredentialLaneCapability(t *testing.T) {
	for _, feature := range []string{transport.ManagedEndpointPrepareProtocol, transport.ManagedEndpointPoPProtocol, transport.ManagedDirectCredentialProtocol} {
		for _, reason := range []string{"missing", "duplicate"} {
			t.Run(feature+"/"+reason, func(t *testing.T) {
				_, lane, peer, executor, issue := managedCredentialLaneFixture(t)
				lane.native.mu.Lock()
				switch reason {
				case "missing":
					var features []string
					for _, value := range lane.native.session.ProtocolFeatures {
						if value != feature {
							features = append(features, value)
						}
					}
					lane.native.session.ProtocolFeatures = features
				case "duplicate":
					lane.native.session.ProtocolFeatures = append(lane.native.session.ProtocolFeatures, feature)

				}
				lane.native.mu.Unlock()
				if !lane.handle(nativeBindingEnvelope(t, transport.MsgManagedDirectCredential, issue)) {
					t.Fatal("reserved command escaped dedicated lane")
				}
				_ = peer.SetReadDeadline(time.Now().Add(time.Second))
				if _, _, err := peer.ReadMessage(); err == nil {
					t.Fatal("unnegotiated command produced ACK")
				}
				select {
				case <-executor.started:
					t.Fatal("unnegotiated command reached executor")
				default:
				}
			})
		}
	}
}

func TestManagedCredentialLaneExactACKV2(t *testing.T) {
	d, lane, peer, executor, issue := managedCredentialLaneFixture(t)
	expected := append([]byte(nil), executor.result...)
	wantError := ""

	env := nativeBindingEnvelope(t, transport.MsgManagedDirectCredential, issue)
	// Reserved plaintext bypasses generic persistence even without state.
	d.handleCommand(nil, env)
	select {
	case <-executor.started:
		t.Fatal("generic command reached executor")
	default:
	}
	if lane.handle(transport.Envelope{Type: "unrelated"}) {
		t.Fatal("consumed unrelated command")
	}
	if !lane.handle(env) {
		t.Fatal("credential command escaped dedicated lane")
	}
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	var reply transport.Envelope
	if err := peer.ReadJSON(&reply); err != nil {
		t.Fatal(err)
	}
	var outer struct {
		CommandID domain.ID       `json:"commandId"`
		Error     string          `json:"error"`
		Result    json.RawMessage `json:"result"`
	}
	var fields map[string]json.RawMessage
	if reply.Type != transport.MsgCommandAck || json.Unmarshal(reply.Payload, &outer) != nil || json.Unmarshal(reply.Payload, &fields) != nil || len(fields) != 3 || outer.CommandID != issue.CredentialID || outer.Error != wantError || !bytes.Equal(outer.Result, expected) {
		t.Fatal("credential ACK did not retain exact result and canonical outer fields")
	}
	if bytes.Contains(reply.Payload, []byte("private executor diagnostic")) {
		t.Fatal("private diagnostic escaped")
	}
}

func TestManagedCredentialLaneCloseCancelsQueueV2(t *testing.T) {
	_, lane, peer, executor, issue := managedCredentialLaneFixture(t)
	executor.canceled = make(chan struct{})
	executor.finished = make(chan struct{})
	lane.handle(nativeBindingEnvelope(t, transport.MsgManagedDirectCredential, issue))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("credential install did not start")
	}
	second := issue
	second.CredentialID = domain.NewID()
	lane.handle(nativeBindingEnvelope(t, transport.MsgManagedDirectCredential, second))
	lane.close()
	select {
	case <-executor.canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("close did not cancel install")
	}
	<-executor.finished
	_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("closed lane published ACK")
	}
	select {
	case <-executor.started:
		t.Fatal("queued install ran after close")
	default:
	}
}

func TestManagedCredentialLaneCloseFencesACKV2(t *testing.T) {
	d, lane, peer, executor, issue := managedCredentialLaneFixture(t)
	session, err := lane.native.AuthenticatedNativeHostSession()
	if err != nil {
		t.Fatal(err)
	}
	d.writeMu.Lock()
	started, finished := make(chan struct{}), make(chan struct{})
	go func() { close(started); lane.ack(executor.result, session, issue); close(finished) }()
	<-started
	lane.close()
	d.writeMu.Unlock()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("writer did not finish")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("closed lane published waiting ACK")
	}
}

func TestManagedCredentialLaneQueueSaturationV2(t *testing.T) {
	_, lane, peer, executor, issue := managedCredentialLaneFixture(t)
	executor.release = make(chan struct{})
	executor.finished = make(chan struct{})
	lane.handle(nativeBindingEnvelope(t, transport.MsgManagedDirectCredential, issue))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("credential install did not start")
	}
	for i := 0; i < managedDirectCredentialQueueLimit; i++ {
		issue.CredentialID = domain.NewID()
		lane.handle(nativeBindingEnvelope(t, transport.MsgManagedDirectCredential, issue))
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("saturation produced an ACK")
	} else if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
		t.Fatal("saturation did not close socket")
	}
	close(executor.release)
	select {
	case <-executor.finished:
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight install did not finish")
	}
	select {
	case <-executor.started:
		t.Fatal("queued install ran after saturation")
	default:
	}
}

func TestManagedCredentialLanePrivateFailureClosesV2(t *testing.T) {
	for _, reason := range []string{"private", "retryable", "rejected", "key"} {
		t.Run(reason, func(t *testing.T) {
			_, lane, peer, executor, issue := managedCredentialLaneFixture(t)
			executor.err = errors.New("private executor diagnostic")
			if reason == "rejected" {
				executor.err = errors.Join(ErrManagedEndpointPrepareRejected, executor.err)
			}
			if reason == "key" {
				executor.err = errManagedEndpointKey
			}
			if reason == "retryable" {
				executor.err = errors.Join(ErrManagedEndpointPrepareRetryable, executor.err)
			}
			lane.handle(nativeBindingEnvelope(t, transport.MsgManagedDirectCredential, issue))
			_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, _, err := peer.ReadMessage(); err == nil {
				t.Fatal("private or retryable executor failure produced an ACK")
			} else if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
				t.Fatal("private or retryable executor failure did not close socket")
			}
		})
	}
}

func TestManagedCredentialWriteFailureClosesLaneV2(t *testing.T) {
	_, lane, _, executor, issue := managedCredentialLaneFixture(t)
	if err := lane.socket.Close(); err != nil {
		t.Fatal(err)
	}
	lane.ack(executor.result, lane.negotiation.session, issue)
	select {
	case <-lane.done:
	default:
		t.Fatal("write failure left lane active")
	}
}
