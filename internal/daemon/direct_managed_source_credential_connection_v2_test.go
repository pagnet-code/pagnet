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

type directSourceCredentialLaneExecutorV2 struct {
	available bool
	install   func(transport.DirectManagedSourceCredentialIssueV2) ([]byte, error)
	started   chan transport.DirectManagedSourceCredentialIssueV2
	canceled  chan struct{}
	release   chan struct{}
	finished  chan struct{}
	result    []byte
	err       error
}

func (e *directSourceCredentialLaneExecutorV2) ready() bool { return e.available }
func (e *directSourceCredentialLaneExecutorV2) installCredential(ctx context.Context, _ *websocket.Conn, _ *NativeObservationConnection, _ transport.HostSessionPayload, _ string, issue transport.DirectManagedSourceCredentialIssueV2, _ *directManagedSourceCredentialPublicationLane) ([]byte, error) {
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
func (e *directSourceCredentialLaneExecutorV2) verifyCredentialPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourceCredentialIssueV2) (*nativeWorkerPublicationToken, error) {
	return nil, nil
}
func (e *directSourceCredentialLaneExecutorV2) publishCredentialACK(ctx context.Context, _ *nativeWorkerPublicationToken, _ *websocket.Conn, _ *NativeObservationConnection, _ transport.HostSessionPayload, _ string, _ transport.DirectManagedSourceCredentialIssueV2, lane *directManagedSourceCredentialPublicationLane, _ []byte, write func() error) error {
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

func directSourceCredentialLaneFixtureV2(t *testing.T) (*Daemon, *directManagedSourceCredentialConnectionV2, *websocket.Conn, *directSourceCredentialLaneExecutorV2, transport.DirectManagedSourceCredentialIssueV2) {
	t.Helper()
	keys, issue, session := directSourceCredentialFixtureV2(t)
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.DirectManagedSourcePrepareProtocolV2, transport.DirectManagedSourcePoPProtocolV2, transport.DirectManagedSourceCredentialProtocolV2}
	result, err := keys.InstallCredential(issue, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2)
	if err != nil {
		t.Fatal(err)
	}
	socket, peer := nativeBindingSocketPair(t)
	native := NewNativeObservationConnection("https://example.test", session.HostID, session.BootID, nil)
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	executor := &directSourceCredentialLaneExecutorV2{available: true, started: make(chan transport.DirectManagedSourceCredentialIssueV2, 16), result: result}
	d := &Daemon{directManagedSourcePrepareV2: &directSourcePrepareLaneExecutorV2{available: true}, directManagedSourcePoPV2: &directSourcePoPLaneExecutorV2{available: true}, directManagedSourceCredentialV2: executor, curConn: socket, nativeConn: native, writeTimeout: time.Second}
	lane := newDirectManagedSourceCredentialConnectionV2(d, socket, native, &directManagedSourceCredentialNegotiationV2{socket: socket, native: native, session: session})
	t.Cleanup(lane.close)
	return d, lane, peer, executor, issue
}

func TestDirectManagedSourceCredentialLaneCapabilityV2(t *testing.T) {
	for _, feature := range []string{transport.DirectManagedSourcePrepareProtocolV2, transport.DirectManagedSourcePoPProtocolV2, transport.DirectManagedSourceCredentialProtocolV2} {
		for _, reason := range []string{"missing", "duplicate"} {
			t.Run(feature+"/"+reason, func(t *testing.T) {
				_, lane, peer, executor, issue := directSourceCredentialLaneFixtureV2(t)
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
				if !lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredentialV2, issue)) {
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

func TestDirectManagedSourceCredentialLaneExactACKV2(t *testing.T) {
	d, lane, peer, executor, issue := directSourceCredentialLaneFixtureV2(t)
	expected := append([]byte(nil), executor.result...)
	wantError := ""

	env := nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredentialV2, issue)
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

func TestDirectManagedSourceCredentialLaneCloseCancelsQueueV2(t *testing.T) {
	_, lane, peer, executor, issue := directSourceCredentialLaneFixtureV2(t)
	executor.canceled = make(chan struct{})
	executor.finished = make(chan struct{})
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredentialV2, issue))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("credential install did not start")
	}
	second := issue
	second.CredentialID = domain.NewID()
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredentialV2, second))
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

func TestDirectManagedSourceCredentialLaneCloseFencesACKV2(t *testing.T) {
	d, lane, peer, executor, issue := directSourceCredentialLaneFixtureV2(t)
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

func TestDirectManagedSourceCredentialLaneQueueSaturationV2(t *testing.T) {
	_, lane, peer, executor, issue := directSourceCredentialLaneFixtureV2(t)
	executor.release = make(chan struct{})
	executor.finished = make(chan struct{})
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredentialV2, issue))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("credential install did not start")
	}
	for i := 0; i < directManagedSourceCredentialQueueLimitV2; i++ {
		issue.CredentialID = domain.NewID()
		lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredentialV2, issue))
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

func TestDirectManagedSourceCredentialLanePrivateFailureClosesV2(t *testing.T) {
	for _, reason := range []string{"private", "retryable", "rejected", "key"} {
		t.Run(reason, func(t *testing.T) {
			_, lane, peer, executor, issue := directSourceCredentialLaneFixtureV2(t)
			executor.err = errors.New("private executor diagnostic")
			if reason == "rejected" {
				executor.err = errors.Join(ErrManagedEndpointPrepareRejected, executor.err)
			}
			if reason == "key" {
				executor.err = errDirectManagedSourceKey
			}
			if reason == "retryable" {
				executor.err = errors.Join(ErrManagedEndpointPrepareRetryable, executor.err)
			}
			lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredentialV2, issue))
			_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, _, err := peer.ReadMessage(); err == nil {
				t.Fatal("private or retryable executor failure produced an ACK")
			} else if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
				t.Fatal("private or retryable executor failure did not close socket")
			}
		})
	}
}

func TestDirectManagedSourceCredentialLaneMissingEvidenceRetryV2(t *testing.T) {
	keys, issue, session := directSourceCredentialFixtureV2(t)
	if _, err := keys.registry.db.Exec(`CREATE TEMP TABLE saved_pop AS SELECT * FROM native_direct_managed_source_v2_pop_challenges`); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.registry.db.Exec(`DELETE FROM native_direct_managed_source_v2_pop_challenges`); err != nil {
		t.Fatal(err)
	}
	attempt := func(expectSuccess bool) {
		d, lane, peer, executor, _ := directSourceCredentialLaneFixtureV2(t)
		executor.install = func(retained transport.DirectManagedSourceCredentialIssueV2) ([]byte, error) {
			return keys.InstallCredential(retained, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2)
		}
		d.handleCommand(nil, nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredentialV2, issue))
		lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredentialV2, issue))
		_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
		var env transport.Envelope
		err := peer.ReadJSON(&env)
		if !expectSuccess {
			if err == nil {
				t.Fatal("missing evidence emitted a failure ACK")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		var outer struct {
			Result json.RawMessage `json:"result"`
			Error  string          `json:"error"`
		}
		if env.Type != transport.MsgCommandAck || json.Unmarshal(env.Payload, &outer) != nil || outer.Error != "" {
			t.Fatal("retry did not return success")
		}
		ack, err := transport.DecodeDirectManagedSourceCredentialACKV2(outer.Result)
		if err != nil || ack.CredentialID != issue.CredentialID {
			t.Fatal("retry changed exact issue")
		}
	}
	attempt(false)
	if _, err := keys.registry.db.Exec(`INSERT INTO native_direct_managed_source_v2_pop_challenges SELECT * FROM saved_pop`); err != nil {
		t.Fatal(err)
	}
	attempt(true)
}

func TestDirectManagedSourceCredentialCapturedSuiteV2(t *testing.T) {
	_, lane, _, executor, issue := directSourceCredentialLaneFixtureV2(t)
	// The wire type is shared; a V1 payload is consumed and rejected before execution.
	_, v1, _ := directSourceCredentialFixture(t)
	if !lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredential, v1)) {
		t.Fatal("reserved V1 payload escaped")
	}
	raw, _ := issue.CanonicalBytes()
	malformed := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unexpected":true}`)...)
	if !lane.handle(transport.Envelope{Type: transport.MsgDirectManagedSourceCredentialV2, Payload: malformed}) {
		t.Fatal("malformed reserved command escaped")
	}
	select {
	case <-executor.started:
		t.Fatal("malformed command reached executor")
	default:
	}
	n := &directManagedSourceCredentialNegotiationV2{socket: lane.socket, native: lane.native, session: lane.negotiation.session}
	// Constructor requires the captured socket and complete authenticated suite.
	if newDirectManagedSourceCredentialConnectionV2(lane.d, &websocket.Conn{}, lane.native, n) != nil {
		t.Fatal("retargeted captured negotiation")
	}
	n.session.ProtocolFeatures = []string{transport.DirectManagedSourcePrepareProtocol, transport.DirectManagedSourcePoPProtocol, transport.DirectManagedSourceCredentialProtocol}
	if newDirectManagedSourceCredentialConnectionV2(lane.d, lane.socket, lane.native, n) != nil {
		t.Fatal("V1 negotiation fell back to V2")
	}
}

func TestDirectManagedSourceCredentialWriteFailureClosesLaneV2(t *testing.T) {
	_, lane, _, executor, issue := directSourceCredentialLaneFixtureV2(t)
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
