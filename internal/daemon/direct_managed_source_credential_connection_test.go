//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

type directSourceCredentialLaneExecutor struct {
	available bool
	install   func(transport.DirectManagedSourceCredentialIssue) ([]byte, error)
	started   chan transport.DirectManagedSourceCredentialIssue
	canceled  chan struct{}
	release   chan struct{}
	finished  chan struct{}
	result    []byte
	err       error
}

func (e *directSourceCredentialLaneExecutor) ready() bool { return e.available }
func (e *directSourceCredentialLaneExecutor) installCredential(ctx context.Context, _ *websocket.Conn, _ *NativeObservationConnection, _ transport.HostSessionPayload, _ string, issue transport.DirectManagedSourceCredentialIssue, _ *directManagedSourceCredentialPublicationLane) ([]byte, error) {
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
func (e *directSourceCredentialLaneExecutor) verifyCredentialPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourceCredentialIssue) (*nativeWorkerPublicationToken, error) {
	return nil, nil
}
func (e *directSourceCredentialLaneExecutor) publishCredentialACK(ctx context.Context, _ *nativeWorkerPublicationToken, _ *websocket.Conn, _ *NativeObservationConnection, _ transport.HostSessionPayload, _ string, _ transport.DirectManagedSourceCredentialIssue, lane *directManagedSourceCredentialPublicationLane, _ []byte, write func() error) error {
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

func directSourceCredentialLaneFixture(t *testing.T) (*Daemon, *directManagedSourceCredentialConnection, *websocket.Conn, *directSourceCredentialLaneExecutor, transport.DirectManagedSourceCredentialIssue) {
	t.Helper()
	keys, issue, session := directSourceCredentialFixture(t)
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.DirectManagedSourcePrepareProtocol, transport.DirectManagedSourcePoPProtocol, transport.DirectManagedSourceCredentialProtocol}
	result, err := keys.InstallCredential(issue, "https://example.test", session, directSourceCredentialScopeOK, directSourceCredentialFenceOK)
	if err != nil {
		t.Fatal(err)
	}
	socket, peer := nativeBindingSocketPair(t)
	native := NewNativeObservationConnection("https://example.test", session.HostID, session.BootID, nil)
	native.offeredDirectManagedSourcePrepare, native.offeredDirectManagedSourcePoP = true, true
	native.offeredDirectManagedSourceCredential = transport.DirectManagedSourceCredentialProtocol
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	executor := &directSourceCredentialLaneExecutor{available: true, started: make(chan transport.DirectManagedSourceCredentialIssue, 16), result: result}
	d := &Daemon{Config: Config{DirectManagedSourcePrepareEnabled: true, DirectManagedSourcePoPEnabled: true, DirectManagedSourceCredentialEnabled: true}, directManagedSourcePrepare: &directSourcePrepareLaneExecutor{available: true}, directManagedSourcePoP: &directSourcePoPLaneExecutor{available: true}, directManagedSourceCredential: executor, curConn: socket, nativeConn: native, writeTimeout: time.Second}
	lane := newDirectManagedSourceCredentialConnection(d, socket, native)
	t.Cleanup(lane.close)
	return d, lane, peer, executor, issue
}

func TestDirectManagedSourceCredentialLaneOfferReadiness(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, ready := range []bool{false, true} {
			executor := &directSourceCredentialLaneExecutor{available: ready}
			d := &Daemon{Config: Config{ServerURL: "https://example.test?direct_managed_source_credential=injected&direct_managed_source_credential=duplicate", DirectManagedSourcePrepareEnabled: true, DirectManagedSourcePoPEnabled: true, DirectManagedSourceCredentialEnabled: enabled}, directManagedSourcePrepare: &directSourcePrepareLaneExecutor{available: true}, directManagedSourcePoP: &directSourcePoPLaneExecutor{available: true}, directManagedSourceCredential: executor}
			if d.directManagedSourceCredentialReady() != (enabled && ready) {
				t.Fatal("credential readiness ignored opt-in or executor readiness")
			}
			u, err := url.Parse(d.wsURL(context.Background()))
			if err != nil {
				t.Fatal(err)
			}
			values := u.Query()["direct_managed_source_credential"]
			if enabled && ready {
				if len(values) != 1 || values[0] != transport.DirectManagedSourceCredentialProtocol {
					t.Fatalf("incorrect offer: %v", values)
				}
			} else if len(values) != 0 {
				t.Fatalf("unready offer: %v", values)
			}
		}
	}
}

func TestDirectManagedSourceCredentialLaneCapability(t *testing.T) {
	for _, feature := range []string{transport.DirectManagedSourcePrepareProtocol, transport.DirectManagedSourcePoPProtocol, transport.DirectManagedSourceCredentialProtocol} {
		for _, reason := range []string{"missing", "duplicate", "offer"} {
			t.Run(feature+"/"+reason, func(t *testing.T) {
				_, lane, peer, executor, issue := directSourceCredentialLaneFixture(t)
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
				case "offer":
					switch feature {
					case transport.DirectManagedSourcePrepareProtocol:
						lane.native.offeredDirectManagedSourcePrepare = false
					case transport.DirectManagedSourcePoPProtocol:
						lane.native.offeredDirectManagedSourcePoP = false
					default:
						lane.native.offeredDirectManagedSourceCredential = ""
					}
				}
				lane.native.mu.Unlock()
				if !lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredential, issue)) {
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

func TestDirectManagedSourceCredentialLaneExactACK(t *testing.T) {
	d, lane, peer, executor, issue := directSourceCredentialLaneFixture(t)
	expected := append([]byte(nil), executor.result...)
	wantError := ""

	env := nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredential, issue)
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

func TestDirectManagedSourceCredentialLaneCloseCancelsQueue(t *testing.T) {
	_, lane, peer, executor, issue := directSourceCredentialLaneFixture(t)
	executor.canceled = make(chan struct{})
	executor.finished = make(chan struct{})
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredential, issue))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("credential install did not start")
	}
	second := issue
	second.CredentialID = domain.NewID()
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredential, second))
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

func TestDirectManagedSourceCredentialLaneCloseFencesACK(t *testing.T) {
	d, lane, peer, executor, issue := directSourceCredentialLaneFixture(t)
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

func TestDirectManagedSourceCredentialLaneQueueSaturation(t *testing.T) {
	_, lane, peer, executor, issue := directSourceCredentialLaneFixture(t)
	executor.release = make(chan struct{})
	executor.finished = make(chan struct{})
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredential, issue))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("credential install did not start")
	}
	for i := 0; i < directManagedSourceCredentialQueueLimit; i++ {
		issue.CredentialID = domain.NewID()
		lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredential, issue))
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

func TestDirectManagedSourceCredentialLanePrivateFailureCloses(t *testing.T) {
	for _, reason := range []string{"private", "retryable", "rejected", "key"} {
		t.Run(reason, func(t *testing.T) {
			_, lane, peer, executor, issue := directSourceCredentialLaneFixture(t)
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
			lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredential, issue))
			_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, _, err := peer.ReadMessage(); err == nil {
				t.Fatal("private or retryable executor failure produced an ACK")
			} else if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
				t.Fatal("private or retryable executor failure did not close socket")
			}
		})
	}
}

func TestDirectManagedSourceCredentialLaneMissingEvidenceRetry(t *testing.T) {
	keys, issue, session := directSourceCredentialFixture(t)
	if _, err := keys.registry.db.Exec(`CREATE TEMP TABLE saved_pop AS SELECT * FROM native_direct_managed_source_pop_challenges`); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.registry.db.Exec(`DELETE FROM native_direct_managed_source_pop_challenges`); err != nil {
		t.Fatal(err)
	}
	attempt := func(expectSuccess bool) {
		d, lane, peer, executor, _ := directSourceCredentialLaneFixture(t)
		executor.install = func(retained transport.DirectManagedSourceCredentialIssue) ([]byte, error) {
			return keys.InstallCredential(retained, "https://example.test", session, directSourceCredentialScopeOK, directSourceCredentialFenceOK)
		}
		d.handleCommand(nil, nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredential, issue))
		lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredential, issue))
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
		ack, err := transport.DecodeDirectManagedSourceCredentialACK(outer.Result)
		if err != nil || ack.CredentialID != issue.CredentialID {
			t.Fatal("retry changed exact issue")
		}
	}
	attempt(false)
	if _, err := keys.registry.db.Exec(`INSERT INTO native_direct_managed_source_pop_challenges SELECT * FROM saved_pop`); err != nil {
		t.Fatal(err)
	}
	attempt(true)
}
