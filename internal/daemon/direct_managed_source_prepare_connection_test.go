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

type directSourcePrepareLaneExecutor struct {
	available        bool
	publicationError error
	token            *nativeWorkerPublicationToken
	started          chan transport.DirectManagedSourcePrepareCommand
	release          chan struct{}
	finished         chan struct{}
	canceled         chan struct{}
}

func (e *directSourcePrepareLaneExecutor) verifyPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourcePrepareCommand) (*nativeWorkerPublicationToken, error) {
	return e.token, e.publicationError
}
func (e *directSourcePrepareLaneExecutor) ready() bool { return e.available }
func (e *directSourcePrepareLaneExecutor) prepare(ctx context.Context, _ *websocket.Conn, _ *NativeObservationConnection, _ transport.HostSessionPayload, _ string, command transport.DirectManagedSourcePrepareCommand) ([]byte, error) {
	e.started <- command
	if e.canceled != nil {
		<-ctx.Done()
		close(e.canceled)
		return nil, ctx.Err()
	}
	if e.release != nil {
		<-e.release
	}
	if e.finished != nil {
		defer func() { e.finished <- struct{}{} }()
	}
	return nil, errors.New("private executor diagnostic")
}

func directSourcePrepareLaneFixture(t *testing.T, feature bool) (*Daemon, *directManagedSourcePrepareConnection, *websocket.Conn, *directSourcePrepareLaneExecutor, transport.DirectManagedSourcePrepareCommand) {
	t.Helper()
	_, command, session := directSourceStoreFixture(t)
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol}
	if feature {
		session.ProtocolFeatures = append(session.ProtocolFeatures, transport.DirectManagedSourcePrepareProtocol)
	}
	socket, peer := nativeBindingSocketPair(t)
	native := NewNativeObservationConnection("https://example.test", session.HostID, session.BootID, nil)
	native.offeredDirectManagedSourcePrepare = true
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	executor := &directSourcePrepareLaneExecutor{available: true, started: make(chan transport.DirectManagedSourcePrepareCommand, 16)}
	d := &Daemon{Config: Config{DirectManagedSourcePrepareEnabled: true}, directManagedSourcePrepare: executor, curConn: socket, nativeConn: native, writeTimeout: time.Second}
	lane := newDirectManagedSourcePrepareConnection(d, socket, native)
	t.Cleanup(lane.close)
	return d, lane, peer, executor, command
}

func directSourcePrepareLaneFailure(t *testing.T, peer *websocket.Conn, command transport.DirectManagedSourcePrepareCommand) {
	t.Helper()
	result := directSourcePrepareLaneReply(t, peer, command, transport.DirectManagedSourcePrepareFailure)
	if _, err := transport.DecodeDirectManagedSourcePrepareFailureACK(result, command.CommandID); err != nil {
		t.Fatalf("reply was not a closed failure ACK: %s: %v", result, err)
	}
}

// Match the server's strict host.command_ack payload contract before decoding
// the canonical prepare ACK carried in result.
func directSourcePrepareLaneReply(t *testing.T, peer *websocket.Conn, command transport.DirectManagedSourcePrepareCommand, errorCode string) json.RawMessage {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	var env transport.Envelope
	if err := peer.ReadJSON(&env); err != nil {
		t.Fatal(err)
	}
	if env.Type != transport.MsgCommandAck {
		t.Fatalf("unexpected reply type %s", env.Type)
	}
	var outer struct {
		CommandID domain.ID       `json:"commandId"`
		Error     string          `json:"error"`
		Result    json.RawMessage `json:"result"`
	}
	decoder := json.NewDecoder(bytes.NewReader(env.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&outer); err != nil {
		t.Fatalf("reply violated server ACK envelope: %s: %v", env.Payload, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(env.Payload, &fields); err != nil || len(fields) != 3 {
		t.Fatalf("reply must contain exactly commandId, error, result: %s", env.Payload)
	}
	for _, key := range []string{"commandId", "error", "result"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("reply missing server ACK key %q: %s", key, env.Payload)
		}
	}
	if outer.CommandID != command.CommandID || outer.Error != errorCode {
		t.Fatalf("unexpected outer ACK: %s", env.Payload)
	}
	return outer.Result
}

func TestDirectManagedSourcePrepareLaneACKEnvelopeCompatibility(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure", true: "success"}[success], func(t *testing.T) {
			_, lane, peer, _, command := directSourcePrepareLaneFixture(t, true)
			session, err := lane.native.AuthenticatedNativeHostSession()
			if err != nil {
				t.Fatal(err)
			}
			canonical := directManagedSourcePrepareFailure(command)
			errorCode := transport.DirectManagedSourcePrepareFailure
			if success {
				keys, keyCommand, keySession := directSourceStoreFixture(t)
				command = keyCommand
				canonical = directSourcePrepareACKBytes(t, keys, command, keySession)
				errorCode = ""
			}
			if success {
				p := &NativeWorkerProxy{connection: lane.native, done: make(chan struct{}), abortDone: make(chan struct{})}
				link := &nativeWorkerLink{conn: lane.socket, proxy: p}
				lane.d.nativeWorkers = map[string]*nativeWorkerLink{command.Subject.InstanceID.String(): link}
				lane.executor.(*directSourcePrepareLaneExecutor).token = &nativeWorkerPublicationToken{instanceID: command.Subject.InstanceID.String(), link: link, proxy: p}
			}
			original := bytes.Clone(canonical)
			lane.ack(canonical, session, command)
			result := directSourcePrepareLaneReply(t, peer, command, errorCode)
			if !bytes.Equal(result, original) || !bytes.Equal(canonical, original) {
				t.Fatal("wire envelope changed canonical ACK bytes")
			}
			if success {
				if _, err := transport.DecodeDirectManagedSourcePrepareACK(result, command); err != nil {
					t.Fatal(err)
				}
			} else if _, err := transport.DecodeDirectManagedSourcePrepareFailureACK(result, command.CommandID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDirectManagedSourcePrepareLaneReadinessRequiresOptIn(t *testing.T) {
	executor := &directSourcePrepareLaneExecutor{available: true}
	d := &Daemon{directManagedSourcePrepare: executor}
	if d.directManagedSourcePrepareReady() {
		t.Fatal("default configuration enabled prepare")
	}
	d.DirectManagedSourcePrepareEnabled = true
	if !d.directManagedSourcePrepareReady() {
		t.Fatal("enabled ready executor was unavailable")
	}
	executor.available = false
	if d.directManagedSourcePrepareReady() {
		t.Fatal("unready executor advertised prepare")
	}
	d.directManagedSourcePrepare = nil
	if d.directManagedSourcePrepareReady() {
		t.Fatal("missing executor advertised prepare")
	}
}

func TestDirectManagedSourcePrepareLaneCapabilityAndMalformed(t *testing.T) {
	for _, reason := range []string{"feature", "offer", "gate", "unready"} {
		t.Run(reason, func(t *testing.T) {
			d, lane, peer, executor, command := directSourcePrepareLaneFixture(t, reason != "feature")
			switch reason {
			case "offer":
				lane.native.offeredDirectManagedSourcePrepare = false
			case "gate":
				d.DirectManagedSourcePrepareEnabled = false
			case "unready":
				executor.available = false
			}
			if lane.handle(transport.Envelope{Type: "unrelated"}) {
				t.Fatal("lane consumed an unrelated command")
			}
			for _, raw := range []string{`{}`, `{"commandId":null}`, `{"CommandId":"x"}`, `{"commandId":"x","commandId":"y"}`} {
				if !lane.handle(transport.Envelope{Type: transport.MsgDirectManagedSourcePrepare, Payload: json.RawMessage(raw)}) {
					t.Fatal("lane did not consume malformed prepare")
				}
			}
			env := nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepare, command)
			d.handleCommand(nil, env)
			lane.handle(env)
			directSourcePrepareLaneFailure(t, peer, command)
			select {
			case <-executor.started:
				t.Fatal("rejected or generic command reached executor")
			default:
			}
		})
	}
}

func TestDirectManagedSourcePrepareLaneSerialAndSanitizedFailure(t *testing.T) {
	_, lane, peer, executor, command := directSourcePrepareLaneFixture(t, true)
	executor.release = make(chan struct{})
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepare, command))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("executor did not start")
	}
	second := command
	second.CommandID = domain.NewID()
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepare, second))
	select {
	case <-executor.started:
		t.Fatal("prepare commands ran concurrently")
	default:
	}
	close(executor.release)
	directSourcePrepareLaneFailure(t, peer, command)
	directSourcePrepareLaneFailure(t, peer, second)
	select {
	case got := <-executor.started:
		if got.CommandID != second.CommandID {
			t.Fatal("wrong queued command")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("queued command did not run")
	}
}

func TestDirectManagedSourcePrepareLaneQueueSaturation(t *testing.T) {
	_, lane, peer, executor, command := directSourcePrepareLaneFixture(t, true)
	executor.release = make(chan struct{})
	executor.finished = make(chan struct{}, 8)
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepare, command))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("executor did not start")
	}
	for i := 1; i <= 8; i++ {
		command.CommandID = domain.NewID()
		lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepare, command))
	}
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("saturation produced an ACK")
	} else if websocket.IsCloseError(err, websocket.CloseAbnormalClosure) == false {
		if network, ok := err.(interface{ Timeout() bool }); ok && network.Timeout() {
			t.Fatal("saturation did not close socket")
		}
	}
	lane.close()
	close(executor.release)
	select {
	case <-executor.finished:
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight executor did not finish")
	}
	select {
	case <-executor.started:
		t.Fatal("queued command ran after saturation")
	default:
	}
}

func TestDirectManagedSourcePrepareLaneExactScopeSupersession(t *testing.T) {
	for _, reason := range []string{"socket", "connection", "session"} {
		t.Run(reason, func(t *testing.T) {
			d, lane, peer, executor, command := directSourcePrepareLaneFixture(t, true)
			executor.release = make(chan struct{})
			executor.finished = make(chan struct{}, 8)
			lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepare, command))
			select {
			case <-executor.started:
			case <-time.After(3 * time.Second):
				t.Fatal("executor did not start")
			}
			command.CommandID = domain.NewID()
			lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepare, command))
			switch reason {
			case "socket":
				replacement, _ := nativeBindingSocketPair(t)
				d.connMu.Lock()
				d.curConn = replacement
				d.connMu.Unlock()
			case "connection":
				d.connMu.Lock()
				d.nativeConn = NewNativeObservationConnection("https://example.test", "", "", nil)
				d.connMu.Unlock()
			case "session":
				lane.native.mu.Lock()
				lane.native.session.NativeAdmissionID = domain.NewID().String()
				lane.native.mu.Unlock()
			}
			close(executor.release)
			select {
			case <-executor.finished:
			case <-time.After(3 * time.Second):
				t.Fatal("in-flight executor did not finish")
			}
			peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if _, _, err := peer.ReadMessage(); err == nil {
				t.Fatal("stale ACK escaped")
			}
			select {
			case <-executor.started:
				t.Fatal("queued command ran after scope supersession")
			default:
			}
		})
	}
}

func TestDirectManagedSourcePrepareLaneOfferReadiness(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, ready := range []bool{false, true} {
			d := &Daemon{Config: Config{ServerURL: "https://example.test?direct_managed_source_prepare=wrong&direct_managed_source_prepare=wrong", DirectManagedSourcePrepareEnabled: enabled}, directManagedSourcePrepare: &directSourcePrepareLaneExecutor{available: ready}}
			u, err := url.Parse(d.wsURL(context.Background()))
			if err != nil {
				t.Fatal(err)
			}
			values := u.Query()["direct_managed_source_prepare"]
			if enabled && ready {
				if len(values) != 1 || values[0] != transport.DirectManagedSourcePrepareProtocol {
					t.Fatalf("incorrect offer: %v", values)
				}
			} else if len(values) != 0 {
				t.Fatalf("unready offer: %v", values)
			}
		}
	}
}

func TestDirectManagedSourcePrepareLaneBeforeHostSessionDrops(t *testing.T) {
	_, lane, peer, executor, command := directSourcePrepareLaneFixture(t, true)
	lane.native.mu.Lock()
	lane.native.session = nil
	lane.native.mu.Unlock()
	raw, err := command.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !lane.handle(transport.Envelope{Type: transport.MsgDirectManagedSourcePrepare, Payload: raw}) {
		t.Fatal("prepare escaped dedicated lane")
	}
	select {
	case <-executor.started:
		t.Fatal("unauthenticated command executed")
	default:
	}
	_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("ACK before authenticated host.session")
	}
}

func TestDirectManagedSourcePrepareLaneRechecksBeforeACK(t *testing.T) {
	_, lane, peer, executor, command := directSourcePrepareLaneFixture(t, true)
	session, err := lane.native.AuthenticatedNativeHostSession()
	if err != nil {
		t.Fatal(err)
	}
	keys, keyCommand, keySession := directSourceStoreFixture(t)
	command = keyCommand
	ack := directSourcePrepareACKBytes(t, keys, command, keySession)
	executor.publicationError = errors.New("owner revoked while writer waited")
	lane.ack(ack, session, command)
	_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("success ACK published after verifier rejection")
	}
}

func directSourcePrepareACKBytes(t *testing.T, keys *DirectManagedSourceKeyStore, command transport.DirectManagedSourcePrepareCommand, session transport.HostSessionPayload) []byte {
	t.Helper()
	ack := directSourcePrepare(t, keys, command, session)
	raw, err := ack.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDirectManagedSourcePrepareLaneCloseCancelsAllocation(t *testing.T) {
	_, lane, peer, executor, command := directSourcePrepareLaneFixture(t, true)
	executor.canceled = make(chan struct{})
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepare, command))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("allocation did not start")
	}
	lane.close()
	select {
	case <-executor.canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("close did not cancel allocation")
	}
	lane.socket.Close()
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("closed lane published ACK")
	}
}

func TestDirectManagedSourcePrepareLaneRejectsUntrustedResult(t *testing.T) {
	_, lane, peer, _, command := directSourcePrepareLaneFixture(t, true)
	session, err := lane.native.AuthenticatedNativeHostSession()
	if err != nil {
		t.Fatal(err)
	}
	lane.ack([]byte(`{"private":"diagnostic"}`), session, command)
	lane.socket.Close()
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("untrusted result published")
	}
}
