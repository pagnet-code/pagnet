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

type managedPrepareLaneExecutor struct {
	available        bool
	publicationError error
	started          chan transport.ManagedEndpointPrepareCommand
	release          chan struct{}
	finished         chan struct{}
}

func (e *managedPrepareLaneExecutor) verifyPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.ManagedEndpointPrepareCommand) error {
	return e.publicationError
}
func (e *managedPrepareLaneExecutor) ready() bool { return e.available }
func (e *managedPrepareLaneExecutor) prepare(_ context.Context, _ *websocket.Conn, _ *NativeObservationConnection, _ transport.HostSessionPayload, _ string, command transport.ManagedEndpointPrepareCommand) ([]byte, error) {
	e.started <- command
	if e.release != nil {
		<-e.release
	}
	if e.finished != nil {
		defer func() { e.finished <- struct{}{} }()
	}
	return nil, errors.New("private executor diagnostic")
}

func managedPrepareLaneFixture(t *testing.T, feature bool) (*Daemon, *managedEndpointPrepareConnection, *websocket.Conn, *managedPrepareLaneExecutor, transport.ManagedEndpointPrepareCommand) {
	t.Helper()
	_, subject, session := managedEndpointFixture(t)
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol}
	if feature {
		session.ProtocolFeatures = append(session.ProtocolFeatures, transport.ManagedEndpointPrepareProtocol)
	}
	socket, peer := nativeBindingSocketPair(t)
	native := NewNativeObservationConnection("https://example.test", session.HostID, session.BootID, nil)
	native.offeredManagedEndpointPrepare = true
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	executor := &managedPrepareLaneExecutor{available: true, started: make(chan transport.ManagedEndpointPrepareCommand, 16)}
	d := &Daemon{Config: Config{ManagedEndpointPrepareEnabled: true}, managedEndpointPrepare: executor, curConn: socket, nativeConn: native, writeTimeout: time.Second}
	lane := newManagedEndpointPrepareConnection(d, socket, native)
	t.Cleanup(lane.close)
	return d, lane, peer, executor, transport.ManagedEndpointPrepareCommand{ProtocolVersion: transport.ManagedEndpointPrepareProtocol, CommandID: domain.NewID(), Subject: subject}
}

func managedPrepareLaneFailure(t *testing.T, peer *websocket.Conn, command transport.ManagedEndpointPrepareCommand) {
	t.Helper()
	result := managedPrepareLaneReply(t, peer, command, transport.ManagedEndpointPrepareFailure)
	if _, err := transport.DecodeManagedEndpointPrepareFailureACK(result, command.CommandID); err != nil {
		t.Fatalf("reply was not a closed failure ACK: %s: %v", result, err)
	}
}

// Match the server's strict host.command_ack payload contract before decoding
// the canonical prepare ACK carried in result.
func managedPrepareLaneReply(t *testing.T, peer *websocket.Conn, command transport.ManagedEndpointPrepareCommand, errorCode string) json.RawMessage {
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

func TestManagedEndpointPrepareLaneACKEnvelopeCompatibility(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure", true: "success"}[success], func(t *testing.T) {
			_, lane, peer, _, command := managedPrepareLaneFixture(t, true)
			session, err := lane.native.AuthenticatedNativeHostSession()
			if err != nil {
				t.Fatal(err)
			}
			canonical := managedPrepareFailure(command)
			errorCode := transport.ManagedEndpointPrepareFailure
			if success {
				keys, subject, keySession := managedEndpointFixture(t)
				command.Subject = subject
				canonical = managedPrepareSuccess(t, keys, command, keySession)
				errorCode = ""
			}
			original := bytes.Clone(canonical)
			lane.ack(canonical, session, command)
			result := managedPrepareLaneReply(t, peer, command, errorCode)
			if !bytes.Equal(result, original) || !bytes.Equal(canonical, original) {
				t.Fatal("wire envelope changed canonical ACK bytes")
			}
			if success {
				if _, err := transport.DecodeManagedEndpointPrepareACK(result, command); err != nil {
					t.Fatal(err)
				}
			} else if _, err := transport.DecodeManagedEndpointPrepareFailureACK(result, command.CommandID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManagedEndpointPrepareLaneReadinessRequiresOptIn(t *testing.T) {
	executor := &managedPrepareLaneExecutor{available: true}
	d := &Daemon{managedEndpointPrepare: executor}
	if d.managedEndpointPrepareReady() {
		t.Fatal("default configuration enabled prepare")
	}
	d.ManagedEndpointPrepareEnabled = true
	if !d.managedEndpointPrepareReady() {
		t.Fatal("enabled ready executor was unavailable")
	}
	executor.available = false
	if d.managedEndpointPrepareReady() {
		t.Fatal("unready executor advertised prepare")
	}
	d.managedEndpointPrepare = nil
	if d.managedEndpointPrepareReady() {
		t.Fatal("missing executor advertised prepare")
	}
}

func TestManagedEndpointPrepareLaneCapabilityAndMalformed(t *testing.T) {
	for _, reason := range []string{"feature", "offer", "gate", "unready"} {
		t.Run(reason, func(t *testing.T) {
			d, lane, peer, executor, command := managedPrepareLaneFixture(t, reason != "feature")
			switch reason {
			case "offer":
				lane.native.offeredManagedEndpointPrepare = false
			case "gate":
				d.ManagedEndpointPrepareEnabled = false
			case "unready":
				executor.available = false
			}
			if lane.handle(transport.Envelope{Type: "unrelated"}) {
				t.Fatal("lane consumed an unrelated command")
			}
			for _, raw := range []string{`{}`, `{"commandId":null}`, `{"CommandId":"x"}`, `{"commandId":"x","commandId":"y"}`} {
				if !lane.handle(transport.Envelope{Type: transport.MsgManagedEndpointPrepare, Payload: json.RawMessage(raw)}) {
					t.Fatal("lane did not consume malformed prepare")
				}
			}
			env := nativeBindingEnvelope(t, transport.MsgManagedEndpointPrepare, command)
			d.handleCommand(nil, env)
			lane.handle(env)
			managedPrepareLaneFailure(t, peer, command)
			select {
			case <-executor.started:
				t.Fatal("rejected or generic command reached executor")
			default:
			}
		})
	}
}

func TestManagedEndpointPrepareLaneSerialAndSanitizedFailure(t *testing.T) {
	_, lane, peer, executor, command := managedPrepareLaneFixture(t, true)
	executor.release = make(chan struct{})
	lane.handle(nativeBindingEnvelope(t, transport.MsgManagedEndpointPrepare, command))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("executor did not start")
	}
	second := command
	second.CommandID = domain.NewID()
	lane.handle(nativeBindingEnvelope(t, transport.MsgManagedEndpointPrepare, second))
	select {
	case <-executor.started:
		t.Fatal("prepare commands ran concurrently")
	default:
	}
	close(executor.release)
	managedPrepareLaneFailure(t, peer, command)
	managedPrepareLaneFailure(t, peer, second)
	select {
	case got := <-executor.started:
		if got.CommandID != second.CommandID {
			t.Fatal("wrong queued command")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("queued command did not run")
	}
}

func TestManagedEndpointPrepareLaneQueueSaturation(t *testing.T) {
	_, lane, peer, executor, command := managedPrepareLaneFixture(t, true)
	executor.release = make(chan struct{})
	executor.finished = make(chan struct{}, 8)
	lane.handle(nativeBindingEnvelope(t, transport.MsgManagedEndpointPrepare, command))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("executor did not start")
	}
	for i := 1; i <= 8; i++ {
		command.CommandID = domain.NewID()
		lane.handle(nativeBindingEnvelope(t, transport.MsgManagedEndpointPrepare, command))
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

func TestManagedEndpointPrepareLaneExactScopeSupersession(t *testing.T) {
	for _, reason := range []string{"socket", "connection", "session"} {
		t.Run(reason, func(t *testing.T) {
			d, lane, peer, executor, command := managedPrepareLaneFixture(t, true)
			executor.release = make(chan struct{})
			executor.finished = make(chan struct{}, 8)
			lane.handle(nativeBindingEnvelope(t, transport.MsgManagedEndpointPrepare, command))
			select {
			case <-executor.started:
			case <-time.After(3 * time.Second):
				t.Fatal("executor did not start")
			}
			command.CommandID = domain.NewID()
			lane.handle(nativeBindingEnvelope(t, transport.MsgManagedEndpointPrepare, command))
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

func TestManagedEndpointPrepareLaneOfferReadiness(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, ready := range []bool{false, true} {
			d := &Daemon{Config: Config{ServerURL: "https://example.test?managed_endpoint_prepare=wrong&managed_endpoint_prepare=wrong", ManagedEndpointPrepareEnabled: enabled}, managedEndpointPrepare: &managedPrepareLaneExecutor{available: ready}}
			u, err := url.Parse(d.wsURL(context.Background()))
			if err != nil {
				t.Fatal(err)
			}
			values := u.Query()["managed_endpoint_prepare"]
			if enabled && ready {
				if len(values) != 1 || values[0] != transport.ManagedEndpointPrepareProtocol {
					t.Fatalf("incorrect offer: %v", values)
				}
			} else if len(values) != 0 {
				t.Fatalf("unready offer: %v", values)
			}
		}
	}
}

func TestManagedEndpointPrepareLaneBeforeHostSessionDrops(t *testing.T) {
	_, lane, peer, executor, command := managedPrepareLaneFixture(t, true)
	lane.native.mu.Lock()
	lane.native.session = nil
	lane.native.mu.Unlock()
	raw, err := command.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !lane.handle(transport.Envelope{Type: transport.MsgManagedEndpointPrepare, Payload: raw}) {
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

func TestManagedEndpointPrepareLaneRechecksBeforeACK(t *testing.T) {
	_, lane, peer, executor, command := managedPrepareLaneFixture(t, true)
	session, err := lane.native.AuthenticatedNativeHostSession()
	if err != nil {
		t.Fatal(err)
	}
	keys, subject, keySession := managedEndpointFixture(t)
	command.Subject = subject
	ack := managedPrepareSuccess(t, keys, command, keySession)
	executor.publicationError = errors.New("owner revoked while writer waited")
	lane.ack(ack, session, command)
	_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("success ACK published after verifier rejection")
	}
}
