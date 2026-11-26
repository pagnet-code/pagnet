//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

type directSourcePrepareLaneExecutorV2 struct {
	available        bool
	publicationError error
	token            *nativeWorkerPublicationToken
	started          chan transport.DirectManagedSourcePrepareCommandV2
	release          chan struct{}
	finished         chan struct{}
	canceled         chan struct{}
}

func (e *directSourcePrepareLaneExecutorV2) verifyPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourcePrepareCommandV2) (*nativeWorkerPublicationToken, error) {
	return e.token, e.publicationError
}
func (e *directSourcePrepareLaneExecutorV2) ready() bool { return e.available }
func (e *directSourcePrepareLaneExecutorV2) prepare(ctx context.Context, _ *websocket.Conn, _ *NativeObservationConnection, _ transport.HostSessionPayload, _ string, command transport.DirectManagedSourcePrepareCommandV2) ([]byte, error) {
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

func directSourcePrepareLaneFixtureV2(t *testing.T, feature bool) (*Daemon, *directManagedSourcePrepareConnectionV2, *websocket.Conn, *directSourcePrepareLaneExecutorV2, transport.DirectManagedSourcePrepareCommandV2) {
	t.Helper()
	_, _, command, session := directSourceStoreFixtureV2(t)
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol}
	if feature {
		session.ProtocolFeatures = append(session.ProtocolFeatures, directManagedSourceProtocolsV2[:]...)
	}
	socket, peer := nativeBindingSocketPair(t)
	native := NewNativeObservationConnection("https://example.test", session.HostID, session.BootID, nil)
	native.offeredDirectManagedSourceV2 = directManagedSourceProtocolsV2
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	executor := &directSourcePrepareLaneExecutorV2{available: true, started: make(chan transport.DirectManagedSourcePrepareCommandV2, 16)}
	d := &Daemon{Log: slog.Default(), directManagedSourcePrepareV2: executor, curConn: socket, nativeConn: native, writeTimeout: time.Second}
	lane := newDirectManagedSourcePrepareConnectionV2(d, socket, native, &directManagedSourcePrepareNegotiationV2{socket: socket, native: native, session: session})
	t.Cleanup(lane.close)
	return d, lane, peer, executor, command
}

func directSourcePrepareLaneFailureV2(t *testing.T, peer *websocket.Conn, command transport.DirectManagedSourcePrepareCommandV2) {
	t.Helper()
	result := directSourcePrepareLaneReplyV2(t, peer, command, transport.DirectManagedSourcePrepareFailureV2)
	if _, err := transport.DecodeDirectManagedSourcePrepareFailureACKV2(result, command.CommandID); err != nil {
		t.Fatalf("reply was not a closed failure ACK: %s: %v", result, err)
	}
}

// Match the server's strict host.command_ack payload contract before decoding
// the canonical prepare ACK carried in result.
func directSourcePrepareLaneReplyV2(t *testing.T, peer *websocket.Conn, command transport.DirectManagedSourcePrepareCommandV2, errorCode string) json.RawMessage {
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

func TestDirectManagedSourcePrepareLaneACKEnvelopeCompatibilityV2(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure", true: "success"}[success], func(t *testing.T) {
			_, lane, peer, _, command := directSourcePrepareLaneFixtureV2(t, true)
			session, err := lane.native.AuthenticatedNativeHostSession()
			if err != nil {
				t.Fatal(err)
			}
			canonical := directManagedSourcePrepareFailureV2(command)
			errorCode := transport.DirectManagedSourcePrepareFailureV2
			if success {
				keys, journal, keyCommand, keySession := directSourceStoreFixtureV2(t)
				command = keyCommand
				canonical = directSourcePrepareACKBytesV2(t, keys, journal, command, keySession)
				errorCode = ""
			}
			if success {
				p := &NativeWorkerProxy{connection: lane.native, done: make(chan struct{})}
				link := &nativeWorkerLink{conn: lane.socket, proxy: p}
				lane.d.nativeWorkers = map[string]*nativeWorkerLink{command.Subject.InstanceID.String(): link}
				lane.executor.(*directSourcePrepareLaneExecutorV2).token = &nativeWorkerPublicationToken{instanceID: command.Subject.InstanceID.String(), link: link, proxy: p}
			}
			original := bytes.Clone(canonical)
			lane.ack(canonical, session, command)
			result := directSourcePrepareLaneReplyV2(t, peer, command, errorCode)
			if !bytes.Equal(result, original) || !bytes.Equal(canonical, original) {
				t.Fatal("wire envelope changed canonical ACK bytes")
			}
			if success {
				if _, err := transport.DecodeDirectManagedSourcePrepareACKV2(result, command); err != nil {
					t.Fatal(err)
				}
			} else if _, err := transport.DecodeDirectManagedSourcePrepareFailureACKV2(result, command.CommandID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDirectManagedSourcePrepareLaneSerialAndSanitizedFailureV2(t *testing.T) {
	_, lane, peer, executor, command := directSourcePrepareLaneFixtureV2(t, true)
	executor.release = make(chan struct{})
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepareV2, command))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("executor did not start")
	}
	second := command
	second.CommandID = domain.NewID()
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepareV2, second))
	select {
	case <-executor.started:
		t.Fatal("prepare commands ran concurrently")
	default:
	}
	close(executor.release)
	directSourcePrepareLaneFailureV2(t, peer, command)
	directSourcePrepareLaneFailureV2(t, peer, second)
	select {
	case got := <-executor.started:
		if got.CommandID != second.CommandID {
			t.Fatal("wrong queued command")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("queued command did not run")
	}
}

func TestDirectManagedSourcePrepareLaneQueueSaturationV2(t *testing.T) {
	_, lane, peer, executor, command := directSourcePrepareLaneFixtureV2(t, true)
	executor.release = make(chan struct{})
	executor.finished = make(chan struct{}, 8)
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepareV2, command))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("executor did not start")
	}
	for i := 1; i <= 8; i++ {
		command.CommandID = domain.NewID()
		lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepareV2, command))
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

func TestDirectManagedSourcePrepareLaneExactScopeSupersessionV2(t *testing.T) {
	for _, reason := range []string{"socket", "connection", "session"} {
		t.Run(reason, func(t *testing.T) {
			d, lane, peer, executor, command := directSourcePrepareLaneFixtureV2(t, true)
			executor.release = make(chan struct{})
			executor.finished = make(chan struct{}, 8)
			lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepareV2, command))
			select {
			case <-executor.started:
			case <-time.After(3 * time.Second):
				t.Fatal("executor did not start")
			}
			command.CommandID = domain.NewID()
			lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepareV2, command))
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

func TestDirectManagedSourcePrepareLaneRechecksBeforeACKV2(t *testing.T) {
	_, lane, peer, executor, command := directSourcePrepareLaneFixtureV2(t, true)
	session, err := lane.native.AuthenticatedNativeHostSession()
	if err != nil {
		t.Fatal(err)
	}
	keys, journal, keyCommand, keySession := directSourceStoreFixtureV2(t)
	command = keyCommand
	ack := directSourcePrepareACKBytesV2(t, keys, journal, command, keySession)
	executor.publicationError = errors.New("owner revoked while writer waited")
	lane.ack(ack, session, command)
	_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("success ACK published after verifier rejection")
	}
}

func TestDirectManagedSourcePrepareLaneCloseCancelsAllocationV2(t *testing.T) {
	_, lane, peer, executor, command := directSourcePrepareLaneFixtureV2(t, true)
	executor.canceled = make(chan struct{})
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepareV2, command))
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

func TestDirectManagedSourcePrepareLaneRejectsUntrustedResultV2(t *testing.T) {
	_, lane, peer, _, command := directSourcePrepareLaneFixtureV2(t, true)
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

func directSourcePrepareACKBytesV2(t *testing.T, keys *DirectManagedSourceKeyStoreV2, journal *DirectManagedSourcePrepareJournalV2, c transport.DirectManagedSourcePrepareCommandV2, session transport.HostSessionPayload) []byte {
	t.Helper()
	e := &localDirectManagedSourcePrepareV2{keys: keys, journal: journal}
	ack, err := e.execute(session, "https://example.test", c, directSourceScopeOKV2)
	if err != nil {
		t.Fatal(err)
	}
	return ack
}

func TestDirectManagedSourcePrepareV2RequiresCapturedNegotiation(t *testing.T) {
	d, lane, _, _, _ := directSourcePrepareLaneFixtureV2(t, true)
	if newDirectManagedSourcePrepareConnectionV2(d, lane.socket, lane.native, nil) != nil {
		t.Fatal("missing negotiation admitted")
	}
	n := *lane.negotiation
	n.session.ProtocolFeatures = []string{transport.DirectManagedSourcePrepareProtocol}
	if newDirectManagedSourcePrepareConnectionV2(d, lane.socket, lane.native, &n) != nil {
		t.Fatal("V1 negotiation admitted")
	}
}

func TestDirectManagedSourcePrepareLaneNoV1FallbackV2(t *testing.T) {
	_, lane, _, executor, _ := directSourcePrepareLaneFixtureV2(t, true)
	_, v1, _ := directSourceStoreFixture(t)
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePrepare, v1))
	select {
	case <-executor.started:
		t.Fatal("V1 command reached V2 executor")
	default:
	}
	if lane.handle(transport.Envelope{Type: "unrelated"}) {
		t.Fatal("unrelated command consumed")
	}
}

func TestDirectManagedSourcePrepareLaneSendFailureRetainsACKV2(t *testing.T) {
	keys, journal, command, keySession := directSourceStoreFixtureV2(t)
	canonical := directSourcePrepareACKBytesV2(t, keys, journal, command, keySession)
	_, lane, _, executor, _ := directSourcePrepareLaneFixtureV2(t, true)
	session, err := lane.native.AuthenticatedNativeHostSession()
	if err != nil {
		t.Fatal(err)
	}
	p := &NativeWorkerProxy{connection: lane.native, done: make(chan struct{})}
	link := &nativeWorkerLink{conn: lane.socket, proxy: p}
	lane.d.nativeWorkers = map[string]*nativeWorkerLink{command.Subject.InstanceID.String(): link}
	executor.token = &nativeWorkerPublicationToken{instanceID: command.Subject.InstanceID.String(), link: link, proxy: p}
	lane.socket.Close()
	lane.ack(canonical, session, command)
	e := &localDirectManagedSourcePrepareV2{keys: keys, journal: journal}
	retry, err := e.execute(keySession, "https://example.test", command, directSourceScopeOKV2)
	if err != nil || !bytes.Equal(canonical, retry) {
		t.Fatal("failed ACK send replaced retained evidence", err)
	}
	_, next, peer, nextExecutor, _ := directSourcePrepareLaneFixtureV2(t, true)
	nextSession, err := next.native.AuthenticatedNativeHostSession()
	if err != nil {
		t.Fatal(err)
	}
	p = &NativeWorkerProxy{connection: next.native, done: make(chan struct{})}
	link = &nativeWorkerLink{conn: next.socket, proxy: p}
	next.d.nativeWorkers = map[string]*nativeWorkerLink{command.Subject.InstanceID.String(): link}
	nextExecutor.token = &nativeWorkerPublicationToken{instanceID: command.Subject.InstanceID.String(), link: link, proxy: p}
	next.ack(retry, nextSession, command)
	received := directSourcePrepareLaneReplyV2(t, peer, command, "")
	if !bytes.Equal(received, canonical) {
		t.Fatal("retry ACK bytes changed")
	}
}

func TestDirectManagedSourcePrepareLaneBlockedWriterSupersessionV2(t *testing.T) {
	d, lane, peer, executor, command := directSourcePrepareLaneFixtureV2(t, true)
	session, err := lane.native.AuthenticatedNativeHostSession()
	if err != nil {
		t.Fatal(err)
	}
	keys, journal, command, keySession := directSourceStoreFixtureV2(t)
	ack := directSourcePrepareACKBytesV2(t, keys, journal, command, keySession)
	p := &NativeWorkerProxy{connection: lane.native, done: make(chan struct{})}
	link := &nativeWorkerLink{conn: lane.socket, proxy: p}
	d.nativeWorkers = map[string]*nativeWorkerLink{command.Subject.InstanceID.String(): link}
	executor.token = &nativeWorkerPublicationToken{instanceID: command.Subject.InstanceID.String(), link: link, proxy: p}
	d.writeMu.Lock()
	started, finished := make(chan struct{}), make(chan struct{})
	go func() { close(started); lane.ack(ack, session, command); close(finished) }()
	<-started
	replacement, _ := nativeBindingSocketPair(t)
	d.connMu.Lock()
	d.curConn = replacement
	d.connMu.Unlock()
	d.writeMu.Unlock()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("writer did not finish")
	}
	lane.socket.Close()
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("superseded writer published success")
	}
}
