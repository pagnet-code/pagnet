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

type directSourcePoPLaneExecutorV2 struct {
	available         bool
	publicationError  error
	token             *nativeWorkerPublicationToken
	beforePublication func()
	started           chan transport.DirectManagedSourcePoPChallengeV2
	release           chan struct{}
	finished          chan struct{}
	canceled          chan struct{}
	result            []byte
}

func (e *directSourcePoPLaneExecutorV2) verifyPoPPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourcePoPChallengeV2) (*nativeWorkerPublicationToken, error) {
	if e.beforePublication != nil {
		e.beforePublication()
	}
	return e.token, e.publicationError
}
func (e *directSourcePoPLaneExecutorV2) ready() bool { return e.available }
func (e *directSourcePoPLaneExecutorV2) confirmPoP(ctx context.Context, _ *websocket.Conn, _ *NativeObservationConnection, _ transport.HostSessionPayload, _ string, command transport.DirectManagedSourcePoPChallengeV2) ([]byte, error) {
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
	if e.result != nil {
		return append([]byte(nil), e.result...), nil
	}
	return nil, errors.New("private executor diagnostic")
}

func directSourcePoPLaneFixtureV2(t *testing.T, feature bool) (*Daemon, *directManagedSourcePoPConnectionV2, *websocket.Conn, *directSourcePoPLaneExecutorV2, transport.DirectManagedSourcePoPChallengeV2) {
	t.Helper()

	keys, challenge, session, private := directSourcePoPFixtureV2(t)
	clear(private)
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
	proof, err := keys.ConfirmPoP(challenge, "https://example.test", session, directSourcePoPScopeOKV2)
	if err != nil {
		t.Fatal(err)
	}
	executor := &directSourcePoPLaneExecutorV2{available: true, started: make(chan transport.DirectManagedSourcePoPChallengeV2, 16), result: proof}
	d := &Daemon{Log: slog.Default(), directManagedSourcePrepareV2: &directSourcePrepareLaneExecutorV2{available: true}, directManagedSourcePoPV2: executor, curConn: socket, nativeConn: native, writeTimeout: time.Second}
	proxy := &NativeWorkerProxy{connection: native, done: make(chan struct{})}
	link := &nativeWorkerLink{conn: socket, proxy: proxy}
	d.nativeWorkers = map[string]*nativeWorkerLink{challenge.Prepare.Subject.InstanceID.String(): link}
	executor.token = &nativeWorkerPublicationToken{instanceID: challenge.Prepare.Subject.InstanceID.String(), link: link, proxy: proxy}
	lane := newDirectManagedSourcePoPConnectionV2(d, socket, native, &directManagedSourcePoPNegotiationV2{socket: socket, native: native, session: session})
	t.Cleanup(lane.close)
	return d, lane, peer, executor, challenge
}

func directSourcePoPLaneFailureV2(t *testing.T, peer *websocket.Conn, command transport.DirectManagedSourcePoPChallengeV2) {
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
	var fields map[string]json.RawMessage
	if json.Unmarshal(env.Payload, &outer) != nil || json.Unmarshal(env.Payload, &fields) != nil || len(fields) != 3 || outer.CommandID != command.ChallengeID || outer.Error != transport.DirectManagedSourcePoPFailureV2 {
		t.Fatalf("invalid outer ACK: %s", env.Payload)
	}
	if _, err := transport.DecodeDirectManagedSourcePoPFailureACKV2(outer.Result, command.ChallengeID); err != nil {
		t.Fatalf("invalid bounded failure: %s", outer.Result)
	}

}

func TestDirectManagedSourcePoPLaneSerialAndSanitizedFailureV2(t *testing.T) {
	_, lane, peer, executor, command := directSourcePoPLaneFixtureV2(t, true)
	executor.release = make(chan struct{})
	executor.result = nil
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoPV2, command))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("executor did not start")
	}
	second := command
	second.ChallengeID = domain.NewID()
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoPV2, second))
	select {
	case <-executor.started:
		t.Fatal("proof commands ran concurrently")
	default:
	}
	close(executor.release)
	directSourcePoPLaneFailureV2(t, peer, command)
	directSourcePoPLaneFailureV2(t, peer, second)
	select {
	case got := <-executor.started:
		if got.ChallengeID != second.ChallengeID {
			t.Fatal("wrong queued command")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("queued command did not run")
	}
}

func TestDirectManagedSourcePoPLaneQueueSaturationV2(t *testing.T) {
	_, lane, peer, executor, command := directSourcePoPLaneFixtureV2(t, true)
	executor.release = make(chan struct{})
	executor.finished = make(chan struct{}, 8)
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoPV2, command))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("executor did not start")
	}
	for i := 1; i <= 8; i++ {
		command.ChallengeID = domain.NewID()
		lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoPV2, command))
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

func TestDirectManagedSourcePoPLaneExactScopeSupersessionV2(t *testing.T) {
	for _, reason := range []string{"socket", "connection", "session"} {
		t.Run(reason, func(t *testing.T) {
			d, lane, peer, executor, command := directSourcePoPLaneFixtureV2(t, true)
			executor.release = make(chan struct{})
			executor.finished = make(chan struct{}, 8)
			lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoPV2, command))
			select {
			case <-executor.started:
			case <-time.After(3 * time.Second):
				t.Fatal("executor did not start")
			}
			command.ChallengeID = domain.NewID()
			lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoPV2, command))
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

func TestDirectManagedSourcePoPLaneBeforeHostSessionDropsV2(t *testing.T) {
	_, lane, peer, executor, command := directSourcePoPLaneFixtureV2(t, true)
	lane.native.mu.Lock()
	lane.native.session = nil
	lane.native.mu.Unlock()
	raw, err := command.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !lane.handle(transport.Envelope{Type: transport.MsgDirectManagedSourcePoPV2, Payload: raw}) {
		t.Fatal("PoP escaped dedicated lane")
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

func TestDirectManagedSourcePoPLaneRechecksBeforeACKV2(t *testing.T) {
	_, lane, peer, executor, command := directSourcePoPLaneFixtureV2(t, true)
	session, err := lane.native.AuthenticatedNativeHostSession()
	if err != nil {
		t.Fatal(err)
	}
	ack := executor.result
	executor.publicationError = errors.New("owner revoked while writer waited")
	lane.ack(ack, session, command)
	_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("success ACK published after verifier rejection")
	}
}

func TestDirectManagedSourcePoPLaneIdempotentRetryV2(t *testing.T) {
	_, lane, peer, executor, command := directSourcePoPLaneFixtureV2(t, true)
	expected := append([]byte(nil), executor.result...)
	for i := 0; i < 2; i++ {
		lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoPV2, command))
		_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
		var env transport.Envelope
		if err := peer.ReadJSON(&env); err != nil {
			t.Fatal(err)
		}
		var outer struct {
			CommandID domain.ID       `json:"commandId"`
			Error     string          `json:"error"`
			Result    json.RawMessage `json:"result"`
		}
		var fields map[string]json.RawMessage
		if env.Type != transport.MsgCommandAck || json.Unmarshal(env.Payload, &outer) != nil || json.Unmarshal(env.Payload, &fields) != nil || len(fields) != 3 || outer.CommandID != command.ChallengeID || outer.Error != "" || !bytes.Equal(expected, outer.Result) {
			t.Fatalf("invalid proof ACK: %s", env.Payload)
		}
		if proof, err := transport.DecodeDirectManagedSourcePoPProofV2(outer.Result); err != nil || proof.ChallengeID != command.ChallengeID {
			t.Fatal("invalid proof", err)
		}
	}
}

func TestDirectManagedSourcePoPLaneBlockedWriterSupersessionV2(t *testing.T) {
	d, lane, peer, executor, command := directSourcePoPLaneFixtureV2(t, true)
	session, err := lane.native.AuthenticatedNativeHostSession()
	if err != nil {
		t.Fatal(err)
	}
	d.writeMu.Lock()
	started, finished := make(chan struct{}), make(chan struct{})
	go func() { close(started); lane.ack(executor.result, session, command); close(finished) }()
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
	_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("superseded writer published proof")
	}
}

func TestDirectManagedSourcePoPLaneRejectsUntrustedResultV2(t *testing.T) {
	for _, reason := range []string{"malformed", "wrong-challenge", "wrong-transcript", "failure-wrong-challenge"} {
		t.Run(reason, func(t *testing.T) {
			_, lane, peer, executor, command := directSourcePoPLaneFixtureV2(t, true)
			session, err := lane.native.AuthenticatedNativeHostSession()
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte(`{"private":"diagnostic"}`)
			if reason == "wrong-challenge" {
				proof, _ := transport.DecodeDirectManagedSourcePoPProofV2(executor.result)
				proof.ChallengeID = domain.NewID()
				raw, _ = proof.CanonicalBytes()
			} else if reason == "wrong-transcript" {
				proof, _ := transport.DecodeDirectManagedSourcePoPProofV2(executor.result)
				proof.TranscriptHash = command.Nonce
				raw, _ = proof.CanonicalBytes()
			} else if reason == "failure-wrong-challenge" {
				wrong := command
				wrong.ChallengeID = domain.NewID()
				raw = directManagedSourcePoPFailureV2(wrong)
			}
			lane.ack(raw, session, command)
			_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			if _, _, err := peer.ReadMessage(); err == nil {
				t.Fatal("untrusted result escaped")
			}
		})
	}
}

func TestDirectManagedSourcePoPLaneCloseCancelsProofV2(t *testing.T) {
	_, lane, peer, executor, command := directSourcePoPLaneFixtureV2(t, true)
	executor.canceled = make(chan struct{})
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoPV2, command))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("proof did not start")
	}
	lane.close()
	select {
	case <-executor.canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("close did not cancel proof")
	}
	_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("closed lane published ACK")
	}
}

func TestDirectManagedSourcePoPLaneVerifiedWorkerPublicationV2(t *testing.T) {
	for _, mutation := range []string{"unchanged", "worker replacement", "ownership mutation", "proxy close"} {
		t.Run(mutation, func(t *testing.T) {
			d, lane, peer, executor, command := directSourcePoPLaneFixtureV2(t, true)
			session, err := lane.native.AuthenticatedNativeHostSession()
			if err != nil {
				t.Fatal(err)
			}
			executor.beforePublication = func() {
				token := executor.token
				switch mutation {
				case "worker replacement":
					d.nativeWorkersMu.Lock()
					d.nativeWorkers[token.instanceID] = &nativeWorkerLink{conn: lane.socket, proxy: token.proxy, ownership: token.ownership}
					d.nativeWorkersMu.Unlock()
				case "ownership mutation":
					token.link.mu.Lock()
					token.link.ownership.State = "retired"
					token.link.mu.Unlock()
				case "proxy close":
					if err := token.proxy.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			lane.ack(executor.result, session, command)
			// ACK publication has completed synchronously. Closing its socket
			// makes absence observable without waiting for a scheduling timeout.
			if err := lane.socket.Close(); err != nil {
				t.Fatal(err)
			}
			_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
			var env transport.Envelope
			err = peer.ReadJSON(&env)
			if mutation != "unchanged" {
				if err == nil {
					t.Fatal("stale verified worker published proof")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var outer struct {
				CommandID domain.ID       `json:"commandId"`
				Error     string          `json:"error"`
				Result    json.RawMessage `json:"result"`
			}
			if env.Type != transport.MsgCommandAck || json.Unmarshal(env.Payload, &outer) != nil || outer.CommandID != command.ChallengeID || outer.Error != "" || !bytes.Equal(outer.Result, executor.result) {
				t.Fatalf("unchanged verified worker did not publish exact proof: %s", env.Payload)
			}
		})
	}
}

func TestDirectManagedSourcePoPLaneCapturedNegotiationV2(t *testing.T) {
	for _, reason := range []string{"missing", "socket", "native", "session", "prepare", "pop", "duplicate", "v1"} {
		t.Run(reason, func(t *testing.T) {
			d, lane, _, _, _ := directSourcePoPLaneFixtureV2(t, true)
			n := *lane.negotiation
			switch reason {
			case "missing":
				if newDirectManagedSourcePoPConnectionV2(d, lane.socket, lane.native, nil) != nil {
					t.Fatal("missing negotiation accepted")
				}
				return
			case "socket":
				n.socket = nil
			case "native":
				n.native = NewNativeObservationConnection("https://example.test", "", "", nil)
			case "session":
				n.session.NativeAdmissionID = domain.NewID().String()
			default:
				features := []string{transport.NativeObservationReceiptProtocol}
				if reason != "prepare" {
					features = append(features, transport.DirectManagedSourcePrepareProtocolV2)
				}
				if reason != "pop" {
					features = append(features, transport.DirectManagedSourcePoPProtocolV2)
				}
				if reason == "duplicate" {
					features = append(features, transport.DirectManagedSourcePoPProtocolV2)
				}
				if reason == "v1" {
					features = []string{transport.NativeObservationReceiptProtocol, transport.DirectManagedSourcePrepareProtocol, transport.DirectManagedSourcePoPProtocol}
				}
				lane.native.mu.Lock()
				lane.native.session.ProtocolFeatures = features
				lane.native.mu.Unlock()
				n.session.ProtocolFeatures = features
			}
			if newDirectManagedSourcePoPConnectionV2(d, lane.socket, lane.native, &n) != nil {
				t.Fatal("invalid captured negotiation accepted")
			}
		})
	}
}

func TestDirectManagedSourcePoPLaneMalformedAndNoFallbackV2(t *testing.T) {
	d, lane, peer, executor, command := directSourcePoPLaneFixtureV2(t, true)
	for _, raw := range []string{`{}`, `{"protocolVersion":"direct_managed_source_host_custody_pop_v1"}`, `{"challengeId":"x","challengeId":"y"}`} {
		if !lane.handle(transport.Envelope{Type: transport.MsgDirectManagedSourcePoPV2, Payload: json.RawMessage(raw)}) {
			t.Fatal("malformed challenge escaped")
		}
	}
	// A valid V1 transcript shares the message type but cannot reach this executor.
	_, old, _, private := directSourcePoPFixture(t)
	clear(private)
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoP, old))
	// Generic command handling is deliberately not wired to this dormant lane.
	d.handleCommand(nil, nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoPV2, command))
	lane.close()
	select {
	case <-executor.started:
		t.Fatal("command reached dormant executor")
	default:
	}
	_ = lane.socket.Close()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("malformed input produced ACK")
	}
}

func TestDirectManagedSourcePoPLaneWriteFailureInvalidatesSocketV2(t *testing.T) {
	d, lane, _, executor, command := directSourcePoPLaneFixtureV2(t, true)
	session, _ := lane.native.AuthenticatedNativeHostSession()
	_ = lane.socket.Close()
	lane.ack(executor.result, session, command)
	d.connMu.Lock()
	current := d.curConn
	d.connMu.Unlock()
	if current == lane.socket {
		t.Fatal("failed writer remains current")
	}
}

func TestDirectManagedSourcePoPLaneCopiesNegotiationV2(t *testing.T) {
	d, original, _, _, _ := directSourcePoPLaneFixtureV2(t, true)
	session, _ := original.native.AuthenticatedNativeHostSession()
	n := &directManagedSourcePoPNegotiationV2{socket: original.socket, native: original.native, session: session}
	lane := newDirectManagedSourcePoPConnectionV2(d, original.socket, original.native, n)
	if lane == nil {
		t.Fatal("valid negotiation rejected")
	}
	defer lane.close()
	n.session.NativeAdmissionID = domain.NewID().String()
	n.session.ProtocolFeatures[1] = transport.DirectManagedSourcePrepareProtocol
	n.socket = nil
	if !lane.negotiation.valid() {
		t.Fatal("caller mutation changed captured negotiation")
	}
}
