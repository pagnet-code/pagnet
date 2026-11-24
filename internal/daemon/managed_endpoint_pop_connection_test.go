//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

type managedPoPLaneExecutor struct {
	available         bool
	publicationError  error
	token             *nativeWorkerPublicationToken
	beforePublication func()
	started           chan transport.ManagedEndpointPoPChallenge
	release           chan struct{}
	finished          chan struct{}
	canceled          chan struct{}
	result            []byte
}

func (e *managedPoPLaneExecutor) verifyPoPPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.ManagedEndpointPoPChallenge) (*nativeWorkerPublicationToken, error) {
	if e.beforePublication != nil {
		e.beforePublication()
	}
	return e.token, e.publicationError
}
func (e *managedPoPLaneExecutor) ready() bool { return e.available }
func (e *managedPoPLaneExecutor) confirmPoP(ctx context.Context, _ *websocket.Conn, _ *NativeObservationConnection, _ transport.HostSessionPayload, _ string, command transport.ManagedEndpointPoPChallenge) ([]byte, error) {
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

func managedPoPLaneFixture(t *testing.T, feature bool) (*Daemon, *managedEndpointPoPConnection, *websocket.Conn, *managedPoPLaneExecutor, transport.ManagedEndpointPoPChallenge) {
	t.Helper()

	keys, challenge, session, private := managedPoPStoreFixture(t, false)
	clear(private)
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.ManagedEndpointPrepareProtocol}
	if feature {
		session.ProtocolFeatures = append(session.ProtocolFeatures, transport.ManagedEndpointPoPProtocol)
	}
	socket, peer := nativeBindingSocketPair(t)
	native := NewNativeObservationConnection("https://example.test", session.HostID, session.BootID, nil)
	native.offeredManagedEndpointPrepare = true
	native.offeredManagedEndpointPoP = true
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	proof, err := keys.confirmPoP(challenge, "https://example.test", session, managedPrepareScopeOK)
	if err != nil {
		t.Fatal(err)
	}
	executor := &managedPoPLaneExecutor{available: true, started: make(chan transport.ManagedEndpointPoPChallenge, 16), result: proof}
	d := &Daemon{Config: Config{ManagedEndpointPrepareEnabled: true, ManagedEndpointPoPEnabled: true}, managedEndpointPrepare: &managedPrepareLaneExecutor{available: true}, managedEndpointPoP: executor, curConn: socket, nativeConn: native, writeTimeout: time.Second}
	proxy := &NativeWorkerProxy{connection: native, done: make(chan struct{})}
	link := &nativeWorkerLink{conn: socket, proxy: proxy}
	d.nativeWorkers = map[string]*nativeWorkerLink{challenge.Prepare.Subject.InstanceID.String(): link}
	executor.token = &nativeWorkerPublicationToken{instanceID: challenge.Prepare.Subject.InstanceID.String(), link: link, proxy: proxy}
	lane := newManagedEndpointPoPConnection(d, socket, native)
	t.Cleanup(lane.close)
	return d, lane, peer, executor, challenge
}

func managedPoPLaneFailure(t *testing.T, peer *websocket.Conn, command transport.ManagedEndpointPoPChallenge) {
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
	if json.Unmarshal(env.Payload, &outer) != nil || json.Unmarshal(env.Payload, &fields) != nil || len(fields) != 3 || outer.CommandID != command.ChallengeID || outer.Error != transport.ManagedEndpointPoPFailure {
		t.Fatalf("invalid outer ACK: %s", env.Payload)
	}
	if _, err := transport.DecodeManagedEndpointPoPFailureACK(outer.Result, command.ChallengeID); err != nil {
		t.Fatalf("invalid bounded failure: %s", outer.Result)
	}

}

func TestManagedEndpointPoPLaneReadinessRequiresOptIn(t *testing.T) {
	executor := &managedPoPLaneExecutor{available: true}
	d := &Daemon{Config: Config{ManagedEndpointPrepareEnabled: true}, managedEndpointPrepare: &managedPrepareLaneExecutor{available: true}, managedEndpointPoP: executor}
	if d.managedEndpointPoPReady() {
		t.Fatal("default configuration enabled PoP")
	}
	d.ManagedEndpointPoPEnabled = true
	if !d.managedEndpointPoPReady() {
		t.Fatal("enabled ready executor was unavailable")
	}
	executor.available = false
	if d.managedEndpointPoPReady() {
		t.Fatal("unready executor advertised PoP")
	}
	d.managedEndpointPoP = nil
	if d.managedEndpointPoPReady() {
		t.Fatal("missing executor advertised PoP")
	}
}

func TestManagedEndpointPoPLaneCapabilityAndMalformed(t *testing.T) {
	for _, reason := range []string{"feature", "offer", "gate", "unready", "prepare-unready", "prepare-feature", "prepare-offer"} {
		t.Run(reason, func(t *testing.T) {
			d, lane, peer, executor, command := managedPoPLaneFixture(t, reason != "feature")
			switch reason {
			case "prepare-unready":
				d.managedEndpointPrepare = nil
			case "prepare-feature":
				lane.native.mu.Lock()
				lane.native.session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.ManagedEndpointPoPProtocol}
				lane.native.mu.Unlock()
			case "prepare-offer":
				lane.native.offeredManagedEndpointPrepare = false
			case "offer":
				lane.native.offeredManagedEndpointPoP = false
			case "gate":
				d.ManagedEndpointPoPEnabled = false
			case "unready":
				executor.available = false
			}
			if lane.handle(transport.Envelope{Type: "unrelated"}) {
				t.Fatal("lane consumed an unrelated command")
			}
			for _, raw := range []string{`{}`, `{"commandId":null}`, `{"CommandId":"x"}`, `{"commandId":"x","commandId":"y"}`} {
				if !lane.handle(transport.Envelope{Type: transport.MsgManagedEndpointPoP, Payload: json.RawMessage(raw)}) {
					t.Fatal("lane did not consume malformed prepare")
				}
			}
			env := nativeBindingEnvelope(t, transport.MsgManagedEndpointPoP, command)
			d.handleCommand(nil, env)
			lane.handle(env)
			managedPoPLaneFailure(t, peer, command)
			select {
			case <-executor.started:
				t.Fatal("rejected or generic command reached proof executor")
			default:
			}
		})
	}
}

func TestManagedEndpointPoPLaneSerialAndSanitizedFailure(t *testing.T) {
	_, lane, peer, executor, command := managedPoPLaneFixture(t, true)
	executor.release = make(chan struct{})
	executor.result = nil
	lane.handle(nativeBindingEnvelope(t, transport.MsgManagedEndpointPoP, command))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("executor did not start")
	}
	second := command
	second.ChallengeID = domain.NewID()
	lane.handle(nativeBindingEnvelope(t, transport.MsgManagedEndpointPoP, second))
	select {
	case <-executor.started:
		t.Fatal("proof commands ran concurrently")
	default:
	}
	close(executor.release)
	managedPoPLaneFailure(t, peer, command)
	managedPoPLaneFailure(t, peer, second)
	select {
	case got := <-executor.started:
		if got.ChallengeID != second.ChallengeID {
			t.Fatal("wrong queued command")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("queued command did not run")
	}
}

func TestManagedEndpointPoPLaneQueueSaturation(t *testing.T) {
	_, lane, peer, executor, command := managedPoPLaneFixture(t, true)
	executor.release = make(chan struct{})
	executor.finished = make(chan struct{}, 8)
	lane.handle(nativeBindingEnvelope(t, transport.MsgManagedEndpointPoP, command))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("executor did not start")
	}
	for i := 1; i <= 8; i++ {
		command.ChallengeID = domain.NewID()
		lane.handle(nativeBindingEnvelope(t, transport.MsgManagedEndpointPoP, command))
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

func TestManagedEndpointPoPLaneExactScopeSupersession(t *testing.T) {
	for _, reason := range []string{"socket", "connection", "session"} {
		t.Run(reason, func(t *testing.T) {
			d, lane, peer, executor, command := managedPoPLaneFixture(t, true)
			executor.release = make(chan struct{})
			executor.finished = make(chan struct{}, 8)
			lane.handle(nativeBindingEnvelope(t, transport.MsgManagedEndpointPoP, command))
			select {
			case <-executor.started:
			case <-time.After(3 * time.Second):
				t.Fatal("executor did not start")
			}
			command.ChallengeID = domain.NewID()
			lane.handle(nativeBindingEnvelope(t, transport.MsgManagedEndpointPoP, command))
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

func TestManagedEndpointPoPLaneOfferReadiness(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, ready := range []bool{false, true} {
			d := &Daemon{Config: Config{ServerURL: "https://example.test?managed_endpoint_pop=wrong&managed_endpoint_pop=wrong", ManagedEndpointPrepareEnabled: true, ManagedEndpointPoPEnabled: enabled}, managedEndpointPrepare: &managedPrepareLaneExecutor{available: true}, managedEndpointPoP: &managedPoPLaneExecutor{available: ready}}
			u, err := url.Parse(d.wsURL(context.Background()))
			if err != nil {
				t.Fatal(err)
			}
			values := u.Query()["managed_endpoint_pop"]
			if enabled && ready {
				if len(values) != 1 || values[0] != transport.ManagedEndpointPoPProtocol {
					t.Fatalf("incorrect offer: %v", values)
				}
			} else if len(values) != 0 {
				t.Fatalf("unready offer: %v", values)
			}
		}
	}
}

func TestManagedEndpointPoPLaneBeforeHostSessionDrops(t *testing.T) {
	_, lane, peer, executor, command := managedPoPLaneFixture(t, true)
	lane.native.mu.Lock()
	lane.native.session = nil
	lane.native.mu.Unlock()
	raw, err := command.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !lane.handle(transport.Envelope{Type: transport.MsgManagedEndpointPoP, Payload: raw}) {
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

func TestManagedEndpointPoPLaneRechecksBeforeACK(t *testing.T) {
	_, lane, peer, executor, command := managedPoPLaneFixture(t, true)
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

func TestManagedEndpointPoPLaneIdempotentRetry(t *testing.T) {
	_, lane, peer, executor, command := managedPoPLaneFixture(t, true)
	expected := append([]byte(nil), executor.result...)
	for i := 0; i < 2; i++ {
		lane.handle(nativeBindingEnvelope(t, transport.MsgManagedEndpointPoP, command))
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
		if proof, err := transport.DecodeManagedEndpointPoPProof(outer.Result); err != nil || proof.ChallengeID != command.ChallengeID {
			t.Fatal("invalid proof", err)
		}
	}
}

func TestManagedEndpointPoPLaneBlockedWriterSupersession(t *testing.T) {
	d, lane, peer, executor, command := managedPoPLaneFixture(t, true)
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

func TestManagedEndpointPoPLaneRejectsUntrustedResult(t *testing.T) {
	for _, reason := range []string{"malformed", "wrong-challenge", "failure-wrong-challenge"} {
		t.Run(reason, func(t *testing.T) {
			_, lane, peer, executor, command := managedPoPLaneFixture(t, true)
			session, err := lane.native.AuthenticatedNativeHostSession()
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte(`{"private":"diagnostic"}`)
			if reason == "wrong-challenge" {
				proof, _ := transport.DecodeManagedEndpointPoPProof(executor.result)
				proof.ChallengeID = domain.NewID()
				raw, _ = proof.CanonicalBytes()
			} else if reason == "failure-wrong-challenge" {
				wrong := command
				wrong.ChallengeID = domain.NewID()
				raw = managedPoPFailure(wrong)
			}
			lane.ack(raw, session, command)
			_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			if _, _, err := peer.ReadMessage(); err == nil {
				t.Fatal("untrusted result escaped")
			}
		})
	}
}

func TestManagedEndpointPoPLaneNegotiation(t *testing.T) {
	for _, reason := range []string{"unsolicited", "duplicate", "missing-prepare"} {
		t.Run(reason, func(t *testing.T) {
			_, lane, _, _, _ := managedPoPLaneFixture(t, true)
			session, err := lane.native.AuthenticatedNativeHostSession()
			if err != nil {
				t.Fatal(err)
			}
			native := NewNativeObservationConnection("https://example.test", session.HostID, session.BootID, nil)
			native.offeredManagedEndpointPrepare = true
			native.offeredManagedEndpointPoP = reason != "unsolicited"
			if reason == "duplicate" {
				session.ProtocolFeatures = append(session.ProtocolFeatures, transport.ManagedEndpointPoPProtocol)
			}
			if reason == "missing-prepare" {
				session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.ManagedEndpointPoPProtocol}
			}
			if err := native.Admit(session); err == nil {
				t.Fatal("invalid PoP negotiation admitted")
			}
		})
	}
}

func TestManagedEndpointPoPLaneCloseCancelsProof(t *testing.T) {
	_, lane, peer, executor, command := managedPoPLaneFixture(t, true)
	executor.canceled = make(chan struct{})
	lane.handle(nativeBindingEnvelope(t, transport.MsgManagedEndpointPoP, command))
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

func TestManagedEndpointPoPLaneStartupReadiness(t *testing.T) {
	f := newManagedPrepareVerifierFixture(t)
	d := f.d
	d.Config = Config{StateDir: filepath.Dir(d.nativeRegistry.root), ManagedEndpointPrepareEnabled: true}
	d.Log = discardLog()
	release, err := d.acquireServeLock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	d.initManagedEndpointKeys()
	d.initManagedEndpointPrepare()
	if d.managedEndpointPoPReady() || d.managedEndpointPoP != nil {
		t.Fatal("PoP initialized without opt-in")
	}
	d.ManagedEndpointPoPEnabled = true
	d.initManagedEndpointPrepare()
	if !d.managedEndpointPoPReady() {
		t.Fatal("closed prerequisites unavailable")
	}
	for _, table := range []string{"native_managed_endpoint_keys", "native_managed_endpoint_prepare_commands", "native_managed_endpoint_pop_challenges"} {
		var count int
		if err := d.nativeRegistry.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("readiness mutated %s: count=%d err=%v", table, count, err)
		}
	}
	if err := d.serveLockFile.Close(); err != nil {
		t.Fatal(err)
	}
	if d.managedEndpointPoPReady() {
		t.Fatal("ready with closed serve lock")
	}
}

func TestManagedEndpointPoPLaneVerifiedWorkerPublication(t *testing.T) {
	for _, mutation := range []string{"unchanged", "worker replacement", "ownership mutation", "proxy close"} {
		t.Run(mutation, func(t *testing.T) {
			d, lane, peer, executor, command := managedPoPLaneFixture(t, true)
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
