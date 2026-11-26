//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

type directSourcePoPLaneExecutor struct {
	available         bool
	publicationError  error
	token             *nativeWorkerPublicationToken
	beforePublication func()
	started           chan transport.DirectManagedSourcePoPChallenge
	release           chan struct{}
	finished          chan struct{}
	canceled          chan struct{}
	result            []byte
}

func (e *directSourcePoPLaneExecutor) verifyPoPPublication(context.Context, *websocket.Conn, *NativeObservationConnection, transport.HostSessionPayload, string, transport.DirectManagedSourcePoPChallenge) (*nativeWorkerPublicationToken, error) {
	if e.beforePublication != nil {
		e.beforePublication()
	}
	return e.token, e.publicationError
}
func (e *directSourcePoPLaneExecutor) ready() bool { return e.available }
func (e *directSourcePoPLaneExecutor) confirmPoP(ctx context.Context, _ *websocket.Conn, _ *NativeObservationConnection, _ transport.HostSessionPayload, _ string, command transport.DirectManagedSourcePoPChallenge) ([]byte, error) {
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

func directSourcePoPLaneFixture(t *testing.T, feature bool) (*Daemon, *directManagedSourcePoPConnection, *websocket.Conn, *directSourcePoPLaneExecutor, transport.DirectManagedSourcePoPChallenge) {
	t.Helper()

	keys, challenge, session, private := directSourcePoPFixture(t)
	clear(private)
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.DirectManagedSourcePrepareProtocol}
	if feature {
		session.ProtocolFeatures = append(session.ProtocolFeatures, transport.DirectManagedSourcePoPProtocol)
	}
	socket, peer := nativeBindingSocketPair(t)
	native := NewNativeObservationConnection("https://example.test", session.HostID, session.BootID, nil)
	native.offeredDirectManagedSourcePrepare = true
	native.offeredDirectManagedSourcePoP = true
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	proof, err := keys.ConfirmPoP(challenge, "https://example.test", session, directSourcePoPScopeOK)
	if err != nil {
		t.Fatal(err)
	}
	executor := &directSourcePoPLaneExecutor{available: true, started: make(chan transport.DirectManagedSourcePoPChallenge, 16), result: proof}
	d := &Daemon{Config: Config{DirectManagedSourcePrepareEnabled: true, DirectManagedSourcePoPEnabled: true}, directManagedSourcePrepare: &directSourcePrepareLaneExecutor{available: true}, directManagedSourcePoP: executor, curConn: socket, nativeConn: native, writeTimeout: time.Second}
	proxy := &NativeWorkerProxy{connection: native, done: make(chan struct{}), abortDone: make(chan struct{})}
	link := &nativeWorkerLink{conn: socket, proxy: proxy}
	d.nativeWorkers = map[string]*nativeWorkerLink{challenge.Prepare.Subject.InstanceID.String(): link}
	executor.token = &nativeWorkerPublicationToken{instanceID: challenge.Prepare.Subject.InstanceID.String(), link: link, proxy: proxy}
	lane := newDirectManagedSourcePoPConnection(d, socket, native)
	t.Cleanup(lane.close)
	return d, lane, peer, executor, challenge
}

func directSourcePoPLaneFailure(t *testing.T, peer *websocket.Conn, command transport.DirectManagedSourcePoPChallenge) {
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
	if json.Unmarshal(env.Payload, &outer) != nil || json.Unmarshal(env.Payload, &fields) != nil || len(fields) != 3 || outer.CommandID != command.ChallengeID || outer.Error != transport.DirectManagedSourcePoPFailure {
		t.Fatalf("invalid outer ACK: %s", env.Payload)
	}
	if _, err := transport.DecodeDirectManagedSourcePoPFailureACK(outer.Result, command.ChallengeID); err != nil {
		t.Fatalf("invalid bounded failure: %s", outer.Result)
	}

}

func TestDirectManagedSourcePoPLaneReadinessRequiresOptIn(t *testing.T) {
	executor := &directSourcePoPLaneExecutor{available: true}
	d := &Daemon{Config: Config{DirectManagedSourcePrepareEnabled: true}, directManagedSourcePrepare: &directSourcePrepareLaneExecutor{available: true}, directManagedSourcePoP: executor}
	if d.directManagedSourcePoPReady() {
		t.Fatal("default configuration enabled PoP")
	}
	d.DirectManagedSourcePoPEnabled = true
	if !d.directManagedSourcePoPReady() {
		t.Fatal("enabled ready executor was unavailable")
	}
	executor.available = false
	if d.directManagedSourcePoPReady() {
		t.Fatal("unready executor advertised PoP")
	}
	d.directManagedSourcePoP = nil
	if d.directManagedSourcePoPReady() {
		t.Fatal("missing executor advertised PoP")
	}
}

func TestDirectManagedSourcePoPLaneCapabilityAndMalformed(t *testing.T) {
	for _, reason := range []string{"feature", "offer", "gate", "unready", "prepare-unready", "prepare-feature", "prepare-offer"} {
		t.Run(reason, func(t *testing.T) {
			d, lane, peer, executor, command := directSourcePoPLaneFixture(t, reason != "feature")
			switch reason {
			case "prepare-unready":
				d.directManagedSourcePrepare = nil
			case "prepare-feature":
				lane.native.mu.Lock()
				lane.native.session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.DirectManagedSourcePoPProtocol}
				lane.native.mu.Unlock()
			case "prepare-offer":
				lane.native.offeredDirectManagedSourcePrepare = false
			case "offer":
				lane.native.offeredDirectManagedSourcePoP = false
			case "gate":
				d.DirectManagedSourcePoPEnabled = false
			case "unready":
				executor.available = false
			}
			if lane.handle(transport.Envelope{Type: "unrelated"}) {
				t.Fatal("lane consumed an unrelated command")
			}
			for _, raw := range []string{`{}`, `{"commandId":null}`, `{"CommandId":"x"}`, `{"commandId":"x","commandId":"y"}`} {
				if !lane.handle(transport.Envelope{Type: transport.MsgDirectManagedSourcePoP, Payload: json.RawMessage(raw)}) {
					t.Fatal("lane did not consume malformed prepare")
				}
			}
			env := nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoP, command)
			d.handleCommand(nil, env)
			lane.handle(env)
			directSourcePoPLaneFailure(t, peer, command)
			select {
			case <-executor.started:
				t.Fatal("rejected or generic command reached proof executor")
			default:
			}
		})
	}
}

func TestDirectManagedSourcePoPLaneSerialAndSanitizedFailure(t *testing.T) {
	_, lane, peer, executor, command := directSourcePoPLaneFixture(t, true)
	executor.release = make(chan struct{})
	executor.result = nil
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoP, command))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("executor did not start")
	}
	second := command
	second.ChallengeID = domain.NewID()
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoP, second))
	select {
	case <-executor.started:
		t.Fatal("proof commands ran concurrently")
	default:
	}
	close(executor.release)
	directSourcePoPLaneFailure(t, peer, command)
	directSourcePoPLaneFailure(t, peer, second)
	select {
	case got := <-executor.started:
		if got.ChallengeID != second.ChallengeID {
			t.Fatal("wrong queued command")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("queued command did not run")
	}
}

func TestDirectManagedSourcePoPLaneQueueSaturation(t *testing.T) {
	_, lane, peer, executor, command := directSourcePoPLaneFixture(t, true)
	executor.release = make(chan struct{})
	executor.finished = make(chan struct{}, 8)
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoP, command))
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("executor did not start")
	}
	for i := 1; i <= 8; i++ {
		command.ChallengeID = domain.NewID()
		lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoP, command))
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

func TestDirectManagedSourcePoPLaneExactScopeSupersession(t *testing.T) {
	for _, reason := range []string{"socket", "connection", "session"} {
		t.Run(reason, func(t *testing.T) {
			d, lane, peer, executor, command := directSourcePoPLaneFixture(t, true)
			executor.release = make(chan struct{})
			executor.finished = make(chan struct{}, 8)
			lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoP, command))
			select {
			case <-executor.started:
			case <-time.After(3 * time.Second):
				t.Fatal("executor did not start")
			}
			command.ChallengeID = domain.NewID()
			lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoP, command))
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

func TestDirectManagedSourcePoPLaneOfferReadiness(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, ready := range []bool{false, true} {
			d := &Daemon{Config: Config{ServerURL: "https://example.test?direct_managed_source_pop=wrong&direct_managed_source_pop=wrong", DirectManagedSourcePrepareEnabled: true, DirectManagedSourcePoPEnabled: enabled}, directManagedSourcePrepare: &directSourcePrepareLaneExecutor{available: true}, directManagedSourcePoP: &directSourcePoPLaneExecutor{available: ready}}
			u, err := url.Parse(d.wsURL(context.Background()))
			if err != nil {
				t.Fatal(err)
			}
			values := u.Query()["direct_managed_source_pop"]
			if enabled && ready {
				if len(values) != 1 || values[0] != transport.DirectManagedSourcePoPProtocol {
					t.Fatalf("incorrect offer: %v", values)
				}
			} else if len(values) != 0 {
				t.Fatalf("unready offer: %v", values)
			}
		}
	}
}

func TestDirectManagedSourcePoPLaneBeforeHostSessionDrops(t *testing.T) {
	_, lane, peer, executor, command := directSourcePoPLaneFixture(t, true)
	lane.native.mu.Lock()
	lane.native.session = nil
	lane.native.mu.Unlock()
	raw, err := command.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !lane.handle(transport.Envelope{Type: transport.MsgDirectManagedSourcePoP, Payload: raw}) {
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

func TestDirectManagedSourcePoPLaneRechecksBeforeACK(t *testing.T) {
	_, lane, peer, executor, command := directSourcePoPLaneFixture(t, true)
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

func TestDirectManagedSourcePoPLaneIdempotentRetry(t *testing.T) {
	_, lane, peer, executor, command := directSourcePoPLaneFixture(t, true)
	expected := append([]byte(nil), executor.result...)
	for i := 0; i < 2; i++ {
		lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoP, command))
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
		if proof, err := transport.DecodeDirectManagedSourcePoPProof(outer.Result); err != nil || proof.ChallengeID != command.ChallengeID {
			t.Fatal("invalid proof", err)
		}
	}
}

func TestDirectManagedSourcePoPLaneBlockedWriterSupersession(t *testing.T) {
	d, lane, peer, executor, command := directSourcePoPLaneFixture(t, true)
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

func TestDirectManagedSourcePoPLaneRejectsUntrustedResult(t *testing.T) {
	for _, reason := range []string{"malformed", "wrong-challenge", "failure-wrong-challenge"} {
		t.Run(reason, func(t *testing.T) {
			_, lane, peer, executor, command := directSourcePoPLaneFixture(t, true)
			session, err := lane.native.AuthenticatedNativeHostSession()
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte(`{"private":"diagnostic"}`)
			if reason == "wrong-challenge" {
				proof, _ := transport.DecodeDirectManagedSourcePoPProof(executor.result)
				proof.ChallengeID = domain.NewID()
				raw, _ = proof.CanonicalBytes()
			} else if reason == "failure-wrong-challenge" {
				wrong := command
				wrong.ChallengeID = domain.NewID()
				raw = directManagedSourcePoPFailure(wrong)
			}
			lane.ack(raw, session, command)
			_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			if _, _, err := peer.ReadMessage(); err == nil {
				t.Fatal("untrusted result escaped")
			}
		})
	}
}

func TestDirectManagedSourcePoPLaneNegotiation(t *testing.T) {
	for _, reason := range []string{"unsolicited", "duplicate", "missing-prepare"} {
		t.Run(reason, func(t *testing.T) {
			_, lane, _, _, _ := directSourcePoPLaneFixture(t, true)
			session, err := lane.native.AuthenticatedNativeHostSession()
			if err != nil {
				t.Fatal(err)
			}
			native := NewNativeObservationConnection("https://example.test", session.HostID, session.BootID, nil)
			native.offeredDirectManagedSourcePrepare = true
			native.offeredDirectManagedSourcePoP = reason != "unsolicited"
			if reason == "duplicate" {
				session.ProtocolFeatures = append(session.ProtocolFeatures, transport.DirectManagedSourcePoPProtocol)
			}
			if reason == "missing-prepare" {
				session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.DirectManagedSourcePoPProtocol}
			}
			if err := native.Admit(session); err == nil {
				t.Fatal("invalid PoP negotiation admitted")
			}
		})
	}
}

func TestDirectManagedSourcePoPLaneCloseCancelsProof(t *testing.T) {
	_, lane, peer, executor, command := directSourcePoPLaneFixture(t, true)
	executor.canceled = make(chan struct{})
	lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourcePoP, command))
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

func TestDirectManagedSourcePoPLaneStartupReadiness(t *testing.T) {
	f := newManagedPrepareVerifierFixture(t)
	d := f.d
	d.Config = Config{StateDir: filepath.Dir(d.nativeRegistry.root), DirectManagedSourcePrepareEnabled: true}
	d.Log = discardLog()
	release, err := d.acquireServeLock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	d.initDirectManagedSourcePrepare()
	if d.directManagedSourcePoPReady() || d.directManagedSourcePoP != nil {
		t.Fatal("PoP initialized without opt-in")
	}
	d.DirectManagedSourcePoPEnabled = true
	d.initDirectManagedSourcePrepare()
	if !d.directManagedSourcePoPReady() {
		t.Fatal("closed prerequisites unavailable")
	}
	for _, table := range []string{"native_direct_managed_source_keys", "native_direct_managed_source_prepare_commands", "native_direct_managed_source_pop_challenges"} {
		var count int
		if err := d.nativeRegistry.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("readiness mutated %s: count=%d err=%v", table, count, err)
		}
	}
	for _, namespace := range []string{nativeDirectManagedSourceKeyNamespace, directManagedSourcePrepareJournalNamespace} {
		path := filepath.Join(d.nativeRegistry.root, namespace)
		if err := os.Symlink(t.TempDir(), path); err != nil {
			t.Fatal(err)
		}
		if d.directManagedSourcePoPReady() {
			t.Fatal("unsafe source namespace advertised")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	original := d.directManagedSourcePrepare.(*localDirectManagedSourcePrepare).keys.installation
	d.directManagedSourcePrepare.(*localDirectManagedSourcePrepare).keys.installation = domain.NewID()
	if d.directManagedSourcePoPReady() {
		t.Fatal("changed source installation advertised")
	}
	d.directManagedSourcePrepare.(*localDirectManagedSourcePrepare).keys.installation = original
	if err := d.serveLockFile.Close(); err != nil {
		t.Fatal(err)
	}
	if d.directManagedSourcePoPReady() {
		t.Fatal("ready with closed serve lock")
	}
}

func TestDirectManagedSourcePoPLaneVerifiedWorkerPublication(t *testing.T) {
	for _, mutation := range []string{"unchanged", "worker replacement", "ownership mutation", "proxy close"} {
		t.Run(mutation, func(t *testing.T) {
			d, lane, peer, executor, command := directSourcePoPLaneFixture(t, true)
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
