//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func sourceProveLaneFixture(t *testing.T, features ...string) (*NativeShareSourceHolderStore, transport.HostSessionPayload, transport.NativeShareSourceProvePayload) {
	t.Helper()
	holder, session, prepare := sourcePrepareLaneFixture(t, features...)
	executor, err := NewNativeShareSourcePrepareExecutor(holder.registry, sourcePrepareExecutorNow)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := executor.Prepare(prepare.Enrollment.Subject.ServerURL, session, prepare)
	if err != nil {
		t.Fatal(err)
	}
	return holder, session, sourceProveRouteRequest(t, prepared)
}

func sourceProveRouteRequest(t *testing.T, prepared transport.NativeShareSourcePreparedPayload) transport.NativeShareSourceProvePayload {
	t.Helper()
	var err error
	p := transport.NativeShareSourceProvePayload{NativeShareSourceChallengeContext: transport.NativeShareSourceChallengeContext{
		Version: transport.NativeShareSourceVersion, EnrollmentID: prepared.Prepare.Enrollment.EnrollmentID, CommandID: domain.NewID(), EnrollmentDigest: prepared.EnrollmentDigest, DescriptorFingerprint: prepared.Descriptor.Fingerprint, ChallengeID: domain.NewID(), ExpiresAt: prepared.Prepare.Enrollment.ExpiresAt,
	}}
	plain := bytes.Repeat([]byte{0xa7}, 32)
	public, err := hex.DecodeString(prepared.Descriptor.X25519)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := p.ChallengeAAD()
	if err != nil {
		t.Fatal(err)
	}
	p.Challenge.Enc, p.Challenge.Ciphertext, err = crypto.WrapKey(public, []byte(transport.NativeShareSourceChallengeInfo), aad, plain)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func sourceProveLane(t *testing.T, executor nativeShareSourceProveExecutor, session transport.HostSessionPayload) (*Daemon, *nativeShareSourceProveConnection, *websocket.Conn) {
	t.Helper()
	return sourceProveLaneWithOffer(t, executor, session, true)
}

func sourceProveLaneWithOffer(t *testing.T, executor nativeShareSourceProveExecutor, session transport.HostSessionPayload, offered bool) (*Daemon, *nativeShareSourceProveConnection, *websocket.Conn) {
	t.Helper()
	socket, peer := nativeBindingSocketPair(t)
	native := NewNativeObservationConnection("https://example.test", session.HostID, session.BootID, nil)
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{nativeSourceProve: executor, curConn: socket, nativeConn: native, writeTimeout: time.Second}
	c := newNativeShareSourceProveConnection(d, socket, native, offered)
	t.Cleanup(c.close)
	return d, c, peer
}

func TestNativeShareSourceProveSocketRetryAndRestart(t *testing.T) {
	holder, session, request := sourceProveLaneFixture(t, transport.NativeShareSourceProveProtocol)
	executor, err := NewNativeShareSourceProveExecutor(holder.registry, sourcePrepareExecutorNow)
	if err != nil {
		t.Fatal(err)
	}
	_, c, peer := sourceProveLane(t, executor, session)
	env := nativeBindingEnvelope(t, transport.MsgNativeShareSourceProve, request)
	var first transport.NativeShareSourceProvedPayload
	c.handle(env)
	if err := nativeBindingReadAck(t, peer, request.CommandID, &first); err != "" {
		t.Fatal(err)
	}
	changed := request
	changed.EnrollmentDigest = strings.Repeat("cd", 32)
	c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareSourceProve, changed))
	if err := nativeBindingReadAck(t, peer, request.CommandID, nil); err == "" {
		t.Fatal("changed replay accepted")
	}
	c.close()
	// Reopen the same authoritative registry and retry through a new socket lane.
	reopened := sourcePrepareReopen(t, holder)
	executor, err = NewNativeShareSourceProveExecutor(reopened.holder.registry, sourcePrepareExecutorNow)
	if err != nil {
		t.Fatal(err)
	}
	_, retryLane, retryPeer := sourceProveLane(t, executor, session)
	retryLane.handle(env)
	var retry transport.NativeShareSourceProvedPayload
	if err := nativeBindingReadAck(t, retryPeer, request.CommandID, &retry); err != "" {
		t.Fatal(err)
	}
	if !bytes.Equal(sourceProveRouteBytes(t, first), sourceProveRouteBytes(t, retry)) {
		t.Fatal("restart changed ACK result")
	}
}

func TestNativeShareSourceProveCapabilityAndMalformed(t *testing.T) {
	for _, features := range [][]string{nil, {transport.NativeShareSourceEnrollmentProtocol}, {transport.NativeShareSourceProveProtocol, transport.NativeShareSourceProveProtocol}} {
		holder, session, request := sourceProveLaneFixture(t, features...)
		executor, err := NewNativeShareSourceProveExecutor(holder.registry, sourcePrepareExecutorNow)
		if err != nil {
			t.Fatal(err)
		}
		d, c, peer := sourceProveLane(t, executor, session)
		before := sourceProveRouteCounts(t, holder.registry)
		c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareSourceProve, request))
		if err := nativeBindingReadAck(t, peer, request.CommandID, nil); err == "" {
			t.Fatal("missing independent capability accepted")
		}
		// Bypassing the socket dispatcher must not enter generic worker handling.
		d.handleCommand(nil, nativeBindingEnvelope(t, transport.MsgNativeShareSourceProve, request))
		for _, raw := range []string{`{}`, `{"commandId":null}`, `{"CommandId":"x"}`, `{"commandId":"x","commandId":"y"}`} {
			c.handle(transport.Envelope{Type: transport.MsgNativeShareSourceProve, Payload: json.RawMessage(raw)})
		}
		if after := sourceProveRouteCounts(t, holder.registry); after != before {
			t.Fatal("rejected command persisted state")
		}
	}
}

type sourceProveBlockingExecutor struct {
	executor nativeShareSourceProveExecutor
	started  chan struct{}
	release  chan struct{}
	finished chan struct{}
}

func (*sourceProveBlockingExecutor) nativeShareSourceProveReady() bool { return true }
func (e *sourceProveBlockingExecutor) Prove(endpoint string, session transport.HostSessionPayload, request transport.NativeShareSourceProvePayload) (transport.NativeShareSourceProvedPayload, error) {
	defer func() { e.finished <- struct{}{} }()
	e.started <- struct{}{}
	<-e.release
	return e.executor.Prove(endpoint, session, request)
}

func TestNativeShareSourceProveQueueAndSupersession(t *testing.T) {
	for _, closeNative := range []bool{false, true} {
		holder, session, request := sourceProveLaneFixture(t, transport.NativeShareSourceProveProtocol)
		executor, err := NewNativeShareSourceProveExecutor(holder.registry, sourcePrepareExecutorNow)
		if err != nil {
			t.Fatal(err)
		}
		blocked := &sourceProveBlockingExecutor{executor: executor, started: make(chan struct{}, 8), release: make(chan struct{}), finished: make(chan struct{}, 8)}
		d, c, peer := sourceProveLane(t, blocked, session)
		c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareSourceProve, request))
		<-blocked.started
		for i := 1; i < nativeShareSourceProveQueueLimit; i++ {
			next := request
			next.CommandID = domain.NewID()
			next.EnrollmentID = domain.NewID()
			c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareSourceProve, next))
		}
		if closeNative {
			c.native.Close()
		} else {
			d.connMu.Lock()
			d.curConn = nil
			d.connMu.Unlock()
		}
		c.close()
		close(blocked.release)
		select {
		case <-blocked.finished:
		case <-time.After(3 * time.Second):
			t.Fatal("in-flight command did not finish")
		}
		// An in-flight persistence may finish, but no stale reply or queued execution escapes.
		peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, _, err := peer.ReadMessage(); err == nil {
			t.Fatal("stale ACK escaped")
		}
		select {
		case <-blocked.started:
			t.Fatal("queued command ran after shutdown")
		default:
		}
	}
}

func sourceProveRouteBytes(t *testing.T, p transport.NativeShareSourceProvedPayload) []byte {
	t.Helper()
	raw, err := p.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNativeShareSourceProveDisabled(t *testing.T) {
	holder, session, request := sourceProveLaneFixture(t, transport.NativeShareSourceProveProtocol)
	d, lane, peer := sourceProveLane(t, nil, session)
	if !lane.handle(nativeBindingEnvelope(t, transport.MsgNativeShareSourceProve, request)) {
		t.Fatal("prove escaped dedicated lane")
	}
	if err := nativeBindingReadAck(t, peer, request.CommandID, nil); err == "" {
		t.Fatal("disabled prove accepted")
	}
	d.handleCommand(nil, nativeBindingEnvelope(t, transport.MsgNativeShareSourceProve, request))
	var count int
	if err := holder.registry.db.QueryRow(`SELECT COUNT(*) FROM native_source_prove_journal`).Scan(&count); err != nil || count != 0 {
		t.Fatal("disabled command persisted", err)
	}
}

func TestNativeShareSourceProveCapabilityOffer(t *testing.T) {
	holder, session, _ := sourceProveLaneFixture(t, transport.NativeShareSourceProveProtocol)
	executor, err := NewNativeShareSourceProveExecutor(holder.registry, sourcePrepareExecutorNow)
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{Config: Config{ServerURL: "https://example.test?native_share_source_prove=untrusted", HostID: session.HostID}}
	capability := func() string {
		u, err := url.Parse(d.wsURL(context.Background()))
		if err != nil {
			t.Fatal(err)
		}
		return u.Query().Get("native_share_source_prove")
	}
	if capability() != "" {
		t.Fatal("disabled daemon offered prove")
	}
	d.nativeSourceProve = executor
	if capability() != transport.NativeShareSourceProveProtocol {
		t.Fatal("missing independent prove offer")
	}
	if err := holder.registry.Close(); err != nil {
		t.Fatal(err)
	}
	if capability() != "" {
		t.Fatal("closed registry offered prove")
	}
}

func TestNativeShareSourceProveProductionDispatch(t *testing.T) {
	t.Run("offered", func(t *testing.T) { sourceProveProductionDispatch(t, true) })
	t.Run("unoffered recovery", func(t *testing.T) { sourceProveProductionDispatch(t, false) })
}

func sourceProveProductionDispatch(t *testing.T, offer bool) {
	_, session, prepare := sourcePrepareLaneFixture(t, transport.NativeShareSourceProveProtocol)
	peers := make(chan *websocket.Conn, 1)
	offered := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offered <- r.URL.Query().Get("native_share_source_prove")
		peer, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err == nil {
			peers <- peer
		}
	}))
	defer server.Close()
	d, err := New(Config{StateDir: privateDaemonStateDir(t), ServerURL: server.URL, HostID: session.HostID}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.bootID = session.BootID
	d.Heartbeat = time.Hour
	release, err := d.acquireServeLock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if d.nativeSourceProve != nil {
		t.Fatal("constructor composed prove before serve lock")
	}
	d.initNativeShareSourcePrepare()
	d.initNativeShareSourceProve()
	prepare.Enrollment.Subject.ServerURL = server.URL
	prepared, err := d.nativeSourcePrepare.Prepare(server.URL, session, prepare)
	if err != nil {
		t.Fatal(err)
	}
	request := sourceProveRouteRequest(t, prepared)
	gate := &sourceProveReadinessExecutor{nativeShareSourceProveExecutor: d.nativeSourceProve}
	gate.ready.Store(offer)
	d.nativeSourceProve = gate
	before := sourceProveRouteCounts(t, d.nativeRegistry)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := d.connectAndRun(ctx); done <- err }()
	var peer *websocket.Conn
	select {
	case peer = <-peers:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not connect")
	}
	defer peer.Close()
	expectedOffer := ""
	if offer {
		expectedOffer = transport.NativeShareSourceProveProtocol
	}
	if got := <-offered; got != expectedOffer {
		t.Fatal("incorrect prove capability", got)
	}
	// Recovery after dial must not upgrade this socket's immutable offer.
	gate.ready.Store(true)
	if err := peer.WriteJSON(nativeBindingEnvelope(t, transport.MsgHostSession, session)); err != nil {
		t.Fatal(err)
	}
	if err := peer.WriteJSON(nativeBindingEnvelope(t, transport.MsgNativeShareSourceProve, request)); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		var env transport.Envelope
		if err := peer.ReadJSON(&env); err != nil {
			t.Fatal(err)
		}
		if env.Type != transport.MsgCommandAck {
			continue
		}
		var ack struct {
			CommandID domain.ID                                `json:"commandId"`
			Error     string                                   `json:"error"`
			Result    transport.NativeShareSourceProvedPayload `json:"result"`
		}
		if err := json.Unmarshal(env.Payload, &ack); err != nil {
			t.Fatal(err)
		}
		if ack.CommandID != request.CommandID {
			t.Fatal("incorrect command ACK")
		}
		if offer {
			if ack.Error != "" {
				t.Fatal("production prove rejected", ack.Error)
			}
			sourceProveRouteBytes(t, ack.Result)
		} else {
			if ack.Error == "" || ack.Result.Challenge != nil {
				t.Fatal("unoffered prove accepted after recovery")
			}
			if after := sourceProveRouteCounts(t, d.nativeRegistry); after != before {
				t.Fatal("unoffered command persisted")
			}
		}
		break
	}
	peer.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("connection did not exit")
	}
}

func sourceProveRouteCounts(t *testing.T, registry *NativeWorkerRegistry) [4]int {
	t.Helper()
	prepare := sourcePrepareExecutorCounts(t, registry)
	counts := [4]int{prepare[0], prepare[1], prepare[2], 0}
	if err := registry.db.QueryRow(`SELECT COUNT(*) FROM native_source_prove_journal`).Scan(&counts[3]); err != nil {
		t.Fatal(err)
	}
	return counts
}

type sourceProveReadinessExecutor struct {
	nativeShareSourceProveExecutor
	ready atomic.Bool
}

func (e *sourceProveReadinessExecutor) nativeShareSourceProveReady() bool { return e.ready.Load() }

func TestNativeShareSourceProvePendingOutcome(t *testing.T) {
	for _, reason := range []string{"overflow", "readiness"} {
		t.Run(reason, func(t *testing.T) {
			holder, session, request := sourceProveLaneFixture(t, transport.NativeShareSourceProveProtocol)
			executor, err := NewNativeShareSourceProveExecutor(holder.registry, sourcePrepareExecutorNow)
			if err != nil {
				t.Fatal(err)
			}
			blocked := &sourceProveBlockingExecutor{executor: executor, started: make(chan struct{}, 8), release: make(chan struct{}), finished: make(chan struct{}, 8)}
			gate := &sourceProveReadinessExecutor{nativeShareSourceProveExecutor: blocked}
			gate.ready.Store(true)
			_, lane, peer := sourceProveLane(t, gate, session)
			env := nativeBindingEnvelope(t, transport.MsgNativeShareSourceProve, request)
			lane.handle(env)
			<-blocked.started
			accepted := 1
			if reason == "overflow" {
				for accepted < nativeShareSourceProveQueueLimit {
					lane.handle(env)
					accepted++
				}
			} else {
				gate.ready.Store(false)
			}
			lane.handle(env)
			gate.ready.Store(true)
			close(blocked.release)
			for i := 0; i < accepted; i++ {
				var proof transport.NativeShareSourceProvedPayload
				if err := nativeBindingReadAck(t, peer, request.CommandID, &proof); err != "" {
					t.Fatal("pending command received premature rejection", err)
				}
				sourceProveRouteBytes(t, proof)
			}
			peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if _, _, err := peer.ReadMessage(); err == nil {
				t.Fatal("suppressed retry emitted another ACK")
			}
		})
	}
}

func TestNativeShareSourceProveNewCommandOverflowCloses(t *testing.T) {
	holder, session, request := sourceProveLaneFixture(t, transport.NativeShareSourceProveProtocol)
	executor, err := NewNativeShareSourceProveExecutor(holder.registry, sourcePrepareExecutorNow)
	if err != nil {
		t.Fatal(err)
	}
	blocked := &sourceProveBlockingExecutor{executor: executor, started: make(chan struct{}, 8), release: make(chan struct{}), finished: make(chan struct{}, 8)}
	_, lane, peer := sourceProveLane(t, blocked, session)
	env := nativeBindingEnvelope(t, transport.MsgNativeShareSourceProve, request)
	lane.handle(env)
	<-blocked.started
	for i := 1; i < nativeShareSourceProveQueueLimit; i++ {
		lane.handle(env)
	}
	overflow := request
	overflow.CommandID = domain.NewID()
	lane.handle(nativeBindingEnvelope(t, transport.MsgNativeShareSourceProve, overflow))
	close(blocked.release)
	<-blocked.finished
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("overflow emitted an ACK")
	}
	var count int
	if err := holder.registry.db.QueryRow(`SELECT COUNT(*) FROM native_source_prove_journal WHERE command_id=?`, overflow.CommandID).Scan(&count); err != nil || count != 0 {
		t.Fatal("overflow command persisted", err)
	}
}
