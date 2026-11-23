//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func sourcePrepareLaneFixture(t *testing.T, features ...string) (*NativeShareSourceHolderStore, transport.HostSessionPayload, transport.NativeShareSourcePreparePayload) {
	t.Helper()
	holder, session, request := sourcePrepareExecutorFixture(t)
	session.HostCredentialID = domain.NewID().String()
	request.Enrollment.HostCredentialID = session.HostCredentialID
	session.ProtocolFeatures = append([]string{transport.NativeObservationReceiptProtocol}, features...)
	return holder, session, request
}

func sourcePrepareLane(t *testing.T, executor nativeShareSourcePrepareExecutor, session transport.HostSessionPayload) (*Daemon, *nativeShareSourcePrepareConnection, *websocket.Conn) {
	t.Helper()
	socket, peer := nativeBindingSocketPair(t)
	native := NewNativeObservationConnection("https://example.test", session.HostID, session.BootID, nil)
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{nativeSourcePrepare: executor, curConn: socket, nativeConn: native, writeTimeout: time.Second}
	c := newNativeShareSourcePrepareConnection(d, socket, native)
	t.Cleanup(c.close)
	return d, c, peer
}

func TestNativeShareSourcePrepareSocketRetryAndRestart(t *testing.T) {
	holder, session, request := sourcePrepareLaneFixture(t, transport.NativeShareSourceEnrollmentProtocol)
	executor, err := NewNativeShareSourcePrepareExecutor(holder.registry, sourcePrepareExecutorNow)
	if err != nil {
		t.Fatal(err)
	}
	_, c, peer := sourcePrepareLane(t, executor, session)
	env := nativeBindingEnvelope(t, transport.MsgNativeShareSourcePrepare, request)
	var first transport.NativeShareSourcePreparedPayload
	c.handle(env)
	if err := nativeBindingReadAck(t, peer, request.CommandID, &first); err != "" {
		t.Fatal(err)
	}
	changed := request
	changed.Enrollment.BindingDigest = strings.Repeat("cd", 32)
	c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareSourcePrepare, changed))
	if err := nativeBindingReadAck(t, peer, request.CommandID, nil); err == "" {
		t.Fatal("changed replay accepted")
	}
	c.close()
	// Reopen the same authoritative registry and retry through a new socket lane.
	reopened := sourcePrepareReopen(t, holder)
	executor, err = NewNativeShareSourcePrepareExecutor(reopened.holder.registry, sourcePrepareExecutorNow)
	if err != nil {
		t.Fatal(err)
	}
	_, retryLane, retryPeer := sourcePrepareLane(t, executor, session)
	retryLane.handle(env)
	var retry transport.NativeShareSourcePreparedPayload
	if err := nativeBindingReadAck(t, retryPeer, request.CommandID, &retry); err != "" {
		t.Fatal(err)
	}
	if !bytes.Equal(sourcePrepareBytes(t, first), sourcePrepareBytes(t, retry)) {
		t.Fatal("restart changed ACK result")
	}
}

func TestNativeShareSourcePrepareCapabilityAndMalformed(t *testing.T) {
	for _, features := range [][]string{nil, {transport.NativeShareBindingProtocol}, {transport.NativeShareSourceEnrollmentProtocol, transport.NativeShareSourceEnrollmentProtocol}} {
		holder, session, request := sourcePrepareLaneFixture(t, features...)
		executor, err := NewNativeShareSourcePrepareExecutor(holder.registry, sourcePrepareExecutorNow)
		if err != nil {
			t.Fatal(err)
		}
		d, c, peer := sourcePrepareLane(t, executor, session)
		before := sourcePrepareExecutorCounts(t, holder.registry)
		c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareSourcePrepare, request))
		if err := nativeBindingReadAck(t, peer, request.CommandID, nil); err == "" {
			t.Fatal("missing independent capability accepted")
		}
		// Bypassing the socket dispatcher must not enter generic worker handling.
		d.handleCommand(nil, nativeBindingEnvelope(t, transport.MsgNativeShareSourcePrepare, request))
		for _, raw := range []string{`{}`, `{"commandId":null}`, `{"CommandId":"x"}`, `{"commandId":"x","commandId":"y"}`} {
			c.handle(transport.Envelope{Type: transport.MsgNativeShareSourcePrepare, Payload: json.RawMessage(raw)})
		}
		if after := sourcePrepareExecutorCounts(t, holder.registry); after != before {
			t.Fatal("rejected command persisted state")
		}
	}
}

type sourcePrepareBlockingExecutor struct {
	executor nativeShareSourcePrepareExecutor
	started  chan struct{}
	release  chan struct{}
	finished chan struct{}
}

func (*sourcePrepareBlockingExecutor) nativeShareSourcePrepareReady() bool { return true }
func (e *sourcePrepareBlockingExecutor) Prepare(endpoint string, session transport.HostSessionPayload, request transport.NativeShareSourcePreparePayload) (transport.NativeShareSourcePreparedPayload, error) {
	defer func() { e.finished <- struct{}{} }()
	e.started <- struct{}{}
	<-e.release
	return e.executor.Prepare(endpoint, session, request)
}

func TestNativeShareSourcePrepareQueueAndSupersession(t *testing.T) {
	for _, closeNative := range []bool{false, true} {
		holder, session, request := sourcePrepareLaneFixture(t, transport.NativeShareSourceEnrollmentProtocol)
		executor, err := NewNativeShareSourcePrepareExecutor(holder.registry, sourcePrepareExecutorNow)
		if err != nil {
			t.Fatal(err)
		}
		blocked := &sourcePrepareBlockingExecutor{executor: executor, started: make(chan struct{}, 8), release: make(chan struct{}), finished: make(chan struct{}, 8)}
		d, c, peer := sourcePrepareLane(t, blocked, session)
		c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareSourcePrepare, request))
		<-blocked.started
		for i := 1; i < nativeShareSourcePrepareQueueLimit; i++ {
			next := request
			next.CommandID = domain.NewID()
			next.Enrollment.EnrollmentID = domain.NewID()
			next.Enrollment.BindingID = domain.NewID()
			c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareSourcePrepare, next))
		}
		overflow := request
		overflow.CommandID = domain.NewID()
		c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareSourcePrepare, overflow))
		if err := nativeBindingReadAck(t, peer, overflow.CommandID, nil); err == "" {
			t.Fatal("queue overflow accepted")
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

func TestNativeShareSourcePrepareProductionDispatch(t *testing.T) {
	_, session, request := sourcePrepareLaneFixture(t, transport.NativeShareSourceEnrollmentProtocol)
	peers := make(chan *websocket.Conn, 1)
	offered := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offered <- r.URL.Query().Get("native_share_source_enrollment")
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
	// Production composition uses only the authoritative registry, without host keys.
	release, err := d.acquireServeLock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if d.nativeSourcePrepare != nil {
		t.Fatal("constructor composed executor before serve lock")
	}
	d.initNativeShareSourcePrepare()
	request.Enrollment.Subject.ServerURL = server.URL
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
	if got := <-offered; got != transport.NativeShareSourceEnrollmentProtocol {
		t.Fatal("missing source capability offer", got)
	}
	if err := peer.WriteJSON(nativeBindingEnvelope(t, transport.MsgHostSession, session)); err != nil {
		t.Fatal(err)
	}
	if err := peer.WriteJSON(nativeBindingEnvelope(t, transport.MsgNativeShareSourcePrepare, request)); err != nil {
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
			CommandID domain.ID                                  `json:"commandId"`
			Error     string                                     `json:"error"`
			Result    transport.NativeShareSourcePreparedPayload `json:"result"`
		}
		if err := json.Unmarshal(env.Payload, &ack); err != nil {
			t.Fatal(err)
		}
		if ack.CommandID != request.CommandID || ack.Error != "" {
			t.Fatal("production command rejected", ack.Error)
		}
		sourcePrepareBytes(t, ack.Result)
		break
	}
	peer.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("connection did not exit")
	}
	d.Close()
	u, err := url.Parse(d.wsURL(t.Context()))
	if err != nil || u.Query().Get("native_share_source_enrollment") != "" {
		t.Fatal("closed registry advertised capability", err)
	}
}

// A transient readiness failure during connection setup must not strand later
// admitted commands in a queue without a consumer.
type sourcePrepareRecoveringExecutor struct {
	nativeShareSourcePrepareExecutor
	ready bool
}

func (e *sourcePrepareRecoveringExecutor) nativeShareSourcePrepareReady() bool { return e.ready }

func TestNativeShareSourcePrepareReadinessRecovery(t *testing.T) {
	holder, session, request := sourcePrepareLaneFixture(t, transport.NativeShareSourceEnrollmentProtocol)
	executor, err := NewNativeShareSourcePrepareExecutor(holder.registry, sourcePrepareExecutorNow)
	if err != nil {
		t.Fatal(err)
	}
	recovering := &sourcePrepareRecoveringExecutor{nativeShareSourcePrepareExecutor: executor}
	_, lane, peer := sourcePrepareLane(t, recovering, session)
	recovering.ready = true
	lane.handle(nativeBindingEnvelope(t, transport.MsgNativeShareSourcePrepare, request))
	var prepared transport.NativeShareSourcePreparedPayload
	if err := nativeBindingReadAck(t, peer, request.CommandID, &prepared); err != "" {
		t.Fatal(err)
	}
	sourcePrepareBytes(t, prepared)
}
