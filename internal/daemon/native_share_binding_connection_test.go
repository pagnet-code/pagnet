//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func nativeBindingSocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	accepted := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err == nil {
			accepted <- c
		}
	}))
	t.Cleanup(server.Close)
	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	socket := <-accepted
	t.Cleanup(func() { client.Close(); socket.Close() })
	return socket, client
}

func nativeBindingConnectionFixture(t *testing.T, executor nativeShareBindingExecutor, session transport.HostSessionPayload) (*Daemon, *nativeShareBindingConnection, *websocket.Conn) {
	t.Helper()
	socket, peer := nativeBindingSocketPair(t)
	native := NewNativeObservationConnection("https://example.test", session.HostID, session.BootID, nil)
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{nativeShareBindings: executor, curConn: socket, nativeConn: native, writeTimeout: time.Second}
	c := newNativeShareBindingConnection(d, socket, native)
	t.Cleanup(c.close)
	return d, c, peer
}

func nativeBindingEnvelope(t *testing.T, kind string, payload any) transport.Envelope {
	t.Helper()
	env, err := transport.NewEnvelope(kind, payload)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func nativeBindingReadAck(t *testing.T, peer *websocket.Conn, id domain.ID, result any) string {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	var env transport.Envelope
	if err := peer.ReadJSON(&env); err != nil {
		t.Fatal(err)
	}
	if env.Type != transport.MsgCommandAck {
		t.Fatalf("unexpected reply type %s", env.Type)
	}
	var ack struct {
		CommandID domain.ID       `json:"commandId"`
		Error     string          `json:"error"`
		Result    json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(env.Payload, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.CommandID != id {
		t.Fatalf("unexpected command ID %s", ack.CommandID)
	}
	if result != nil && ack.Error == "" {
		if err := json.Unmarshal(ack.Result, result); err != nil {
			t.Fatal(err)
		}
	}
	return ack.Error
}

func nativeBindingWaitIdle(t *testing.T, c *nativeShareBindingConnection) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.pending)
		c.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("binding attempts did not finish")
}

type nativeBindingBlockingStore struct {
	store   nativeShareBindingExecutor
	started chan struct{}
	release chan struct{}
	mu      sync.Mutex
	calls   int
}

func (s *nativeBindingBlockingStore) Prepare(p transport.NativeShareBindingPreparePayload, endpoint string, session transport.HostSessionPayload) (transport.NativeShareBindingPreparedPayload, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	if s.started != nil {
		s.started <- struct{}{}
	}
	if s.release != nil {
		<-s.release
	}
	return s.store.Prepare(p, endpoint, session)
}
func (s *nativeBindingBlockingStore) Prove(p transport.NativeShareBindingProvePayload, endpoint string, session transport.HostSessionPayload) (transport.NativeShareBindingProvedPayload, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return s.store.Prove(p, endpoint, session)
}
func (s *nativeBindingBlockingStore) nativeShareBindingReady() bool {
	return s.store != nil && s.store.nativeShareBindingReady()
}
func (s *nativeBindingBlockingStore) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.calls }

func TestNativeShareBindingPayloadStrict(t *testing.T) {
	prepare, _, _ := nativeShareValidationFixture()
	raw, err := json.Marshal(prepare)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(raw)
	cases := map[string]string{
		"duplicate root":    strings.Replace(valid, `"commandId":`, `"commandId":"ignored","commandId":`, 1),
		"duplicate binding": strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		"unknown root":      strings.Replace(valid, `{`, `{"unexpected":1,`, 1),
		"unknown binding":   strings.Replace(valid, `"binding":{`, `"binding":{"unexpected":1,`, 1),
		"root case":         strings.Replace(valid, `"commandId"`, `"CommandId"`, 1),
		"nested case":       strings.Replace(valid, `"bindingId"`, `"BindingId"`, 1),
		"trailing object":   valid + ` {}`,
		"oversize":          valid + strings.Repeat(" ", nativeShareBindingPayloadLimit),
		"null":              "null",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			var target transport.NativeShareBindingPreparePayload
			if decodeNativeShareBindingPayload([]byte(input), &target) == nil {
				t.Fatal("accepted malformed payload")
			}
		})
	}
	var target transport.NativeShareBindingPreparePayload
	if err := decodeNativeShareBindingPayload(raw, &target); err != nil || target != prepare {
		t.Fatal("valid payload rejected", err)
	}
	for name, input := range map[string]string{
		"duplicate challenge":  `{"challenge":{"enc":"","enc":""}}`,
		"unknown challenge":    `{"challenge":{"unknown":""}}`,
		"challenge case":       `{"challenge":{"Enc":""}}`,
		"duplicate prove root": `{"version":1,"version":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			var target transport.NativeShareBindingProvePayload
			if decodeNativeShareBindingPayload([]byte(input), &target) == nil {
				t.Fatal("accepted malformed proof")
			}
		})
	}
}

func TestNativeShareBindingAdvertisementRequiresInjection(t *testing.T) {
	store, _, _, _ := nativeShareStoreFixture(t)
	d := &Daemon{ServerURL: "https://example.test?native_share_binding=forged"}
	for _, tc := range []struct {
		name     string
		executor nativeShareBindingExecutor
		want     string
	}{{"default", nil, ""}, {"typed nil", (*NativeShareHolderStore)(nil), ""}, {"injected", store, transport.NativeShareBindingProtocol}} {
		t.Run(tc.name, func(t *testing.T) {
			d.nativeShareBindings = tc.executor
			u, err := url.Parse(d.wsURL(context.Background()))
			if err != nil {
				t.Fatal(err)
			}
			if got := u.Query().Get("native_share_binding"); got != tc.want {
				t.Fatalf("advertised %q", got)
			}
		})
	}
}

func TestNativeShareBindingSocketStoreRoundTripAndRetry(t *testing.T) {
	store, identity, prepare, session := nativeShareStoreFixture(t)
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.NativeShareBindingProtocol}
	counted := &nativeBindingBlockingStore{store: store}
	d, c, peer := nativeBindingConnectionFixture(t, counted, session)
	if d.state != nil {
		t.Fatal("fixture unexpectedly has generic command store")
	}
	var prepared transport.NativeShareBindingPreparedPayload
	env := nativeBindingEnvelope(t, transport.MsgNativeShareBindingPrepare, prepare)
	for i := 0; i < 2; i++ {
		if !c.handle(env) {
			t.Fatal("prepare not handled")
		}
		var got transport.NativeShareBindingPreparedPayload
		if err := nativeBindingReadAck(t, peer, prepare.CommandID, &got); err != "" {
			t.Fatal(err)
		}
		if err := got.Verify(prepare, got.Subject, identity.Ed25519Verifier()); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			prepared = got
		} else {
			a, _ := json.Marshal(prepared)
			b, _ := json.Marshal(got)
			if !bytes.Equal(a, b) {
				t.Fatal("retry changed prepared evidence")
			}
		}
		nativeBindingWaitIdle(t, c)
	}
	prove, challenge := nativeShareProveChallenge(t, prepared)
	for i := 0; i < 2; i++ {
		c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareBindingProve, prove))
		var got transport.NativeShareBindingProvedPayload
		if err := nativeBindingReadAck(t, peer, prove.CommandID, &got); err != "" {
			t.Fatal(err)
		}
		if err := got.Verify(prove, challenge, identity.Ed25519Verifier()); err != nil {
			t.Fatal(err)
		}
		nativeBindingWaitIdle(t, c)
	}
	if counted.count() != 4 {
		t.Fatalf("retry bypassed executor: %d calls", counted.count())
	}
}

func TestNativeShareBindingRequiresFeatureExactlyOnce(t *testing.T) {
	for _, count := range []int{0, 2} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			store, _, prepare, session := nativeShareStoreFixture(t)
			session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol}
			for i := 0; i < count; i++ {
				session.ProtocolFeatures = append(session.ProtocolFeatures, transport.NativeShareBindingProtocol)
			}
			counted := &nativeBindingBlockingStore{store: store}
			_, c, peer := nativeBindingConnectionFixture(t, counted, session)
			c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareBindingPrepare, prepare))
			if err := nativeBindingReadAck(t, peer, prepare.CommandID, nil); err != nativeShareBindingError {
				t.Fatalf("unexpected error %q", err)
			}
			if counted.count() != 0 {
				t.Fatal("unnegotiated request reached store")
			}
		})
	}
}

func TestNativeShareBindingQueueDedupAndSocketReplacement(t *testing.T) {
	store, _, prepare, session := nativeShareStoreFixture(t)
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.NativeShareBindingProtocol}
	blocked := &nativeBindingBlockingStore{store: store, started: make(chan struct{}, nativeShareBindingQueueLimit), release: make(chan struct{})}
	defer close(blocked.release)
	d, c, peer := nativeBindingConnectionFixture(t, blocked, session)
	env := nativeBindingEnvelope(t, transport.MsgNativeShareBindingPrepare, prepare)
	c.handle(env)
	select {
	case <-blocked.started:
	case <-time.After(3 * time.Second):
		t.Fatal("store did not start")
	}
	c.handle(env)
	for i := 1; i < nativeShareBindingQueueLimit; i++ {
		p := prepare
		p.CommandID = domain.ID(fmt.Sprintf("90000000-0000-4000-8000-%012d", i))
		c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareBindingPrepare, p))
	}
	overflow := prepare
	overflow.CommandID = "90000000-0000-4000-8000-999999999999"
	c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareBindingPrepare, overflow))
	if err := nativeBindingReadAck(t, peer, overflow.CommandID, nil); err != nativeShareBindingError {
		t.Fatalf("overflow error %q", err)
	}
	c.mu.Lock()
	pending := len(c.pending)
	c.mu.Unlock()
	if pending != nativeShareBindingQueueLimit {
		t.Fatalf("pending count %d", pending)
	}
	replacement, replacementPeer := nativeBindingSocketPair(t)
	d.connMu.Lock()
	d.curConn = replacement
	d.connMu.Unlock()
	blocked.release <- struct{}{}
	nativeBindingWaitIdle(t, c)
	if blocked.count() != 1 {
		t.Fatalf("queued work ran after replacement: %d", blocked.count())
	}
	for _, socket := range []*websocket.Conn{peer, replacementPeer} {
		socket.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, _, err := socket.ReadMessage(); err == nil {
			t.Fatal("superseded attempt sent a reply")
		}
	}
}

func TestNativeShareBindingUnavailableExecutorAndStoreError(t *testing.T) {
	for _, kind := range []string{transport.MsgNativeShareBindingPrepare, transport.MsgNativeShareBindingProve} {
		t.Run(kind, func(t *testing.T) {
			_, _, prepare, session := nativeShareStoreFixture(t)
			session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.NativeShareBindingProtocol}
			_, c, peer := nativeBindingConnectionFixture(t, nil, session)
			var payload any = prepare
			if kind == transport.MsgNativeShareBindingProve {
				payload = transport.NativeShareBindingProvePayload{CommandID: prepare.CommandID}
			}
			if !c.handle(nativeBindingEnvelope(t, kind, payload)) {
				t.Fatal("binding message not consumed")
			}
			if err := nativeBindingReadAck(t, peer, prepare.CommandID, nil); err != nativeShareBindingError {
				t.Fatalf("unexpected error %q", err)
			}
		})
	}
	t.Run("store error", func(t *testing.T) {
		store, _, prepare, session := nativeShareStoreFixture(t)
		session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.NativeShareBindingProtocol}
		_, c, peer := nativeBindingConnectionFixture(t, store, session)
		prepare.Binding.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
		c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareBindingPrepare, prepare))
		if err := nativeBindingReadAck(t, peer, prepare.CommandID, nil); err != nativeShareBindingError {
			t.Fatalf("store details escaped error: %q", err)
		}
		nativeBindingWaitIdle(t, c)
	})
}

func TestNativeShareBindingClosedAdmissionStopsQueuedWork(t *testing.T) {
	store, _, prepare, session := nativeShareStoreFixture(t)
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.NativeShareBindingProtocol}
	blocked := &nativeBindingBlockingStore{store: store, started: make(chan struct{}, 2), release: make(chan struct{})}
	defer close(blocked.release)
	_, c, peer := nativeBindingConnectionFixture(t, blocked, session)
	c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareBindingPrepare, prepare))
	select {
	case <-blocked.started:
	case <-time.After(3 * time.Second):
		t.Fatal("store did not start")
	}
	queued := prepare
	queued.CommandID = "90000000-0000-4000-8000-999999999999"
	c.handle(nativeBindingEnvelope(t, transport.MsgNativeShareBindingPrepare, queued))
	c.native.Close()
	blocked.release <- struct{}{}
	nativeBindingWaitIdle(t, c)
	if blocked.count() != 1 {
		t.Fatalf("queued work ran after admission closed: %d", blocked.count())
	}
	peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := peer.ReadMessage(); err == nil {
		t.Fatal("closed admission sent a reply")
	}
}
