package sdk

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/transport"
)

type sharingCoordinatorFixture struct {
	mu                     sync.Mutex
	messages               *sharingMessageFixture
	issuer, recipient      *Client
	calls                  int
	principalCalls         map[string]int
	failLists              int
	paginateLists          bool
	pinWakes, packageWakes int
}

func coordinatorClients(t *testing.T, active bool) (*sharingCoordinatorFixture, *Client, *Client) {
	t.Helper()
	p, i, r := pairRESTClients(t)
	p.status.Limits.MaxMessageWireBytes = 4096
	p.server.Close()
	f := &sharingCoordinatorFixture{messages: &sharingMessageFixture{pair: p, messages: map[string]pairMessageWire{}, canonical: map[string][]byte{}, acked: map[string]bool{}}, issuer: i, recipient: r}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	for _, c := range []*Client{i, r} {
		c.rest.base = server.URL + "/api/v1"
		c.closeCh = make(chan struct{})
		c.terminalCh = make(chan struct{})
	}
	t.Cleanup(func() {
		if err := i.Close(); err != nil {
			t.Error(err)
		}
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	if active {
		for _, c := range []*Client{i, r, i, r, i} {
			if _, err := c.EnrollSharingPair(context.Background(), "grant"); err != nil {
				t.Fatal(err)
			}
		}
	}
	return f, i, r
}
func (f *sharingCoordinatorFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls++
	if f.principalCalls == nil {
		f.principalCalls = map[string]int{}
	}
	principal := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer pgn_epd_v1_")
	f.principalCalls[principal]++
	if strings.HasSuffix(r.URL.Path, "/sharing-pairs") && f.failLists > 0 {
		f.failLists--
		f.mu.Unlock()
		w.WriteHeader(503)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/sharing-pairs") && f.paginateLists && r.URL.Query().Get("cursor") == "" {
		f.mu.Unlock()
		w.Header().Set("X-Next-Cursor", "next")
		_, _ = w.Write([]byte("[]"))
		return
	}
	p := f.messages.pair
	issuerPinned, recipientPinned := p.status.IssuerPublicKey != nil, p.status.RecipientPublicKey != nil
	hadEpoch := p.epoch != nil
	wasActive := p.status.State == "active"
	f.messages.serve(w, r)
	firstPin := issuerPinned != (p.status.IssuerPublicKey != nil) || recipientPinned != (p.status.RecipientPublicKey != nil)
	packagePublished := !hadEpoch && p.epoch != nil
	changed := firstPin || packagePublished || (!wasActive && p.status.State == "active")
	if firstPin {
		f.pinWakes++
	}
	if packagePublished {
		f.packageWakes++
	}
	message := r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/messages")
	f.mu.Unlock()
	if changed {
		for _, c := range []*Client{f.issuer, f.recipient} {
			c.queueSharingPairWake(sharingPairWake{"grant", 1, "state"})
		}
	}
	if message {
		for _, c := range []*Client{f.issuer, f.recipient} {
			c.queueSharingPairWake(sharingPairWake{"grant", 1, "message"})
		}
	}
}
func waitSharing(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for sharing coordinator")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func (f *sharingCoordinatorFixture) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }
func waitSharingIdle(t *testing.T, f *sharingCoordinatorFixture) {
	t.Helper()
	waitSharing(t, func() bool { before := f.count(); time.Sleep(30 * time.Millisecond); return f.count() == before })
}
func sendCoordinatorMessage(t *testing.T, c *Client, text string) PreparedSharingMessage {
	t.Helper()
	p, err := c.PrepareSharingMessage(context.Background(), SharingMessageRequest{GrantID: "grant", Parts: []MessagePart{TextPart(text)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SendPreparedSharingMessage(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSharingCoordinatorFirstPinPackageAndIdle(t *testing.T) {
	f, i, r := coordinatorClients(t, false)
	f.mu.Lock()
	f.paginateLists = true
	f.mu.Unlock()
	i.EnableSharingPairs()
	waitSharing(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.messages.pair.status.IssuerPublicKey != nil })
	waitSharingIdle(t, f)
	before := f.count()
	time.Sleep(150 * time.Millisecond)
	if f.count() != before {
		t.Fatal("pending enrollment polled while idle")
	}
	r.EnableSharingPairs()
	waitSharing(t, func() bool { return i.cryptoReady("network") && r.cryptoReady("network") })
	f.mu.Lock()
	pins, packages := f.pinWakes, f.packageWakes
	f.mu.Unlock()
	if pins != 2 || packages != 1 {
		t.Fatalf("pin wakes=%d package wakes=%d", pins, packages)
	}
	waitSharingIdle(t, f)
	before = f.count()
	time.Sleep(150 * time.Millisecond)
	if f.count() != before {
		t.Fatal("active coordinator polled while idle")
	}
	// Repeated opt-in requests retain exactly one coordinator.
	i.sharingMu.Lock()
	original := i.sharingCoordinator
	i.sharingMu.Unlock()
	i.EnableSharingPairs()
	i.EnableSharingPairs()
	i.sharingMu.Lock()
	same := i.sharingCoordinator == original
	i.sharingMu.Unlock()
	if !same {
		t.Fatal("created a second coordinator")
	}
}

func TestSharingCoordinatorNotificationDuringDrain(t *testing.T) {
	f, i, r := coordinatorClients(t, true)
	first := make(chan struct{})
	release := make(chan struct{})
	second := make(chan struct{})
	var calls atomic.Int32
	r.OnSharingMessage(func(ctx context.Context, m SharingMessage) error {
		if calls.Add(1) == 1 {
			close(first)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		} else {
			close(second)
		}
		return nil
	})
	waitSharingIdle(t, f)
	f.mu.Lock()
	proofsBefore := f.messages.pair.proofs
	f.mu.Unlock()
	sendCoordinatorMessage(t, i, "first")
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("missing first handler")
	}
	sendCoordinatorMessage(t, i, "arrived during drain")
	close(release)
	select {
	case <-second:
	case <-time.After(5 * time.Second):
		t.Fatal("wake during drain lost")
	}
	waitSharing(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.messages.acks == 2 })
	if calls.Load() != 2 {
		t.Fatal("duplicate message handling")
	}
	f.mu.Lock()
	proofsAfter := f.messages.pair.proofs
	f.mu.Unlock()
	if proofsAfter != proofsBefore {
		t.Fatal("message wake repeated enrollment proof")
	}
}

func TestSharingCoordinatorHandlerFailureWaitsForTrigger(t *testing.T) {
	f, i, r := coordinatorClients(t, true)
	var calls atomic.Int32
	r.OnSharingMessage(func(context.Context, SharingMessage) error {
		if calls.Add(1) == 2 {
			panic("handler panic")
		}
		return errors.New("handler failed")
	})
	sendCoordinatorMessage(t, i, "pending")
	waitSharing(t, func() bool { return calls.Load() == 1 })
	waitSharingIdle(t, f)
	before := f.count()
	time.Sleep(150 * time.Millisecond)
	if calls.Load() != 1 || f.count() != before {
		t.Fatal("failed handler spun or polled")
	}
	r.EnableSharingPairs()
	waitSharing(t, func() bool { return calls.Load() == 2 })
	r.OnSharingMessage(func(context.Context, SharingMessage) error { calls.Add(1); return nil })
	waitSharing(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.messages.acks == 1 })
	if calls.Load() != 3 {
		t.Fatalf("handler calls %d", calls.Load())
	}
}

func TestSharingCoordinatorReconnectFencesHandlerAndReplaysInbox(t *testing.T) {
	f, i, r := coordinatorClients(t, true)
	first := make(chan struct{})
	firstDone := make(chan struct{})
	second := make(chan struct{})
	var calls, inflight, maxInflight atomic.Int32
	r.OnSharingMessage(func(ctx context.Context, m SharingMessage) error {
		n := inflight.Add(1)
		defer inflight.Add(-1)
		for old := maxInflight.Load(); n > old && !maxInflight.CompareAndSwap(old, n); old = maxInflight.Load() {
		}
		if calls.Add(1) == 1 {
			close(first)
			<-ctx.Done()
			close(firstDone)
			return ctx.Err()
		}
		select {
		case <-firstDone:
		default:
			t.Error("overlapping callbacks across reconnect")
		}
		close(second)
		return nil
	})
	sendCoordinatorMessage(t, i, "reconnect")
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("missing handler")
	}
	r.connected.Store(false)
	r.sharingPairDisconnected(r.connGeneration.Load())
	r.connGeneration.Add(1)
	r.endpointID.Store("recipient-reconnected")
	r.connected.Store(true)
	r.sharingPairLive()
	select {
	case <-second:
	case <-time.After(5 * time.Second):
		t.Fatal("inbox not replayed after reconnect")
	}
	waitSharing(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.messages.acks == 1 })
	if maxInflight.Load() != 1 || calls.Load() != 2 {
		t.Fatal("overlapping or missing redelivery")
	}
}

func TestSharingCoordinatorRetriesTransientAndClose(t *testing.T) {
	f, i, r := coordinatorClients(t, true)
	f.mu.Lock()
	f.failLists = 2
	f.mu.Unlock()
	i.EnableSharingPairs()
	waitSharing(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.failLists == 0 })
	waitSharingIdle(t, f)
	started := make(chan struct{})
	r.OnSharingMessage(func(ctx context.Context, m SharingMessage) error { close(started); <-ctx.Done(); return ctx.Err() })
	sendCoordinatorMessage(t, i, "close")
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("missing handler")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	before := f.principalCalls[r.PrincipalID()]
	f.mu.Unlock()
	r.EnableSharingPairs()
	r.OnSharingMessage(nil)
	time.Sleep(150 * time.Millisecond)
	f.mu.Lock()
	after := f.principalCalls[r.PrincipalID()]
	f.mu.Unlock()
	if after != before {
		t.Fatal("closed coordinator restarted")
	}
}

func TestSharingCoordinatorOverflowFencesSession(t *testing.T) {
	f, i, _ := coordinatorClients(t, true)
	i.EnableSharingPairs()
	waitSharingIdle(t, f)
	// Fill the idle worker's bounded map without signalling it. Session
	// cancellation is the reconnect/rescan fence even without a fixture WS.
	i.sharingMu.Lock()
	s := i.sharingCoordinator
	for n := 0; n < sharingPairWakeCap; n++ {
		s.pending[fmt.Sprint(n)] = sharingPairWake{GrantID: fmt.Sprint(n), Generation: 1, Kind: "state"}
	}
	oldCtx := s.ctx
	i.sharingMu.Unlock()
	i.queueSharingPairWake(sharingPairWake{"overflow", 1, "state"})
	i.sharingMu.Lock()
	cancelled := s.ctx == nil && s.full
	i.sharingMu.Unlock()
	if !cancelled || oldCtx.Err() == nil {
		t.Fatal("overflow failed to force session cancellation/full rescan")
	}
}

func TestSharingCoordinatorWebSocketWakeAndOverflowReconnect(t *testing.T) {
	f, i, _ := coordinatorClients(t, true)
	frames := make(chan transport.Envelope, 1)
	stop := make(chan struct{})
	serverClosed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		socket, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer socket.Close()
		go func() {
			defer close(serverClosed)
			for {
				if _, _, err := socket.ReadMessage(); err != nil {
					return
				}
			}
		}()
		for {
			select {
			case frame := <-frames:
				if err := socket.WriteJSON(frame); err != nil {
					return
				}
			case <-serverClosed:
				return
			case <-stop:
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(stop) })
	socket, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pc := &conn{ws: socket, c: i, dead: make(chan struct{})}
	i.connMu.Lock()
	i.cur = pc
	i.connMu.Unlock()
	go pc.readLoop()
	t.Cleanup(func() { socket.Close(); <-pc.dead; i.connMu.Lock(); i.cur = nil; i.connMu.Unlock() })
	i.EnableSharingPairs()
	waitSharingIdle(t, f)
	before := f.count()
	wake, err := transport.NewEnvelope(sharingPairWakeType, sharingPairWake{"grant", 1, "state"})
	if err != nil {
		t.Fatal(err)
	}
	frames <- wake
	waitSharing(t, func() bool { return f.count() > before })
	waitSharingIdle(t, f)
	i.sharingMu.Lock()
	for n := 0; n < sharingPairWakeCap; n++ {
		key := fmt.Sprint(n)
		i.sharingCoordinator.pending[key] = sharingPairWake{key, 1, "state"}
	}
	i.sharingMu.Unlock()
	i.queueSharingPairWake(sharingPairWake{"overflow", 1, "message"})
	select {
	case <-serverClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("overflow did not close websocket for reconnect")
	}
}

func TestSharingCoordinatorMalformedWakeReconnects(t *testing.T) {
	fs := newFakeServer(t)
	principal, credential := fs.createPrincipal("agent", "pair-wake")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Connect(ctx, Config{Server: fs.URL(), Credential: credential, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.EnableSharingPairs()
	oldEndpoint, oldGeneration := client.endpointID.Load(), client.connGeneration.Load()
	fs.mu.Lock()
	endpoint := fs.endpoints[oldEndpoint]
	fs.mu.Unlock()
	if endpoint == nil {
		t.Fatal("missing live endpoint")
	}
	if err := fs.sendTo(endpoint, sharingPairWakeType, map[string]any{"grantId": "grant", "generation": 0, "kind": "state"}); err != nil {
		t.Fatal(err)
	}
	waitSharing(t, func() bool {
		client.sharingMu.Lock()
		defer client.sharingMu.Unlock()
		coordinator := client.sharingCoordinator
		return client.connected.Load() && client.PrincipalID() == principal && client.endpointID.Load() != oldEndpoint && client.connGeneration.Load() > oldGeneration && coordinator.ctx != nil && coordinator.connection == client.connGeneration.Load()
	})
}

func TestSharingCoordinatorFailurePreservesNewerTrigger(t *testing.T) {
	for _, trigger := range []string{"handler", "manual", "wake"} {
		t.Run(trigger, func(t *testing.T) {
			f, i, r := coordinatorClients(t, true)
			started := make(chan struct{})
			release := make(chan struct{})
			delivered := make(chan struct{})
			var calls atomic.Int32
			handler := func(ctx context.Context, m SharingMessage) error {
				if calls.Add(1) == 1 {
					close(started)
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
					return errors.New("old callback failed")
				}
				close(delivered)
				return nil
			}
			r.OnSharingMessage(handler)
			sendCoordinatorMessage(t, i, "new trigger must survive")
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("missing old handler")
			}
			switch trigger {
			case "handler":
				r.OnSharingMessage(func(context.Context, SharingMessage) error { calls.Add(1); close(delivered); return nil })
			case "manual":
				r.EnableSharingPairs()
			case "wake":
				r.queueSharingPairWake(sharingPairWake{"grant", 1, "message"})
			}
			close(release)
			select {
			case <-delivered:
			case <-time.After(5 * time.Second):
				t.Fatal("new trigger lost after old failure")
			}
			waitSharing(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.messages.acks == 1 })
			if calls.Load() != 2 {
				t.Fatalf("handler calls %d", calls.Load())
			}
		})
	}
}
