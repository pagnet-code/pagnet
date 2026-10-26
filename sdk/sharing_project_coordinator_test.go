package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

type projectCoordinatorFixture struct {
	mu                 sync.Mutex
	project            string
	clients            []*Client
	status             SharingProjectStatus
	inbox              map[string][]json.RawMessage
	acked              map[string]bool
	calls, acks, lists int
	failACK            bool
}

func newProjectCoordinatorFixture(t *testing.T) *projectCoordinatorFixture {
	t.Helper()
	project, clients := projectMessageFixture(t)
	d, hash, err := clients[0].projectMessageDescriptor(project)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(d)
	f := &projectCoordinatorFixture{project: project, clients: clients, status: SharingProjectStatus{ProjectID: project, NetworkID: d.NetworkID, State: "active", Descriptor: raw, DescriptorHash: hash, RosterSize: len(d.Roster), EndpointProved: true}, inbox: map[string][]json.RawMessage{}, acked: map[string]bool{}}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	for _, c := range clients {
		c.closeCh, c.terminalCh = make(chan struct{}), make(chan struct{})
		c.endpointID.Store(c.PrincipalID())
		c.credential.Store("pgn_epd_v1_test")
		c.connected.Store(true)
		c.connGeneration.Store(1)
		c.rest = newRestClient(server.URL, "test", func() string { return "pgn_epd_v1_test" })
		client := c
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	return f
}

func (f *projectCoordinatorFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch {
	case strings.HasSuffix(r.URL.Path, "/sharing-project-transports"):
		f.lists++
		write([]SharingProjectStatus{f.status})
	case strings.HasSuffix(r.URL.Path, "/status"), strings.HasSuffix(r.URL.Path, "/pin"):
		write(f.status)
	case strings.HasSuffix(r.URL.Path, "/messages"):
		messages := []json.RawMessage{}
		for _, raw := range f.inbox[r.URL.Query().Get("endpointId")] {
			var wire sharingProjectMessageWire
			_ = json.Unmarshal(raw, &wire)
			if !f.acked[wire.ID] {
				messages = append(messages, raw)
			}
		}
		write(messages)
	case strings.HasSuffix(r.URL.Path, "/ack"):
		if f.failACK {
			http.Error(w, "retry", 503)
			return
		}
		parts := strings.Split(r.URL.Path, "/")
		f.acked[parts[len(parts)-2]] = true
		f.acks++
		w.WriteHeader(204)
	default:
		http.NotFound(w, r)
	}
}
func (f *projectCoordinatorFixture) inject(t *testing.T, sender, recipient *Client, kind, body string, predecessor []byte) PreparedSharingProjectMessage {
	t.Helper()
	m, err := sender.PrepareSharingProjectMessage(f.project, recipient.PrincipalID(), kind, []byte(body), predecessor)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.inbox[recipient.PrincipalID()] = append(f.inbox[recipient.PrincipalID()], m.Wire)
	f.mu.Unlock()
	recipient.queueSharingProjectWake(sharingProjectWake{f.project, "message"})
	return m
}
func (f *projectCoordinatorFixture) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }
func (f *projectCoordinatorFixture) waitIdle(t *testing.T) {
	t.Helper()
	waitSharing(t, func() bool { before := f.count(); time.Sleep(30 * time.Millisecond); return before == f.count() })
}

func TestSharingProjectCoordinatorAskReplyAndIdle(t *testing.T) {
	f := newProjectCoordinatorFixture(t)
	alice, bob := f.clients[0], f.clients[1]
	received := make(chan SharingProjectMessage, 2)
	var ready atomic.Int32
	alice.OnSharingProjectReady(func(project string) {
		if project != f.project {
			t.Error("wrong ready project")
		}
		ready.Add(1)
	})
	alice.OnSharingProjectMessage(func(ctx context.Context, m SharingProjectMessage) error { received <- m; return nil })
	bob.OnSharingProjectMessage(func(ctx context.Context, m SharingProjectMessage) error { received <- m; return nil })
	waitSharing(t, func() bool { return ready.Load() > 0 })
	f.waitIdle(t)
	before := f.count()
	time.Sleep(150 * time.Millisecond)
	if f.count() != before {
		t.Fatal("idle coordinator polled")
	}
	ask := f.inject(t, alice, bob, "ASK", "question", nil)
	var got SharingProjectMessage
	select {
	case got = <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("ASK not delivered")
	}
	if got.Header.ID != ask.ID || string(got.Plaintext) != "question" {
		t.Fatal("wrong ASK")
	}
	reply := f.inject(t, bob, alice, "REPLY", "answer", got.Wire)
	select {
	case got = <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("REPLY not delivered")
	}
	if got.Header.ID != reply.ID || string(got.Plaintext) != "answer" {
		t.Fatal("wrong REPLY")
	}
	waitSharing(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.acks == 2 })
}

func TestSharingProjectCoordinatorFailureReconnectAndACKRetry(t *testing.T) {
	f := newProjectCoordinatorFixture(t)
	alice, bob := f.clients[0], f.clients[1]
	var calls atomic.Int32
	bob.OnSharingProjectMessage(func(context.Context, SharingProjectMessage) error { calls.Add(1); panic("callback") })
	f.waitIdle(t)
	f.inject(t, alice, bob, "ASK", "pending", nil)
	waitSharing(t, func() bool { return calls.Load() == 1 })
	f.waitIdle(t)
	before := f.count()
	time.Sleep(150 * time.Millisecond)
	if f.count() != before || calls.Load() != 1 {
		t.Fatal("failed callback retried while idle")
	}
	f.mu.Lock()
	f.failACK = true
	f.mu.Unlock()
	bob.OnSharingProjectMessage(func(context.Context, SharingProjectMessage) error { calls.Add(1); return nil })
	waitSharing(t, func() bool { return calls.Load() >= 2 })
	f.mu.Lock()
	f.failACK = false
	f.mu.Unlock()
	waitSharing(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.acks == 1 })
	// A callback on the old generation is cancelled, then replayed serially.
	started := make(chan struct{})
	var inflight, maxInflight atomic.Int32
	bob.OnSharingProjectMessage(func(ctx context.Context, m SharingProjectMessage) error {
		n := inflight.Add(1)
		defer inflight.Add(-1)
		if n > maxInflight.Load() {
			maxInflight.Store(n)
		}
		select {
		case <-started:
			return nil
		default:
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}
	})
	f.waitIdle(t)
	f.inject(t, alice, bob, "ASK", "reconnect", nil)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("missing callback")
	}
	bob.connected.Store(false)
	bob.sharingPairDisconnected(bob.connGeneration.Load())
	bob.connGeneration.Add(1)
	bob.connected.Store(true)
	bob.sharingPairLive()
	waitSharing(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.acks == 2 })
	if maxInflight.Load() != 1 {
		t.Fatal("callbacks overlapped")
	}
}

func TestSharingCoordinatorProjectOptInDoesNotListPairs(t *testing.T) {
	f := newProjectCoordinatorFixture(t)
	c := f.clients[0]
	c.EnableSharingProjects()
	f.waitIdle(t)
	c.sharingMu.Lock()
	s := c.sharingCoordinator
	if s.pairsEnabled || !s.projectsEnabled {
		t.Error("wrong opt-in")
	}
	// Pair and project work with the same identifier retain distinct keys.
	s.pairsEnabled = true
	c.sharingMu.Unlock()
	c.queueSharingPairWake(sharingPairWake{GrantID: f.project, Generation: 1, Kind: "state"})
	c.queueSharingProjectWake(sharingProjectWake{f.project, "state"})
	f.waitIdle(t)
	c.sharingMu.Lock()
	same := s == c.sharingCoordinator
	c.sharingMu.Unlock()
	if !same {
		t.Fatal("multiple callback workers")
	}
}

func TestSharingProjectCoordinatorEnvelopeAndOverflow(t *testing.T) {
	f := newProjectCoordinatorFixture(t)
	c := f.clients[0]
	c.EnableSharingProjects()
	f.waitIdle(t)
	before := f.count()
	env, err := transport.NewEnvelope(sharingProjectWakeType, sharingProjectWake{f.project, "state"})
	if err != nil {
		t.Fatal(err)
	}
	c.handleSharingProjectWake(nil, env)
	waitSharing(t, func() bool { return f.count() > before })
	f.waitIdle(t)
	c.sharingMu.Lock()
	s := c.sharingCoordinator
	for n := 0; n < sharingPairWakeCap; n++ {
		key := sharingProjectJobKey(strings.Repeat("a", n+1))
		s.pending[key] = sharingPairWake{GrantID: key, Kind: "state"}
	}
	oldCtx := s.ctx
	c.sharingMu.Unlock()
	c.queueSharingProjectWake(sharingProjectWake{f.project, "message"})
	c.sharingMu.Lock()
	cancelled := s.ctx == nil && s.full
	c.sharingMu.Unlock()
	if !cancelled || oldCtx.Err() == nil {
		t.Fatal("project overflow failed to fence session")
	}
}

func TestSharingCoordinatorNamespacedJobs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{}
	c.connected.Store(true)
	s := &sharingCoordinator{ctx: ctx, notify: make(chan struct{}, 1), pending: map[string]sharingPairWake{}, blocked: map[string]bool{}, grantRevision: map[string]uint64{}, pairsEnabled: true, projectsEnabled: true}
	c.sharingCoordinator = s
	c.queueSharingPairWake(sharingPairWake{GrantID: enrollmentProjectID, Generation: 1, Kind: "message"})
	c.queueSharingProjectWake(sharingProjectWake{enrollmentProjectID, "state"})
	c.queueSharingProjectWake(sharingProjectWake{enrollmentProjectID, "message"})
	if len(s.pending) != 2 {
		t.Fatal("project wake collided with pair wake")
	}
	seen := map[bool]string{}
	for n := 0; n < 2; n++ {
		job, ok := c.nextSharingJob(s)
		if !ok {
			t.Fatal("missing job")
		}
		seen[job.project] = job.kind
	}
	if seen[true] != "state" || seen[false] != "message" {
		t.Fatal("wake kind or namespace lost")
	}
}
