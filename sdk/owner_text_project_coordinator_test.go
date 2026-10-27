package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/transport"
)

type ownerTextCoordinatorFixture struct {
	mu           sync.Mutex
	transport    *ownerTextTransportFixture
	inbox        map[string][]json.RawMessage
	acked        map[string]bool
	calls, lists int
	repeatWire   []byte
	repeatCount  int
}

func newOwnerTextCoordinatorFixture(t *testing.T) *ownerTextCoordinatorFixture {
	t.Helper()
	f := &ownerTextCoordinatorFixture{transport: newOwnerTextTransportFixture(t), inbox: map[string][]json.RawMessage{}, acked: map[string]bool{}}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	for _, c := range f.transport.clients {
		c.closeCh, c.terminalCh = make(chan struct{}), make(chan struct{})
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
func (f *ownerTextCoordinatorFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	base := "/api/v1/owner-text-project-transports"
	if r.URL.Path == base {
		f.lists++
		_ = json.NewEncoder(w).Encode([]OwnerTextProjectStatus{f.transport.status})
		return
	}
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages") {
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil || limit < 1 || limit > 50 {
			f.transport.t.Error("coordinator inbox must be bounded")
		}
		if f.repeatCount > 0 {
			remaining := f.repeatCount - f.transport.acks
			count := remaining
			if count > limit {
				count = limit
			}
			messages := make([]json.RawMessage, count)
			for i := range messages {
				messages[i] = f.repeatWire
			}
			if remaining > count {
				w.Header().Set("X-Next-Cursor", strconv.Itoa(f.transport.acks+count))
			}
			_ = json.NewEncoder(w).Encode(messages)
			return
		}
		messages := []json.RawMessage{}
		for _, raw := range f.inbox[r.URL.Query().Get("endpointId")] {
			var wire ownerTextProjectMessageWire
			_ = json.Unmarshal(raw, &wire)
			if !f.acked[wire.ID] {
				messages = append(messages, raw)
			}
		}
		_ = json.NewEncoder(w).Encode(messages)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/ack") && !f.transport.failACK {
		parts := strings.Split(r.URL.Path, "/")
		f.acked[parts[len(parts)-2]] = true
	}
	f.transport.serve(w, r)
}
func (f *ownerTextCoordinatorFixture) enable(t *testing.T, index int) {
	t.Helper()
	if err := f.transport.clients[index].EnableOwnerTextProjects(f.transport.status.Roles[index].InstallationID); err != nil {
		t.Fatal(err)
	}
}
func (f *ownerTextCoordinatorFixture) inject(t *testing.T, sender, recipient int, kind, body string, previous []byte) PreparedOwnerTextProjectMessage {
	t.Helper()
	c, peer := f.transport.clients[sender], f.transport.clients[recipient]
	prepared, err := c.PrepareOwnerTextProjectMessage(f.transport.project, peer.PrincipalID(), kind, []byte(body), previous)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.inbox[peer.endpointID.Load()] = append(f.inbox[peer.endpointID.Load()], prepared.Wire)
	f.mu.Unlock()
	peer.queueOwnerTextProjectWake(ownerTextProjectWake{f.transport.project, "message"})
	return prepared
}
func (f *ownerTextCoordinatorFixture) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }
func (f *ownerTextCoordinatorFixture) waitIdle(t *testing.T) {
	t.Helper()
	waitSharing(t, func() bool { before := f.count(); time.Sleep(30 * time.Millisecond); return before == f.count() })
}
func TestOwnerTextMessageCoordinatorAskReplyAndIdle(t *testing.T) {
	f := newOwnerTextCoordinatorFixture(t)
	sender, responder := f.transport.clients[0], f.transport.clients[1]
	received := make(chan OwnerTextProjectMessage, 2)
	sender.OnOwnerTextProjectMessage(func(ctx context.Context, m OwnerTextProjectMessage) error { received <- m; return nil })
	responder.OnOwnerTextProjectMessage(func(ctx context.Context, m OwnerTextProjectMessage) error { received <- m; return nil })
	f.enable(t, 0)
	f.enable(t, 1)
	f.waitIdle(t)
	before := f.count()
	time.Sleep(150 * time.Millisecond)
	if f.count() != before {
		t.Fatal("idle owner coordinator polled")
	}
	ask := f.inject(t, 0, 1, "ASK", "question", nil)
	var got OwnerTextProjectMessage
	select {
	case got = <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("ASK not delivered")
	}
	if got.Header.ID != ask.ID {
		t.Fatal("wrong ASK")
	}
	waitSharing(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.acked[ask.ID] })
	reply := f.inject(t, 1, 0, "REPLY", "answer", got.Wire)
	select {
	case got = <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("REPLY not delivered")
	}
	if got.Header.ID != reply.ID || string(got.Plaintext) != "answer" {
		t.Fatal("wrong REPLY")
	}
	waitSharing(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.transport.acks == 2 })
}
func TestOwnerTextMessageCoordinatorHandlerFailureAndReconnect(t *testing.T) {
	for _, failure := range []string{"error", "panic"} {
		t.Run(failure, func(t *testing.T) {
			f := newOwnerTextCoordinatorFixture(t)
			responder := f.transport.clients[1]
			var calls atomic.Int32
			responder.OnOwnerTextProjectMessage(func(context.Context, OwnerTextProjectMessage) error {
				calls.Add(1)
				if failure == "panic" {
					panic("callback")
				}
				return errors.New("retry")
			})
			f.enable(t, 1)
			f.waitIdle(t)
			f.inject(t, 0, 1, "ASK", "pending", nil)
			waitSharing(t, func() bool { return calls.Load() == 1 })
			f.waitIdle(t)
			before := f.count()
			time.Sleep(150 * time.Millisecond)
			f.mu.Lock()
			acks := f.transport.acks
			f.mu.Unlock()
			if f.count() != before || calls.Load() != 1 || acks != 0 {
				t.Fatal("failed callback ACKed or retried while idle")
			}
			responder.OnOwnerTextProjectMessage(func(context.Context, OwnerTextProjectMessage) error { calls.Add(1); return nil })
			waitSharing(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.transport.acks == 1 })
			if calls.Load() != 2 {
				t.Fatal("failure not redelivered")
			}
			started := make(chan struct{})
			var inFlight, maxInFlight atomic.Int32
			responder.OnOwnerTextProjectMessage(func(ctx context.Context, m OwnerTextProjectMessage) error {
				active := inFlight.Add(1)
				defer inFlight.Add(-1)
				if active > maxInFlight.Load() {
					maxInFlight.Store(active)
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
			f.inject(t, 0, 1, "ASK", "reconnect", nil)
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("callback missing")
			}
			responder.connected.Store(false)
			responder.sharingPairDisconnected(responder.connGeneration.Load())
			f.mu.Lock()
			f.transport.status.Roles[1].Ready = false
			f.transport.status.PrincipalsProved = 1
			f.transport.status.Ready = false
			f.mu.Unlock()
			responder.connGeneration.Add(1)
			responder.connected.Store(true)
			responder.sharingPairLive()
			waitSharing(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.transport.acks == 2 })
			f.mu.Lock()
			proofs := f.transport.proofs
			f.mu.Unlock()
			if proofs != 1 || maxInFlight.Load() != 1 {
				t.Fatalf("reconnect: proofs=%d maxHandlers=%d", proofs, maxInFlight.Load())
			}
		})
	}
}
func TestOwnerTextMessageCoordinatorMaxInFlightReplyAfterACK(t *testing.T) {
	f := newOwnerTextCoordinatorFixture(t)
	responder := f.transport.clients[1]
	var outbox *PreparedOwnerTextProjectMessage
	sent := make(chan string, 1)
	responder.OnOwnerTextProjectMessage(func(ctx context.Context, m OwnerTextProjectMessage) error {
		prepared, err := responder.PrepareOwnerTextProjectMessage(f.transport.project, f.transport.clients[0].PrincipalID(), "REPLY", []byte("answer"), m.Wire)
		if err != nil {
			return err
		}
		outbox = &prepared
		return nil
	})
	responder.OnOwnerTextProjectReady(func(project string) {
		if outbox == nil {
			return
		}
		f.mu.Lock()
		acked := f.acked[*extractOwnerTextCorrelation(t, outbox.Wire)]
		f.mu.Unlock()
		if !acked {
			t.Error("reply scheduled before ASK ACK")
			return
		}
		if _, err := responder.SendPreparedOwnerTextProjectMessage(context.Background(), project, outbox.ID); err != nil {
			t.Error(err)
			return
		}
		sent <- outbox.ID
		outbox = nil
	})
	f.enable(t, 1)
	f.waitIdle(t)
	f.inject(t, 0, 1, "ASK", "question", nil)
	select {
	case <-sent:
	case <-time.After(5 * time.Second):
		t.Fatal("post-ACK reply not sent")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.transport.posts != 1 || f.transport.acks != 1 {
		t.Fatal("unexpected automatic reply or ACK count")
	}
}
func extractOwnerTextCorrelation(t *testing.T, wire []byte) *string {
	t.Helper()
	var parsed ownerTextProjectMessageWire
	if err := json.Unmarshal(wire, &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed.CorrelationID
}
func TestOwnerTextCoordinatorFrameIsolationCoalescingAndFIFO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{}
	c.connected.Store(true)
	s := &sharingCoordinator{ctx: ctx, cancel: cancel, notify: make(chan struct{}, 1), pending: map[string]sharingPairWake{}, blocked: map[string]bool{}, grantRevision: map[string]uint64{}, pairsEnabled: true, projectsEnabled: true, ownerTextInstallation: ownerTextInstallation}
	c.sharingCoordinator = s
	wrong, _ := transport.NewEnvelope(sharingProjectWakeType, sharingProjectWake{enrollmentProjectID, "state"})
	c.handleOwnerTextProjectWake(nil, wrong)
	if len(s.pending) != 0 {
		t.Fatal("sharing frame reached owner queue")
	}
	owner, _ := transport.NewEnvelope(ownerTextProjectWakeType, ownerTextProjectWake{enrollmentProjectID, "message"})
	c.handleOwnerTextProjectWake(nil, owner)
	c.handleOwnerTextProjectWake(nil, owner)
	c.queueSharingProjectWake(sharingProjectWake{enrollmentProjectID, "state"})
	c.queueSharingPairWake(sharingPairWake{GrantID: enrollmentProjectID, Generation: 1, Kind: "message"})
	if len(s.pending) != 3 || len(s.pendingOrder) != 3 {
		t.Fatal("domain collision or duplicate wake not coalesced")
	}
	job, ok := c.nextSharingJob(s)
	if !ok || !job.ownerProject || job.project || job.key != ownerTextProjectJobKey(enrollmentProjectID) {
		t.Fatal("wrong owner job")
	}
	c.queueOwnerTextProjectWake(ownerTextProjectWake{enrollmentProjectID, "message"})
	job, ok = c.nextSharingJob(s)
	if !ok || !job.project {
		t.Fatal("requeue did not preserve FIFO fairness")
	}
	job, ok = c.nextSharingJob(s)
	if !ok || job.project || job.ownerProject {
		t.Fatal("pair namespace lost")
	}
	job, ok = c.nextSharingJob(s)
	if !ok || !job.ownerProject {
		t.Fatal("owner requeue not at tail")
	}
	s.blocked[sharingProjectJobKey(enrollmentProjectID)] = true
	s.blocked[ownerTextProjectJobKey(enrollmentProjectID)] = true
	c.queueOwnerTextProjectWake(ownerTextProjectWake{enrollmentProjectID, "message"})
	if s.blocked[ownerTextProjectJobKey(enrollmentProjectID)] || !s.blocked[sharingProjectJobKey(enrollmentProjectID)] {
		t.Fatal("owner wake changed sharing block")
	}
	invalid, _ := transport.NewEnvelope(ownerTextProjectWakeType, map[string]any{"projectId": enrollmentProjectID, "kind": "message", "extra": true})
	c.handleOwnerTextProjectWake(nil, invalid)
	if s.ctx != nil || ctx.Err() == nil {
		t.Fatal("malformed wake did not fence session")
	}
}

func TestOwnerTextMessageCoordinatorReadyAfterPartialACKFailure(t *testing.T) {
	f := newOwnerTextCoordinatorFixture(t)
	responder := f.transport.clients[1]
	first := f.inject(t, 0, 1, "ASK", "first", nil)
	second := f.inject(t, 0, 1, "ASK", "second", nil)
	var calls atomic.Int32
	ready := make(chan bool, 1)
	responder.OnOwnerTextProjectMessage(func(context.Context, OwnerTextProjectMessage) error {
		if calls.Add(1) == 2 {
			return errors.New("second handler failed")
		}
		return nil
	})
	responder.OnOwnerTextProjectReady(func(string) {
		f.mu.Lock()
		acked := f.acked[first.ID] && !f.acked[second.ID]
		f.mu.Unlock()
		ready <- acked
	})
	f.enable(t, 1)
	select {
	case acked := <-ready:
		if !acked {
			t.Fatal("ready did not follow committed ACK before later failure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("committed ACK did not notify ready")
	}
	f.waitIdle(t)
	if calls.Load() != 2 {
		t.Fatal("failed later message retried while idle")
	}
}

func TestOwnerTextMessageCoordinatorCapRequeuesWithoutTimer(t *testing.T) {
	f := newOwnerTextCoordinatorFixture(t)
	responder := f.transport.clients[1]
	prepared, err := f.transport.clients[0].PrepareOwnerTextProjectMessage(f.transport.project, responder.PrincipalID(), "ASK", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.repeatWire = prepared.Wire
	f.repeatCount = 257
	f.mu.Unlock()
	var calls atomic.Int32
	batches := make(chan int, 2)
	responder.OnOwnerTextProjectMessage(func(context.Context, OwnerTextProjectMessage) error { calls.Add(1); return nil })
	responder.OnOwnerTextProjectReady(func(string) { f.mu.Lock(); acks := f.transport.acks; f.mu.Unlock(); batches <- acks })
	f.enable(t, 1)
	for _, expected := range []int{256, 257} {
		select {
		case acks := <-batches:
			if acks != expected {
				t.Fatalf("batch ACKs=%d want %d", acks, expected)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("bounded drain did not requeue")
		}
	}
	if calls.Load() != 257 {
		t.Fatal("pending messages lost at drain cap")
	}
	f.waitIdle(t)
	before := f.count()
	time.Sleep(150 * time.Millisecond)
	if f.count() != before {
		t.Fatal("drain cap introduced idle polling")
	}
}

func TestOwnerTextCoordinatorContinuationCapacity(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "overflow reconnects", true: "coalesces at capacity"}[existing], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := &Client{}
			c.connected.Store(true)
			s := &sharingCoordinator{ctx: ctx, cancel: cancel, notify: make(chan struct{}, 1), pending: map[string]sharingPairWake{}, blocked: map[string]bool{}, grantRevision: map[string]uint64{}, ownerTextInstallation: ownerTextInstallation}
			c.sharingCoordinator = s
			for i := 0; i < sharingPairWakeCap; i++ {
				id := uuid.NewString()
				enqueueSharingPendingLocked(s, ownerTextProjectJobKey(id), sharingPairWake{GrantID: id, Kind: "message"})
			}
			if existing {
				key := s.pendingOrder[0]
				delete(s.pending, key)
				s.pendingOrder = s.pendingOrder[1:]
				enqueueSharingPendingLocked(s, ownerTextProjectJobKey(enrollmentProjectID), sharingPairWake{GrantID: enrollmentProjectID, Kind: "state"})
			}
			job := sharingReconcileJob{ctx: ctx}
			c.requeueOwnerTextProjectDrain(s, job, enrollmentProjectID)
			if existing {
				if len(s.pending) != sharingPairWakeCap || len(s.pendingOrder) != sharingPairWakeCap || s.pendingOrder[len(s.pendingOrder)-1] != ownerTextProjectJobKey(enrollmentProjectID) || s.pending[ownerTextProjectJobKey(enrollmentProjectID)].Kind != "state" {
					t.Fatal("continuation exceeded capacity or lost FIFO/state")
				}
			} else if s.ctx != nil || !s.full || ctx.Err() == nil || len(s.pending) != 0 || len(s.pendingOrder) != 0 {
				t.Fatal("overflow did not fence for resumable full reconciliation")
			}
		})
	}
}
