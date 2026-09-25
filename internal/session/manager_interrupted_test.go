package session

// ErrTurnInterrupted contract (the accepted-then-died split, layer 2) +
// activation single-flight + locked state queries.
//
// When the driver's endpoint dies AFTER the runtime accepted the turn, the
// driver reports ErrTurnInterrupted (the contract in driver.go). This file
// proves the Manager's side:
//
//   - an ErrTurnInterrupted is NEVER re-submitted (zero automatic retries —
//     the outcome may be partially applied);
//   - the session is settled (not wedged Busy) and PRESERVED: a
//     materialised session keeps its native id (the next explicit retry
//     resumes it), an unmaterialised one cold-starts;
//   - at most ONE Driver.Activate runs per instance at a time (a concurrent
//     EnsureActive joins the in-flight activation instead of launching a
//     second runtime);
//   - the locked State/NativeID queries are race-free against live state
//     transitions (the daemon reads session state through them).

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

// interruptDriver is a Driver double whose endpoint ACCEPTS the prompt turn
// (it emits EventTurnStarted) and then dies before a terminal result:
// Submit returns ErrTurnInterrupted, exactly as QwenPersistent does when the
// endpoint process disappears after the runtime accepted the submit. Once
// the interrupt budget is spent the endpoint is healthy and turns complete.
type interruptDriver struct {
	mu          sync.Mutex
	activations int
	submits     int
	interrupts  int
	live        bool
}

func (d *interruptDriver) setInterrupts(n int) {
	d.mu.Lock()
	d.interrupts = n
	d.mu.Unlock()
}

func (d *interruptDriver) counts() (activations, submits int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.activations, d.submits
}

func (d *interruptDriver) Name() domain.RuntimeName { return domain.RuntimeFake }

func (d *interruptDriver) Capabilities() Capabilities {
	return Capabilities{
		PersistentEndpoint: true,
		StructuredEvents:   true,
		NativeSubmit:       true,
	}
}

func (d *interruptDriver) Activate(ctx context.Context, sess *RuntimeSession, events chan<- SessionEvent) (*RuntimeEndpoint, error) {
	d.mu.Lock()
	d.activations++
	resume := sess.NativeID != ""
	// The driver sets sess.NativeID as the native exchange happens (the
	// Driver contract); EnsureActive runs this under the per-instance
	// activation lock, so the write is serialized with the NativeID query.
	if !resume {
		sess.NativeID = "native-interrupted"
	}
	d.live = true
	pid := 3000 + d.activations
	d.mu.Unlock()
	if events != nil {
		if resume {
			events <- SessionEvent{Type: EventSessionResumed, SessionID: sess.NativeID}
		} else {
			events <- SessionEvent{Type: EventSessionStarted, SessionID: sess.NativeID}
		}
	}
	return &RuntimeEndpoint{
		ID:        "ep-interrupt-" + sess.NativeID,
		Runtime:   sess.Runtime,
		Ownership: OwnershipPagnet,
		Lease:     LeaseClaimed,
		PID:       pid,
		PGID:      pid,
		Healthy:   true,
		Transport: "stdio",
		Sessions:  []string{sess.NativeID},
		StartedAt: time.Now(),
	}, nil
}

func (d *interruptDriver) Submit(ctx context.Context, sess *RuntimeSession, req SubmitRequest, events chan<- SessionEvent) error {
	if req.Kind == SubmitInteraction {
		return nil
	}
	d.mu.Lock()
	d.submits++
	interrupt := d.interrupts > 0
	if interrupt {
		d.interrupts--
		// The endpoint process is gone: the liveness probe the Manager
		// consults on the next EnsureActive must see it.
		d.live = false
	}
	d.mu.Unlock()
	if interrupt {
		// The runtime ACCEPTED the turn (EventTurnStarted) and then the
		// endpoint died: NO terminal event, ErrTurnInterrupted.
		events <- SessionEvent{Type: EventTurnStarted, SessionID: sess.NativeID, TurnID: req.TurnID}
		return ErrTurnInterrupted
	}
	events <- SessionEvent{Type: EventTurnStarted, SessionID: sess.NativeID, TurnID: req.TurnID}
	events <- SessionEvent{Type: EventTurnOutput, SessionID: sess.NativeID, TurnID: req.TurnID, Output: "echo: " + req.Input}
	events <- SessionEvent{Type: EventTurnCompleted, SessionID: sess.NativeID, TurnID: req.TurnID, Model: "interrupt-mem-1"}
	return nil
}

func (d *interruptDriver) Hibernate(ctx context.Context, sess *RuntimeSession) error {
	d.mu.Lock()
	d.live = false
	d.mu.Unlock()
	return nil
}

func (d *interruptDriver) Stop(instanceID string) error {
	d.mu.Lock()
	d.live = false
	d.mu.Unlock()
	return nil
}

func (d *interruptDriver) PID(instanceID string) *int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.live {
		return nil
	}
	p := 3000 + d.activations
	return &p
}

func (d *interruptDriver) Live(instanceID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.live
}

// TestManager_TurnInterrupted_NeverResubmitted is the core contract: an
// accepted turn whose endpoint died is surfaced as ErrTurnInterrupted with
// ZERO automatic re-submits, the session is not wedged, and it is
// PRESERVED (invariant A4): the materialised session keeps its native id
// and the next EXPLICIT submit resumes it.
func TestManager_TurnInterrupted_NeverResubmitted(t *testing.T) {
	d := &interruptDriver{}
	m := newTestManager(t, d)
	sess := m.Session("inst-interrupted", domain.RuntimeFake, "/tmp/ws")

	// Turn 1 completes normally: the session is materialised.
	res, err, _ := runSubmit(t, m, sess, "t1", "first")
	if err != nil || !res.Completed {
		t.Fatalf("turn 1: err=%v res=%+v, want a completed turn", err, res)
	}
	nativeID := sess.NativeID
	if nativeID == "" {
		t.Fatal("no native id after turn 1")
	}

	// Turn 2 is ACCEPTED and then the endpoint dies mid-turn.
	d.setInterrupts(1)
	res, err, evs := runSubmit(t, m, sess, "t2", "second")
	if !errors.Is(err, ErrTurnInterrupted) {
		t.Fatalf("turn 2: err=%v, want ErrTurnInterrupted surfaced", err)
	}
	if res.Completed {
		t.Fatal("an interrupted turn must not report completion")
	}
	// ZERO automatic re-submits: exactly one submit reached the endpoint
	// for turn 2 (the accepted one — never re-written).
	acts, subs := d.counts()
	if subs != 2 {
		t.Fatalf("submits = %d, want exactly 2 (t1 + the accepted t2 — an interrupted turn is NEVER re-submitted)", subs)
	}
	if acts != 1 {
		t.Fatalf("activations = %d, want 1 (an interrupted turn is not re-activated automatically)", acts)
	}
	// The session is settled, not wedged Busy.
	if st, _ := m.State("inst-interrupted"); st == StateBusy {
		t.Fatal("session wedged Busy after the interruption")
	}
	if st, _ := m.State("inst-interrupted"); st != StateInactive {
		t.Fatalf("post-interruption state = %v, want inactive", st)
	}
	// PRESERVED (A4): the materialised session keeps its native id (the
	// next explicit retry resumes it — no cold start, no deletion).
	if id, _ := m.NativeID("inst-interrupted"); id != nativeID {
		t.Fatalf("native id after interruption = %q, want %q preserved", id, nativeID)
	}
	// The turn was cut off: no terminal event was fabricated for it.
	if n := countEvents(evs, EventTurnCompleted); n != 0 {
		t.Fatalf("the interrupted turn produced %d completions, want 0", n)
	}

	// The next EXPLICIT submit re-activates and RESUMES the same session.
	res, err, evs = runSubmit(t, m, sess, "t3", "third")
	if err != nil || !res.Completed {
		t.Fatalf("explicit retry: err=%v res=%+v, want a completed turn", err, res)
	}
	if id, _ := m.NativeID("inst-interrupted"); id != nativeID {
		t.Fatalf("native id after the explicit retry = %q, want %q (resumed, not fresh)", id, nativeID)
	}
	if n := countEvents(evs, EventSessionResumed); n != 1 {
		t.Fatalf("the explicit retry did not resume the session once: %v", evs)
	}
	acts, subs = d.counts()
	if subs != 3 {
		t.Fatalf("submits after the explicit retry = %d, want 3 (t1 + t2 + t3)", subs)
	}
	if acts != 2 {
		t.Fatalf("activations after the explicit retry = %d, want 2 (initial + the retry's re-activation)", acts)
	}
}

// TestManager_TurnInterrupted_UnmaterialisedColdStarts proves the
// conservative half of invariant A4: an UNMATERIALISED session (no real
// exchange reached the runtime) has a stale minted native id after an
// interruption — it is cleared, and the next explicit submit cold-starts a
// fresh session instead of tripping the resume gate.
func TestManager_TurnInterrupted_UnmaterialisedColdStarts(t *testing.T) {
	d := &interruptDriver{}
	m := newTestManager(t, d)
	sess := m.Session("inst-interrupt-unmat", domain.RuntimeFake, "/tmp/ws")

	// The FIRST turn (nothing materialised yet) is accepted, then the
	// endpoint dies.
	d.setInterrupts(1)
	_, err, _ := runSubmit(t, m, sess, "t1", "first")
	if !errors.Is(err, ErrTurnInterrupted) {
		t.Fatalf("turn 1: err=%v, want ErrTurnInterrupted surfaced", err)
	}
	if id, _ := m.NativeID("inst-interrupt-unmat"); id != "" {
		t.Fatalf("unmaterialised session kept native id %q after the interruption; want it cleared (nothing durable to resume)", id)
	}
	if st, _ := m.State("inst-interrupt-unmat"); st != StateInactive {
		t.Fatalf("post-interruption state = %v, want inactive", st)
	}

	// The next explicit submit cold-starts (a fresh session, not a resume).
	res, err, evs := runSubmit(t, m, sess, "t2", "second")
	if err != nil || !res.Completed {
		t.Fatalf("explicit retry: err=%v res=%+v, want a completed turn", err, res)
	}
	if n := countEvents(evs, EventSessionStarted); n != 1 {
		t.Fatalf("the cold start did not start a fresh session once: %v", evs)
	}
	if n := countEvents(evs, EventSessionResumed); n != 0 {
		t.Fatalf("an unmaterialised session must not be resumed: %v", evs)
	}
}

// gatedActivationDriver is a Driver double whose FIRST Activate blocks on a
// gate (the test holds it open), so a concurrent EnsureActive can be
// observed racing an in-flight activation.
type gatedActivationDriver struct {
	mu        sync.Mutex
	activated int
	started   chan struct{} // closed when the first Activate begins
	gate      chan struct{} // the first Activate blocks until this is closed
	live      bool
}

func (d *gatedActivationDriver) Name() domain.RuntimeName { return domain.RuntimeFake }

func (d *gatedActivationDriver) Capabilities() Capabilities {
	return Capabilities{
		PersistentEndpoint: true,
		StructuredEvents:   true,
		NativeSubmit:       true,
	}
}

func (d *gatedActivationDriver) Activate(ctx context.Context, sess *RuntimeSession, events chan<- SessionEvent) (*RuntimeEndpoint, error) {
	d.mu.Lock()
	d.activated++
	first := d.activated == 1
	d.live = true
	pid := 4000 + d.activated
	d.mu.Unlock()
	if first {
		close(d.started)
		<-d.gate // hold the first activation open (the race window)
	}
	// The driver sets sess.NativeID as the native exchange happens (the
	// Driver contract); EnsureActive runs this under the per-instance
	// activation lock, so the write is serialized with the NativeID query.
	if sess.NativeID == "" {
		sess.NativeID = "native-gated"
	}
	if events != nil {
		events <- SessionEvent{Type: EventSessionStarted, SessionID: sess.NativeID}
	}
	return &RuntimeEndpoint{
		ID:        "ep-gated-" + sess.NativeID,
		Runtime:   sess.Runtime,
		Ownership: OwnershipPagnet,
		Lease:     LeaseClaimed,
		PID:       pid,
		PGID:      pid,
		Healthy:   true,
		Transport: "stdio",
		Sessions:  []string{sess.NativeID},
		StartedAt: time.Now(),
	}, nil
}

func (d *gatedActivationDriver) Submit(ctx context.Context, sess *RuntimeSession, req SubmitRequest, events chan<- SessionEvent) error {
	return nil
}

func (d *gatedActivationDriver) Hibernate(ctx context.Context, sess *RuntimeSession) error {
	return nil
}

func (d *gatedActivationDriver) Stop(instanceID string) error { return nil }

func (d *gatedActivationDriver) PID(instanceID string) *int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.live {
		return nil
	}
	p := 4000 + d.activated
	return &p
}

func (d *gatedActivationDriver) Live(instanceID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.live
}

// TestManager_ActivationSingleFlight is the attach-vs-turn race: a second
// EnsureActive arrives while the first is blocked INSIDE Driver.Activate.
// The per-instance activation lock must make it JOIN the first activation
// (reconcile to the live endpoint) instead of launching a SECOND runtime:
// Driver.Activate is called exactly ONCE.
func TestManager_ActivationSingleFlight(t *testing.T) {
	d := &gatedActivationDriver{
		started: make(chan struct{}),
		gate:    make(chan struct{}),
	}
	m := newTestManager(t, d)
	sess := m.Session("inst-singleflight", domain.RuntimeFake, "/tmp/ws")

	type result struct {
		ep  *RuntimeEndpoint
		err error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			ep, err := m.EnsureActive(context.Background(), sess, nil)
			results <- result{ep, err}
		}()
	}
	close(start)

	// The first EnsureActive is now INSIDE Driver.Activate (blocked on the
	// gate); the second EnsureActive is blocked on the per-instance
	// activation lock (or will join after the first settles).
	<-d.started
	// Give the second caller a moment to reach the lock (it must not
	// matter whether it is blocked or still starting — the invariant is on
	// the activation count, not on the interleaving).
	time.Sleep(50 * time.Millisecond)
	close(d.gate)

	var eps []*RuntimeEndpoint
	var errs []error
	for i := 0; i < 2; i++ {
		r := <-results
		eps = append(eps, r.ep)
		errs = append(errs, r.err)
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("EnsureActive %d: %v", i+1, err)
		}
	}
	if d.activated != 1 {
		t.Fatalf("Driver.Activate called %d times, want exactly 1 (a concurrent EnsureActive must join the in-flight activation, not launch a second runtime)", d.activated)
	}
	if eps[0] == nil || eps[1] == nil {
		t.Fatalf("EnsureActive returned a nil endpoint: %+v", eps)
	}
	if eps[0].ID != eps[1].ID {
		t.Fatalf("the two EnsureActive calls returned different endpoints: %q vs %q (want the same live endpoint)", eps[0].ID, eps[1].ID)
	}
	if st, _ := m.State("inst-singleflight"); st != StateIdle {
		t.Fatalf("post-activation state = %v, want idle", st)
	}
}

// TestManager_StateQueryConcurrent hammers the locked State/NativeID
// queries while real turns drive the session through its state
// transitions (Inactive → Activating → Busy → Idle, plus endpoint deaths).
// Under `go test -race` this is the proof that the daemon's state reads
// (routed through these queries) are race-free against the Manager's
// mutations — the unsynchronized sess.State read the daemon used to do is
// what the race detector would catch.
func TestManager_StateQueryConcurrent(t *testing.T) {
	d := &interruptDriver{}
	m := newTestManager(t, d)
	sess := m.Session("inst-state-race", domain.RuntimeFake, "/tmp/ws")

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if st, ok := m.State("inst-state-race"); !ok {
				t.Error("State query reported no session for a live instance")
				return
			} else if st == StateBusy && d.Live("inst-state-race") == false {
				// Busy with a dead endpoint is a legitimate transient
				// (the death window); nothing to assert — the read itself
				// being race-free is the point.
				_ = st
			}
			if _, ok := m.NativeID("inst-state-race"); !ok {
				t.Error("NativeID query reported no session for a live instance")
				return
			}
		}
	}()
	// Drive real turns (including one accepted-then-died) so the state
	// transitions and endpoint mutations race the reader.
	d.setInterrupts(1)
	for i := 0; i < 6; i++ {
		_, err, _ := runSubmit(t, m, sess, fmt.Sprintf("t%d", i), "input")
		if i == 0 {
			// The interrupt lands on the first turn (unmaterialised).
			if !errors.Is(err, ErrTurnInterrupted) {
				t.Fatalf("turn 0: err=%v, want ErrTurnInterrupted", err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("turn %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
}
