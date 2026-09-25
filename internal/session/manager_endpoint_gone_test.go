package session

// ErrEndpointGone recovery (the stuck-instance regression, layer 2).
//
// When the driver's endpoint process dies MID-TURN it must report
// ErrEndpointGone (the contract in driver.go), NOT a settled nil and NOT a
// generic process error. This file proves the Manager's side of that
// contract: EnsureActive → Submit → ErrEndpointGone → EnsureActive again
// (resume the SAME materialised session) → the logical submit is retried
// exactly ONCE. A second ErrEndpointGone is surfaced. Either way the session
// must never be wedged Busy, and there must never be an endless retry.
//
// The driver double here is the Manager-level mirror of what
// QwenPersistent.Submit now does on the cleanupOnExit wake path.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

// endpointDeathDriver is a Driver double whose endpoint dies mid-turn for the
// first N prompt submits (N = setDeaths): Submit registers the turn and then
// returns ErrEndpointGone with NO terminal event, exactly as the real drivers
// do when the endpoint process disappears while the turn is in flight. Once
// the death budget is spent the endpoint is healthy and turns complete.
type endpointDeathDriver struct {
	mu          sync.Mutex
	deaths      int
	activations int
	submits     int
	live        bool
}

func (d *endpointDeathDriver) setDeaths(n int) {
	d.mu.Lock()
	d.deaths = n
	d.mu.Unlock()
}

func (d *endpointDeathDriver) counts() (activations, submits int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.activations, d.submits
}

func (d *endpointDeathDriver) Name() domain.RuntimeName { return domain.RuntimeFake }

func (d *endpointDeathDriver) Capabilities() Capabilities {
	return Capabilities{
		PersistentEndpoint: true,
		StructuredEvents:   true,
		NativeSubmit:       true,
	}
}

func (d *endpointDeathDriver) Activate(ctx context.Context, sess *RuntimeSession, events chan<- SessionEvent) (*RuntimeEndpoint, error) {
	d.mu.Lock()
	d.activations++
	resume := sess.NativeID != ""
	if !resume {
		sess.NativeID = "native-mid-turn-death"
	}
	d.live = true
	pid := 2000 + d.activations
	d.mu.Unlock()
	if events != nil {
		if resume {
			events <- SessionEvent{Type: EventSessionResumed, SessionID: sess.NativeID}
		} else {
			events <- SessionEvent{Type: EventSessionStarted, SessionID: sess.NativeID}
		}
	}
	return &RuntimeEndpoint{
		ID:        "ep-death-" + sess.NativeID,
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

func (d *endpointDeathDriver) Submit(ctx context.Context, sess *RuntimeSession, req SubmitRequest, events chan<- SessionEvent) error {
	if req.Kind == SubmitInteraction {
		return nil
	}
	d.mu.Lock()
	d.submits++
	die := d.deaths > 0
	if die {
		d.deaths--
		// The endpoint process is gone: the liveness probe the Manager
		// consults on the next EnsureActive must see it.
		d.live = false
	}
	d.mu.Unlock()
	if die {
		// Mid-turn process death: NO terminal event, and the driver's own
		// liveness probe already reports the endpoint gone.
		return ErrEndpointGone
	}
	events <- SessionEvent{Type: EventTurnStarted, SessionID: sess.NativeID, TurnID: req.TurnID}
	events <- SessionEvent{Type: EventTurnOutput, SessionID: sess.NativeID, TurnID: req.TurnID, Output: "echo: " + req.Input}
	events <- SessionEvent{Type: EventTurnCompleted, SessionID: sess.NativeID, TurnID: req.TurnID, Model: "death-mem-1"}
	return nil
}

func (d *endpointDeathDriver) Hibernate(ctx context.Context, sess *RuntimeSession) error {
	d.mu.Lock()
	d.live = false
	d.mu.Unlock()
	return nil
}

func (d *endpointDeathDriver) Stop(instanceID string) error {
	d.mu.Lock()
	d.live = false
	d.mu.Unlock()
	return nil
}

func (d *endpointDeathDriver) PID(instanceID string) *int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.live {
		return nil
	}
	p := 2000 + d.activations
	return &p
}

func (d *endpointDeathDriver) Live(instanceID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.live
}

// runSubmit drives one prompt turn through the Manager and returns its
// result, its error, and every event it produced (the Manager closes the
// channel, so a plain drain is complete).
func runSubmit(t *testing.T, m *Manager, sess *RuntimeSession, turnID, input string) (*TurnResult, error, []SessionEvent) {
	t.Helper()
	events := make(chan SessionEvent, 64)
	type outcome struct {
		res *TurnResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		r, err := m.Submit(context.Background(), sess, SubmitRequest{
			TurnID: turnID, Kind: SubmitPrompt, Input: input,
		}, events)
		done <- outcome{r, err}
	}()
	var evs []SessionEvent
	for ev := range events {
		evs = append(evs, ev)
	}
	o := <-done
	if o.res == nil {
		t.Fatalf("Submit(%s) returned a nil result (err=%v)", turnID, o.err)
	}
	return o.res, o.err, evs
}

// countEvents returns how many of evs carry the given type.
func countEvents(evs []SessionEvent, ty string) int {
	n := 0
	for _, ev := range evs {
		if ev.Type == ty {
			n++
		}
	}
	return n
}

// TestManager_EndpointDiesMidTurn_ResumesAndRetriesOnce is the recovery
// proof: a materialised session's endpoint dies during the SECOND turn; the
// Manager observes ErrEndpointGone, re-activates the SAME session (a resume,
// not a fresh one), and retries the logical submit once. The turn completes,
// the session is not wedged Busy, and the retry count is exactly one.
func TestManager_EndpointDiesMidTurn_ResumesAndRetriesOnce(t *testing.T) {
	d := &endpointDeathDriver{}
	m := newTestManager(t, d)
	sess := m.Session("inst-midturn", domain.RuntimeFake, "/tmp/ws")

	// Turn 1 completes normally: the session is materialised (it now has
	// durable native state to resume).
	res, err, _ := runSubmit(t, m, sess, "t1", "first")
	if err != nil || !res.Completed {
		t.Fatalf("turn 1: err=%v res=%+v, want a completed turn", err, res)
	}
	if !sess.Materialised {
		t.Fatal("turn 1 did not materialise the session")
	}
	nativeID := sess.NativeID
	if nativeID == "" {
		t.Fatal("no native id after turn 1")
	}
	acts, subs := d.counts()
	if acts != 1 || subs != 1 {
		t.Fatalf("after turn 1: activations=%d submits=%d, want 1/1", acts, subs)
	}

	// Turn 2's endpoint dies MID-TURN (before any terminal event).
	d.setDeaths(1)
	res, err, evs := runSubmit(t, m, sess, "t2", "second")
	if err != nil {
		t.Fatalf("turn 2: err=%v, want the retry to succeed", err)
	}
	if !res.Completed {
		t.Fatalf("turn 2 not completed after the recovery: %+v", res)
	}
	if sess.State == StateBusy {
		t.Fatal("session wedged Busy after the endpoint died mid-turn")
	}
	if sess.State != StateIdle {
		t.Fatalf("post-turn state = %v, want idle", sess.State)
	}
	// The SAME materialised session was resumed (never a silent fresh one).
	if sess.NativeID != nativeID {
		t.Fatalf("native id changed on the recovery: before=%q after=%q", nativeID, sess.NativeID)
	}
	if countEvents(evs, EventSessionResumed) != 1 {
		t.Fatalf("the recovery did not resume the session once: %v", evs)
	}
	// Exactly one re-activation and exactly ONE retry of the logical submit
	// (t1 + the cut-off attempt + the retry), and exactly one completion.
	acts, subs = d.counts()
	if acts != 2 {
		t.Fatalf("activations = %d, want 2 (the original + one re-activation)", acts)
	}
	if subs != 3 {
		t.Fatalf("submits = %d, want 3 (t1 + the cut-off attempt + the single retry)", subs)
	}
	if n := countEvents(evs, EventTurnCompleted); n != 1 {
		t.Fatalf("the retried turn produced %d completions, want exactly 1", n)
	}
}

// TestManager_EndpointGoneTwice_SurfacesAfterOneRetry proves the retry is
// bounded: when the endpoint is gone on BOTH attempts, the Manager surfaces
// ErrEndpointGone after exactly one retry (never an endless loop) and the
// session is not left wedged Busy.
func TestManager_EndpointGoneTwice_SurfacesAfterOneRetry(t *testing.T) {
	d := &endpointDeathDriver{}
	m := newTestManager(t, d)
	sess := m.Session("inst-gone-twice", domain.RuntimeFake, "/tmp/ws")

	d.setDeaths(2)
	res, err, _ := runSubmit(t, m, sess, "t1", "hello")
	if !errors.Is(err, ErrEndpointGone) {
		t.Fatalf("Submit err = %v, want ErrEndpointGone surfaced after the single retry", err)
	}
	if res.Completed {
		t.Fatal("a turn whose endpoint died twice must not report completion")
	}
	if sess.State == StateBusy {
		t.Fatal("session wedged Busy after two endpoint-gone attempts")
	}
	acts, subs := d.counts()
	if subs != 2 {
		t.Fatalf("submits = %d, want exactly 2 (the attempt + ONE retry — no endless retry)", subs)
	}
	if acts != 2 {
		t.Fatalf("activations = %d, want 2 (the initial activation + one re-activation)", acts)
	}
}
