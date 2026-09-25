package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

// memDriver is a deterministic in-memory Driver used to exercise the
// Manager's state machine, materialised gate, and submit serialisation
// without a real process. It records calls so tests can assert on them.
type memDriver struct {
	mu sync.Mutex
	// minted is the native id a cold start mints.
	minted string
	// stored is the set of native ids that "exist" for resume (a resume of
	// an id not in stored returns ErrSessionLost).
	stored map[string]bool
	// failResume forces the next resume to lose the session.
	failResume bool
	// scriptedInteraction, when non-empty, makes the next prompt turn
	// BLOCK on a native interaction (the turn is busy until a
	// SubmitInteraction answers it) — models a runtime that parks a turn
	// on a pending interaction (the fake's PAGNET_FAKE_INTERACTION).
	scriptedInteraction string
	// danglingInteraction, when non-empty, makes the next prompt turn
	// complete while leaving a native interaction UNRESOLVED (the session
	// goes idle with a pending interaction) — models a runtime whose turn
	// ends with an outstanding deferrable interaction.
	danglingInteraction string

	activated    int
	hibernated   int
	submitted    int
	interactions int
	// live tracks which instances have a live endpoint.
	live map[string]bool
	// pid is the fake endpoint pid; it increments on every activation so
	// a re-activation is a NEW process (the hibernate/wake and
	// launch-env-restart proofs assert on it).
	pid int
	// answerOnce/answerCh model the in-flight interaction's answer:
	// SubmitInteraction closes answerCh once, unblocking the scripted
	// turn.
	answerOnce sync.Once
	answerCh   chan struct{}
}

func newMemDriver() *memDriver {
	return &memDriver{
		minted:   "native-abc",
		stored:   map[string]bool{},
		live:     map[string]bool{},
		pid:      4242,
		answerCh: make(chan struct{}),
	}
}

func (d *memDriver) Name() domain.RuntimeName { return domain.RuntimeFake }

func (d *memDriver) Capabilities() Capabilities {
	return Capabilities{
		PersistentEndpoint:              true,
		StructuredEvents:                true,
		NativeSubmit:                    true,
		NativeInteractionObserve:        true,
		RemoteInteractionResolve:        true,
		TerminalAttachmentFullAuthority: true,
	}
}

func (d *memDriver) Activate(ctx context.Context, sess *RuntimeSession, events chan<- SessionEvent) (*RuntimeEndpoint, error) {
	d.mu.Lock()
	d.activated++
	resume := sess.NativeID != ""
	fail := d.failResume
	d.mu.Unlock()
	if resume && !sess.Materialised {
		// Mirror the Manager's gate (defense-in-depth).
		return nil, ErrNotMaterialised
	}
	// The driver sets sess.NativeID as the native exchange happens (the
	// Driver contract); EnsureActive runs this under the per-instance
	// activation lock, so the write is serialized with the NativeID query.
	if resume {
		if fail || !d.stored[sess.NativeID] {
			if events != nil {
				events <- SessionEvent{Type: EventSessionLost, SessionID: sess.NativeID, Error: "no rollout"}
			}
			return nil, ErrSessionLost
		}
		if events != nil {
			events <- SessionEvent{Type: EventSessionResumed, SessionID: sess.NativeID}
		}
	} else {
		sess.NativeID = d.minted
		if events != nil {
			events <- SessionEvent{Type: EventSessionStarted, SessionID: d.minted}
		}
	}
	d.mu.Lock()
	d.live[sess.InstanceID] = true
	// A fresh activation is a NEW process: bump the pid so re-activation
	// (hibernate/wake, launch-env restart) is observable as a new endpoint.
	d.pid++
	pid := d.pid
	d.mu.Unlock()
	return &RuntimeEndpoint{
		ID:        "ep-" + sess.InstanceID,
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

func (d *memDriver) Submit(ctx context.Context, sess *RuntimeSession, req SubmitRequest, events chan<- SessionEvent) error {
	d.mu.Lock()
	if req.Kind == SubmitInteraction {
		d.interactions++
	} else {
		d.submitted++
	}
	d.mu.Unlock()
	if !d.live[sess.InstanceID] {
		return errors.New("memDriver: no live endpoint")
	}
	if req.Kind == SubmitInteraction {
		// The answer is delivered. For a scripted (blocking) interaction it
		// unblocks the in-flight turn (whose stream carries the
		// interaction.resolved). For a dangling one, THIS stream carries
		// the resolution (the turn already completed).
		d.answerOnce.Do(func() { close(d.answerCh) })
		if d.danglingInteraction != "" {
			events <- SessionEvent{
				Type:      EventInteractionResolved,
				SessionID: sess.NativeID,
				TurnID:    req.TurnID,
				Interaction: &InteractionEvent{
					NativeInteractionID: "int-1", Kind: d.danglingInteraction,
					Resolved: true, Decision: req.Decision, Answer: req.Answer,
				},
			}
		}
		return nil
	}
	// Every turn event echoes the submit's logical turn id (the
	// end-to-end turn-identity contract the real drivers honor).
	events <- SessionEvent{Type: EventBusy, SessionID: sess.NativeID, TurnID: req.TurnID}
	events <- SessionEvent{Type: EventTurnStarted, SessionID: sess.NativeID, TurnID: req.TurnID}
	if d.scriptedInteraction != "" {
		// The turn blocks on the native interaction until it is answered.
		events <- SessionEvent{
			Type: EventInteractionStarted, SessionID: sess.NativeID, TurnID: req.TurnID,
			Interaction: &InteractionEvent{NativeInteractionID: "int-1", Kind: d.scriptedInteraction, Summary: "mem " + d.scriptedInteraction},
		}
		<-d.answerCh
		events <- SessionEvent{
			Type: EventInteractionResolved, SessionID: sess.NativeID, TurnID: req.TurnID,
			Interaction: &InteractionEvent{NativeInteractionID: "int-1", Kind: d.scriptedInteraction, Resolved: true, Decision: "resolved"},
		}
	}
	if d.danglingInteraction != "" {
		// The turn completes with the interaction still outstanding.
		events <- SessionEvent{
			Type: EventInteractionStarted, SessionID: sess.NativeID, TurnID: req.TurnID,
			Interaction: &InteractionEvent{NativeInteractionID: "int-1", Kind: d.danglingInteraction, Summary: "mem " + d.danglingInteraction},
		}
	}
	events <- SessionEvent{Type: EventTurnOutput, SessionID: sess.NativeID, TurnID: req.TurnID, Output: "echo: " + req.Input}
	events <- SessionEvent{Type: EventTurnCompleted, SessionID: sess.NativeID, TurnID: req.TurnID, Model: "mem-1"}
	events <- SessionEvent{Type: EventIdle, SessionID: sess.NativeID, TurnID: req.TurnID}
	return nil
}

func (d *memDriver) Hibernate(ctx context.Context, sess *RuntimeSession) error {
	d.mu.Lock()
	d.hibernated++
	if d.live[sess.InstanceID] {
		// A real exchange happened, so the native session is durable.
		if sess.Materialised {
			d.stored[sess.NativeID] = true
		}
		d.live[sess.InstanceID] = false
	}
	d.mu.Unlock()
	return nil
}

func (d *memDriver) Stop(instanceID string) error {
	d.mu.Lock()
	d.live[instanceID] = false
	d.mu.Unlock()
	return nil
}

func (d *memDriver) PID(instanceID string) *int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.live[instanceID] {
		return nil
	}
	p := d.pid
	return &p
}

func (d *memDriver) Live(instanceID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.live[instanceID]
}

// Locked counter accessors (tests read these after the work settles).
func (d *memDriver) submittedCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.submitted
}

func (d *memDriver) activatedCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.activated
}

func (d *memDriver) hibernatedCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hibernated
}

func newTestManager(t *testing.T, d Driver) *Manager {
	t.Helper()
	m := NewManager()
	m.RegisterDriver(d)
	return m
}

func TestManager_ColdStartThenTurn(t *testing.T) {
	d := newMemDriver()
	m := newTestManager(t, d)
	sess := m.Session("inst-1", domain.RuntimeFake, "/tmp/ws")
	if sess.State != StateInactive {
		t.Fatalf("new session state = %v, want inactive", sess.State)
	}
	events := make(chan SessionEvent, 16)
	resultCh := make(chan *TurnResult, 1)
	go func() {
		r, _ := m.Submit(context.Background(), sess, SubmitRequest{TurnID: "t1", Kind: SubmitPrompt, Input: "hello"}, events)
		resultCh <- r
	}()
	var gotStarted bool
	for ev := range events {
		if ev.Type == EventSessionStarted && ev.SessionID == d.minted {
			gotStarted = true
		}
	}
	res := <-resultCh
	if !gotStarted {
		t.Fatal("did not observe session.started with the minted id")
	}
	if !res.Completed {
		t.Fatalf("turn not completed: %+v", res)
	}
	if sess.NativeID != d.minted {
		t.Fatalf("session native id = %q, want %q", sess.NativeID, d.minted)
	}
	if !sess.Materialised {
		t.Fatal("session should be materialised after a completed exchange")
	}
	if sess.State != StateIdle {
		t.Fatalf("post-turn state = %v, want idle", sess.State)
	}
	if n := d.submittedCount(); n != 1 {
		t.Fatalf("driver submitted = %d, want 1", n)
	}
}

func TestManager_MaterialisedGate_RefusesResumeBeforeFirstExchange(t *testing.T) {
	d := newMemDriver()
	m := newTestManager(t, d)
	sess := m.Session("inst-1", domain.RuntimeFake, "/tmp/ws")

	// Cold start (mints the native id) but NO exchange.
	if _, err := m.EnsureActive(context.Background(), sess, nil); err != nil {
		t.Fatalf("cold activate: %v", err)
	}
	if sess.NativeID == "" {
		t.Fatal("cold start should mint a native id")
	}
	if sess.Materialised {
		t.Fatal("session must not be materialised before any exchange")
	}
	// Hibernate the (unmaterialised) session.
	if err := m.Hibernate(context.Background(), sess); err != nil {
		t.Fatalf("hibernate: %v", err)
	}
	// Resume must be REFUSED (honest), not silently a fresh session.
	_, err := m.EnsureActive(context.Background(), sess, nil)
	if !errors.Is(err, ErrNotMaterialised) {
		t.Fatalf("resume before first exchange = %v, want ErrNotMaterialised", err)
	}
	if sess.State != StateInactive {
		t.Fatalf("state after refused resume = %v, want inactive", sess.State)
	}
	// The driver must NOT have been asked to activate a second time.
	if n := d.activatedCount(); n != 1 {
		t.Fatalf("driver activated = %d, want 1 (resume refused before the driver)", n)
	}
}

func TestManager_MaterialisedGate_AllowsResumeAfterFirstExchange(t *testing.T) {
	d := newMemDriver()
	m := newTestManager(t, d)
	sess := m.Session("inst-1", domain.RuntimeFake, "/tmp/ws")

	// First exchange (materialises the session).
	events := make(chan SessionEvent, 16)
	go func() {
		_, _ = m.Submit(context.Background(), sess, SubmitRequest{TurnID: "t1", Kind: SubmitPrompt, Input: "hi"}, events)
	}()
	for range events {
	}
	if !sess.Materialised {
		t.Fatal("session should be materialised after the first exchange")
	}
	id := sess.NativeID
	// Hibernate.
	if err := m.Hibernate(context.Background(), sess); err != nil {
		t.Fatalf("hibernate: %v", err)
	}
	if sess.State != StateInactive {
		t.Fatalf("state after hibernate = %v, want inactive", sess.State)
	}
	// Resume: must succeed and restore the SAME native id.
	resumed := make(chan SessionEvent, 16)
	go func() {
		_, _ = m.EnsureActive(context.Background(), sess, resumed)
		close(resumed) // the caller owns the channel lifecycle
	}()
	gotResumed := false
	for ev := range resumed {
		if ev.Type == EventSessionResumed && ev.SessionID == id {
			gotResumed = true
		}
	}
	if !gotResumed {
		t.Fatal("resume did not emit session.resumed with the same id")
	}
	if sess.NativeID != id {
		t.Fatalf("resumed native id = %q, want %q", sess.NativeID, id)
	}
}

func TestManager_SessionLostOnBadResume(t *testing.T) {
	d := newMemDriver()
	m := newTestManager(t, d)
	sess := m.Session("inst-1", domain.RuntimeFake, "/tmp/ws")
	// Forge a materialised session with an id the driver does not have.
	m.mu.Lock()
	sess.NativeID = "ghost-id"
	sess.Materialised = true
	m.mu.Unlock()

	lost := make(chan SessionEvent, 16)
	go func() {
		_, _ = m.EnsureActive(context.Background(), sess, lost)
		close(lost) // the caller owns the channel lifecycle
	}()
	gotLost := false
	for ev := range lost {
		if ev.Type == EventSessionLost {
			gotLost = true
		}
	}
	if !gotLost {
		t.Fatal("did not observe session.lost on a bad resume")
	}
	if sess.State != StateLost {
		t.Fatalf("state after lost resume = %v, want lost", sess.State)
	}
}

func TestManager_HibernateRefusesBusy(t *testing.T) {
	d := newMemDriver()
	m := newTestManager(t, d)
	sess := m.Session("inst-1", domain.RuntimeFake, "/tmp/ws")
	m.mu.Lock()
	sess.State = StateBusy
	m.mu.Unlock()
	if err := m.Hibernate(context.Background(), sess); err == nil {
		t.Fatal("hibernate of a busy session must be refused")
	}
}

func TestManager_PromptTurnsSerialized(t *testing.T) {
	d := newMemDriver()
	m := newTestManager(t, d)
	sess := m.Session("inst-1", domain.RuntimeFake, "/tmp/ws")
	// Two concurrent prompt submits must not overlap in the driver.
	var inFlight, maxInFlight int
	var mu sync.Mutex
	origSubmit := d.Submit
	_ = origSubmit
	// Wrap the driver's Submit to count concurrency.
	wrapped := &countingDriver{inner: d, inFlight: &inFlight, max: &maxInFlight, mu: &mu}
	m.RegisterDriver(wrapped)

	for i := 0; i < 5; i++ {
		events := make(chan SessionEvent, 16)
		go func() {
			// Submit must run in its OWN goroutine: it blocks sending into
			// events until the reader drains them.
			go func() {
				_, _ = m.Submit(context.Background(), sess, SubmitRequest{TurnID: "t", Kind: SubmitPrompt, Input: "x"}, events)
			}()
			for range events {
			}
		}()
	}
	// Give them time to run and settle.
	submitted := d.submittedCount
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := inFlight == 0
		mu.Unlock()
		if done && submitted() >= 5 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := submitted(); n != 5 {
		t.Fatalf("driver submitted = %d, want 5", n)
	}
	mu.Lock()
	mif := maxInFlight
	mu.Unlock()
	if mif > 1 {
		t.Fatalf("max concurrent prompt turns = %d, want 1 (serialized)", mif)
	}
}

// countingDriver wraps a Driver to count concurrent Submits.
type countingDriver struct {
	inner    Driver
	inFlight *int
	max      *int
	mu       *sync.Mutex
}

func (c *countingDriver) Name() domain.RuntimeName   { return c.inner.Name() }
func (c *countingDriver) Capabilities() Capabilities { return c.inner.Capabilities() }
func (c *countingDriver) Hibernate(ctx context.Context, s *RuntimeSession) error {
	return c.inner.Hibernate(ctx, s)
}
func (c *countingDriver) Stop(i string) error { return c.inner.Stop(i) }
func (c *countingDriver) PID(i string) *int   { return c.inner.PID(i) }
func (c *countingDriver) Live(i string) bool  { return c.inner.Live(i) }

func (c *countingDriver) Activate(ctx context.Context, s *RuntimeSession, e chan<- SessionEvent) (*RuntimeEndpoint, error) {
	return c.inner.Activate(ctx, s, e)
}

func (c *countingDriver) Submit(ctx context.Context, s *RuntimeSession, req SubmitRequest, e chan<- SessionEvent) error {
	c.mu.Lock()
	*c.inFlight++
	if *c.inFlight > *c.max {
		*c.max = *c.inFlight
	}
	c.mu.Unlock()
	err := c.inner.Submit(ctx, s, req, e)
	c.mu.Lock()
	*c.inFlight--
	c.mu.Unlock()
	return err
}

func TestManager_InteractionRoundTrip(t *testing.T) {
	d := newInteractionDriver()
	m := newTestManager(t, d)
	sess := m.Session("inst-1", domain.RuntimeFake, "/tmp/ws")

	// Start a prompt turn that blocks on a native interaction.
	events := make(chan SessionEvent, 16)
	resultCh := make(chan *TurnResult, 1)
	go func() {
		r, _ := m.Submit(context.Background(), sess, SubmitRequest{TurnID: "t1", Kind: SubmitPrompt, Input: "ask me"}, events)
		resultCh <- r
	}()

	// Consume until the interaction starts, then answer it via the submit
	// path (NOT by the blocked turn itself).
	sawInteraction := false
	for ev := range events {
		if ev.Type == EventInteractionStarted {
			sawInteraction = true
			break
		}
	}
	if !sawInteraction {
		t.Fatal("did not observe interaction.started")
	}
	// Answer the interaction via the Submit path.
	ansEvents := make(chan SessionEvent, 16)
	ansCh := make(chan error, 1)
	go func() {
		_, err := m.Submit(context.Background(), sess, SubmitRequest{
			TurnID: "a1", Kind: SubmitInteraction,
			InteractionID: "int-1", Decision: "resolved", Answer: "yes",
		}, ansEvents)
		ansCh <- err
	}()
	for range ansEvents {
	}
	if err := <-ansCh; err != nil {
		t.Fatalf("interaction submit: %v", err)
	}
	// The blocked turn must now complete.
	select {
	case res := <-resultCh:
		if !res.Completed {
			t.Fatalf("turn did not complete after interaction answer: %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("turn did not complete after interaction answer (deadlock?)")
	}
	if n := d.interactionsCount(); n != 1 {
		t.Fatalf("driver interactions = %d, want 1", n)
	}
}

// interactionDriver is a standalone Driver whose prompt turn blocks on a
// native interaction until an interaction resolution is submitted. A fresh
// answered channel is minted per blocking turn so the driver is reusable.
type interactionDriver struct {
	mu           sync.Mutex
	minted       string
	live         map[string]bool
	submitted    int
	interactions int
	blocking     bool
	answered     chan struct{}
}

func newInteractionDriver() *interactionDriver {
	return &interactionDriver{minted: "native-abc", live: map[string]bool{}}
}

func (d *interactionDriver) Name() domain.RuntimeName { return domain.RuntimeFake }

func (d *interactionDriver) Capabilities() Capabilities {
	return Capabilities{PersistentEndpoint: true, NativeSubmit: true,
		NativeInteractionObserve: true, RemoteInteractionResolve: true}
}

func (d *interactionDriver) Activate(ctx context.Context, sess *RuntimeSession, events chan<- SessionEvent) (*RuntimeEndpoint, error) {
	// The driver sets sess.NativeID as the native exchange happens (the
	// Driver contract); EnsureActive runs this under the per-instance
	// activation lock, so the write is serialized with the NativeID query.
	d.mu.Lock()
	if sess.NativeID == "" {
		sess.NativeID = d.minted
	}
	d.live[sess.InstanceID] = true
	d.mu.Unlock()
	if events != nil {
		events <- SessionEvent{Type: EventSessionStarted, SessionID: sess.NativeID}
	}
	return &RuntimeEndpoint{ID: "ep", Runtime: sess.Runtime, PID: 1, PGID: 1, Healthy: true}, nil
}

func (d *interactionDriver) Hibernate(ctx context.Context, sess *RuntimeSession) error {
	d.mu.Lock()
	d.live[sess.InstanceID] = false
	d.mu.Unlock()
	return nil
}

func (d *interactionDriver) Stop(i string) error {
	d.mu.Lock()
	d.live[i] = false
	d.mu.Unlock()
	return nil
}

func (d *interactionDriver) PID(i string) *int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.live[i] {
		return nil
	}
	p := 1
	return &p
}

func (d *interactionDriver) Live(i string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.live[i]
}

func (d *interactionDriver) interactionsCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.interactions
}

func (d *interactionDriver) Submit(ctx context.Context, sess *RuntimeSession, req SubmitRequest, events chan<- SessionEvent) error {
	if req.Kind == SubmitInteraction {
		d.mu.Lock()
		d.interactions++
		if d.blocking {
			d.blocking = false
			close(d.answered)
		}
		d.mu.Unlock()
		return nil
	}
	d.mu.Lock()
	d.submitted++
	d.mu.Unlock()
	if !d.live[sess.InstanceID] {
		return errors.New("interactionDriver: no live endpoint")
	}
	events <- SessionEvent{Type: EventBusy, SessionID: sess.NativeID}
	events <- SessionEvent{Type: EventTurnStarted, SessionID: sess.NativeID}
	events <- SessionEvent{Type: EventInteractionStarted, SessionID: sess.NativeID,
		Interaction: &InteractionEvent{NativeInteractionID: "int-1", Kind: "question", Summary: "answer?"}}
	// Block until the interaction is answered (or ctx cancels).
	d.mu.Lock()
	d.blocking = true
	d.answered = make(chan struct{})
	ch := d.answered
	d.mu.Unlock()
	select {
	case <-ch:
	case <-ctx.Done():
		return ctx.Err()
	}
	events <- SessionEvent{Type: EventInteractionResolved, SessionID: sess.NativeID,
		Interaction: &InteractionEvent{NativeInteractionID: "int-1", Kind: "question", Resolved: true, Decision: "resolved"}}
	events <- SessionEvent{Type: EventTurnCompleted, SessionID: sess.NativeID, Model: "mem-1"}
	events <- SessionEvent{Type: EventIdle, SessionID: sess.NativeID}
	return nil
}

func TestCapabilities_StringAndResumable(t *testing.T) {
	s := &RuntimeSession{NativeID: "x", Materialised: true}
	if !s.Resumable() {
		t.Fatal("materialised session with an id must be resumable")
	}
	s2 := &RuntimeSession{NativeID: "x", Materialised: false}
	if s2.Resumable() {
		t.Fatal("unmaterialised session must not be resumable")
	}
	s3 := &RuntimeSession{NativeID: "", Materialised: true}
	if s3.Resumable() {
		t.Fatal("session without an id must not be resumable")
	}
	if OwnershipPagnet.String() != "pagnet" || OwnershipExternal.String() != "external" {
		t.Fatal("ownership string mismatch")
	}
	if LeaseForeign.String() != "foreign" || LeaseReclaimed.String() != "reclaimed" {
		t.Fatal("lease string mismatch")
	}
}

func TestValidateSubmitRequest(t *testing.T) {
	if err := ValidateSubmitRequest(SubmitRequest{Kind: SubmitPrompt, Input: ""}); err == nil {
		t.Fatal("empty prompt input must be rejected")
	}
	if err := ValidateSubmitRequest(SubmitRequest{Kind: SubmitPrompt, Input: "hi"}); err != nil {
		t.Fatalf("valid prompt rejected: %v", err)
	}
	if err := ValidateSubmitRequest(SubmitRequest{Kind: SubmitInteraction, InteractionID: "i", Decision: ""}); err == nil {
		t.Fatal("interaction without decision must be rejected")
	}
	if err := ValidateSubmitRequest(SubmitRequest{Kind: SubmitInteraction, InteractionID: "i", Decision: "resolved"}); err != nil {
		t.Fatalf("valid interaction rejected: %v", err)
	}
}

// Phase 2 (deliverable 4): the submit's logical turn id is echoed by the
// driver on every event it emits for the turn, so the normalized event
// stream carries the logical identity end-to-end (the daemon correlates
// its host-protocol events with it; Phases 4–8 map it to the vendor's
// idempotency key).
func TestManager_TurnIDEchoedInEvents(t *testing.T) {
	d := newMemDriver()
	m := newTestManager(t, d)
	sess := m.Session("inst-turnid", domain.RuntimeFake, "/tmp/ws")

	events := make(chan SessionEvent, 16)
	done := make(chan *TurnResult, 1)
	go func() {
		r, _ := m.Submit(context.Background(), sess, SubmitRequest{
			TurnID: "turn-xyz-123", Kind: SubmitPrompt, Input: "hello",
		}, events)
		done <- r
	}()
	var turnEvents int
	for ev := range events {
		switch ev.Type {
		case EventSessionStarted, EventSessionResumed:
			// Activation events are not part of a turn: no turn id.
			if ev.TurnID != "" {
				t.Fatalf("activation event carries a turn id: %+v", ev)
			}
		default:
			turnEvents++
			if ev.TurnID != "turn-xyz-123" {
				t.Fatalf("turn event %q does not echo the submit's turn id: got %q", ev.Type, ev.TurnID)
			}
		}
	}
	res := <-done
	if !res.Completed {
		t.Fatalf("turn not completed: %+v", res)
	}
	if turnEvents == 0 {
		t.Fatal("no turn events observed")
	}
}

// Phase 2 (deliverable 1, plan §20): a session with an UNRESOLVED
// interaction is never hibernated — even when it is idle (the turn
// completed with the interaction still outstanding). The hibernate is
// refused until the interaction is resolved.
func TestManager_HibernateRefusesPendingInteraction(t *testing.T) {
	d := newMemDriver()
	d.danglingInteraction = "question"
	m := newTestManager(t, d)
	sess := m.Session("inst-pending", domain.RuntimeFake, "/tmp/ws")

	// The turn completes, leaving the interaction unresolved (idle +
	// pending).
	events := make(chan SessionEvent, 16)
	done := make(chan *TurnResult, 1)
	go func() {
		r, _ := m.Submit(context.Background(), sess, SubmitRequest{TurnID: "t1", Kind: SubmitPrompt, Input: "hi"}, events)
		done <- r
	}()
	for range events {
	}
	res := <-done
	if !res.Completed {
		t.Fatalf("turn not completed: %+v", res)
	}
	if sess.State != StateIdle {
		t.Fatalf("state after the turn = %v, want idle", sess.State)
	}
	if !m.HasPendingInteraction("inst-pending") {
		t.Fatal("the unresolved interaction was not tracked as pending")
	}

	// Hibernate is REFUSED (plan §20: never hibernate an unresolved
	// interaction) — even though the session is idle.
	if err := m.Hibernate(context.Background(), sess); err == nil {
		t.Fatal("hibernate of a session with an unresolved interaction was not refused")
	}
	if !d.live["inst-pending"] {
		t.Fatal("the endpoint was stopped despite the hibernate refusal")
	}

	// Resolve the interaction (the submit path).
	iEvents := make(chan SessionEvent, 16)
	if _, err := m.Submit(context.Background(), sess, SubmitRequest{
		TurnID: "t2", Kind: SubmitInteraction, InteractionID: "int-1", Decision: "resolved", Answer: "yes",
	}, iEvents); err != nil {
		t.Fatalf("interaction submit: %v", err)
	}
	for range iEvents {
	}
	if m.HasPendingInteraction("inst-pending") {
		t.Fatal("the interaction is still pending after the resolution")
	}

	// Now the hibernate succeeds (idle, no pending interaction).
	if err := m.Hibernate(context.Background(), sess); err != nil {
		t.Fatalf("hibernate after the resolution: %v", err)
	}
	if sess.State != StateInactive {
		t.Fatalf("state after hibernate = %v, want inactive", sess.State)
	}
}

// Phase 2 (deliverable 3 / R8): the endpoint's launch env is FIXED AT
// LAUNCH. When the session's env changes while the endpoint is live, the
// Manager RESTARTS the endpoint (stop + re-activate) so the new env takes
// effect — the session is preserved (a materialised session resumes the
// same native session; the endpoint is a NEW process).
func TestManager_EnvChangeRestartsEndpoint(t *testing.T) {
	d := newMemDriver()
	m := newTestManager(t, d)
	sess := m.Session("inst-env", domain.RuntimeFake, "/tmp/ws")

	// Turn 1 with env A (cold start).
	m.SetLaunchEnv(sess, []string{"PAGNET_TEST_ENV=A"})
	events := make(chan SessionEvent, 16)
	done := make(chan *TurnResult, 1)
	go func() {
		r, _ := m.Submit(context.Background(), sess, SubmitRequest{TurnID: "t1", Kind: SubmitPrompt, Input: "one"}, events)
		done <- r
	}()
	for range events {
	}
	if res := <-done; !res.Completed {
		t.Fatalf("turn 1 not completed: %+v", res)
	}
	sessionID := sess.NativeID
	if sessionID == "" {
		t.Fatal("no native session id after turn 1")
	}
	pid1 := d.PID("inst-env")
	if pid1 == nil {
		t.Fatal("no live endpoint after turn 1")
	}
	if ep := sess.Endpoint; ep == nil || !sameEnv(ep.LaunchEnv, []string{"PAGNET_TEST_ENV=A"}) {
		t.Fatalf("endpoint launch env not recorded: %+v", sess.Endpoint)
	}

	// Turn 2 with a CHANGED env: the endpoint must be restarted (new
	// process) and the SAME session resumed.
	m.SetLaunchEnv(sess, []string{"PAGNET_TEST_ENV=B"})
	events = make(chan SessionEvent, 16)
	done = make(chan *TurnResult, 1)
	var resumed bool
	go func() {
		r, _ := m.Submit(context.Background(), sess, SubmitRequest{TurnID: "t2", Kind: SubmitPrompt, Input: "two"}, events)
		done <- r
	}()
	for ev := range events {
		if ev.Type == EventSessionResumed && ev.SessionID == sessionID {
			resumed = true
		}
	}
	if res := <-done; !res.Completed {
		t.Fatalf("turn 2 not completed: %+v", res)
	}
	if n := d.activatedCount(); n != 2 {
		t.Fatalf("driver activated = %d, want 2 (the env change restarts the endpoint)", n)
	}
	if n := d.hibernatedCount(); n != 1 {
		t.Fatalf("driver hibernated = %d, want 1 (the restart stops the old endpoint)", n)
	}
	pid2 := d.PID("inst-env")
	if pid2 == nil {
		t.Fatal("no live endpoint after turn 2")
	}
	if *pid2 == *pid1 {
		t.Fatalf("the env change did not restart the endpoint (pid %d unchanged)", *pid1)
	}
	if !resumed {
		t.Fatal("the restart did not resume the same native session")
	}
	if sess.NativeID != sessionID {
		t.Fatalf("native session id changed across the restart: %q != %q", sess.NativeID, sessionID)
	}
	if ep := sess.Endpoint; ep == nil || !sameEnv(ep.LaunchEnv, []string{"PAGNET_TEST_ENV=B"}) {
		t.Fatalf("restarted endpoint launch env = %+v, want the new env", sess.Endpoint)
	}
}

// Instruction-model Wave 3 (plan 3F): the standing document is a
// LAUNCH-CONFIGURATION value (like env and model). When it changes while
// the endpoint is live, the Manager RESTARTS the endpoint so the new
// standing context takes effect on the native surface — the session is
// preserved (a materialised session resumes the same native session; the
// endpoint is a NEW process).
func TestManager_StandingChangeRestartsEndpoint(t *testing.T) {
	d := newMemDriver()
	m := newTestManager(t, d)
	sess := m.Session("inst-standing", domain.RuntimeFake, "/tmp/ws")

	// Turn 1 with standing A (cold start).
	m.SetStandingInstructions(sess, "standing A")
	events := make(chan SessionEvent, 16)
	done := make(chan *TurnResult, 1)
	go func() {
		r, _ := m.Submit(context.Background(), sess, SubmitRequest{TurnID: "t1", Kind: SubmitPrompt, Input: "one"}, events)
		done <- r
	}()
	for range events {
	}
	if res := <-done; !res.Completed {
		t.Fatalf("turn 1 not completed: %+v", res)
	}
	sessionID := sess.NativeID
	if sessionID == "" {
		t.Fatal("no native session id after turn 1")
	}
	pid1 := d.PID("inst-standing")
	if pid1 == nil {
		t.Fatal("no live endpoint after turn 1")
	}
	if ep := sess.Endpoint; ep == nil || ep.LaunchStandingInstructions != "standing A" {
		t.Fatalf("endpoint launch standing not recorded: %+v", sess.Endpoint)
	}

	// Turn 2 with a CHANGED standing document: the endpoint must be
	// restarted (new process) and the SAME session resumed.
	m.SetStandingInstructions(sess, "standing B")
	events = make(chan SessionEvent, 16)
	done = make(chan *TurnResult, 1)
	var resumed bool
	go func() {
		r, _ := m.Submit(context.Background(), sess, SubmitRequest{TurnID: "t2", Kind: SubmitPrompt, Input: "two"}, events)
		done <- r
	}()
	for ev := range events {
		if ev.Type == EventSessionResumed && ev.SessionID == sessionID {
			resumed = true
		}
	}
	if res := <-done; !res.Completed {
		t.Fatalf("turn 2 not completed: %+v", res)
	}
	if n := d.activatedCount(); n != 2 {
		t.Fatalf("driver activated = %d, want 2 (the standing change restarts the endpoint)", n)
	}
	if n := d.hibernatedCount(); n != 1 {
		t.Fatalf("driver hibernated = %d, want 1 (the restart stops the old endpoint)", n)
	}
	pid2 := d.PID("inst-standing")
	if pid2 == nil {
		t.Fatal("no live endpoint after turn 2")
	}
	if *pid2 == *pid1 {
		t.Fatalf("the standing change did not restart the endpoint (pid %d unchanged)", *pid1)
	}
	if !resumed {
		t.Fatal("the restart did not resume the same native session")
	}
	if sess.NativeID != sessionID {
		t.Fatalf("native session id changed across the restart: %q != %q", sess.NativeID, sessionID)
	}
	if ep := sess.Endpoint; ep == nil || ep.LaunchStandingInstructions != "standing B" {
		t.Fatalf("restarted endpoint launch standing = %+v, want the new document", sess.Endpoint)
	}
}

// Phase 2 (deliverable 3 / R8 + plan §20): a launch-env change on a
// session with an UNRESOLVED interaction is DEFERRED — restarting the
// endpoint would lose the in-flight interaction (never hibernate an
// unresolved interaction). The live endpoint is kept; the change is
// applied at the next restart opportunity (after the resolution).
func TestManager_EnvChangeDeferredWithPendingInteraction(t *testing.T) {
	d := newMemDriver()
	d.danglingInteraction = "question"
	m := newTestManager(t, d)
	sess := m.Session("inst-envdef", domain.RuntimeFake, "/tmp/ws")

	// Turn 1 with env A, completing with the interaction unresolved.
	m.SetLaunchEnv(sess, []string{"PAGNET_TEST_ENV=A"})
	events := make(chan SessionEvent, 16)
	done := make(chan *TurnResult, 1)
	go func() {
		r, _ := m.Submit(context.Background(), sess, SubmitRequest{TurnID: "t1", Kind: SubmitPrompt, Input: "one"}, events)
		done <- r
	}()
	for range events {
	}
	if res := <-done; !res.Completed {
		t.Fatalf("turn 1 not completed: %+v", res)
	}
	pid1 := d.PID("inst-envdef")
	if pid1 == nil {
		t.Fatal("no live endpoint after turn 1")
	}

	// Turn 2 with a CHANGED env while the interaction is still pending:
	// the restart is DEFERRED (the live endpoint is kept).
	m.SetLaunchEnv(sess, []string{"PAGNET_TEST_ENV=B"})
	events = make(chan SessionEvent, 16)
	done = make(chan *TurnResult, 1)
	go func() {
		r, _ := m.Submit(context.Background(), sess, SubmitRequest{TurnID: "t2", Kind: SubmitPrompt, Input: "two"}, events)
		done <- r
	}()
	for range events {
	}
	if res := <-done; !res.Completed {
		t.Fatalf("turn 2 not completed: %+v", res)
	}
	if n := d.activatedCount(); n != 1 {
		t.Fatalf("driver activated = %d, want 1 (the env change must be deferred while the interaction is pending)", n)
	}
	pid2 := d.PID("inst-envdef")
	if pid2 == nil || *pid2 != *pid1 {
		t.Fatalf("the deferred env change restarted the endpoint anyway: pid1=%v pid2=%v", pid1, pid2)
	}

	// Resolve the interaction, then turn 3: the restart now happens.
	iEvents := make(chan SessionEvent, 16)
	if _, err := m.Submit(context.Background(), sess, SubmitRequest{
		TurnID: "t3", Kind: SubmitInteraction, InteractionID: "int-1", Decision: "resolved", Answer: "yes",
	}, iEvents); err != nil {
		t.Fatalf("interaction submit: %v", err)
	}
	for range iEvents {
	}
	events = make(chan SessionEvent, 16)
	done = make(chan *TurnResult, 1)
	go func() {
		r, _ := m.Submit(context.Background(), sess, SubmitRequest{TurnID: "t4", Kind: SubmitPrompt, Input: "three"}, events)
		done <- r
	}()
	for range events {
	}
	if res := <-done; !res.Completed {
		t.Fatalf("turn 3 not completed: %+v", res)
	}
	if n := d.activatedCount(); n != 2 {
		t.Fatalf("driver activated = %d, want 2 (the deferred env change applies after the resolution)", n)
	}
	pid3 := d.PID("inst-envdef")
	if pid3 == nil || *pid3 == *pid1 {
		t.Fatalf("the deferred env change did not restart the endpoint: pid1=%d pid3=%v", *pid1, pid3)
	}
}
