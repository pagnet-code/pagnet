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

	activated    int
	hibernated   int
	submitted    int
	interactions int
	// live tracks which instances have a live endpoint.
	live map[string]bool
	// pid is the fake endpoint pid (stable per instance while live).
	pid int
}

func newMemDriver() *memDriver {
	return &memDriver{
		minted: "native-abc",
		stored: map[string]bool{},
		live:   map[string]bool{},
		pid:    4242,
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
	d.mu.Unlock()
	return &RuntimeEndpoint{
		ID:        "ep-" + sess.InstanceID,
		Runtime:   sess.Runtime,
		Ownership: OwnershipPagnet,
		Lease:     LeaseClaimed,
		PID:       d.pid,
		PGID:      d.pid,
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
		// The answer is delivered; the in-flight turn's stream carries the
		// interaction.resolved. This stream carries no turn events.
		return nil
	}
	events <- SessionEvent{Type: EventBusy, SessionID: sess.NativeID}
	events <- SessionEvent{Type: EventTurnStarted, SessionID: sess.NativeID}
	events <- SessionEvent{Type: EventTurnOutput, SessionID: sess.NativeID, Output: "echo: " + req.Input}
	events <- SessionEvent{Type: EventTurnCompleted, SessionID: sess.NativeID, Model: "mem-1"}
	events <- SessionEvent{Type: EventIdle, SessionID: sess.NativeID}
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
