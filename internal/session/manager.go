package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

// Manager is the stateful orchestrator the daemon drives. It owns the
// RuntimeSession state (lifecycle phase, materialised flag, native id) for
// every instance and routes work to the per-runtime Driver.
//
// The Manager is the single place the resume gate (materialised) and the
// per-session submit serialisation live, so no vendor adapter can silently
// start a fresh session on a failed resume or run two prompt turns at once.
//
// Concurrency model:
//   - m.mu guards the session map and each session's state fields. It is
//     held only for quick state updates, NEVER across a Driver call.
//   - promptLocks[instanceID] serializes PROMPT turns per instance (one
//     prompt turn in flight at a time). It is held across the prompt
//     Driver.Submit (which blocks until the turn settles).
//   - INTERACTION submits do not take the promptLock: they must be
//     deliverable while a prompt turn is blocked on a native interaction
//     (the busy/idle + interaction round-trip). They serialize only on
//     m.mu for state updates.
type Manager struct {
	mu          sync.Mutex
	drivers     map[domain.RuntimeName]Driver
	sessions    map[string]*RuntimeSession // keyed by instanceID
	promptLocks map[string]*sync.Mutex     // keyed by instanceID
	now         func() time.Time
}

// NewManager builds an empty Manager. Drivers are registered with
// RegisterDriver before use.
func NewManager() *Manager {
	return &Manager{
		drivers:     map[domain.RuntimeName]Driver{},
		sessions:    map[string]*RuntimeSession{},
		promptLocks: map[string]*sync.Mutex{},
		now:         time.Now,
	}
}

// SetClock injects a clock (tests).
func (m *Manager) SetClock(now func() time.Time) {
	if now != nil {
		m.now = now
	}
}

// RegisterDriver installs the Driver for a runtime. It must be called
// before any session for that runtime is used.
func (m *Manager) RegisterDriver(d Driver) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drivers[d.Name()] = d
}

// DriverFor returns the registered Driver for a runtime (nil when none).
func (m *Manager) DriverFor(runtime domain.RuntimeName) Driver {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.drivers[runtime]
}

// Drivers returns a snapshot of the registered drivers (runtime name →
// driver). The Manager is the source of truth for which runtimes are
// session-driven; callers that report or probe session-driven runtimes
// (the daemon's inventory) enumerate from here instead of a hardcoded
// list. The returned map is a copy — mutating it does not affect the
// Manager.
func (m *Manager) Drivers() map[domain.RuntimeName]Driver {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[domain.RuntimeName]Driver, len(m.drivers))
	for k, v := range m.drivers {
		out[k] = v
	}
	return out
}

// Session returns the session for an instance, creating it (inactive) when
// absent. The runtime and workspace are stamped on creation; a later call
// with the same instance returns the existing session unchanged.
func (m *Manager) Session(instanceID string, runtime domain.RuntimeName, workspace string) *RuntimeSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[instanceID]; ok {
		return s
	}
	d := m.drivers[runtime]
	s := &RuntimeSession{
		InstanceID:          instanceID,
		Runtime:             runtime,
		Workspace:           workspace,
		State:               StateInactive,
		Ownership:           OwnershipPagnet,
		PendingInteractions: map[string]bool{},
	}
	if d != nil {
		s.Capabilities = d.Capabilities()
	}
	m.sessions[instanceID] = s
	return s
}

// SetLaunchEnv sets the session's launch environment (the turn spec's env,
// Phase 2 / R8). It is called by the daemon before each Submit so the
// endpoint (re)activation uses the current spec env. See RuntimeSession.Env
// for the launch-env semantics (fixed at spawn; a change restarts the
// endpoint on the next EnsureActive).
func (m *Manager) SetLaunchEnv(sess *RuntimeSession, env []string) {
	if sess == nil {
		return
	}
	m.mu.Lock()
	sess.Env = env
	m.mu.Unlock()
}

// SetModel sets the session's launch model (the turn spec's resolved model,
// Phase 4 / B9). It is called by the daemon before each Submit so the
// endpoint (re)activation uses the current model. See RuntimeSession.Model
// for the launch-model semantics (fixed at spawn; a change restarts the
// endpoint on the next EnsureActive, preserving the session).
func (m *Manager) SetModel(sess *RuntimeSession, model string) {
	if sess == nil {
		return
	}
	m.mu.Lock()
	sess.Model = model
	m.mu.Unlock()
}

// GetSession returns the session for an instance (nil when none).
func (m *Manager) GetSession(instanceID string) *RuntimeSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[instanceID]
}

// RestoreNativeState sets the session's native id and materialised flag from
// the daemon's stored session (the pagnet-persisted native id, Codex R4). It
// is called at turn start so a daemon restart (fresh in-memory Manager) can
// resume the session the control plane stored. It is a no-op when the
// session is already live (the in-memory state is authoritative then).
func (m *Manager) RestoreNativeState(instanceID, nativeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[instanceID]
	if !ok {
		return
	}
	if s.State.Live() {
		return
	}
	s.NativeID = nativeID
	s.Materialised = nativeID != ""
}

// promptLock returns (creating when needed) the per-instance prompt
// serialization lock.
func (m *Manager) promptLock(instanceID string) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.promptLocks[instanceID]
	if !ok {
		l = &sync.Mutex{}
		m.promptLocks[instanceID] = l
	}
	return l
}

// EnsureActive activates the session's endpoint when it is not already
// live. It enforces the materialised resume gate. The events channel (when
// non-nil) receives the activation events (session.started / resumed /
// lost). It returns the live endpoint, or an error (ErrNotMaterialised,
// ErrSessionLost, or a driver error).
//
// Liveness is PROBED, not assumed: a session whose state is live but whose
// endpoint process died unexpectedly (crash, SIGKILL, OOM, a supervisor
// explosion-kill) is NOT wedged. The stale endpoint is dropped and the
// session is re-activated — resuming the SAME session (same native id,
// on-disk state preserved) when materialised, cold-starting when not. An
// endpoint death is never surfaced as a session loss or an instance
// failure.
func (m *Manager) EnsureActive(ctx context.Context, sess *RuntimeSession, events chan<- SessionEvent) (*RuntimeEndpoint, error) {
	// Read the state AND the endpoint under the lock (the endpoint is
	// mutated by activation/hibernation; a torn read would let a stale
	// endpoint escape the liveness check below).
	m.mu.Lock()
	st := sess.State
	ep := sess.Endpoint
	wantEnv := sess.Env
	wantModel := sess.Model
	pending := len(sess.PendingInteractions) > 0
	m.mu.Unlock()
	if st.Live() {
		d := m.driverLocked(sess.Runtime)
		live := d == nil || d.Live(sess.InstanceID)
		// Launch-env / launch-model change (Phase 2 / R8, Phase 4 / B9):
		// the endpoint's environment AND model are FIXED AT SPAWN. When
		// the session's current env or model differs from what the live
		// endpoint was launched with, the endpoint must be RESTARTED
		// (stopped + re-activated) so the new value takes effect — the
		// session is preserved (a materialised session resumes the same
		// native session on re-activation). The one exception is a
		// session with an unresolved interaction: restarting it would lose
		// the in-flight interaction (plan §20: never hibernate a session
		// with an unresolved interaction), so the change is DEFERRED —
		// the live endpoint is returned and it is applied at the next
		// restart opportunity.
		staleLaunch := live && ep != nil &&
			(!sameEnv(wantEnv, ep.LaunchEnv) || wantModel != ep.LaunchModel)
		if live && !staleLaunch {
			return ep, nil
		}
		if staleLaunch && pending {
			return ep, nil
		}
		if staleLaunch {
			// Stop the (still-live) endpoint, preserving the session —
			// the driver's hibernate is the graceful stop (the runtime
			// persists its native session state on the way out). Then fall
			// through to re-activation with the new env/model.
			if err := d.Hibernate(ctx, sess); err != nil {
				return nil, err
			}
		}
		// The endpoint died unexpectedly (or was just stopped for a
		// launch-env change): clear the stale reference and fall through
		// to (re)activation. A MATERIALISED session keeps its native id
		// (the on-disk state survives) and resumes the same native
		// session. An UNMATERIALISED session never had a real exchange, so
		// its minted native id is stale (nothing durable to resume) —
		// clear it so the re-activation COLD-STARTS a fresh session,
		// instead of tripping the resume gate (which is for an explicit
		// resume request of a stored id, not a death re-activation).
		m.mu.Lock()
		sess.Endpoint = nil
		sess.State = StateInactive
		if !sess.Materialised {
			sess.NativeID = ""
		}
		// A dead endpoint's pending interactions are stale: they cannot be
		// resolved against a re-activated session.
		sess.PendingInteractions = map[string]bool{}
		m.mu.Unlock()
	}
	d := m.driverLocked(sess.Runtime)
	if d == nil {
		return nil, fmt.Errorf("session: no driver registered for runtime %q", sess.Runtime)
	}
	// Resume gate: a stored native id with no real exchange is not
	// resumable — refuse honestly (Codex R3, Hermes R3).
	if sess.NativeID != "" && !sess.Materialised {
		return nil, ErrNotMaterialised
	}
	m.setState(sess, StateActivating)
	ep, err := d.Activate(ctx, sess, events)
	if err != nil {
		if errors.Is(err, ErrSessionLost) {
			m.setState(sess, StateLost)
		} else if errors.Is(err, ErrNotMaterialised) {
			m.setState(sess, StateInactive)
		} else {
			m.setState(sess, StateInactive)
		}
		return nil, err
	}
	m.mu.Lock()
	sess.Endpoint = ep
	sess.State = StateIdle
	sess.LastActivity = m.now()
	// Record the env AND model the endpoint was actually launched with,
	// so a later turn's env/model can be compared against it (the
	// launch-change restart above).
	ep.LaunchEnv = append([]string(nil), sess.Env...)
	ep.LaunchModel = sess.Model
	m.mu.Unlock()
	return ep, nil
}

// sameEnv reports whether two launch environments are identical. Pair
// order is part of the comparison: the daemon builds the spec env
// deterministically and the launch env is a copy of it, so any difference
// (value, order, or length) is a change.
func sameEnv(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Submit delivers one logical input into the session and streams the
// normalized events into events (closed before returning). It returns the
// settled TurnResult and a delivery error (nil when the submit was
// delivered; a turn that fails at the runtime level is reported in the
// result, not as an error).
func (m *Manager) Submit(ctx context.Context, sess *RuntimeSession, req SubmitRequest, events chan SessionEvent) (*TurnResult, error) {
	defer close(events)
	if err := ValidateSubmitRequest(req); err != nil {
		return nil, err
	}
	if req.Kind == SubmitInteraction {
		return m.submitInteraction(ctx, sess, req, events)
	}
	return m.submitPrompt(ctx, sess, req, events)
}

// submitPrompt runs one prompt turn: ensure active, mark busy, drive the
// turn, settle. Prompt turns are serialized per instance.
//
// The endpoint may die in the narrow window between EnsureActive's
// liveness check and the driver's submit (a kill landing exactly there).
// When the driver reports the endpoint gone (ErrEndpointGone), the turn
// consumed no work: re-activate (resuming the materialised session or
// cold-starting) and retry the submit ONCE. A second ErrEndpointGone is
// surfaced (the endpoint is not coming back on its own).
func (m *Manager) submitPrompt(ctx context.Context, sess *RuntimeSession, req SubmitRequest, events chan SessionEvent) (*TurnResult, error) {
	lock := m.promptLock(sess.InstanceID)
	lock.Lock()
	defer lock.Unlock()

	result := &TurnResult{}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := m.EnsureActive(ctx, sess, events); err != nil {
			// Activation failed: the events channel already carries the
			// session.lost / not-materialised signal (when the driver
			// emitted one). Settle the result accordingly.
			if errors.Is(err, ErrSessionLost) {
				result.SessionLost = true
			}
			return result, err
		}
		m.setState(sess, StateBusy)
		d := m.driverLocked(sess.Runtime)
		driverEvents := make(chan SessionEvent, 16)
		submitErr := make(chan error, 1)
		go func() {
			submitErr <- d.Submit(ctx, sess, req, driverEvents)
			close(driverEvents)
		}()
		for ev := range driverEvents {
			m.applyEvent(sess, result, ev)
			events <- ev
		}
		err := <-submitErr
		if !errors.Is(err, ErrEndpointGone) {
			m.settlePrompt(sess, result)
			return result, err
		}
		// The endpoint died after EnsureActive confirmed it live. Loop:
		// EnsureActive re-probes liveness, drops the stale endpoint, and
		// re-activates (resume or cold start).
	}
	// Two ErrEndpointGone in a row: the endpoint is not coming back on its
	// own. Settle and surface the error (the turn consumed no work).
	m.settlePrompt(sess, result)
	return result, ErrEndpointGone
}

// submitInteraction delivers an interaction resolution. It does NOT take
// the promptLock (it must reach a prompt turn blocked on the interaction).
// The in-flight turn's own stream carries the interaction.resolved and
// terminal events; this submit's stream carries no turn events.
func (m *Manager) submitInteraction(ctx context.Context, sess *RuntimeSession, req SubmitRequest, events chan SessionEvent) (*TurnResult, error) {
	d := m.driverLocked(sess.Runtime)
	if d == nil {
		return nil, fmt.Errorf("session: no driver registered for runtime %q", sess.Runtime)
	}
	driverEvents := make(chan SessionEvent, 16)
	submitErr := make(chan error, 1)
	go func() {
		submitErr <- d.Submit(ctx, sess, req, driverEvents)
		close(driverEvents)
	}()
	// Forward any events the driver chose to emit on the interaction
	// stream (most drivers emit none; the turn stream carries the
	// interaction.resolved).
	for ev := range driverEvents {
		m.applyEvent(sess, nil, ev)
		events <- ev
	}
	return &TurnResult{}, <-submitErr
}

// settlePrompt records the post-turn session state: a lost session goes to
// StateLost; otherwise the session is idle again and (having had a real
// exchange) materialised.
func (m *Manager) settlePrompt(sess *RuntimeSession, result *TurnResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if result.SessionLost {
		sess.State = StateLost
		sess.Endpoint = nil
		return
	}
	sess.State = StateIdle
	sess.LastActivity = m.now()
	if result.Completed || result.Failed {
		// Any completed-or-failed exchange that reached the runtime
		// materialises the session (the native side has durable state
		// now). A pure delivery failure (no runtime exchange) does not.
		sess.Materialised = true
	}
}

// Hibernate stops the session's endpoint, preserving the session
// (invariant F). It refuses to hibernate a busy session (a turn in
// flight) or a session with an unresolved interaction (plan §20: never
// hibernate busy / unresolved-interaction sessions) — the caller must
// drain first.
func (m *Manager) Hibernate(ctx context.Context, sess *RuntimeSession) error {
	m.mu.Lock()
	st := sess.State
	pending := len(sess.PendingInteractions) > 0
	m.mu.Unlock()
	if st == StateBusy {
		return errors.New("session: cannot hibernate a busy session")
	}
	if pending {
		return errors.New("session: cannot hibernate a session with an unresolved interaction")
	}
	d := m.driverLocked(sess.Runtime)
	if d == nil {
		return nil
	}
	m.setState(sess, StateHibernating)
	if err := d.Hibernate(ctx, sess); err != nil {
		m.setState(sess, StateIdle)
		return err
	}
	m.mu.Lock()
	sess.State = StateInactive
	sess.Endpoint = nil
	m.mu.Unlock()
	return nil
}

// Stop terminates the session's endpoint unconditionally (shutdown /
// explicit stop).
func (m *Manager) Stop(instanceID string) error {
	m.mu.Lock()
	sess := m.sessions[instanceID]
	var d Driver
	if sess != nil {
		d = m.drivers[sess.Runtime]
	}
	m.mu.Unlock()
	if d == nil {
		return nil
	}
	return d.Stop(instanceID)
}

// HasPendingInteraction reports whether the instance's session has an
// observed started-but-unresolved native interaction (locked read). The
// daemon consults it before hibernating (plan §20: never hibernate a
// session with an unresolved interaction).
func (m *Manager) HasPendingInteraction(instanceID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[instanceID]
	return s != nil && len(s.PendingInteractions) > 0
}

// PID is the session's endpoint process id (nil when none).
func (m *Manager) PID(instanceID string) *int {
	m.mu.Lock()
	sess := m.sessions[instanceID]
	var d Driver
	if sess != nil {
		d = m.drivers[sess.Runtime]
	}
	m.mu.Unlock()
	if d == nil {
		return nil
	}
	return d.PID(instanceID)
}

// Forget removes the instance's session state AND its prompt lock from the
// Manager. The instance is gone for good (forgotten / restarted fresh):
// there is nothing to preserve, and the next Session() call mints a fresh
// session (no native id → cold start). It does NOT stop the endpoint — the
// caller does that first via Stop — it only drops the in-memory state.
// Dropping the prompt lock too is what bounds the Manager's maps: without
// it, every forgotten instance would leak a session entry and a lock
// forever (unbounded growth in a long-lived daemon).
func (m *Manager) Forget(instanceID string) {
	m.mu.Lock()
	delete(m.sessions, instanceID)
	delete(m.promptLocks, instanceID)
	m.mu.Unlock()
}

// driverLocked returns the driver for the session's runtime. Callers must
// NOT hold m.mu (it is a quick lookup that takes the lock itself).
func (m *Manager) driverLocked(runtime domain.RuntimeName) Driver {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.drivers[runtime]
}

// state returns the session's current state (locked read).
func (m *Manager) state(sess *RuntimeSession) SessionState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return sess.State
}

// setState updates the session's state (locked write).
func (m *Manager) setState(sess *RuntimeSession, st SessionState) {
	m.mu.Lock()
	sess.State = st
	m.mu.Unlock()
}

// applyEvent folds one normalized event into the session's data fields and
// (when non-nil) the turn result. It does NOT change the session's State —
// the Manager owns the State transitions explicitly. It is safe to call
// from the prompt and interaction streams concurrently (all writes are
// under m.mu).
func (m *Manager) applyEvent(sess *RuntimeSession, result *TurnResult, ev SessionEvent) {
	m.mu.Lock()
	switch ev.Type {
	case EventSessionStarted, EventSessionResumed:
		if ev.SessionID != "" {
			sess.NativeID = ev.SessionID
		}
	case EventSessionIdentityChanged:
		if ev.SessionID != "" {
			sess.NativeID = ev.SessionID
		}
	case EventTurnCompleted:
		sess.Materialised = true
		sess.LastActivity = m.now()
	case EventInteractionStarted:
		// The interaction is now outstanding: it must be resolved before
		// the session may be hibernated (plan §20).
		if ev.Interaction != nil && ev.Interaction.NativeInteractionID != "" {
			if sess.PendingInteractions == nil {
				sess.PendingInteractions = map[string]bool{}
			}
			sess.PendingInteractions[ev.Interaction.NativeInteractionID] = true
		}
	case EventInteractionResolved:
		if ev.Interaction != nil && ev.Interaction.NativeInteractionID != "" {
			delete(sess.PendingInteractions, ev.Interaction.NativeInteractionID)
		}
	}
	m.mu.Unlock()
	if result == nil {
		return
	}
	switch ev.Type {
	case EventSessionStarted, EventSessionResumed, EventTurnStarted,
		EventTurnOutput:
		if ev.SessionID != "" {
			result.SessionID = ev.SessionID
		}
	case EventSessionLost:
		result.SessionLost = true
	case EventTurnCompleted:
		result.Completed = true
		if ev.SessionID != "" {
			result.SessionID = ev.SessionID
		}
		result.Model = ev.Model
		result.InputTokens = ev.InputTokens
		result.OutputTokens = ev.OutputTokens
		result.CachedTokens = ev.CachedTokens
	case EventTurnFailed:
		result.Failed = true
		if ev.SessionID != "" {
			result.SessionID = ev.SessionID
		}
		result.FailureKind = ev.FailureKind
		result.Error = ev.Error
		result.RetryAt = ev.RetryAt
	case EventInteractionStarted:
		result.PendingInteraction = true
	case EventInteractionResolved:
		result.PendingInteraction = false
	}
}
