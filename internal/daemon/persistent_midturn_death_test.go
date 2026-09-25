//go:build linux

package daemon

// Mid-turn endpoint death: the stuck-instance regression (layer 3 — the
// daemon's persisted status and the terminal attach plane).
//
// The bug this guards: a Qwen instance sat persisted as `working` with NO
// live endpoint, and every terminal attach was refused with "endpoint is not
// active; attach refused". One layer down, the endpoint's mid-turn death was
// reported to the session core as a NORMALLY SETTLED submit (no terminal turn
// event), so nothing reconciled the persisted status.
//
// The invariant these tests hold:
//
//	persisted `working`  =>  a logical turn is actually in flight
//	session-driven endpoint disappears  =>  the session core notices
//	(ErrEndpointGone)  =>  resume/retry or a classified failure  =>  NEVER
//	permanently `working` with no endpoint
//
// They drive the daemon's REAL command flow against the fake-persistent
// runtime (a real deterministic process on the supervisor's PTY-owning
// ClassEndpoint path), using PAGNET_FAKE_DIE_MID_TURN=1 to crash the endpoint
// exactly once, in the middle of a turn.

import (
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

// setPersistentFakeEnv configures the fake-persistent driver's endpoint
// simulation environment BEFORE the first launch (the endpoint's env is fixed
// at launch).
func setPersistentFakeEnv(t *testing.T, d *Daemon, env []string) {
	t.Helper()
	pf, ok := d.sessions.DriverFor(domain.RuntimeFakePersistent).(*agentruntime.PersistentFake)
	if !ok {
		t.Fatal("expected the PersistentFake driver to be registered (debug mode)")
	}
	pf.Env = env
}

// waitForNoEndpoint blocks until the driver has fully observed the endpoint's
// death (PTYMaster reports nil) so a following attach deterministically takes
// the reconciliation path instead of racing the reader.
func waitForNoEndpoint(t *testing.T, d *Daemon, instanceID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for d.sessions.PTYMaster(instanceID) != nil {
		if time.Now().After(deadline) {
			t.Fatal("PTYMaster still non-nil after the endpoint died")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// C. The daemon's REAL persistent-turn path with an endpoint that dies
// mid-turn. The session core must notice (ErrEndpointGone), re-activate, and
// retry the logical submit once. Whatever the outcome, the instance must
// NEVER be left stranded `working` with no endpoint.
func TestDaemon_PersistentEndpointDiesMidTurn_NotStrandedWorking(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	// The endpoint crashes (hard SIGKILL to itself, no terminal event, no
	// session save) in the middle of the first turn its session services.
	setPersistentFakeEnv(t, d, []string{"PAGNET_FAKE_DIE_MID_TURN=1"})

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-mdt-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})

	// driveDeliver fails the test if the deliver acks an error, so this
	// already proves the turn settled through the recovery rather than
	// surfacing a crash as an instance failure.
	envs := driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-mdt-deliver", InstanceID: instanceID,
		Kind: "task", Body: "crash me once",
	})

	for _, env := range envs {
		if env.Type == transport.MsgRuntimeTurnFailed {
			t.Fatalf("the mid-turn crash surfaced a turn failure envelope: %+v", env)
		}
	}
	if !hasEnvelopeType(envs, transport.MsgRuntimeTurnCompleted) {
		t.Fatalf("the retried turn did not complete: %+v", envs)
	}

	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after the turn: ok=%v err=%v", ok, err)
	}
	// THE INVARIANT: never `working` with no endpoint.
	if row.Status == "working" {
		t.Fatalf("instance stranded `working` after the endpoint died mid-turn (pid=%v pty=%v)",
			d.sup.EndpointPID(instanceID), d.sessions.PTYMaster(instanceID))
	}
	if row.Status != "idle" {
		t.Fatalf("status after the recovery = %q, want idle (the retry completed)", row.Status)
	}
	if row.SessionID == "" {
		t.Fatal("no session id after the recovered turn")
	}
	if d.busy(instanceID) {
		t.Fatal("the daemon still records a turn in flight after the turn settled")
	}
	if d.turnInFlight(instanceID) {
		t.Fatal("the session core still reports Busy after the turn settled")
	}
	// The recovered endpoint is the ONE live endpoint (never a second one).
	if n := d.sup.Stats().ActiveEndpoints; n != 1 {
		t.Fatalf("active endpoints after the recovery = %d, want 1", n)
	}
	if d.sessions.PTYMaster(instanceID) == nil {
		t.Fatal("the recovered instance has no live endpoint PTY")
	}
}

// D. Attach recovery (defense in depth for the exact stuck state). The
// persisted row says `working`, no PTY exists, and no turn is actually in
// flight — status and liveness disagree. The attach must NOT refuse; it
// reconciles through the SAME activation path a turn uses (resume the stored
// session) and succeeds.
func TestDaemon_AttachReconcilesStaleWorkingStatus(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-asw-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-asw-deliver", InstanceID: instanceID,
		Kind: "task", Body: "first",
	})
	row, _, _ := d.state.GetInstance(instanceID)
	sessionID := row.SessionID
	if sessionID == "" {
		t.Fatal("no session id after turn 1")
	}
	pid1 := d.sup.EndpointPID(instanceID)
	if pid1 == nil {
		t.Fatal("no live endpoint after turn 1")
	}

	// Recreate the wedged state exactly as the bug leaves it: the endpoint is
	// GONE (a crash — not a hibernate, so nothing saved a hibernated status)
	// and the persisted status still says `working`.
	if err := syscall.Kill(*pid1, syscall.SIGKILL); err != nil {
		t.Fatalf("sigkill the endpoint: %v", err)
	}
	waitForNoEndpoint(t, d, instanceID, 20*time.Second)
	if err := d.state.SetInstanceStatus(instanceID, "working", sessionID); err != nil {
		t.Fatalf("forge the stale working status: %v", err)
	}
	if d.turnInFlight(instanceID) {
		t.Fatal("precondition: no turn may be in flight for the wedged instance")
	}
	if d.sessions.PTYMaster(instanceID) != nil {
		t.Fatal("precondition: no endpoint may be live for the wedged instance")
	}

	// Attach: refused before the fix ("endpoint is not active; attach
	// refused"). Now it reconciles. driveCommand fails the test on an error
	// ack, which is the assertion that the attach succeeded.
	envs := driveCommand(t, d, server, transport.MsgAttachTerminal,
		transport.TerminalAttachPayload{CommandID: "cmd-asw-attach", InstanceID: instanceID, SessionID: sessionID},
		"cmd-asw-attach")

	row, _, _ = d.state.GetInstance(instanceID)
	if row.Status == "working" {
		t.Fatal("the attach left the stale `working` status in place")
	}
	if row.Status != "idle" {
		t.Fatalf("status after the reconciling attach = %q, want idle", row.Status)
	}
	if row.SessionID != sessionID {
		t.Fatalf("the reconciling attach changed the session: before=%q after=%q", sessionID, row.SessionID)
	}
	pid2 := d.sup.EndpointPID(instanceID)
	if pid2 == nil {
		t.Fatal("no endpoint after the reconciling attach")
	}
	if *pid2 == *pid1 {
		t.Fatal("the reconciling attach reused the dead process")
	}
	if n := d.sup.Stats().ActiveEndpoints; n != 1 {
		t.Fatalf("active endpoints after the reconciling attach = %d, want 1 (never a second runtime)", n)
	}
	if !d.attached(instanceID) {
		t.Fatal("the reconciling attach was not recorded")
	}
	if !sawSessionEvent(t, envs, instanceID, true) {
		t.Fatalf("the reconciling attach did not resume the stored session: %+v", envs)
	}
	if !sawSnapshotFrame(envs, instanceID) {
		t.Fatalf("the reconciling attach did not send a PTY snapshot frame: %+v", envs)
	}
	if view := d.terminal.get(instanceID); view == nil || !view.endpointView {
		t.Fatal("no endpoint view after the reconciling attach")
	}
}

// E. Busy protection. `working` + a turn genuinely in flight + the endpoint
// momentarily not live is the narrow window in which the session core is
// ALREADY re-activating the endpoint (EnsureActive + one retry). The attach
// must NOT launch a competing runtime there — it defers (stays queued and is
// re-sent) and lands observationally on the endpoint the session core brings
// back.
//
// That window is shorter than the driver's poll interval in production, so
// the two signals turnInFlight reads are established directly rather than
// raced: the legacy activeTurns map (the process-per-turn path) and the
// session core's own StateBusy (the persistent path, which does not set
// activeTurns — see wakeInstance).
func TestDaemon_AttachDefersWhenTurnInFlightAndEndpointDown(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-adf-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-adf-deliver", InstanceID: instanceID,
		Kind: "task", Body: "first",
	})
	pid := d.sup.EndpointPID(instanceID)
	if pid == nil {
		t.Fatal("no live endpoint after turn 1")
	}
	if err := syscall.Kill(*pid, syscall.SIGKILL); err != nil {
		t.Fatalf("sigkill the endpoint: %v", err)
	}
	waitForNoEndpoint(t, d, instanceID, 20*time.Second)
	if err := d.state.SetInstanceStatus(instanceID, "working", ""); err != nil {
		t.Fatalf("set the working status: %v", err)
	}
	sess := d.sessions.GetSession(instanceID)
	if sess == nil {
		t.Fatal("no session for the instance after turn 1")
	}
	endpointsBefore := d.sup.Stats().ActiveEndpoints

	for _, tc := range []struct {
		name    string
		set     func()
		cleanup func()
	}{
		{
			name: "legacy activeTurns",
			set: func() {
				d.turnMu.Lock()
				d.activeTurns[instanceID] = true
				d.turnMu.Unlock()
			},
			cleanup: func() {
				d.turnMu.Lock()
				delete(d.activeTurns, instanceID)
				d.turnMu.Unlock()
			},
		},
		{
			name:    "session core StateBusy",
			set:     func() { sess.State = session.StateBusy },
			cleanup: func() { sess.State = session.StateIdle },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.set()
			defer tc.cleanup()
			if !d.turnInFlight(instanceID) {
				t.Fatal("precondition: the turn must read as in flight")
			}
			if d.sessions.PTYMaster(instanceID) != nil {
				t.Fatal("precondition: the endpoint must not be live")
			}

			err := d.doAttach(nil, transport.TerminalAttachPayload{
				CommandID: "cmd-adf-attach", InstanceID: instanceID,
			})
			if !errors.Is(err, ErrDeferred) {
				t.Fatalf("doAttach = %v, want ErrDeferred (never launch a competing endpoint)", err)
			}
			if n := d.sup.Stats().ActiveEndpoints; n != endpointsBefore {
				t.Fatalf("the deferred attach launched a competing endpoint (active endpoints %d, was %d)", n, endpointsBefore)
			}
			if d.attached(instanceID) {
				t.Fatal("a deferred attach was recorded as an attach")
			}
			if d.terminal.get(instanceID) != nil {
				t.Fatal("a deferred attach created a terminal view")
			}
			row, _, _ := d.state.GetInstance(instanceID)
			if row.Status != "working" {
				t.Fatalf("status = %q, want working (a deferred attach must not reconcile it)", row.Status)
			}
		})
	}
}
