package daemon

// Regression test for the 2026-09-27 black-terminal race: the launch-time
// session activation runs OFF the per-instance FIFO (doLaunch backgrounds
// it), and the driver registers the PTY master at launch (before the
// handshake settles). A concurrent attach that lands while the activation
// is still in flight (StateActivating) must NOT create a view on the
// in-flight endpoint — when the activation settles it can stop that
// endpoint (a staleLaunch restart, or an activation failure), orphaning
// the view (master EOF) and leaving the terminal black. A detach landing
// in the same window (a client that gave up on a slow attach) must NOT
// hibernate the instance (it would stop the endpoint no human was
// attached to, with the view still bound to the dead master, and leave the
// instance hibernated with an empty session — stuck, because the explicit
// wake runs resume=false and never re-establishes a PTY).
//
// The fix (three coordinated changes in daemon.go):
//  1. attachSessionDriven defers the attach (ErrDeferred) when an
//     activation is in flight (the "idle" branch now checks
//     sessionActivating, the SAME defer the working/waking/starting
//     branch uses). The dispatcher re-sends the attach, and it lands
//     observationally on the endpoint the activation brings back.
//  2. removeAttach returns false when NO attach was recorded for the
//     session (a spurious/late detach for a deferred or refused attach),
//     so doDetach does NOT hibernate on it.
//  3. doWake ensures the view is bound when the session is already Live
//     (the view may be gone — orphaned by a concurrent re-activation, or
//     torn down by a master EOF — and a wake that returned without
//     re-binding it would leave the terminal black on a live instance).
//
// This test proves (1) and (2) directly (the attach is deferred during the
// in-flight activation, and the detach does not hibernate), and that the
// re-sent attach ends with a live PTY view bound to the settled endpoint
// (the instance is not left hibernated-with-empty-session).

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

// gatedPTYDriver is a session-driven test double that models the
// launch-time activation race: it registers a REAL PTY master at the start
// of Activate (before the handshake settles — the driver registers the
// master at launch, so the attach's PTYMaster check passes during the
// in-flight activation), then blocks on a gate (the handshake is in
// flight). It has NativeTUI: true (so the attach is not refused by the
// capability gate) and implements PTYOwner (so the attach's PTYMaster
// check passes). The slave is kept open for the test's duration (the view's
// read loop blocks on it; no EOF, no teardown).
type gatedPTYDriver struct {
	gate     chan struct{} // closed to let the activation settle
	launched chan struct{} // closed when Activate is entered (PTY registered)
	master   *os.File
	slave    *os.File
}

func (g *gatedPTYDriver) Name() domain.RuntimeName { return "test-gated-pty" }

func (g *gatedPTYDriver) Capabilities() session.Capabilities {
	return session.Capabilities{
		PersistentEndpoint: true,
		StructuredEvents:   true,
		NativeSubmit:       true,
		NativeTUI:          true,
	}
}

func (g *gatedPTYDriver) Activate(ctx context.Context, sess *session.RuntimeSession, events chan<- session.SessionEvent) (*session.RuntimeEndpoint, error) {
	// Register the PTY master at the start of Activate (before the
	// handshake settles) — the driver registers it at launch, so the
	// attach's PTYMaster check passes during the in-flight activation.
	master, slave, err := pty.Open()
	if err != nil {
		return nil, err
	}
	g.master = master
	g.slave = slave
	close(g.launched)
	select {
	case <-g.gate:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &session.RuntimeEndpoint{
		ID:        "ep-" + sess.InstanceID,
		Runtime:   sess.Runtime,
		Ownership: session.OwnershipPagnet,
		Lease:     session.LeaseClaimed,
		Healthy:   true,
		Transport: "none",
		StartedAt: time.Now(),
	}, nil
}

// PTYMaster implements session.PTYOwner: the endpoint's TUI PTY master
// (the human plane) — non-nil once Activate has registered it (at launch,
// before the handshake settles).
func (g *gatedPTYDriver) PTYMaster(instanceID string) *os.File {
	return g.master
}

func (g *gatedPTYDriver) Submit(ctx context.Context, sess *session.RuntimeSession, req session.SubmitRequest, events chan<- session.SessionEvent) error {
	return errors.New("gated pty test double: never submitted")
}

func (g *gatedPTYDriver) Hibernate(ctx context.Context, sess *session.RuntimeSession) error { return nil }
func (g *gatedPTYDriver) Stop(instanceID string) error                                      { return nil }
func (g *gatedPTYDriver) PID(instanceID string) *int                                        { return nil }
// Live reports the endpoint as alive once the activation has settled (the
// Manager probes it after the state is Live; returning true keeps the
// Manager from re-activating — which would create a second PTY pair).
func (g *gatedPTYDriver) Live(instanceID string) bool { return g.master != nil }

// TestDaemon_AttachDuringInFlightActivation is the regression test for the
// 2026-09-27 black-terminal race. It simulates: a background launch-time
// activation in flight (the PTY master is registered, the handshake is
// gated) + a concurrent attach. It asserts:
//
//   - the attach is DEFERRED (ErrDeferred) while the activation is in
//     flight (it must not create a view on the in-flight endpoint);
//   - a detach for the (deferred, unrecorded) attach does NOT hibernate
//     the instance (no attach was recorded — hibernating would stop the
//     endpoint no human was attached to);
//   - the instance is NOT left hibernated-with-empty-session (it stays
//     idle with the in-flight activation);
//   - after the activation settles, the re-sent attach SUCCEEDS and ends
//     with a live PTY view bound to the settled endpoint's master.
func TestDaemon_AttachDuringInFlightActivation(t *testing.T) {
	d := newTestDaemon(t)
	client, _ := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	gate := make(chan struct{})
	launched := make(chan struct{})
	drv := &gatedPTYDriver{gate: gate, launched: launched}
	d.sessions.RegisterDriver(drv)
	var gateClosed sync.Once
	closeGate := func() { gateClosed.Do(func() { close(gate) }) }
	t.Cleanup(func() {
		closeGate() // never leak a blocked activation
		if drv.master != nil {
			_ = drv.master.Close()
		}
		if drv.slave != nil {
			_ = drv.slave.Close()
		}
	})

	instanceID := domain.NewID().String()
	env, err := transport.NewEnvelope(transport.MsgLaunchAgent, transport.LaunchAgentPayload{
		CommandID: "cmd-race-launch", InstanceID: instanceID,
		Runtime: "test-gated-pty", Kind: "representative",
	})
	if err != nil {
		t.Fatalf("build launch envelope: %v", err)
	}
	d.handleCommand(nil, env)

	// The background activation started and registered the PTY master
	// (the handshake is gated — the activation is in flight).
	select {
	case <-launched:
	case <-time.After(10 * time.Second):
		t.Fatal("the launch-time activation never registered the PTY master")
	}
	// The activation is in flight (StateActivating) and the PTY master is
	// registered (non-nil) — the exact precondition for the race.
	if !d.sessionActivating(instanceID) {
		t.Fatal("precondition: the activation is not in flight (StateActivating)")
	}
	if d.sessions.PTYMaster(instanceID) == nil {
		t.Fatal("precondition: the PTY master is not registered during the in-flight activation")
	}

	// (1) The concurrent attach is DEFERRED (ErrDeferred) — it must not
	// create a view on the in-flight endpoint.
	attachP := transport.TerminalAttachPayload{
		CommandID: "cmd-race-attach", InstanceID: instanceID, SessionID: "sess-1",
	}
	err = d.doAttach(nil, attachP)
	if !errors.Is(err, ErrDeferred) {
		t.Fatalf("attach during the in-flight activation = %v, want ErrDeferred (never bind a view to the in-flight endpoint)", err)
	}
	// The deferred attach was NOT recorded (no attach bookkeeping).
	if d.attached(instanceID) {
		t.Fatal("a deferred attach was recorded (it must not be — the detach below would then hibernate)")
	}

	// (2) A detach for the (deferred, unrecorded) attach does NOT
	// hibernate the instance (no attach was recorded — hibernating would
	// stop the endpoint no human was attached to, racing the activation's
	// settle).
	detachP := transport.DetachTerminalPayload{
		CommandID: "cmd-race-detach", InstanceID: instanceID, SessionID: "sess-1",
	}
	if err := d.doDetach(nil, detachP); err != nil {
		t.Fatalf("detach for a deferred attach = %v, want nil (no hibernate)", err)
	}

	// (3) The instance is NOT left hibernated-with-empty-session: it stays
	// idle (the in-flight activation has not settled yet, but the detach
	// did not hibernate it).
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after the detach: ok=%v err=%v", ok, err)
	}
	if row.Status == "hibernated" {
		t.Fatalf("the instance was hibernated by a detach for a deferred attach (session=%q) — the black-terminal race", row.SessionID)
	}

	// Settle the activation (release the gate). The background activation
	// completes: the endpoint is live, the instance is idle.
	closeGate()
	// Wait for the activation to settle (the state is no longer
	// StateActivating).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !d.sessionActivating(instanceID) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if d.sessionActivating(instanceID) {
		t.Fatal("the activation did not settle after the gate was released")
	}

	// (4) The re-sent attach SUCCEEDS (the activation is settled) and ends
	// with a live PTY view bound to the settled endpoint's master.
	err = d.doAttach(nil, attachP)
	if err != nil {
		t.Fatalf("re-sent attach after the activation settled = %v, want nil (a live PTY view)", err)
	}
	if !d.attached(instanceID) {
		t.Fatal("the re-sent attach was not recorded")
	}
	view := d.terminal.get(instanceID)
	if view == nil || !view.endpointView {
		t.Fatal("no endpoint view after the re-sent attach (the terminal would be black)")
	}
	if view.f == nil {
		t.Fatal("the view has no live PTY master (the terminal would be black)")
	}
	if view.f != d.sessions.PTYMaster(instanceID) {
		t.Fatal("the view is not bound to the settled endpoint's PTY master")
	}

	// The instance is idle (not hibernated) with the live endpoint.
	row, ok, err = d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after the re-sent attach: ok=%v err=%v", ok, err)
	}
	if row.Status == "hibernated" {
		t.Fatalf("the instance is hibernated after the re-sent attach (session=%q) — stuck", row.SessionID)
	}
	t.Logf("attach during the in-flight activation deferred; the detach did not hibernate; the re-sent attach bound a live PTY view (instance %s, status %s)", instanceID, row.Status)
}
