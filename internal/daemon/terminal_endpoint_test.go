//go:build linux

package daemon

// Phase 3 (terminal session unification): daemon-level tests for the
// SESSION-DRIVEN terminal plane — a session-driven runtime's terminal
// attach connects a human to the ENDPOINT'S OWN PTY (A1: one process owns
// both planes) instead of spawning a separate interactive process.
//
// The tests drive the daemon's REAL command flow (launch → deliver →
// attach/detach/stop) against the fake-persistent runtime (a REAL
// deterministic process launched through the supervisor's PTY-owning
// ClassEndpoint path — the daemon's debug mode sets the driver's PTYSize,
// so every endpoint here owns its TUI PTY).
//
// Proved here (asserted on process/state facts, not logs):
//
//  1. attach to a live endpoint: one endpoint, zero ClassPTY, the view
//     exists from the activation site (A5), the human line on the PTY and
//     the machine message act on the SAME session, and the machine plane's
//     JSONL never crosses into the PTY (two-planes invariant);
//  2. attach wakes a hibernated instance (session.resumed, same id, new
//     PID, view on the new PTY, high-water endpoint count 1);
//  3. refusals: blocked/failed/stopped + a session-driven runtime without
//     a native TUI (capability gate) — honest refusal, no process, no
//     attach bookkeeping;
//  4. terminal stop on a session-driven instance hibernates through the
//     session core (endpoint stopped, session preserved, reason "stopped",
//     view gone);
//  5. an endpoint crash while attached tears the view down observationally
//     (master EOF, no hibernated event, status untouched) and a re-attach
//     (re)activates cleanly;
//  6. the §42 eight-step acceptance proof (fake variant): terminal is the
//     same session;
//  7. keep-awake (A6): a view WITHOUT an attached human does not block
//     hibernation; an attached human does; the last detach hibernates;
//  8. activeWorkCount (A7) counts the live endpoint (a re-exec would
//     orphan it) while terminal.activeCount excludes the view;
//  9. concurrent attachEndpoint calls reconcile to exactly one view;
// 10. the view exists DURING an in-flight turn (A5/G8 placement): the
//     view's read loop is the PTY's only reader while no human is
//     attached, so a turn parked on a native interaction must have a
//     live view from activation — without a reader a native TUI blocks
//     on tty writes once the PTY buffer fills and the model turn never
//     starts.
//
// Linux-gated: the TUI human plane depends on the endpoint owning its
// controlling terminal (Setsid+Setctty, the ClassEndpoint PTY path),
// which is the Linux supervisor shape.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

// --- helpers -----------------------------------------------------------------

// daemonFakeSessionFileVars is the fake runtime's on-disk session file
// including the Phase 3 session memory (vars).
type daemonFakeSessionFileVars struct {
	SessionID string            `json:"sessionId"`
	Turns     int               `json:"turns"`
	Vars      map[string]string `json:"vars,omitempty"`
}

func readDaemonFakeSessionVars(t *testing.T, instanceID string) daemonFakeSessionFileVars {
	t.Helper()
	stateDir := os.Getenv("PAGNET_STATE_DIR")
	if stateDir == "" {
		t.Fatal("PAGNET_STATE_DIR not set")
	}
	path := filepath.Join(stateDir, "sessions", instanceID, "session.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	var s daemonFakeSessionFileVars
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("parse session file: %v", err)
	}
	return s
}

// terminalRing decodes the instance's terminal session ring (the bounded
// PTY scrollback) — the authoritative terminal state the attach snapshot
// frame replays.
func terminalRing(t *testing.T, d *Daemon, instanceID string) string {
	t.Helper()
	s := d.terminal.get(instanceID)
	if s == nil {
		t.Fatalf("no terminal session for %s", instanceID)
	}
	data, _ := d.terminal.snapshot(s)
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		t.Fatalf("decode ring: %v", err)
	}
	return string(b)
}

// ringHasAll reports whether s contains every want substring.
func ringHasAll(s string, want []string) bool {
	for _, w := range want {
		if !strings.Contains(s, w) {
			return false
		}
	}
	return true
}

// waitForRing polls the instance's terminal ring until every want substring
// is present (or the deadline elapses, failing the test with the ring).
func waitForRing(t *testing.T, d *Daemon, instanceID string, want []string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if s := d.terminal.get(instanceID); s != nil {
			if data, _ := d.terminal.snapshot(s); data != "" {
				if b, err := base64.StdEncoding.DecodeString(data); err == nil && ringHasAll(string(b), want) {
					return string(b)
				}
			}
		}
		if time.Now().After(deadline) {
			got := ""
			if s := d.terminal.get(instanceID); s != nil {
				if data, _ := d.terminal.snapshot(s); data != "" {
					if b, _ := base64.StdEncoding.DecodeString(data); b != nil {
						got = string(b)
					}
				}
			}
			t.Fatalf("terminal ring did not contain %v within %v; ring=%q", want, timeout, got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// sawSnapshotFrame reports whether the envelopes carry a terminal_output
// SNAPSHOT frame for the instance (the attach replays the ring before
// switching the client to live output, §11).
func sawSnapshotFrame(envs []transport.Envelope, instanceID string) bool {
	for _, env := range envs {
		if env.Type != transport.MsgTerminalOutput {
			continue
		}
		var p transport.TerminalOutputPayload
		if err := env.DecodePayload(&p); err != nil {
			continue
		}
		if p.InstanceID == instanceID && p.Snapshot {
			return true
		}
	}
	return false
}

// sawOutputContaining reports whether the envelopes carry a runtime_output
// for the instance whose plaintext output contains want.
func sawOutputContaining(envs []transport.Envelope, instanceID, want string) bool {
	for _, env := range envs {
		if env.Type != transport.MsgRuntimeOutput {
			continue
		}
		var p map[string]any
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			continue
		}
		if p["instanceId"] != instanceID {
			continue
		}
		if out, _ := p["output"].(string); strings.Contains(out, want) {
			return true
		}
	}
	return false
}

// sawSessionEvent reports whether the envelopes carry a runtime_session
// event for the instance with the given resumed flag (reportSession).
func sawSessionEvent(t *testing.T, envs []transport.Envelope, instanceID string, resumed bool) bool {
	t.Helper()
	for _, env := range envs {
		if env.Type != transport.MsgRuntimeSession {
			continue
		}
		p := envelopePayload(t, env)
		if p["instanceId"] == instanceID {
			if r, _ := p["resumed"].(bool); r == resumed {
				return true
			}
		}
	}
	return false
}

// sawHibernatedReason reports whether the envelopes carry an
// agent_hibernated for the instance with the given reason.
func sawHibernatedReason(t *testing.T, envs []transport.Envelope, instanceID, reason string) bool {
	t.Helper()
	for _, env := range envs {
		if env.Type != transport.MsgAgentHibernated {
			continue
		}
		p := envelopePayload(t, env)
		if p["instanceId"] == instanceID {
			if r, _ := p["reason"].(string); r == reason {
				return true
			}
		}
	}
	return false
}

// notuiDriver is a session-driven test double WITHOUT a native TUI: it
// proves the attach capability gate refuses an honest "no terminal surface"
// (never a spawned stand-in process) for a session-driven runtime whose
// Capabilities lack NativeTUI. Its Activate establishes a PROCESS-LESS
// endpoint (instruction-model Wave 3: a session-driven launch establishes
// the session at launch) — no real process is ever spawned, so the
// supervisor registry stays empty and the attach refusal is what the test
// exercises.
type notuiDriver struct{}

func (notuiDriver) Name() domain.RuntimeName { return "test-notui" }

func (notuiDriver) Capabilities() session.Capabilities {
	return session.Capabilities{
		PersistentEndpoint: true,
		StructuredEvents:   true,
		NativeSubmit:       true,
		// NativeTUI: false — the gate under test.
	}
}

func (notuiDriver) Activate(ctx context.Context, sess *session.RuntimeSession, events chan<- session.SessionEvent) (*session.RuntimeEndpoint, error) {
	// A process-less endpoint: the launch's idle activation succeeds
	// without a real process (no native session is minted — nothing is
	// exchanged, so the Materialised invariant keeps the id unpersisted).
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

func (notuiDriver) Submit(ctx context.Context, sess *session.RuntimeSession, req session.SubmitRequest, events chan<- session.SessionEvent) error {
	return errors.New("notui test double: never submitted")
}

func (notuiDriver) Hibernate(ctx context.Context, sess *session.RuntimeSession) error { return nil }
func (notuiDriver) Stop(instanceID string) error                                      { return nil }
func (notuiDriver) PID(instanceID string) *int                                        { return nil }
func (notuiDriver) Live(instanceID string) bool                                       { return false }

// --- tests -------------------------------------------------------------------

// 1. Attach to a LIVE endpoint: the human is connected to the endpoint's
// OWN PTY (one process, both planes), the view exists from the activation
// site, the human plane and the machine plane act on the SAME session, and
// the machine plane's JSONL never crosses into the PTY.
func TestDaemon_TerminalAttachLiveEndpoint(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-tal-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-tal-deliver-1", InstanceID: instanceID,
		Kind: "task", Body: "first",
	})
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after turn 1: ok=%v err=%v", ok, err)
	}
	sessionID := row.SessionID
	if sessionID == "" {
		t.Fatal("no session id after turn 1")
	}
	if row.Status != "idle" {
		t.Fatalf("status after turn 1 = %q, want idle", row.Status)
	}

	// A1: ONE process owns both planes — exactly one endpoint, and the
	// terminal plane launched no ClassPTY of its own.
	if n := d.sup.Stats().ActiveEndpoints; n != 1 {
		t.Fatalf("active endpoints = %d, want 1", n)
	}
	if n := d.sup.Stats().ActivePTYs; n != 0 {
		t.Fatalf("active ClassPTY sessions = %d, want 0 (no second interactive process)", n)
	}

	// A5: the view exists from the ACTIVATION (the turn), not from the
	// attach.
	if view := d.terminal.get(instanceID); view == nil || !view.endpointView {
		t.Fatal("no endpoint view after the activation turn (the view is ensured at activation, A5)")
	}

	// Attach (durable command): the human is connected to the endpoint's
	// OWN PTY.
	envs := driveCommand(t, d, server, transport.MsgAttachTerminal,
		transport.TerminalAttachPayload{CommandID: "cmd-tal-attach", InstanceID: instanceID, SessionID: sessionID},
		"cmd-tal-attach")
	if !sawSnapshotFrame(envs, instanceID) {
		t.Fatalf("attach did not send a PTY snapshot frame: %+v", envs)
	}
	if !d.attached(instanceID) {
		t.Fatal("attach not recorded")
	}

	// The snapshot replays the TUI's rendering of the machine turn (the
	// bounded ring is the frame's payload).
	if ring := terminalRing(t, d, instanceID); !strings.Contains(ring, "done") {
		t.Fatalf("snapshot ring missing the TUI turn rendering: %q", ring)
	}

	// Human plane: type a line on the endpoint's OWN PTY (the master).
	master := d.sessions.PTYMaster(instanceID)
	if master == nil {
		t.Fatal("PTYMaster is nil on the live PTY-owning endpoint")
	}
	if _, err := master.Write([]byte("let color blue\n")); err != nil {
		t.Fatalf("write human line to the PTY: %v", err)
	}
	// The TUI renders the line and the let turn's output (the human turn
	// runs through the same in-process turn queue as machine submits).
	waitForRing(t, d, instanceID, []string{"you> let color blue", "let color = blue"}, 20*time.Second)

	// Machine plane: `print color` reads back the value set on the human
	// plane (same session across planes).
	envs = driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-tal-deliver-2", InstanceID: instanceID,
		Kind: "task", Body: "print color",
	})
	if !sawOutputContaining(envs, instanceID, "blue") {
		t.Fatalf("machine print did not read back the human-plane value: %+v", envs)
	}
	row, _, _ = d.state.GetInstance(instanceID)
	if row.SessionID != sessionID {
		t.Fatalf("session id changed across planes: before=%q after=%q", sessionID, row.SessionID)
	}

	// Two-planes invariant: the machine plane's JSONL never crosses into
	// the PTY (the human plane carries only the TUI's rendering).
	if ring := terminalRing(t, d, instanceID); strings.Contains(ring, `"type":"submit"`) || strings.Contains(ring, `"event":"runtime`) {
		t.Fatalf("machine-plane JSONL leaked into the PTY ring: %q", ring)
	}

	// Still exactly one process (the attach never spawned a second one).
	if n := d.sup.Stats().ActiveEndpoints; n != 1 {
		t.Fatalf("active endpoints after the attach = %d, want 1", n)
	}
	if n := d.sup.Stats().ActivePTYs; n != 0 {
		t.Fatalf("active ClassPTY sessions after the attach = %d, want 0", n)
	}
}

// 2. Attach WAKES a hibernated instance: the same activation path a turn
// uses (EnsureActive resume) — session.resumed with the SAME id, a NEW
// endpoint process (PID changed), the view on the NEW PTY, and the
// high-water endpoint count stays 1 (never a second process).
func TestDaemon_TerminalAttachWakesHibernated(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-taw-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-taw-deliver-1", InstanceID: instanceID,
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

	// Hibernate (endpoint stopped, session preserved).
	if err := d.hibernateInstance(nil, instanceID, "test-wake"); err != nil {
		t.Fatalf("hibernate: %v", err)
	}
	if n := d.sup.Stats().ActiveEndpoints; n != 0 {
		t.Fatalf("active endpoints after hibernate = %d, want 0", n)
	}

	// Attach: wakes the hibernated instance.
	envs := driveCommand(t, d, server, transport.MsgAttachTerminal,
		transport.TerminalAttachPayload{CommandID: "cmd-taw-attach", InstanceID: instanceID, SessionID: sessionID},
		"cmd-taw-attach")

	row, _, _ = d.state.GetInstance(instanceID)
	if row.Status != "idle" {
		t.Fatalf("status after the waking attach = %q, want idle", row.Status)
	}
	if row.SessionID != sessionID {
		t.Fatalf("session id changed by the waking attach: before=%q after=%q", sessionID, row.SessionID)
	}
	pid2 := d.sup.EndpointPID(instanceID)
	if pid2 == nil {
		t.Fatal("no live endpoint after the waking attach")
	}
	if *pid2 == *pid1 {
		t.Fatalf("the waking attach reused the old endpoint process (pid %d)", *pid1)
	}
	// High-water: exactly one endpoint was ever live at a time.
	if n := d.sup.Stats().ActiveEndpoints; n != 1 {
		t.Fatalf("active endpoints after the waking attach = %d, want 1 (never a second process)", n)
	}

	// The wake RESUMED the stored session (not a cold start).
	if !sawSessionEvent(t, envs, instanceID, true) {
		t.Fatalf("waking attach did not report session.resumed: %+v", envs)
	}
	if !sawSnapshotFrame(envs, instanceID) {
		t.Fatalf("waking attach did not send a PTY snapshot frame: %+v", envs)
	}

	// The view is on the NEW endpoint's PTY.
	view := d.terminal.get(instanceID)
	if view == nil || !view.endpointView {
		t.Fatal("no endpoint view after the waking attach")
	}
	if view.f != d.sessions.PTYMaster(instanceID) {
		t.Fatal("the view is not on the new endpoint's PTY master")
	}
}

// 3. Refusals: blocked/failed/stopped instances are refused (no process,
// no attach), and a session-driven runtime WITHOUT a native TUI is refused
// by the capability gate with an honest "no terminal surface" — never a
// spawned stand-in process.
func TestDaemon_TerminalAttachRefusals(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	// (a) blocked / failed / stopped: a clean refusal.
	for _, status := range []string{"blocked", "failed", "stopped"} {
		instanceID := domain.NewID().String()
		driveLaunch(t, d, server, transport.LaunchAgentPayload{
			CommandID: "cmd-tar-launch-" + status, InstanceID: instanceID,
			Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
		})
		if err := d.state.SetInstanceStatus(instanceID, status, ""); err != nil {
			t.Fatalf("set status %s: %v", status, err)
		}
		// The launch established the session-driven endpoint (instruction-
		// model Wave 3) — its view exists from the activation (A5); a
		// refused attach must change NOTHING: no second process, no
		// attach bookkeeping, no new/changed terminal session.
		before := d.sup.Stats().ActiveEndpoints
		viewBefore := d.terminal.get(instanceID)
		attachEnv, err := transport.NewEnvelope(transport.MsgAttachTerminal, transport.TerminalAttachPayload{
			CommandID: "cmd-tar-attach-" + status, InstanceID: instanceID,
		})
		if err != nil {
			t.Fatalf("build attach envelope: %v", err)
		}
		d.handleCommand(nil, attachEnv)
		_, ack := readUntilAck(t, server, "cmd-tar-attach-"+status)
		errMsg, _ := ack["error"].(string)
		if !strings.Contains(errMsg, "attach refused") {
			t.Fatalf("status %s: attach ack error = %q, want a refusal", status, errMsg)
		}
		if n := d.sup.Stats().ActiveEndpoints; n != before {
			t.Fatalf("status %s: a process was spawned by a refused attach (endpoints %d -> %d)", status, before, n)
		}
		if d.attached(instanceID) {
			t.Fatalf("status %s: a refused attach was recorded", status)
		}
		if view := d.terminal.get(instanceID); view != viewBefore {
			t.Fatalf("status %s: a refused attach changed the terminal session", status)
		}
	}

	// (b) a session-driven runtime WITHOUT a native TUI: the capability
	// gate refuses BEFORE any bookkeeping or process.
	d.sessions.RegisterDriver(notuiDriver{})
	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-tar-notui-launch", InstanceID: instanceID,
		Runtime: "test-notui", Kind: "representative",
	})
	// The no-TUI launch established a PROCESS-LESS endpoint (the double
	// spawns nothing); the loop above's fake-persistent endpoints are the
	// only live processes. A no-TUI refusal must spawn no NEW one.
	before := d.sup.Stats().ActiveEndpoints
	attachEnv, err := transport.NewEnvelope(transport.MsgAttachTerminal, transport.TerminalAttachPayload{
		CommandID: "cmd-tar-notui-attach", InstanceID: instanceID,
	})
	if err != nil {
		t.Fatalf("build attach envelope: %v", err)
	}
	d.handleCommand(nil, attachEnv)
	_, ack := readUntilAck(t, server, "cmd-tar-notui-attach")
	errMsg, _ := ack["error"].(string)
	if !strings.Contains(errMsg, "no terminal surface") {
		t.Fatalf("no-TUI attach ack error = %q, want the capability-gate refusal", errMsg)
	}
	if n := d.sup.Stats().ActiveEndpoints; n != before {
		t.Fatalf("a process was spawned by a no-TUI refusal (endpoints %d -> %d)", before, n)
	}
	if d.attached(instanceID) {
		t.Fatal("a no-TUI refusal was recorded as an attach")
	}
	if d.terminal.get(instanceID) != nil {
		t.Fatal("a terminal session exists after a no-TUI refusal")
	}
}

// 4. Terminal stop on a session-driven instance hibernates through the
// SESSION CORE: the endpoint is stopped (session preserved — invariant F),
// the wire shape is agent_hibernated with reason "stopped", and the view
// is gone.
func TestDaemon_TerminalStopHibernatesSessionDriven(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-tts-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-tts-deliver-1", InstanceID: instanceID,
		Kind: "task", Body: "first",
	})
	row, _, _ := d.state.GetInstance(instanceID)
	sessionID := row.SessionID
	if sessionID == "" {
		t.Fatal("no session id after turn 1")
	}
	// The view exists (activation site) but NO human is attached.
	if d.attached(instanceID) {
		t.Fatal("test precondition: no human attach")
	}

	envs := driveCommand(t, d, server, transport.MsgTerminalStop,
		transport.TerminalStopPayload{CommandID: "cmd-tts-stop", InstanceID: instanceID},
		"cmd-tts-stop")

	// The endpoint is stopped BY THE SESSION CORE (session preserved).
	if n := d.sup.Stats().ActiveEndpoints; n != 0 {
		t.Fatalf("active endpoints after the stop = %d, want 0", n)
	}
	row, _, _ = d.state.GetInstance(instanceID)
	if row.Status != "hibernated" {
		t.Fatalf("status after the stop = %q, want hibernated", row.Status)
	}
	if row.SessionID != sessionID {
		t.Fatalf("session id not preserved on the row: %q", row.SessionID)
	}
	if sess := d.sessions.GetSession(instanceID); sess == nil || sess.NativeID != sessionID || !sess.Materialised {
		t.Fatalf("session not preserved in the Manager: %+v", sess)
	}

	// The wire shape: agent_hibernated with reason "stopped".
	if !sawHibernatedReason(t, envs, instanceID, "stopped") {
		t.Fatalf("no agent_hibernated(reason=stopped): %+v", envs)
	}
	// The view is gone (the stop dropped it; the endpoint's death EOFs it).
	if d.terminal.get(instanceID) != nil {
		t.Fatal("view still present after the stop")
	}
}

// 5. An endpoint CRASH while attached tears the view down observationally:
// master EOF drops the view, NO hibernated event is emitted (the session
// core owns the lifecycle), the status is untouched, and a re-attach
// (re)activates cleanly (resume on a new process) — no panic, no
// double-close.
func TestDaemon_TerminalEndpointCrashWhileAttached(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-tec-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-tec-deliver-1", InstanceID: instanceID,
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
	driveCommand(t, d, server, transport.MsgAttachTerminal,
		transport.TerminalAttachPayload{CommandID: "cmd-tec-attach", InstanceID: instanceID, SessionID: sessionID},
		"cmd-tec-attach")
	if !d.attached(instanceID) {
		t.Fatal("attach not recorded")
	}

	// Crash the endpoint (SIGKILL — no graceful save, no hibernate).
	if err := syscall.Kill(*pid1, syscall.SIGKILL); err != nil {
		t.Fatalf("sigkill the endpoint: %v", err)
	}

	// The view tears down observationally on master EOF.
	deadline := time.Now().Add(20 * time.Second)
	for d.terminal.get(instanceID) != nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if d.terminal.get(instanceID) != nil {
		t.Fatal("view not torn down after the endpoint crash")
	}

	// The status is untouched (the view's teardown writes no status).
	row, _, _ = d.state.GetInstance(instanceID)
	if row.Status != "idle" {
		t.Fatalf("status after the crash = %q, want idle (untouched by the view's teardown)", row.Status)
	}

	// Wait for the driver to fully observe the death (PTYMaster nil) so
	// the re-attach deterministically takes the (re)activation path.
	deadline = time.Now().Add(20 * time.Second)
	for d.sessions.PTYMaster(instanceID) != nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if d.sessions.PTYMaster(instanceID) != nil {
		t.Fatal("PTYMaster still non-nil after the crash")
	}

	// Re-attach: the endpoint is gone → the attach (re)activates (resume)
	// and views the NEW endpoint's PTY. The envelopes read up to the ack
	// include everything the crash emitted on the wire — a hibernated
	// event among them would mean the view's teardown was NOT
	// observational (the session core owns the lifecycle).
	envs := driveCommand(t, d, server, transport.MsgAttachTerminal,
		transport.TerminalAttachPayload{CommandID: "cmd-tec-attach-2", InstanceID: instanceID, SessionID: sessionID},
		"cmd-tec-attach-2")
	for _, env := range envs {
		if env.Type == transport.MsgAgentHibernated {
			t.Fatalf("the crash emitted a hibernated event (the view's teardown must be observational): %+v", env)
		}
	}
	row, _, _ = d.state.GetInstance(instanceID)
	if row.Status != "idle" {
		t.Fatalf("status after the re-attach = %q, want idle", row.Status)
	}
	if row.SessionID != sessionID {
		t.Fatalf("re-attach changed the session: before=%q after=%q", sessionID, row.SessionID)
	}
	pid2 := d.sup.EndpointPID(instanceID)
	if pid2 == nil {
		t.Fatal("no endpoint after the re-attach")
	}
	if *pid2 == *pid1 {
		t.Fatal("the re-attach reused the crashed process")
	}
	if !sawSessionEvent(t, envs, instanceID, true) {
		t.Fatalf("re-attach did not resume the session: %+v", envs)
	}
	if !sawSnapshotFrame(envs, instanceID) {
		t.Fatalf("re-attach did not send a PTY snapshot frame: %+v", envs)
	}
	if view := d.terminal.get(instanceID); view == nil || !view.endpointView {
		t.Fatal("no endpoint view after the re-attach")
	}
}

// 6. §42 acceptance (fake variant): TERMINAL IS THE SAME SESSION — the
// eight-step proof.
func TestDaemon_TerminalSameSessionEightStep(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	// 1. start Pagnet AgentInstance.
	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-s8-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})

	// 2. get native session ID (the first machine turn materialises it).
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-s8-deliver-1", InstanceID: instanceID,
		Kind: "task", Body: "first",
	})
	row, _, _ := d.state.GetInstance(instanceID)
	sessionID := row.SessionID
	if sessionID == "" {
		t.Fatal("step 2: no native session id after the first turn")
	}

	// 3. attach browser terminal.
	envs := driveCommand(t, d, server, transport.MsgAttachTerminal,
		transport.TerminalAttachPayload{CommandID: "cmd-s8-attach", InstanceID: instanceID, SessionID: sessionID},
		"cmd-s8-attach")
	if !sawSnapshotFrame(envs, instanceID) {
		t.Fatalf("step 3: attach did not connect to a live PTY (no snapshot frame): %+v", envs)
	}

	// 4. type a human prompt (on the endpoint's OWN PTY).
	master := d.sessions.PTYMaster(instanceID)
	if master == nil {
		t.Fatal("step 4: PTYMaster is nil on the live endpoint")
	}
	if _, err := master.Write([]byte("let color blue\n")); err != nil {
		t.Fatalf("step 4: write human prompt: %v", err)
	}

	// 5. observe the runtime event for the SAME session: the native TUI
	// renders the human turn on the PTY, and the session file records it
	// under the SAME session id (the fake variant of the structured-event
	// observation — the TUI is the native event surface).
	ring := waitForRing(t, d, instanceID, []string{"you> let color blue", "let color = blue", "done"}, 20*time.Second)
	if !strings.Contains(ring, "done") {
		t.Fatalf("step 5: the human turn did not complete on the TUI: %q", ring)
	}
	sf := readDaemonFakeSessionVars(t, instanceID)
	if sf.SessionID != sessionID {
		t.Fatalf("step 5: the human turn ran in a different session: file=%q want=%q", sf.SessionID, sessionID)
	}
	if sf.Vars["color"] != "blue" {
		t.Fatalf("step 5: the human prompt did not act on the session: vars=%v", sf.Vars)
	}

	// 6. send Pagnet message through machine channel.
	envs = driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-s8-deliver-2", InstanceID: instanceID,
		Kind: "task", Body: "print color",
	})

	// 7. observe that message appear/act in SAME session: the machine
	// turn reads back the value the human set (host-protocol output AND
	// the TUI rendering), and the session id is unchanged.
	if !sawOutputContaining(envs, instanceID, "blue") {
		t.Fatalf("step 7: the machine message did not act on the human-set state: %+v", envs)
	}
	row, _, _ = d.state.GetInstance(instanceID)
	if row.SessionID != sessionID {
		t.Fatalf("step 7: session id changed: before=%q after=%q", sessionID, row.SessionID)
	}
	waitForRing(t, d, instanceID, []string{"print color: blue"}, 15*time.Second)

	// 8. verify there was never a second runtime process.
	if n := d.sup.Stats().ActiveEndpoints; n != 1 {
		t.Fatalf("step 8: active endpoints = %d, want exactly 1 (never a second runtime process)", n)
	}
	if n := d.sup.Stats().ActivePTYs; n != 0 {
		t.Fatalf("step 8: active ClassPTY sessions = %d, want 0", n)
	}
	t.Logf("§42 (fake variant): session %q shared by the terminal and the machine channel; 1 endpoint, 0 ClassPTY", sessionID)
}

// 7. Keep-awake (A6): a view WITHOUT an attached human does NOT block
// hibernation (the session core already keeps the endpoint alive; the view
// merely watches it); an ATTACHED human does; the last detach hibernates.
func TestDaemon_TerminalViewKeepAwake(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-tvk-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-tvk-deliver-1", InstanceID: instanceID,
		Kind: "task", Body: "first",
	})
	row, _, _ := d.state.GetInstance(instanceID)
	sessionID := row.SessionID
	if sessionID == "" {
		t.Fatal("no session id after turn 1")
	}
	// The view exists (activation site); no human is attached.
	if d.attached(instanceID) {
		t.Fatal("test precondition: no human attach")
	}

	// A6: a view without an attached human does NOT block hibernation.
	if err := d.hibernateInstance(nil, instanceID, "a6-view"); err != nil {
		t.Fatalf("hibernate refused despite no human attach (the view must not keep the instance awake): %v", err)
	}
	if n := d.sup.Stats().ActiveEndpoints; n != 0 {
		t.Fatalf("active endpoints after the view-only hibernate = %d, want 0", n)
	}
	row, _, _ = d.state.GetInstance(instanceID)
	if row.Status != "hibernated" {
		t.Fatalf("status after the view-only hibernate = %q, want hibernated", row.Status)
	}

	// Wake via attach (the session-driven wake path).
	driveCommand(t, d, server, transport.MsgAttachTerminal,
		transport.TerminalAttachPayload{CommandID: "cmd-tvk-attach", InstanceID: instanceID, SessionID: sessionID},
		"cmd-tvk-attach")
	row, _, _ = d.state.GetInstance(instanceID)
	if row.Status != "idle" {
		t.Fatalf("status after the waking attach = %q, want idle", row.Status)
	}
	if !d.attached(instanceID) {
		t.Fatal("human attach not recorded")
	}
	if n := d.sup.Stats().ActiveEndpoints; n != 1 {
		t.Fatalf("active endpoints after the waking attach = %d, want 1", n)
	}

	// With an attached human, hibernate is DEFERRED (keep-awake).
	if err := d.hibernateInstance(nil, instanceID, "a6-attached"); err != nil {
		t.Fatalf("hibernate failed while a human is attached: %v", err)
	}
	if n := d.sup.Stats().ActiveEndpoints; n != 1 {
		t.Fatal("the attached human did not keep the endpoint awake")
	}
	row, _, _ = d.state.GetInstance(instanceID)
	if row.Status != "idle" {
		t.Fatalf("status changed by the deferred hibernate: %q", row.Status)
	}

	// The last detach hibernates (the keep-awake reason is gone).
	envs := driveCommand(t, d, server, transport.MsgDetachTerminal,
		transport.DetachTerminalPayload{CommandID: "cmd-tvk-detach", InstanceID: instanceID, SessionID: sessionID},
		"cmd-tvk-detach")
	if n := d.sup.Stats().ActiveEndpoints; n != 0 {
		t.Fatalf("active endpoints after the last detach = %d, want 0", n)
	}
	row, _, _ = d.state.GetInstance(instanceID)
	if row.Status != "hibernated" {
		t.Fatalf("status after the last detach = %q, want hibernated", row.Status)
	}
	if !sawHibernatedReason(t, envs, instanceID, "attach_closed") {
		t.Fatalf("no agent_hibernated(reason=attach_closed): %+v", envs)
	}
}

// 8. activeWorkCount (A7) counts the LIVE endpoint — a re-exec would
// orphan it, exactly like a legacy PTY process — while terminal.activeCount
// excludes the view (A6).
func TestDaemon_ActiveWorkCountCountsLiveEndpoints(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-a7-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-a7-deliver-1", InstanceID: instanceID,
		Kind: "task", Body: "first",
	})

	// A live (idle) endpoint counts as active work.
	if n := d.sup.EndpointCount(); n != 1 {
		t.Fatalf("EndpointCount = %d, want 1", n)
	}
	if n := d.activeWorkCount(); n < 1 {
		t.Fatalf("activeWorkCount = %d with a live idle endpoint, want >= 1", n)
	}
	// The view does NOT double-count (A6): terminal.activeCount is legacy
	// ClassPTY only.
	if n := d.terminal.activeCount(); n != 0 {
		t.Fatalf("terminal.activeCount = %d, want 0 (views excluded)", n)
	}

	// Hibernate: the endpoint is gone → the count drops.
	if err := d.hibernateInstance(nil, instanceID, "a7"); err != nil {
		t.Fatalf("hibernate: %v", err)
	}
	if n := d.activeWorkCount(); n != 0 {
		t.Fatalf("activeWorkCount = %d after hibernate, want 0", n)
	}
}

// 9. Concurrent attachEndpoint calls on the same master reconcile to
// EXACTLY ONE view (one *ptySession): the first creates, the rest
// reconcile — never a second view on one master.
func TestDaemon_AttachEndpointConcurrent(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-tec2-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-tec2-deliver-1", InstanceID: instanceID,
		Kind: "task", Body: "first",
	})
	master := d.sessions.PTYMaster(instanceID)
	if master == nil {
		t.Fatal("PTYMaster is nil on the live endpoint")
	}

	// Drop the existing view (the endpoint keeps running) so the
	// concurrent calls race to CREATE.
	d.terminal.stop(instanceID)
	if d.terminal.get(instanceID) != nil {
		t.Fatal("view not dropped by stop")
	}

	const n = 8
	type result struct {
		s       *ptySession
		created bool
		err     error
	}
	results := make([]result, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, created, err := d.terminal.attachEndpoint(instanceID, master)
			results[i] = result{s: s, created: created, err: err}
		}(i)
	}
	wg.Wait()

	var createdCount int
	var first *ptySession
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("goroutine %d: attachEndpoint: %v", i, r.err)
		}
		if r.created {
			createdCount++
		}
		if first == nil {
			first = r.s
		} else if r.s != first {
			t.Fatalf("goroutine %d got a different session object (a second view was created)", i)
		}
	}
	if createdCount != 1 {
		t.Fatalf("created count = %d, want exactly 1 (the rest reconcile)", createdCount)
	}
	if d.terminal.get(instanceID) != first {
		t.Fatal("the map does not hold the single created view")
	}
}

// 10. The view exists DURING an in-flight turn (A5/G8): the turn parks on
// a scripted native interaction (the endpoint is live, the turn is
// mid-flight), and while no human is attached the endpoint's PTY must
// still have a reader — the view. Its read loop drains the TUI's
// rendering; without it a native TUI (Ink) blocks on tty writes once the
// PTY buffer fills and the model call never fires (no user event, no
// message_start). Regression: the view was once ensured only after the
// turn settled, leaving the PTY un-read for the whole turn.
func TestDaemon_EndpointViewExistsDuringTurn(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	// The turn parks on a scripted native interaction: the observation
	// window in which the view must exist.
	pf, ok := d.sessions.DriverFor(domain.RuntimeFakePersistent).(*agentruntime.PersistentFake)
	if !ok {
		t.Fatal("expected the PersistentFake driver to be registered (debug mode)")
	}
	pf.Env = []string{"PAGNET_FAKE_INTERACTION=question"}

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-evd-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})

	// Fire the deliver ASYNC: it blocks on the interaction, so its ack
	// will not arrive until the interaction is answered.
	env, err := transport.NewEnvelope(transport.MsgDeliverNetworkEvent, transport.NetworkEventPayload{
		CommandID: "cmd-evd-deliver", InstanceID: instanceID,
		Kind: "task", Body: "needs an answer",
	})
	if err != nil {
		t.Fatalf("build deliver envelope: %v", err)
	}
	d.handleCommand(nil, env)

	// Wait for the turn to park on the interaction (the endpoint is live
	// and the turn is in flight).
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if d.sessions.HasPendingInteraction(instanceID) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !d.sessions.HasPendingInteraction(instanceID) {
		t.Fatal("turn did not park on the interaction")
	}

	// A5/G8: the view exists from the ACTIVATION — while the turn is in
	// flight and no human is attached. The view is ensured when the
	// daemon's turn event loop processes the activation event, which runs
	// concurrently with the parked turn — poll for it (the loop is at most
	// a few scheduler hops behind; a one-shot check races the scheduler
	// on loaded CI VMs and has gone red there).
	viewOK := false
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if view := d.terminal.get(instanceID); view != nil && view.endpointView {
			viewOK = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !viewOK {
		row, _, _ := d.state.GetInstance(instanceID)
		t.Fatalf("no endpoint view while the turn is in flight (the view is ensured at activation, A5/G8); status=%q endpointPid=%v",
			row.Status, d.sup.EndpointPID(instanceID))
	}
	// And the view is actively draining the TUI: the parked interaction's
	// rendering is in the ring (with no reader it would sit in the PTY
	// buffer).
	waitForRing(t, d, instanceID, []string{"? fake question (simulated)"}, 10*time.Second)

	// Answer the interaction; the turn completes and the deliver acks.
	nativeID := readInteractionNativeID(t, server, instanceID)
	ievents := make(chan session.SessionEvent, 16)
	idone := make(chan struct{})
	var ierr error
	go func() {
		defer close(idone)
		_, ierr = d.sessions.Submit(context.Background(), d.sessions.GetSession(instanceID), session.SubmitRequest{
			Kind: session.SubmitInteraction, InteractionID: nativeID,
			Decision: "resolved", Answer: "yes",
		}, ievents)
	}()
	for range ievents {
	}
	<-idone
	if ierr != nil {
		t.Fatalf("interaction answer: %v", ierr)
	}
	_, ack := readUntilAck(t, server, "cmd-evd-deliver")
	if errMsg, _ := ack["error"].(string); errMsg != "" {
		t.Fatalf("deliver failed after the interaction was answered: %s", errMsg)
	}
}
