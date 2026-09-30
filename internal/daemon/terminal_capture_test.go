//go:build linux

package daemon

// The always-on endpoint PTY capture (the activation-deadlock fix,
// 2026-09-30): a persistent TUI runtime (qwen, codex) renders to its
// endpoint PTY BEFORE emitting the session_start activation event. A
// never-read PTY master fills the kernel PTY buffer, the TUI blocks in
// write(), session_start never arrives, and the activation times out at
// the startup budget with a healthy, alive process (the prod incident
// signature: "events_file=absent; process=alive"; repro: never-read PTY =
// no session_start in 60-70s, process alive; reader present = 1-2s).
//
// The terminal plane now adopts the master the moment the driver's launch
// registers it (the PTYAvailable hook → terminal.adoptEndpoint): a capture
// ptySession (readLoop + 256 KiB ring + seq) reads from the first byte.
// These daemon-level tests drive the REAL command flow against the
// fake-persistent runtime (a real deterministic process on the
// supervisor's PTY-owning ClassEndpoint path), which can script the exact
// shape — the PAGNET_FAKE_TUI_BOOT_BYTES knob renders TUI bytes to the
// PTY before the activation event, the deterministic stand-in for the
// real TUIs' pre-session_start render.
//
// Proved here (asserted on process/state facts, not logs):
//
//  1. DEADLOCK MECHANISM (the one that encodes the bug): boot bytes
//     larger than the kernel PTY buffer do NOT starve the activation —
//     the capture exists from the LAUNCH site (before session_start
//     settles), drains the boot render, and the endpoint settles promptly
//     with a live process. RED against the pre-fix code: no terminal
//     session exists until activation settles, so the master is never
//     read, the boot write blocks, and the activation never settles.
//  2. RESIZE DURING ACTIVATION: a resize landing while the endpoint is
//     still activating (boot bytes pending) is APPLIED to the PTY (the
//     live capture relays it), never dropped ("terminal live message
//     dropped (no live PTY)").
//  3. G7: a client is never attached to a dead master — an attach landing
//     on a capture whose master has hit EOF is refused with the existing
//     no-live-PTY error shape.
//
// Linux-gated: the TUI human plane depends on the endpoint owning its
// controlling terminal (the ClassEndpoint PTY path), the same gate as the
// rest of the session-driven terminal tests.

import (
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

// waitCapture polls until the instance's endpoint capture exists in the
// terminal plane (the always-on ptySession the driver's launch adopted
// via its PTYAvailable hook). It fails with the instance's state when the
// deadline elapses.
func waitCapture(t *testing.T, d *Daemon, instanceID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if view := d.terminal.get(instanceID); view != nil && view.endpointView {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	row, _, _ := d.state.GetInstance(instanceID)
	t.Fatalf("no endpoint capture for %s within %v (status=%q endpointPid=%v ptyMaster=%v)",
		instanceID, timeout, row.Status, d.sup.EndpointPID(instanceID),
		d.sessions.PTYMaster(instanceID) != nil)
}

// 1. Activation deadlock mechanism: the endpoint renders 64 KiB of TUI to
// its PTY BEFORE emitting the activation event (16x the 4 KiB kernel PTY
// buffer). Without a reader the write blocks mid-render and the activation
// event never reaches the machine plane — the driver's activation deadline
// kills a healthy, alive process. With the always-on capture (adopted from
// the driver's launch, BEFORE the activation settles) the boot bytes drain
// and the activation completes promptly.
func TestDaemon_EndpointCapturePreventsActivationDeadlock(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	// 64 KiB of TUI boot render before the activation event: without a
	// reader on the master the write blocks mid-render (the deadlock).
	setPersistentFakeEnv(t, d, []string{"PAGNET_FAKE_TUI_BOOT_BYTES=65536"})

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-cpl-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})

	// The endpoint's PTY master is registered at launch (the activation
	// is still settling in the background).
	deadline := time.Now().Add(30 * time.Second)
	for d.sessions.PTYMaster(instanceID) == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if d.sessions.PTYMaster(instanceID) == nil {
		t.Fatal("the endpoint's PTY master was never registered at launch")
	}

	// THE FIX: the capture exists from the LAUNCH site — while the
	// activation is still pending (session_start has not settled). Pre-fix
	// there was NO terminal session until the activation settled, so this
	// is the assertion that encodes the bug: a TUI rendering before
	// session_start must find a reader from the first byte.
	waitCapture(t, d, instanceID, 10*time.Second)

	// The boot render is drained into the capture's ring (the reader read
	// it) and the activation settles PROMPTLY — well within the fake
	// driver's own 15s activation deadline (a never-read master would block
	// the boot write and never settle).
	waitForRing(t, d, instanceID, []string{"pagnet-boot-"}, 10*time.Second)
	waitForEndpointLive(t, d, instanceID)
	if pid := d.sup.EndpointPID(instanceID); pid == nil {
		t.Fatal("no live endpoint after the activation (the boot render must not starve session_start)")
	}
}

// 2. Resize during activation: a resize landing while the endpoint is
// still activating (boot bytes pending) is applied to the PTY — the live
// capture relays it — instead of being dropped with "terminal live message
// dropped (no live PTY)" (the pre-fix behavior: no terminal session exists
// during activation, so every live message was lost).
func TestDaemon_EndpointCaptureResizeDuringActivation(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	// 1 MiB of boot render: the fake writes it (drained by the capture)
	// BEFORE emitting the activation event, so the activation is
	// deterministically still pending the moment the capture exists — the
	// process has not even finished rendering by then.
	setPersistentFakeEnv(t, d, []string{"PAGNET_FAKE_TUI_BOOT_BYTES=1048576"})

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-cra-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})

	// Wait for the capture (adopted at the driver's launch).
	waitCapture(t, d, instanceID, 30*time.Second)
	// Precondition: the activation is still pending. It cannot have
	// settled — the fake's boot render (1 MiB, written before the
	// activation event) precedes session_start, and the capture was
	// adopted at launch, moments before this poll tick.
	if !d.sessionActivating(instanceID) {
		t.Fatal("precondition: the activation must still be pending while the capture exists (boot bytes pending)")
	}
	master := d.sessions.PTYMaster(instanceID)
	if master == nil {
		t.Fatal("PTYMaster is nil on the activating endpoint")
	}

	// The resize arrives WHILE THE ENDPOINT IS STILL ACTIVATING.
	d.terminal.submit(terminalLiveMsg{
		isResize: true, instance: instanceID, session: "sess-resize",
		cols: 132, rows: 45,
	})

	// It is APPLIED to the PTY (the live capture relayed it), never
	// dropped.
	deadline := time.Now().Add(10 * time.Second)
	for {
		rows, cols, err := pty.Getsize(master)
		if err == nil && rows == 45 && cols == 132 {
			break
		}
		if time.Now().After(deadline) {
			rows, cols, _ := pty.Getsize(master)
			t.Fatalf("resize during activation was not applied to the PTY (got rows=%d cols=%d, want rows=45 cols=132 — it was dropped: no live capture)", rows, cols)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// And the activation settles (the boot bytes drained; no deadlock).
	waitForEndpointLive(t, d, instanceID)
}

// 3. G7: never attach a client to a dead master. An attach landing on a
// capture whose master has hit EOF (the endpoint died) is refused with the
// existing no-live-PTY error shape — never a fresh read loop on a dead
// master, never a torn-down terminal bound to a client.
func TestDaemon_AttachEndpointRefusesDeadCapture(t *testing.T) {
	d := newTestDaemon(t)
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatalf("open pty pair: %v", err)
	}
	defer master.Close()

	instanceID := domain.NewID().String()
	s, created, err := d.terminal.adoptEndpoint(instanceID, master)
	if err != nil {
		t.Fatalf("adoptEndpoint: %v", err)
	}
	if !created {
		t.Fatal("adoptEndpoint did not create the capture")
	}
	if !s.endpointView {
		t.Fatal("the capture must carry the endpoint-view (observational) semantics")
	}

	// The endpoint dies: every slave is closed → the master hits EOF →
	// the capture's read loop signals the observational teardown.
	slave.Close()
	select {
	case <-s.eofCh:
	case <-time.After(10 * time.Second):
		t.Fatal("the capture's read loop did not observe the master EOF")
	}

	// The observational teardown (exitLoop) runs AFTER eofCh closes and
	// drops the dead capture from the map; wait for it so the re-insert
	// below is not raced away by the teardown.
	deadline := time.Now().Add(10 * time.Second)
	for d.terminal.get(instanceID) != nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s := d.terminal.get(instanceID); s != nil {
		t.Fatal("the observational teardown did not drop the dead capture")
	}

	// Restore the transient state the live daemon can hold in the EOF
	// window — a DEAD capture still in the sessions map — and assert the
	// attach landing on it is refused.
	d.terminal.mu.Lock()
	d.terminal.sessions[instanceID] = s
	d.terminal.mu.Unlock()
	defer d.terminal.stop(instanceID)

	_, _, err = d.terminal.attachEndpoint(instanceID, master)
	if err == nil {
		t.Fatal("attach to a dead capture succeeded (G7: a dead master must be refused)")
	}
	if !strings.Contains(err.Error(), "no live TUI PTY") {
		t.Fatalf("dead-capture attach refusal error = %q, want the existing no-live-PTY shape", err.Error())
	}
}
