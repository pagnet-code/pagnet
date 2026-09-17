package daemon

// Phase 1 (runtime-lifecycle refactor): daemon-level tests for the
// fake-persistent runtime driven through the session core.
//
// These prove the daemon's REAL command flow (launch → deliver → turn
// completes) works for a session-driven runtime — the missing end-to-end
// proof that runTurnPersistent works through the daemon, not just the
// driver — and that stop/restart/forget manage the persistent endpoint
// (which lives in the session core, not the adapter map).
//
// The fake-persistent runtime is a REAL deterministic process
// (pagnet-fake-runtime in --persistent mode) launched lazily on the first
// turn through the supervisor's ClassEndpoint path — not a test double.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/pagnet-code/pagnet/domain"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/transport"
)

// newPersistentTestDaemon builds a debug daemon with the fake-persistent
// binary set (the session driver is registered in debug mode). It forces a
// fresh build of the fake runtime so the persistent-mode changes (R2/R9)
// are in the binary.
func newPersistentTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	// A fresh scratch dir forces a rebuild (p0FakeBinary's staleness check
	// only tracks main.go, not persistent.go).
	t.Setenv("PAGNET_P0_BIN_DIR", t.TempDir())
	d := newTestDaemon(t)
	pf, ok := d.sessions.DriverFor(domain.RuntimeFakePersistent).(*agentruntime.PersistentFake)
	if !ok {
		t.Fatal("expected the PersistentFake driver to be registered (debug mode)")
	}
	pf.Binary = p0FakeBinary(t)
	// The fake's session files live under PAGNET_STATE_DIR (separate from
	// the daemon's StateDir).
	t.Setenv("PAGNET_STATE_DIR", t.TempDir())
	return d
}

// readUntilAck reads envelopes from the server side until it sees the
// command_ack for commandID (or times out). It returns all envelopes read
// (events + acks) and the ack payload.
func readUntilAck(t *testing.T, server *websocket.Conn, commandID string) ([]transport.Envelope, map[string]any) {
	t.Helper()
	var envs []transport.Envelope
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		_ = server.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, raw, err := server.ReadMessage()
		if err != nil {
			t.Fatalf("read envelope: %v", err)
		}
		var env transport.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("decode envelope: %v", err)
		}
		envs = append(envs, env)
		if env.Type == transport.MsgCommandAck {
			var payload map[string]any
			if err := json.Unmarshal(env.Payload, &payload); err == nil {
				if payload["commandId"] == commandID {
					return envs, payload
				}
			}
		}
	}
	t.Fatalf("did not see ack for %s within deadline; got %d envelopes", commandID, len(envs))
	return nil, nil
}

// hasEnvelopeType reports whether an envelope of the given type is present.
func hasEnvelopeType(envs []transport.Envelope, msgType string) bool {
	for _, env := range envs {
		if env.Type == msgType {
			return true
		}
	}
	return false
}

// envelopePayload decodes one envelope's payload into a map.
func envelopePayload(t *testing.T, env transport.Envelope) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(env.Payload, &m); err != nil {
		t.Fatalf("decode %s payload: %v", env.Type, err)
	}
	return m
}

// driveLaunch drives a launch command through the daemon's real command
// flow and waits for its ack. It returns the observed envelopes.
func driveLaunch(t *testing.T, d *Daemon, server *websocket.Conn, p transport.LaunchAgentPayload) []transport.Envelope {
	t.Helper()
	env, err := transport.NewEnvelope(transport.MsgLaunchAgent, p)
	if err != nil {
		t.Fatalf("build launch envelope: %v", err)
	}
	d.handleCommand(nil, env)
	envs, ack := readUntilAck(t, server, p.CommandID)
	if errMsg, _ := ack["error"].(string); errMsg != "" {
		t.Fatalf("launch failed: %s", errMsg)
	}
	return envs
}

// driveDeliver drives a deliver command through the daemon's real command
// flow and waits for its ack. It returns the observed envelopes.
func driveDeliver(t *testing.T, d *Daemon, server *websocket.Conn, p transport.NetworkEventPayload) []transport.Envelope {
	t.Helper()
	env, err := transport.NewEnvelope(transport.MsgDeliverNetworkEvent, p)
	if err != nil {
		t.Fatalf("build deliver envelope: %v", err)
	}
	d.handleCommand(nil, env)
	envs, ack := readUntilAck(t, server, p.CommandID)
	if errMsg, _ := ack["error"].(string); errMsg != "" {
		t.Fatalf("deliver failed: %s", errMsg)
	}
	return envs
}

// driveCommand drives an arbitrary command (stop/restart/forget) through
// the daemon's real command flow and waits for its ack.
func driveCommand(t *testing.T, d *Daemon, server *websocket.Conn, msgType string, payload any, commandID string) []transport.Envelope {
	t.Helper()
	env, err := transport.NewEnvelope(msgType, payload)
	if err != nil {
		t.Fatalf("build %s envelope: %v", msgType, err)
	}
	d.handleCommand(nil, env)
	envs, ack := readUntilAck(t, server, commandID)
	if errMsg, _ := ack["error"].(string); errMsg != "" {
		t.Fatalf("%s failed: %s", msgType, errMsg)
	}
	return envs
}

// D3: the daemon's REAL command flow for a fake-persistent instance:
// launch → deliver a turn → turn completes. Asserts exactly ONE active
// endpoint process (supervisor registry count), correct instance status
// transitions, and that the turn output/events were emitted. This is the
// end-to-end proof that runTurnPersistent works through the daemon.
func TestDaemon_PersistentLaunchTurnCompletes(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	// (a) detectRuntimes reports fake-persistent (same shape as other
	// runtimes; the server never sees it in non-debug builds).
	runtimes := d.detectRuntimes()
	found := false
	for _, ri := range runtimes {
		if ri.Runtime == string(domain.RuntimeFakePersistent) {
			found = true
			if ri.Path == "" {
				t.Fatal("fake-persistent reported with an empty path")
			}
		}
	}
	if !found {
		t.Fatalf("detectRuntimes did not report fake-persistent: %+v", runtimes)
	}

	instanceID := domain.NewID().String()

	// Launch: the instance is recorded/accepted (NO process spawned at
	// launch time — the endpoint launches lazily on the first turn).
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID:  "cmd-launch-1",
		InstanceID: instanceID,
		Runtime:    string(domain.RuntimeFakePersistent),
		Kind:       "representative",
	})
	// No endpoint process at launch time (lazy launch).
	if n := d.sup.Stats().ActiveEndpoints; n != 0 {
		t.Fatalf("expected 0 active endpoints at launch (lazy), got %d", n)
	}
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance not registered after launch: ok=%v err=%v", ok, err)
	}
	if row.Status != "idle" {
		t.Fatalf("status after launch = %q, want idle", row.Status)
	}

	// Deliver a turn: the endpoint launches (EnsureActive) and the turn
	// completes through runTurnPersistent.
	envs := driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID:  "cmd-deliver-1",
		InstanceID: instanceID,
		Kind:       "task",
		Body:       "do the work",
	})

	// Exactly ONE active endpoint process (the supervisor registry count).
	if n := d.sup.Stats().ActiveEndpoints; n != 1 {
		t.Fatalf("expected exactly 1 active endpoint after the turn, got %d", n)
	}

	// The turn events were emitted (the E2EE output stream + lifecycle).
	if !hasEnvelopeType(envs, transport.MsgRuntimeTurnStarted) {
		t.Fatalf("did not observe runtime.turn.started: %+v", envs)
	}
	if !hasEnvelopeType(envs, transport.MsgRuntimeTurnCompleted) {
		t.Fatalf("did not observe runtime.turn.completed: %+v", envs)
	}
	if !hasEnvelopeType(envs, transport.MsgRuntimeOutput) {
		t.Fatalf("did not observe the runtime output stream: %+v", envs)
	}
	// The output echoes the input (the fake runtime's deterministic work).
	sawOutput := false
	for _, env := range envs {
		if env.Type == transport.MsgRuntimeOutput {
			if p := envelopePayload(t, env); p["output"] != "" {
				sawOutput = true
			}
		}
	}
	if !sawOutput {
		t.Fatal("runtime output stream carried no output")
	}

	// Correct final status: idle (the persistent endpoint stays alive — the
	// instance is idle, not hibernated), and the session id is set.
	row, ok, err = d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after the turn: ok=%v err=%v", ok, err)
	}
	if row.Status != "idle" {
		t.Fatalf("status after the turn = %q, want idle (persistent endpoint stays alive)", row.Status)
	}
	if row.SessionID == "" {
		t.Fatal("session id not set after the turn")
	}
	t.Logf("persistent turn completed; endpoint pid=%v session=%s", d.sup.EndpointPID(instanceID), row.SessionID)
}

// D2: doStop kills the persistent endpoint process (assert the process is
// gone via the supervisor registry) and marks the instance stopped.
func TestDaemon_PersistentStopKillsEndpoint(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-launch-stop", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-deliver-stop", InstanceID: instanceID,
		Kind: "task", Body: "work",
	})
	if n := d.sup.Stats().ActiveEndpoints; n != 1 {
		t.Fatalf("expected 1 active endpoint before stop, got %d", n)
	}

	// doStop: stop the endpoint (TERM → grace → KILL) + "stopped"
	// bookkeeping.
	driveCommand(t, d, server, transport.MsgStopAgent,
		transport.StopAgentPayload{CommandID: "cmd-stop-1", InstanceID: instanceID}, "cmd-stop-1")

	// The endpoint process is gone (reaped and unregistered).
	if n := d.sup.Stats().ActiveEndpoints; n != 0 {
		t.Fatalf("expected 0 active endpoints after stop, got %d", n)
	}
	if pid := d.sup.EndpointPID(instanceID); pid != nil {
		t.Fatalf("endpoint PID still reported after stop: %d", *pid)
	}
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after stop: ok=%v err=%v", ok, err)
	}
	if row.Status != "stopped" {
		t.Fatalf("status after stop = %q, want stopped", row.Status)
	}
}

// D2: doRestart clears the in-memory session so the next turn starts FRESH
// (a new session id) — the explicit "start fresh" semantics.
func TestDaemon_PersistentRestartStartsFreshSession(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-launch-restart", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-deliver-restart-1", InstanceID: instanceID,
		Kind: "task", Body: "first",
	})
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after turn 1: ok=%v err=%v", ok, err)
	}
	sessionID1 := row.SessionID
	if sessionID1 == "" {
		t.Fatal("session id not set after turn 1")
	}

	// doRestart: stop the endpoint + clear the in-memory session (fresh
	// start) + clear the persisted session id.
	driveCommand(t, d, server, transport.MsgRestartAgent,
		transport.RestartAgentPayload{CommandID: "cmd-restart-1", InstanceID: instanceID}, "cmd-restart-1")

	row, ok, err = d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after restart: ok=%v err=%v", ok, err)
	}
	if row.SessionID != "" {
		t.Fatalf("session id not cleared after restart: %q", row.SessionID)
	}
	if row.Status != "idle" {
		t.Fatalf("status after restart = %q, want idle", row.Status)
	}

	// The next turn starts a FRESH session (a new session id).
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-deliver-restart-2", InstanceID: instanceID,
		Kind: "task", Body: "second",
	})
	row, ok, err = d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after turn 2: ok=%v err=%v", ok, err)
	}
	sessionID2 := row.SessionID
	if sessionID2 == "" {
		t.Fatal("session id not set after turn 2")
	}
	if sessionID2 == sessionID1 {
		t.Fatalf("restart did not start a fresh session: both turns used %q", sessionID1)
	}
	t.Logf("restart started a fresh session: %s -> %s", sessionID1, sessionID2)
}
