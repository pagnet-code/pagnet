package daemon

// Phase 2 (runtime-lifecycle refactor): daemon-level ACCEPTANCE tests for
// the session-driven (persistent) delivery path — the daemon's REAL command
// flow driving the fake-persistent runtime through the session core.
//
// These are the acceptance proofs the plan requires (plan §40-41), asserted
// on PROCESS/STATE FACTS (PIDs, /proc environ, on-disk session state,
// Manager state), not logs:
//
//  1. Hibernate cycle (the core architectural proof, §41): activate ->
//     submit (materialises) -> idle -> hibernate -> endpoint GONE (process
//     dead) -> EXACT native session id retained -> wake -> NEW endpoint
//     process (PID changed) -> SAME native session id resumed (the fake's
//     on-disk turn count continues).
//  2. Hibernate refusal: a busy session (a turn parked on a native
//     interaction) cannot be hibernated; the turn still completes after the
//     answer.
//  3. Wake with a lost native session: destroy the session file between
//     hibernate and wake -> wake -> session.lost -> instance BLOCKED,
//     session cleared (NOT a silent fresh session, NOT a failed instance).
//  4. Env injection: the endpoint child's real environment carries the
//     daemon's per-instance spec pairs.
//  5. Turn identity end-to-end: the submit's logical turn id appears on the
//     host-protocol turn events the daemon emits.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

// daemonFakeSessionFile is the shape of the fake runtime's on-disk session
// file (the in-session state that must survive hibernation).
type daemonFakeSessionFile struct {
	SessionID string `json:"sessionId"`
	Turns     int    `json:"turns"`
}

// readDaemonFakeSession reads the fake's on-disk session file for the
// instance (under PAGNET_STATE_DIR, set by newPersistentTestDaemon).
func readDaemonFakeSession(t *testing.T, instanceID string) daemonFakeSessionFile {
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
	var s daemonFakeSessionFile
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("parse session file: %v", err)
	}
	return s
}

// readDaemonProcEnviron reads a process's real environment from
// /proc/<pid>/environ (Linux). It is the ground-truth check that the
// endpoint CHILD received the spec pairs (not just that the daemon computed
// them).
func readDaemonProcEnviron(t *testing.T, pid int) map[string]string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("proc environ check is Linux-only (GOOS=%s)", runtime.GOOS)
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		t.Fatalf("read /proc/%d/environ: %v", pid, err)
	}
	env := map[string]string{}
	for _, kv := range strings.Split(string(b), "\x00") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	return env
}

// readInteractionNativeID reads envelopes from the server side until it sees
// the interaction.started for the instance and returns the native
// interaction id the daemon reported (the control plane learns the id from
// this host-protocol event).
func readInteractionNativeID(t *testing.T, server *websocket.Conn, instanceID string) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
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
		if env.Type == transport.MsgInteractionStarted {
			p := envelopePayload(t, env)
			if p["instanceId"] == instanceID {
				if nid, _ := p["nativeInteractionId"].(string); nid != "" {
					return nid
				}
			}
		}
	}
	t.Fatalf("did not see interaction.started for %s within deadline", instanceID)
	return ""
}

// Acceptance 1 (plan §41): the hibernate cycle — the core architectural
// proof that hibernation stops the ENDPOINT while preserving the SESSION.
func TestDaemon_PersistentHibernateCycle(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-hc-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})

	// Turn 1: materialises the session; the endpoint launches.
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-hc-deliver-1", InstanceID: instanceID,
		Kind: "task", Body: "first",
	})
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after turn 1: ok=%v err=%v", ok, err)
	}
	sessionID1 := row.SessionID
	if sessionID1 == "" {
		t.Fatal("no session id after turn 1")
	}
	if row.Status != "idle" {
		t.Fatalf("status after turn 1 = %q, want idle", row.Status)
	}
	pid1 := d.sup.EndpointPID(instanceID)
	if pid1 == nil {
		t.Fatal("no live endpoint after turn 1")
	}

	// Hibernate (session-oriented): stop the endpoint, PRESERVE the session.
	if err := d.hibernateInstance(nil, instanceID, "test-cycle"); err != nil {
		t.Fatalf("hibernate: %v", err)
	}

	// The endpoint is GONE (a process-level fact, not a log line).
	if n := d.sup.Stats().ActiveEndpoints; n != 0 {
		t.Fatalf("expected 0 active endpoints after hibernate, got %d", n)
	}
	if pid := d.sup.EndpointPID(instanceID); pid != nil {
		t.Fatalf("endpoint PID still reported after hibernate: %d", *pid)
	}
	if proc.ProcessAlive(*pid1) {
		t.Fatalf("endpoint process %d still alive after hibernate", *pid1)
	}

	// The SESSION is preserved (invariant F): the EXACT native id + the
	// materialised flag remain in the Manager.
	sess := d.sessions.GetSession(instanceID)
	if sess == nil {
		t.Fatal("session gone from the Manager after hibernate")
	}
	if sess.NativeID != sessionID1 {
		t.Fatalf("native session id changed after hibernate: before=%q after=%q", sessionID1, sess.NativeID)
	}
	if !sess.Materialised {
		t.Fatal("materialised flag cleared after hibernate (invariant F)")
	}

	// The instance is hibernated, with the session id preserved on the row.
	row, ok, err = d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after hibernate: ok=%v err=%v", ok, err)
	}
	if row.Status != "hibernated" {
		t.Fatalf("status after hibernate = %q, want hibernated", row.Status)
	}
	if row.SessionID != sessionID1 {
		t.Fatalf("session id not preserved on the row: %q", row.SessionID)
	}

	// Wake: resume the EXACT stored session on a NEW endpoint process.
	driveCommand(t, d, server, transport.MsgWakeAgent,
		transport.WakeAgentPayload{WakeRequestID: "hc-wake-1", InstanceID: instanceID, Reason: "test-cycle"},
		"hc-wake-1")

	row, ok, err = d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after wake: ok=%v err=%v", ok, err)
	}
	if row.Status != "idle" {
		t.Fatalf("status after wake = %q, want idle", row.Status)
	}
	if row.SessionID != sessionID1 {
		t.Fatalf("session id changed after wake: before=%q after=%q", sessionID1, row.SessionID)
	}
	pid2 := d.sup.EndpointPID(instanceID)
	if pid2 == nil {
		t.Fatal("no live endpoint after wake")
	}
	if *pid2 == *pid1 {
		t.Fatalf("wake reused the old endpoint process (pid %d) instead of a new one", *pid1)
	}
	// The Manager resumed the SAME native session.
	sess = d.sessions.GetSession(instanceID)
	if sess.NativeID != sessionID1 {
		t.Fatalf("Manager native id after wake = %q, want %q", sess.NativeID, sessionID1)
	}
	// In-session state CONTINUES: the fake's on-disk turn count is now 2
	// (the wake turn ran in the resumed session, not a fresh one).
	sf := readDaemonFakeSession(t, instanceID)
	if sf.SessionID != sessionID1 {
		t.Fatalf("session file id after wake = %q, want %q", sf.SessionID, sessionID1)
	}
	if sf.Turns < 2 {
		t.Fatalf("in-session state did not continue after wake: turns=%d (want >=2)", sf.Turns)
	}
	t.Logf("hibernate cycle: session %q; endpoint pid %d -> %d; on-disk turns=%d",
		sessionID1, *pid1, *pid2, sf.Turns)
}

// Acceptance 2: a busy session (a turn parked on a native interaction) is
// NEVER hibernated. The refusal leaves the endpoint alive; the turn still
// completes once the interaction is answered.
func TestDaemon_PersistentHibernateRefusesBusy(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	// The turn will park on a scripted native interaction.
	pf, ok := d.sessions.DriverFor(domain.RuntimeFakePersistent).(*agentruntime.PersistentFake)
	if !ok {
		t.Fatal("expected the PersistentFake driver to be registered (debug mode)")
	}
	pf.Env = []string{"PAGNET_FAKE_INTERACTION=question"}

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-hb-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})

	// Fire the deliver ASYNC: it blocks on the interaction, so its ack will
	// NOT arrive until the interaction is answered.
	env, err := transport.NewEnvelope(transport.MsgDeliverNetworkEvent, transport.NetworkEventPayload{
		CommandID: "cmd-hb-deliver", InstanceID: instanceID,
		Kind: "task", Body: "needs an answer",
	})
	if err != nil {
		t.Fatalf("build deliver envelope: %v", err)
	}
	d.handleCommand(nil, env)

	// Wait for the turn to park on the interaction (busy + pending).
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
	row, _, _ := d.state.GetInstance(instanceID)
	if row.Status != "working" {
		t.Fatalf("status while parked on the interaction = %q, want working", row.Status)
	}

	// Hibernate must be REFUSED (a busy session is never hibernated).
	if err := d.hibernateInstance(nil, instanceID, "test-busy"); err == nil {
		t.Fatal("hibernate succeeded on a busy session; want a refusal")
	}
	// The refusal did NOT stop the endpoint.
	pid := d.sup.EndpointPID(instanceID)
	if pid == nil {
		t.Fatal("endpoint gone after the hibernate refusal")
	}
	if !proc.ProcessAlive(*pid) {
		t.Fatalf("endpoint process %d not alive after the hibernate refusal", *pid)
	}
	row, _, _ = d.state.GetInstance(instanceID)
	if row.Status == "hibernated" {
		t.Fatal("instance marked hibernated despite the refusal")
	}

	// Answer the interaction (the native id the daemon reported to the
	// control plane). The turn then completes and acks the deliver.
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

	// The deliver now acks (the turn completed).
	_, ack := readUntilAck(t, server, "cmd-hb-deliver")
	if errMsg, _ := ack["error"].(string); errMsg != "" {
		t.Fatalf("deliver failed after the interaction was answered: %s", errMsg)
	}

	// The session is idle again, no longer pending.
	row, _, _ = d.state.GetInstance(instanceID)
	if row.Status != "idle" {
		t.Fatalf("status after the turn completed = %q, want idle", row.Status)
	}
	if d.sessions.HasPendingInteraction(instanceID) {
		t.Fatal("interaction still pending after the answer")
	}
	t.Logf("busy hibernate refused; turn completed after the answer (native %s)", nativeID)
}

// Acceptance 3: a wake whose stored native session no longer exists (the
// session file was destroyed between hibernate and wake) is an HONEST
// session loss: the instance is BLOCKED and the session cleared — never a
// silent fresh session, never a generic failed instance.
func TestDaemon_PersistentWakeLostSessionBlocks(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-wls-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-wls-deliver-1", InstanceID: instanceID,
		Kind: "task", Body: "first",
	})
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after turn 1: ok=%v err=%v", ok, err)
	}
	sessionID1 := row.SessionID
	if sessionID1 == "" {
		t.Fatal("no session id after turn 1")
	}

	// Hibernate (endpoint stopped, session preserved).
	if err := d.hibernateInstance(nil, instanceID, "test-lost"); err != nil {
		t.Fatalf("hibernate: %v", err)
	}

	// Destroy the native session between hibernate and wake (the on-disk
	// state the resume would read is gone).
	stateDir := os.Getenv("PAGNET_STATE_DIR")
	sessionPath := filepath.Join(stateDir, "sessions", instanceID, "session.json")
	if err := os.Remove(sessionPath); err != nil {
		t.Fatalf("remove session file: %v", err)
	}

	// Wake: the resume finds no usable session -> session.lost. Use
	// readUntilAck directly (driveCommand would Fatal on the error ack).
	wakeEnv, err := transport.NewEnvelope(transport.MsgWakeAgent, transport.WakeAgentPayload{
		WakeRequestID: "wls-wake-1", InstanceID: instanceID, Reason: "test-lost",
	})
	if err != nil {
		t.Fatalf("build wake envelope: %v", err)
	}
	d.handleCommand(nil, wakeEnv)
	_, ack := readUntilAck(t, server, "wls-wake-1")
	errMsg, _ := ack["error"].(string)
	if !strings.Contains(errMsg, "session lost") {
		t.Fatalf("wake ack error = %q, want a session-lost refusal", errMsg)
	}

	// The instance is BLOCKED (not failed, not a silent fresh session) and
	// the session reference is cleared.
	row, ok, err = d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after the lost wake: ok=%v err=%v", ok, err)
	}
	if row.Status != "blocked" {
		t.Fatalf("status after the lost wake = %q, want blocked", row.Status)
	}
	if row.SessionID != "" {
		t.Fatalf("session id not cleared after the lost wake: %q", row.SessionID)
	}
	// The Manager records the session as LOST.
	sess := d.sessions.GetSession(instanceID)
	if sess == nil || sess.State != session.StateLost {
		t.Fatalf("Manager session state = %v, want lost", sess)
	}
	// The failed resume left no endpoint behind.
	if n := d.sup.Stats().ActiveEndpoints; n != 0 {
		t.Fatalf("expected 0 active endpoints after the lost wake, got %d", n)
	}

	// An EXPLICIT restart is the only way forward, and it starts a FRESH
	// session — never a resume of the lost one. (The fake's cold-start id
	// is deterministic per instance when no session file exists, so the
	// proof of "fresh, not a silent resume" is the fresh-START event —
	// session.started / resumed:false — not a different id.)
	driveCommand(t, d, server, transport.MsgRestartAgent,
		transport.RestartAgentPayload{CommandID: "cmd-wls-restart", InstanceID: instanceID}, "cmd-wls-restart")
	envs := driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-wls-deliver-2", InstanceID: instanceID,
		Kind: "task", Body: "second",
	})
	row, ok, err = d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after the restart turn: ok=%v err=%v", ok, err)
	}
	if row.SessionID == "" {
		t.Fatal("no session id after the restart turn")
	}
	if row.Status != "idle" {
		t.Fatalf("status after the restart turn = %q, want idle", row.Status)
	}
	// The restart turn is a FRESH start (session.started), not a resume of
	// the lost session (which would be session.resumed / resumed:true).
	sawFreshStart, sawResume := false, false
	for _, env := range envs {
		if env.Type != transport.MsgRuntimeSession {
			continue
		}
		p := envelopePayload(t, env)
		if p["instanceId"] != instanceID {
			continue
		}
		if r, _ := p["resumed"].(bool); r {
			sawResume = true
		} else {
			sawFreshStart = true
		}
	}
	if !sawFreshStart {
		t.Fatalf("the restart turn did not start a fresh session: %+v", envs)
	}
	if sawResume {
		t.Fatalf("the lost session was silently resumed after the restart: %+v", envs)
	}
	t.Logf("lost-session wake blocked the instance (session %q cleared); restart started a fresh session",
		sessionID1)
}

// Deliverable 2: "Wake of an active/idle instance = no-op (already live)."
// A session-driven instance whose persistent endpoint is already up (idle,
// no turn in flight) has nothing to wake: the wake must NOT run a spurious
// turn, change the session, or stop the endpoint.
func TestDaemon_PersistentWakeOfLiveInstanceIsNoOp(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-wlive-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-wlive-deliver-1", InstanceID: instanceID,
		Kind: "task", Body: "first",
	})
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after turn 1: ok=%v err=%v", ok, err)
	}
	sessionID1 := row.SessionID
	if sessionID1 == "" {
		t.Fatal("no session id after turn 1")
	}
	if row.Status != "idle" {
		t.Fatalf("status after turn 1 = %q, want idle", row.Status)
	}
	if pid := d.sup.EndpointPID(instanceID); pid == nil {
		t.Fatal("expected a live endpoint after turn 1")
	}
	turnsBefore := readDaemonFakeSession(t, instanceID).Turns

	// Wake the ALREADY-LIVE instance: it must be a no-op (acks cleanly).
	driveCommand(t, d, server, transport.MsgWakeAgent,
		transport.WakeAgentPayload{WakeRequestID: "wlive-wake-1", InstanceID: instanceID, Reason: "test-nop"},
		"wlive-wake-1")

	// The instance is still idle, the session unchanged, the endpoint still
	// up, and NO new turn ran (the on-disk turn count is unchanged).
	row, ok, err = d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance missing after the no-op wake: ok=%v err=%v", ok, err)
	}
	if row.Status != "idle" {
		t.Fatalf("status after the no-op wake = %q, want idle", row.Status)
	}
	if row.SessionID != sessionID1 {
		t.Fatalf("session id changed by the no-op wake: before=%q after=%q", sessionID1, row.SessionID)
	}
	if pid := d.sup.EndpointPID(instanceID); pid == nil {
		t.Fatal("endpoint gone after the no-op wake")
	}
	turnsAfter := readDaemonFakeSession(t, instanceID).Turns
	if turnsAfter != turnsBefore {
		t.Fatalf("the no-op wake ran a turn: turns before=%d after=%d", turnsBefore, turnsAfter)
	}
	t.Logf("wake of an already-live instance was a no-op (session %q, turns=%d unchanged)",
		sessionID1, turnsAfter)
}

// Acceptance 4: the endpoint child process receives the daemon's per-
// instance spec env (identity vars, MCP bridge config, coordination
// contract). The check reads the CHILD's real /proc/<pid>/environ.
func TestDaemon_PersistentEndpointEnvInjection(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("proc environ check is Linux-only (GOOS=%s)", runtime.GOOS)
	}
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-env-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
		AgentName: "env-agent", NetworkID: "net-env",
	})
	driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-env-deliver", InstanceID: instanceID,
		Kind: "task", Body: "first",
	})
	pid := d.sup.EndpointPID(instanceID)
	if pid == nil {
		t.Fatal("no live endpoint after the turn")
	}
	env := readDaemonProcEnviron(t, *pid)

	// The identity pairs carry the instance's real values.
	if env["PAGNET_INSTANCE_ID"] != instanceID {
		t.Fatalf("PAGNET_INSTANCE_ID = %q, want %q", env["PAGNET_INSTANCE_ID"], instanceID)
	}
	if env["PAGNET_AGENT_NAME"] != "env-agent" {
		t.Fatalf("PAGNET_AGENT_NAME = %q, want %q", env["PAGNET_AGENT_NAME"], "env-agent")
	}
	if env["PAGNET_NETWORK_ID"] != "net-env" {
		t.Fatalf("PAGNET_NETWORK_ID = %q, want %q", env["PAGNET_NETWORK_ID"], "net-env")
	}
	// The MCP bridge config and coordination contract are present (non-
	// empty): the agent can reach the network and read its standing rules.
	if env["PAGNET_MCP_CONFIG"] == "" {
		t.Fatal("PAGNET_MCP_CONFIG missing/empty in the endpoint child env")
	}
	if env["PAGNET_COORDINATION_CONTRACT"] == "" {
		t.Fatal("PAGNET_COORDINATION_CONTRACT missing/empty in the endpoint child env")
	}
	t.Logf("endpoint child (pid %d) carries the daemon's spec env", *pid)
}

// Acceptance 5: the submit's logical turn id appears on the host-protocol
// turn events the daemon emits (turn.started and turn.completed share it,
// and it is non-empty) — the end-to-end logical turn identity.
func TestDaemon_PersistentTurnIdentityEndToEnd(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	instanceID := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{
		CommandID: "cmd-ti-launch", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: "representative",
	})
	envs := driveDeliver(t, d, server, transport.NetworkEventPayload{
		CommandID: "cmd-ti-deliver", InstanceID: instanceID,
		Kind: "task", Body: "first",
	})

	var startedID, completedID string
	for _, env := range envs {
		switch env.Type {
		case transport.MsgRuntimeTurnStarted:
			startedID, _ = envelopePayload(t, env)["turnId"].(string)
		case transport.MsgRuntimeTurnCompleted:
			completedID, _ = envelopePayload(t, env)["turnId"].(string)
		}
	}
	if startedID == "" {
		t.Fatalf("turn.started carried no turn id: %+v", envs)
	}
	if completedID == "" {
		t.Fatalf("turn.completed carried no turn id: %+v", envs)
	}
	if startedID != completedID {
		t.Fatalf("turn id differs between started (%q) and completed (%q)", startedID, completedID)
	}
	t.Logf("logical turn id %q carried on both turn.started and turn.completed", startedID)
}
