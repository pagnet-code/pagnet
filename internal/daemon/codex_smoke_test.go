package daemon

// Codex REAL-binary smoke (runtime-lifecycle rework, Wave 4).
//
// This is the ONE real smoke the Wave 4 spec requires: it drives the REAL
// `codex` binary (not the fake app-server) through the REAL CodexPersistent
// driver + session core + a REAL daemon bridge socket + a REAL pagnet MCP
// worker, and proves, on process/state facts:
//
//  1. launch        — a Codex instance activates (initialize + thread/start;
//                     NativeID = the thread id).
//  2. first turn    — a real model turn completes.
//  3. second turn   — a second turn on the SAME thread (persistence: the
//                     native thread id is unchanged, one endpoint process).
//  4. MCP whoami    — the model calls the pagnet worker MCP network_whoami
//                     tool; the call travels codex → pagnet mcp worker →
//                     daemon bridge socket (authenticated) → relay, and the
//                     identity result comes back into the turn (MCP
//                     injection, end to end).
//  5. hibernate     — the endpoint process is stopped, the session preserved.
//  6. resume        — a new endpoint process resumes the SAME thread.
//  7. third turn    — a turn on the resumed thread completes (same id).
//
// Gating: the smoke runs only when the real codex binary is resolvable (it
// makes REAL model calls). It is skipped otherwise (CI without codex).
//
// Control-plane boundary: network_whoami is relayed by the daemon to the
// control plane (pagnet-server — a separate repo, out of scope here). This
// test does NOT connect to the shared/production control plane (that would
// register a real host). Instead the in-memory host connection answers the
// whoami relay with a deterministic identity — so every component of the
// MCP-injection path is REAL (codex, the -c override, the pagnet mcp worker
// process, the bridge socket + auth, the model's tool call, the daemon
// relay) and only the out-of-scope control-plane identity is stood in for.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/gorilla/websocket"

	"github.com/pagnet-code/pagnet/domain"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

// codexSmokeBinary resolves the real codex CLI (the smoke's subject). It
// returns "" when codex is not installed (the smoke skips).
func codexSmokeBinary() string {
	if p, err := exec.LookPath("codex"); err == nil {
		return p
	}
	if self, err := os.Executable(); err == nil {
		if cand := filepath.Join(filepath.Dir(self), "codex"); fileExists(cand) {
			return cand
		}
	}
	return ""
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// buildPagnetBinary builds the real pagnet CLI (the MCP worker the codex
// endpoint spawns) into a scratch dir. It is the command the daemon's
// rendered PAGNET_MCP_CONFIG points at.
func buildPagnetBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "pagnet")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "go", "build", "-o", bin,
		"github.com/pagnet-code/pagnet/cmd/pagnet").CombinedOutput()
	if err != nil {
		t.Fatalf("build pagnet binary (MCP worker): %v\n%s", err, out)
	}
	return bin
}

// codexSmokeSubmit drives one prompt turn through the session Manager and
// drains the event stream. It returns the settled result, the observed
// events, and the submit error.
func codexSmokeSubmit(t *testing.T, m *session.Manager, sess *session.RuntimeSession, turnID, input string) (*session.TurnResult, []session.SessionEvent, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	events := make(chan session.SessionEvent, 128)
	var result *session.TurnResult
	var submitErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		result, submitErr = m.Submit(ctx, sess, session.SubmitRequest{
			TurnID: turnID, Kind: session.SubmitPrompt, Input: input, InputKind: "task",
		}, events)
	}()
	var evs []session.SessionEvent
	for ev := range events {
		evs = append(evs, ev)
	}
	<-done
	return result, evs, submitErr
}

// codexSmokeOutput concatenates the turn's output events (the transcript).
func codexSmokeOutput(evs []session.SessionEvent) string {
	var b strings.Builder
	for _, ev := range evs {
		if ev.Type == session.EventTurnOutput {
			b.WriteString(ev.Output)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// codexSmokeSawEvent reports whether the event stream carries a session event
// of the given type.
func codexSmokeSawEvent(evs []session.SessionEvent, typ string) bool {
	for _, ev := range evs {
		if ev.Type == typ {
			return true
		}
	}
	return false
}

// truncateCodexSmoke bounds a string for a failure message.
func truncateCodexSmoke(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// codexSmokeNoSpace removes all whitespace from s. Codex's stream-json output
// is fragmented into many small chunks, so a value (e.g. the whoami identity)
// can be split across chunk boundaries; matching on the whitespace-stripped
// form makes the assertion robust to that fragmentation.
func codexSmokeNoSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !unicode.IsSpace(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// codexSmokeEventDump renders an event stream for a failure message: each
// event's type, its output (truncated), and any interaction it carries.
func codexSmokeEventDump(evs []session.SessionEvent) string {
	var b strings.Builder
	for i, ev := range evs {
		fmt.Fprintf(&b, "[%d] %s", i, ev.Type)
		if ev.Output != "" {
			s := ev.Output
			if len(s) > 120 {
				s = s[:120] + "…"
			}
			fmt.Fprintf(&b, " out=%q", s)
		}
		if ev.Error != "" {
			fmt.Fprintf(&b, " err=%q", ev.Error)
		}
		if ev.Interaction != nil {
			fmt.Fprintf(&b, " interaction{id=%s kind=%s resolved=%v decision=%s summary=%q payload=%s}",
				ev.Interaction.NativeInteractionID, ev.Interaction.Kind, ev.Interaction.Resolved, ev.Interaction.Decision, ev.Interaction.Summary, truncateCodexSmoke(string(ev.Interaction.NativePayload), 400))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// codexSmokeSubmitWithApprovals drives one prompt turn and, while it is in
// flight, resolves (approves) any native interaction that surfaces. The test
// plays the role of the client/user: the driver surfaces the approval as a
// generic interaction (spec: no auto-approve in the driver), and the test
// answers it so the turn can proceed. It returns the settled result, the
// observed events, and the submit error.
func codexSmokeSubmitWithApprovals(t *testing.T, m *session.Manager, sess *session.RuntimeSession, turnID, input string) (*session.TurnResult, []session.SessionEvent, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	events := make(chan session.SessionEvent, 256)
	var result *session.TurnResult
	var submitErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		result, submitErr = m.Submit(ctx, sess, session.SubmitRequest{
			TurnID: turnID, Kind: session.SubmitPrompt, Input: input, InputKind: "task",
		}, events)
	}()
	var mu sync.Mutex
	var evs []session.SessionEvent
	resolved := map[string]bool{}
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		for ev := range events {
			mu.Lock()
			evs = append(evs, ev)
			mu.Unlock()
			if ev.Type == session.EventInteractionStarted && ev.Interaction != nil {
				id := ev.Interaction.NativeInteractionID
				mu.Lock()
				already := resolved[id]
				if !already {
					resolved[id] = true
				}
				mu.Unlock()
				if !already {
					t.Logf("interaction %s (kind=%s): %s — approving", id, ev.Interaction.Kind, ev.Interaction.Summary)
					// A SEPARATE events channel: Submit closes its events
					// channel on return (defer close), so the prompt's
					// channel must not be shared with the resolution.
					if _, err := m.Submit(ctx, sess, session.SubmitRequest{
						TurnID:        turnID,
						Kind:          session.SubmitInteraction,
						InteractionID: id,
						Decision:      "resolved",
					}, make(chan session.SessionEvent, 64)); err != nil && !errors.Is(err, session.ErrEndpointGone) {
						t.Logf("resolve interaction %s: %v", id, err)
					}
				}
			}
		}
	}()
	<-done
	<-collectorDone
	mu.Lock()
	defer mu.Unlock()
	return result, evs, submitErr
}

// startWhoamiRelay answers the daemon's agent.request relays on the
// in-memory host connection (standing in for the out-of-scope control
// plane). For network_whoami it returns a deterministic identity; for any
// other tool it returns a generic ok. It runs until the test ends.
func startWhoamiRelay(t *testing.T, server *websocket.Conn, instanceID, networkID string) {
	t.Helper()
	go func() {
		for {
			_, raw, err := server.ReadMessage()
			if err != nil {
				return // connection closed (test end)
			}
			var env transport.Envelope
			if err := json.Unmarshal(raw, &env); err != nil {
				continue
			}
			if env.Type != transport.MsgAgentRequest {
				continue
			}
			var req transport.AgentRequestPayload
			if err := env.DecodePayload(&req); err != nil {
				continue
			}
			var result json.RawMessage
			switch req.Tool {
			case "network_whoami":
				result, _ = json.Marshal(map[string]any{
					"principalId": "principal-codex-smoke",
					"instanceId":  instanceID,
					"networkId":   networkID,
				})
			default:
				result, _ = json.Marshal(map[string]any{"tool": req.Tool, "ok": true})
			}
			resp, err := transport.NewEnvelope(transport.MsgAgentResponse, transport.AgentResponsePayload{
				RequestID: env.ID,
				OK:        true,
				Result:    result,
			})
			if err != nil {
				continue
			}
			b, _ := json.Marshal(resp)
			if err := server.WriteMessage(websocket.TextMessage, b); err != nil {
				return
			}
		}
	}()
}

func TestCodexRealSmoke(t *testing.T) {
	codexBin := codexSmokeBinary()
	if codexBin == "" {
		t.Skip("real codex binary not resolvable; skipping the real smoke")
	}
	pagnetBin := buildPagnetBinary(t)

	// A debug daemon (for the bridge socket + the rendered MCP config + the
	// instance row the bridge authenticates against).
	d := newTestDaemon(t)
	d.selfExe = pagnetBin
	t.Cleanup(func() { d.stopBridgeSocket() })
	if err := d.startBridgeSocket(); err != nil {
		t.Fatalf("start bridge socket: %v", err)
	}

	instanceID := domain.NewID().String()
	networkID := "net-codex-smoke"
	workspace := t.TempDir()
	// The instance row the bridge socket authenticates the MCP worker
	// against (identity: PAGNET_INSTANCE_ID / PAGNET_NETWORK_ID).
	if err := d.state.UpsertInstance(InstanceRow{
		InstanceID: instanceID,
		Runtime:    string(domain.RuntimeCodex),
		Workspace:  workspace,
		Status:     "idle",
		NetworkID:  networkID,
		AgentName:  "codex-smoke",
	}); err != nil {
		t.Fatalf("upsert instance: %v", err)
	}

	// The in-memory host connection (the daemon relays bridge tool calls to
	// it); the whoami relay answers it (standing in for the control plane).
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()
	startWhoamiRelay(t, server, instanceID, networkID)
	// The daemon-side read loop: reads agent.response envelopes from the
	// in-memory host connection and delivers them to the bridge relay. This
	// is the piece of connectAndRun's read loop a real control-plane
	// connection provides; without it the relay's response is never routed
	// back to the waiting MCP worker.
	go func() {
		for {
			_, raw, err := client.ReadMessage()
			if err != nil {
				return
			}
			var env transport.Envelope
			if err := json.Unmarshal(raw, &env); err != nil {
				continue
			}
			if env.Type == transport.MsgAgentResponse {
				d.deliverAgentResponse(env)
			}
		}
	}()

	// The REAL CodexPersistent driver, pointed at the real codex binary.
	cp, ok := d.sessions.DriverFor(domain.RuntimeCodex).(*agentruntime.CodexPersistent)
	if !ok {
		t.Fatal("the CodexPersistent driver is not registered (codex binary should be resolvable)")
	}
	cp.Binary = codexBin

	// The session, with the daemon-rendered MCP config (the real pagnet
	// binary + the real bridge socket) in its launch env.
	row, _, _ := d.state.GetInstance(instanceID)
	mcpCfg := d.mcpConfig(row)
	sess := d.sessions.Session(instanceID, domain.RuntimeCodex, workspace)
	d.sessions.SetLaunchEnv(sess, []string{
		"PAGNET_INSTANCE_ID=" + instanceID,
		"PAGNET_NETWORK_ID=" + networkID,
		"PAGNET_MCP_CONFIG=" + mcpCfg,
	})

	// --- 1. launch + 2. first turn -------------------------------------
	res1, evs1, err1 := codexSmokeSubmit(t, d.sessions, sess, "smoke-1", "Reply with exactly: ONE")
	if err1 != nil {
		t.Fatalf("first turn: %v", err1)
	}
	if res1 == nil || !res1.Completed {
		t.Fatalf("first turn did not complete: %+v (events: %s)", res1, codexSmokeOutput(evs1))
	}
	sessionID1 := res1.SessionID
	if sessionID1 == "" {
		t.Fatal("first turn reported no native session (thread) id")
	}
	if !strings.Contains(codexSmokeNoSpace(codexSmokeOutput(evs1)), "ONE") {
		t.Fatalf("first turn output missing the expected reply: %q", codexSmokeOutput(evs1))
	}
	pid1 := d.sup.EndpointPID(instanceID)
	if pid1 == nil {
		t.Fatal("no live codex endpoint after the first turn")
	}
	t.Logf("launch + first turn: thread %s, endpoint pid %d", sessionID1, *pid1)

	// --- 3. second turn on the SAME thread (persistence) ---------------
	res2, evs2, err2 := codexSmokeSubmit(t, d.sessions, sess, "smoke-2", "Reply with exactly: TWO")
	if err2 != nil {
		t.Fatalf("second turn: %v", err2)
	}
	if res2 == nil || !res2.Completed {
		t.Fatalf("second turn did not complete: %+v (events: %s)", res2, codexSmokeOutput(evs2))
	}
	if res2.SessionID != sessionID1 {
		t.Fatalf("persistence broken: second turn thread %q != first turn thread %q", res2.SessionID, sessionID1)
	}
	pid2 := d.sup.EndpointPID(instanceID)
	if pid2 == nil || *pid2 != *pid1 {
		t.Fatalf("the second turn used a different endpoint process (pid %v vs %v); want the same", pid2, pid1)
	}
	t.Logf("second turn: same thread %s, same endpoint pid %d", sessionID1, *pid1)

	// --- 4. MCP whoami (MCP injection, end to end) ----------------------
	// The model's network_whoami call may require an approval the driver
	// surfaces as a generic interaction; the test approves it (it is the
	// client/user). The helper also collects the full event stream so a
	// failure shows exactly where the turn stalled.
	whoamiPrompt := "Use the pagnet MCP tool network_whoami (it takes no arguments) to fetch your identity. Then reply with the exact JSON object it returns, and nothing else."
	res3, evs3, err3 := codexSmokeSubmitWithApprovals(t, d.sessions, sess, "smoke-whoami", whoamiPrompt)
	if err3 != nil {
		t.Fatalf("whoami turn: %v (events: %s)", err3, codexSmokeEventDump(evs3))
	}
	if res3 == nil || !res3.Completed {
		t.Fatalf("whoami turn did not complete: %+v (events: %s)", res3, codexSmokeEventDump(evs3))
	}
	whoamiOut := codexSmokeOutput(evs3)
	// The identity the (simulated) control plane returned must appear in the
	// turn: proof the model called the pagnet MCP tool and the result came
	// back through codex → mcp worker → bridge → relay → model. The output is
	// matched on its whitespace-stripped form because codex fragments the
	// stream into small chunks that can split the identity across boundaries.
	whoamiNorm := codexSmokeNoSpace(whoamiOut)
	if !strings.Contains(whoamiNorm, "principal-codex-smoke") {
		t.Fatalf("MCP injection not proven: the whoami identity is not in the turn output:\n%s", whoamiOut)
	}
	if !strings.Contains(whoamiNorm, instanceID) {
		t.Fatalf("MCP injection not proven: the instance id is not in the whoami result:\n%s", whoamiOut)
	}
	t.Logf("MCP whoami: the model called network_whoami and the identity came back (MCP injection proven)")

	// --- 5. hibernate (endpoint stopped, session preserved) ------------
	if err := d.sessions.Hibernate(context.Background(), sess); err != nil {
		t.Fatalf("hibernate: %v", err)
	}
	if n := d.sup.Stats().ActiveEndpoints; n != 0 {
		t.Fatalf("expected 0 active endpoints after hibernate, got %d", n)
	}
	if pid := d.sup.EndpointPID(instanceID); pid != nil {
		t.Fatalf("endpoint PID still reported after hibernate: %d", *pid)
	}
	if sess.NativeID != sessionID1 {
		t.Fatalf("native thread id changed after hibernate: before=%q after=%q", sessionID1, sess.NativeID)
	}
	if !sess.Materialised {
		t.Fatal("materialised flag cleared after hibernate (the session must be preserved)")
	}
	t.Logf("hibernate: endpoint stopped, thread %s preserved", sessionID1)

	// --- 6. resume (new endpoint, SAME thread) + 7. third turn ----------
	res4, evs4, err4 := codexSmokeSubmit(t, d.sessions, sess, "smoke-3", "Reply with exactly: THREE")
	if err4 != nil {
		t.Fatalf("third turn (after resume): %v", err4)
	}
	if res4 == nil || !res4.Completed {
		t.Fatalf("third turn did not complete: %+v (events: %s)", res4, codexSmokeOutput(evs4))
	}
	if res4.SessionID != sessionID1 {
		t.Fatalf("resume broken: third turn thread %q != pre-hibernate thread %q", res4.SessionID, sessionID1)
	}
	if !codexSmokeSawEvent(evs4, session.EventSessionResumed) {
		t.Fatalf("want session.resumed after the hibernate/wake (not a fresh start): %+v", evs4)
	}
	pid3 := d.sup.EndpointPID(instanceID)
	if pid3 == nil {
		t.Fatal("no live endpoint after resume")
	}
	if *pid3 == *pid1 {
		t.Fatalf("resume reused the old endpoint process (pid %d); want a new one", *pid1)
	}
	if !strings.Contains(codexSmokeNoSpace(codexSmokeOutput(evs4)), "THREE") {
		t.Fatalf("third turn output missing the expected reply: %q", codexSmokeOutput(evs4))
	}
	t.Logf("resume + third turn: NEW endpoint pid %d resumed thread %s", *pid3, sessionID1)

	fmt.Printf("CODEX REAL SMOKE: PASS (thread %s; pids %d -> %d; MCP whoami proven)\n",
		sessionID1, *pid1, *pid3)
}
