package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func runClaudeStreamFixture() int {
	native := ""
	hasInput, hasPermission := false, false
	for _, arg := range os.Args {
		if v, ok := strings.CutPrefix(arg, "--session-id="); ok {
			native = v
		}
		if v, ok := strings.CutPrefix(arg, "--resume="); ok {
			native = v
		}
		if arg == "stream-json" {
			hasInput = true
		}
		if arg == "stdio" {
			hasPermission = true
		}
	}
	if native == "" || !hasInput || !hasPermission {
		return 10
	}
	send := func(value any) { raw, _ := json.Marshal(value); fmt.Println(string(raw)) }
	result := func() {
		send(map[string]any{"type": "result", "session_id": native, "result": "synthetic complete", "usage": map[string]int{"input_tokens": 2, "output_tokens": 3}})
	}
	scanner := bufio.NewScanner(os.Stdin)
	var awaiting bool
	for scanner.Scan() {
		var message struct {
			Type      string
			RequestID string `json:"request_id"`
			Request   struct{ Subtype string }
			Message   struct{ Content string }
			Response  struct {
				Subtype   string
				RequestID string `json:"request_id"`
				Response  struct {
					Behavior     string
					UpdatedInput map[string]string
				}
			}
		}
		if json.Unmarshal(scanner.Bytes(), &message) != nil {
			return 2
		}
		switch message.Type {
		case "control_request":
			if os.Getenv("PAGNET_CLAUDE_FIXTURE_MODE") == "startup-block" {
				continue
			}
			send(map[string]any{"type": "control_response", "response": map[string]any{"subtype": "success", "request_id": message.RequestID, "response": map[string]any{}}})
		case "user":
			if message.Message.Content == "disconnect" {
				return 0
			}
			if message.Message.Content == "malformed" {
				fmt.Println("invalid-protocol")
				return 0
			}
			sid := native
			if message.Message.Content == "foreign-session" {
				sid = "foreign-native-session"
			}
			send(map[string]any{"type": "system", "subtype": "init", "session_id": sid})
			send(map[string]any{"type": "user", "session_id": native})
			if message.Message.Content == "block" {
				continue
			}
			if message.Message.Content == "permission" {
				awaiting = true
				send(map[string]any{"type": "control_request", "request_id": "native-permission", "request": map[string]any{"subtype": "can_use_tool", "tool_name": "Bash", "input": map[string]string{"command": "synthetic"}}})
				continue
			}
			if message.Message.Content == "background" {
				send(map[string]any{"type": "system", "subtype": "task_started", "session_id": native, "task_id": "native-background"})
			}
			if message.Message.Content == "background-finish" {
				send(map[string]any{"type": "system", "subtype": "task_notification", "session_id": native, "task_id": "native-background", "status": "completed"})
			}
			if message.Message.Content == "scheduler" {
				send(map[string]any{"type": "assistant", "session_id": native, "message": map[string]any{"content": []map[string]string{{"type": "tool_use", "name": "CronCreate"}}}})
			}
			send(map[string]any{"type": "assistant", "session_id": native, "message": map[string]any{"content": []map[string]string{{"type": "text", "text": message.Message.Content}}}})
			result()
		case "control_response":
			if !awaiting || message.Response.RequestID != "native-permission" || message.Response.Response.Behavior != "allow" || message.Response.Response.UpdatedInput["command"] != "synthetic" {
				return 3
			}
			awaiting = false
			result()
		}
	}
	return 0
}
func claudeFixture(t *testing.T) (*ClaudePersistent, *session.RuntimeSession) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	d := NewClaudePersistent(binary)
	d.PrefixArgs = []string{"claude-stream-fixture"}
	d.StateDir = t.TempDir()
	d.NativeDirs = []string{t.TempDir()}
	d.StartupTimeout = 2 * time.Second
	s := &session.RuntimeSession{InstanceID: string(domain.NewID()), Runtime: domain.RuntimeClaudeCode, Workspace: t.TempDir(), Model: "fixture-model", StandingInstructions: "synthetic standing", Env: []string{`PAGNET_MCP_CONFIG={"mcpServers":{"pagnet":{"command":"/bin/true","args":[],"env":{}}}}`}}
	t.Cleanup(func() { _ = d.Stop(s.InstanceID) })
	return d, s
}
func TestClaudePersistentNativeProcessContinuityAndResume(t *testing.T) {
	d, s := claudeFixture(t)
	var mu sync.Mutex
	var observed []session.SessionEvent
	var retired int
	d.NativeEventObserverRegistrationFactory = func(string) session.NativeEventObserverRegistration {
		return session.NativeEventObserverRegistration{Observe: func(event session.SessionEvent) error {
			mu.Lock()
			defer mu.Unlock()
			observed = append(observed, event)
			return nil
		}, Retire: func() { mu.Lock(); defer mu.Unlock(); retired++ }}
	}
	ep, err := d.Activate(context.Background(), s, nil)
	if err != nil {
		t.Fatal(err)
	}
	native := s.NativeID
	for _, input := range []string{"first", "second"} {
		ch := make(chan session.SessionEvent, 32)
		if err = d.Submit(context.Background(), s, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: input, Input: input}, ch); err != nil {
			t.Fatal(err)
		}
		if *d.PID(s.InstanceID) != ep.PID || s.NativeID != native {
			t.Fatal("persistent native PID or session changed")
		}
	}
	if !d.Materialised(s.InstanceID) || d.Capabilities().NativeTUI || d.Capabilities().SecondClientTerminalAttach {
		t.Fatal("incorrect native lifecycle capability")
	}
	s.Materialised = true
	if err = d.Hibernate(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if retired != 1 || len(observed) != 8 || observed[0].Type != session.EventSessionStarted || observed[7].Type != session.EventSessionStopped || observed[7].SessionID != native {
		t.Fatalf("native observation/retirement mismatch: %d/%d", len(observed), retired)
	}
	mu.Unlock()
	if _, err = d.Activate(context.Background(), s, nil); err != nil {
		t.Fatal(err)
	}
	if s.NativeID != native {
		t.Fatal("resume replaced native conversation")
	}
}
func TestClaudePersistentApprovalOriginalPayloadAndNoBlindRetry(t *testing.T) {
	d, s := claudeFixture(t)
	if _, err := d.Activate(context.Background(), s, nil); err != nil {
		t.Fatal(err)
	}
	ch := make(chan session.SessionEvent, 32)
	done := make(chan error, 1)
	go func() {
		done <- d.Submit(context.Background(), s, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: "approval", Input: "permission"}, ch)
	}()
	var interaction *session.InteractionEvent
	for interaction == nil {
		select {
		case event := <-ch:
			interaction = event.Interaction
		case <-time.After(3 * time.Second):
			t.Fatal("native approval missing")
		}
	}
	if interaction.NativeInteractionID != "native-permission" || !strings.Contains(string(interaction.NativePayload), "can_use_tool") {
		t.Fatal("native approval lost its original payload")
	}
	if err := d.Submit(context.Background(), s, session.SubmitRequest{Kind: session.SubmitInteraction, InteractionID: interaction.NativeInteractionID, Decision: "allow-once"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"disconnect", "malformed", "foreign-session"} {
		d, s := claudeFixture(t)
		if _, err := d.Activate(context.Background(), s, nil); err != nil {
			t.Fatal(err)
		}
		if err := d.Submit(context.Background(), s, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: "negative", Input: input}, make(chan session.SessionEvent, 32)); !errors.Is(err, session.ErrTurnInterrupted) {
			t.Fatalf("uncertain native turn could be blindly retried: %v", err)
		}
	}
}

func TestClaudePersistentNativeBackgroundAndSchedulerPreventHibernate(t *testing.T) {
	d, s := claudeFixture(t)
	ep, err := d.Activate(context.Background(), s, nil)
	if err != nil {
		t.Fatal(err)
	}
	prompt := func(input string) {
		t.Helper()
		if err := d.Submit(context.Background(), s, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: input, Input: input}, make(chan session.SessionEvent, 32)); err != nil {
			t.Fatal(err)
		}
	}
	prompt("background")
	if !d.ActiveWork(s.InstanceID) || !errors.Is(d.Hibernate(context.Background(), s), session.ErrBusy) || *d.PID(s.InstanceID) != ep.PID {
		t.Fatal("background task lost or hibernated")
	}
	prompt("background-finish")
	if d.ActiveWork(s.InstanceID) {
		t.Fatal("genuine terminal background task was not cleared")
	}
	prompt("scheduler")
	if !d.ActiveWork(s.InstanceID) || !errors.Is(d.Hibernate(context.Background(), s), session.ErrBusy) || *d.PID(s.InstanceID) != ep.PID {
		t.Fatal("scheduler was inferred idle")
	}
}
