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
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runOpenCodeACPFixture() int {
	if len(os.Args) < 3 || os.Args[len(os.Args)-1] != "acp" {
		return 10
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), acpMaxFrame)
	send := func(value any) { data, _ := json.Marshal(value); fmt.Println(string(data)) }
	response := func(id json.RawMessage, value any) { send(map[string]any{"jsonrpc": "2.0", "id": id, "result": value}) }
	native := "native-opencode-conversation"
	var pending json.RawMessage
	for scanner.Scan() {
		var message acpMessage
		if json.Unmarshal(scanner.Bytes(), &message) != nil {
			return 2
		}
		if message.Method == "" {
			var answer struct {
				Outcome struct{ Outcome, OptionID string } `json:"outcome"`
			}
			_ = json.Unmarshal(message.Result, &answer)
			if answer.Outcome.Outcome != "selected" || answer.Outcome.OptionID != "allow-once" {
				return 3
			}
			response(pending, map[string]string{"stopReason": "end_turn"})
			continue
		}
		switch message.Method {
		case "initialize":
			if os.Getenv("PAGNET_FAKE_ACP_MODE") == "startup-block" {
				select {}
			}
			version := 1
			if os.Getenv("PAGNET_FAKE_ACP_MODE") == "bad-version" {
				version = 2
			}
			load := os.Getenv("PAGNET_FAKE_ACP_MODE") != "no-load"
			response(message.ID, map[string]any{"protocolVersion": version, "agentCapabilities": map[string]bool{"loadSession": load}, "authMethods": []map[string]string{{"id": "xai.api_key"}, {"id": "cached_token"}}})
		case "authenticate":
			response(message.ID, map[string]any{})
		case "session/new", "session/load":
			var params struct {
				SessionID, Cwd string
				MCPServers     []acpMCPServer `json:"mcpServers"`
			}
			if json.Unmarshal(message.Params, &params) != nil || !filepath.IsAbs(params.Cwd) || params.MCPServers == nil {
				return 4
			}
			if home := os.Getenv("XDG_DATA_HOME"); home == "" || !strings.Contains(home, "runtimes/"+string(domain.RuntimeOpenCode)+"/") {
				return 5
			}
			if os.Getenv("PAGNET_FAKE_ACP_MODE") == "verify-mcp" {
				if len(params.MCPServers) != 1 || params.MCPServers[0].Name != "pagnet" || params.MCPServers[0].Command != "/bin/true" || len(params.MCPServers[0].Env) != 1 {
					return 6
				}
			}
			if message.Method == "session/load" {
				if params.SessionID != native {
					return 7
				}
				send(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": native, "update": map[string]any{"sessionUpdate": "agent_message_chunk", "content": map[string]string{"type": "text", "text": "OLD HISTORY"}}}})
				response(message.ID, map[string]any{})
			} else {
				response(message.ID, map[string]string{"sessionId": native})
			}
		case "session/prompt":
			var params struct {
				SessionID string
				Prompt    []struct{ Type, Text string }
			}
			if json.Unmarshal(message.Params, &params) != nil || params.SessionID != native || len(params.Prompt) != 1 || params.Prompt[0].Type != "text" {
				return 8
			}
			if params.Prompt[0].Text == "disconnect" {
				return 0
			}
			if params.Prompt[0].Text == "block" {
				continue
			}
			if params.Prompt[0].Text == "permission" {
				pending = message.ID
				send(map[string]any{"jsonrpc": "2.0", "id": "permission-1", "method": "session/request_permission", "params": map[string]any{"sessionId": native, "toolCall": map[string]string{"title": "Fixture tool"}, "options": []map[string]string{{"optionId": "allow-once", "name": "Allow once", "kind": "allow_once"}, {"optionId": "reject-once", "name": "Reject once", "kind": "reject_once"}}}})
				continue
			}
			if params.Prompt[0].Text == "tool-active" || params.Prompt[0].Text == "tool-complete" {
				status := "in_progress"
				if params.Prompt[0].Text == "tool-complete" {
					status = "completed"
				}
				send(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": native, "update": map[string]string{"sessionUpdate": "tool_call_update", "toolCallId": "background-tool", "status": status}}})
			}
			if params.Prompt[0].Text == "plan" {
				send(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "foreign", "update": map[string]any{"sessionUpdate": "plan", "entries": []map[string]string{{"content": "foreign checklist", "status": "pending", "priority": "high"}}}}})
				send(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": native, "update": map[string]any{"sessionUpdate": "plan", "entries": []map[string]string{{"content": "first", "status": "in_progress", "priority": "high"}, {"content": "second", "status": "pending", "priority": "low"}}}}})
				send(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": native, "update": map[string]any{"sessionUpdate": "plan", "entries": []map[string]string{{"content": "first", "status": "completed", "priority": "high"}}}}})
			}
			send(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "foreign", "update": map[string]any{"sessionUpdate": "agent_message_chunk", "content": map[string]string{"type": "text", "text": "FOREIGN"}}}})
			send(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": native, "update": map[string]any{"sessionUpdate": "agent_message_chunk", "content": map[string]string{"type": "text", "text": "echo: " + params.Prompt[0].Text}}}})
			response(message.ID, map[string]string{"stopReason": "end_turn"})
		case "session/cancel":
			return 0
		default:
			return 9
		}
	}
	return 0
}

func TestOpenCodeACPOwnedPersistentSession(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	d := NewOpenCodePersistent(binary)
	d.PrefixArgs = []string{"opencode-acp-fixture"}
	d.StateDir = t.TempDir()
	d.Env = []string{"PAGNET_FAKE_ACP_MODE=verify-mcp"}
	d.StartupTimeout = 3 * time.Second
	s := &session.RuntimeSession{InstanceID: string(domain.NewID()), Runtime: domain.RuntimeOpenCode, Workspace: t.TempDir(), Model: "provider/model", StandingInstructions: "synthetic standing", Env: []string{`PAGNET_MCP_CONFIG={"mcpServers":{"pagnet":{"command":"/bin/true","args":[],"env":{"FIXTURE":"yes"}}}}`}}
	var observed []session.SessionEvent
	retired := false
	d.NativeEventObserverRegistrationFactory = func(string) session.NativeEventObserverRegistration {
		return session.NativeEventObserverRegistration{Observe: func(event session.SessionEvent) error { observed = append(observed, event); return nil }, Retire: func() { retired = true }}
	}
	t.Cleanup(func() { _ = d.Stop(s.InstanceID) })
	ep, err := d.Activate(context.Background(), s, nil)
	if err != nil {
		t.Fatal(err)
	}
	original := s.NativeID
	for _, input := range []string{"first", "second"} {
		events := make(chan session.SessionEvent, 32)
		if err = d.Submit(context.Background(), s, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: input, Input: input}, events); err != nil {
			t.Fatal(err)
		}
		if *d.PID(s.InstanceID) != ep.PID || s.NativeID != original {
			t.Fatal("native PID/session changed between turns")
		}
	}
	if len(observed) < 5 || retired {
		t.Fatal("native observer was not preserved")
	}
	if d.Capabilities().NativeTUI || d.Capabilities().SecondClientTerminalAttach {
		t.Fatal("machine ACP endpoint advertised replacement TUI")
	}
	state := filepath.Join(d.StateDir, "runtimes", string(domain.RuntimeOpenCode), s.InstanceID)
	raw, err := os.ReadFile(filepath.Join(state, "opencode.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Model        string
		Instructions []string
	}
	if json.Unmarshal(raw, &cfg) != nil || cfg.Model != s.Model || len(cfg.Instructions) != 1 {
		t.Fatal("original model/standing config missing")
	}
	s.Materialised = true
	if err = d.Hibernate(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if !retired || observed[len(observed)-1].Type != session.EventSessionStopped || observed[len(observed)-1].SessionID != original {
		t.Fatal("source registration not retired before hibernate")
	}
	if _, err = d.Activate(context.Background(), s, nil); err != nil {
		t.Fatal(err)
	}
	if s.NativeID != original {
		t.Fatal("resume changed native session")
	}
}
func TestOpenCodeACPUnsupportedResumeRetainsIdentity(t *testing.T) {
	binary, _ := os.Executable()
	d := NewOpenCodePersistent(binary)
	d.PrefixArgs = []string{"opencode-acp-fixture"}
	d.StateDir = t.TempDir()
	d.Env = []string{"PAGNET_FAKE_ACP_MODE=no-load"}
	s := &session.RuntimeSession{InstanceID: string(domain.NewID()), Runtime: domain.RuntimeOpenCode, Workspace: t.TempDir(), NativeID: "native-opencode-conversation", Materialised: true}
	defer d.Stop(s.InstanceID)
	if _, err := d.Activate(context.Background(), s, nil); !errors.Is(err, session.ErrSessionLost) {
		t.Fatalf("missing native load capability did not fail closed: %v", err)
	}
	if s.NativeID != "native-opencode-conversation" {
		t.Fatal("silently replaced source session")
	}
}

func TestOpenCodeACPOriginalPermissionAndToolHibernateFence(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	d := NewOpenCodePersistent(binary)
	d.PrefixArgs = []string{"opencode-acp-fixture"}
	d.StateDir = t.TempDir()
	s := &session.RuntimeSession{InstanceID: string(domain.NewID()), Runtime: domain.RuntimeOpenCode, Workspace: t.TempDir()}
	t.Cleanup(func() { _ = d.Stop(s.InstanceID) })
	ep, err := d.Activate(context.Background(), s, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	events := make(chan session.SessionEvent, 32)
	done := make(chan error, 1)
	go func() {
		done <- d.Submit(ctx, s, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: "permission", Input: "permission"}, events)
	}()
	for {
		select {
		case event := <-events:
			if event.Type != session.EventInteractionStarted {
				continue
			}
			if event.Interaction == nil || len(event.Interaction.NativePayload) == 0 || event.SessionID != s.NativeID {
				t.Fatal("native permission source omitted")
			}
			if err := d.Submit(ctx, s, session.SubmitRequest{Kind: session.SubmitInteraction, InteractionID: event.Interaction.NativeInteractionID, Answer: "allow-once", Decision: "allow-once"}, nil); err != nil {
				t.Fatal(err)
			}
			goto resolved
		case <-ctx.Done():
			t.Fatal("native permission absent")
		}
	}
resolved:
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"tool-active", "tool-complete"} {
		if err := d.Submit(ctx, s, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: input, Input: input}, make(chan session.SessionEvent, 32)); err != nil {
			t.Fatal(err)
		}
		if input == "tool-active" && (!d.ActiveWork(s.InstanceID) || !errors.Is(d.Hibernate(ctx, s), session.ErrBusy) || *d.PID(s.InstanceID) != ep.PID) {
			t.Fatal("active native tool hibernated")
		}
	}
	if d.ActiveWork(s.InstanceID) {
		t.Fatal("terminal native tool remained active")
	}
}
