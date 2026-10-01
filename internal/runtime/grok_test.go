package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

// The fixture is a real supervised executable, speaking the vendor's documented
// ACP protocol. It makes no model, network, or provider-key calls.
func runGrokACPFixture() int {
	if len(os.Args) < 8 || os.Args[len(os.Args)-2] != "agent" || os.Args[len(os.Args)-1] != "stdio" {
		return 10
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), acpMaxFrame)
	send := func(value any) { data, _ := json.Marshal(value); fmt.Println(string(data)) }
	response := func(id json.RawMessage, value any) { send(map[string]any{"jsonrpc": "2.0", "id": id, "result": value}) }
	native := "native-grok-conversation"
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
			if home := os.Getenv("GROK_HOME"); home == "" || !strings.Contains(home, "runtimes/grok-code/") {
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
func grokFixture(t *testing.T, mode string) (*ACPDriver, *session.RuntimeSession) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	d := NewGrok(binary)
	d.PrefixArgs = []string{"grok-acp-fixture"}
	d.StateDir = t.TempDir()
	d.Env = []string{"PAGNET_FAKE_ACP_MODE=" + mode}
	d.StartupTimeout = 3 * time.Second
	s := &session.RuntimeSession{InstanceID: string(domain.NewID()), Runtime: domain.RuntimeGrok, Workspace: t.TempDir(), Model: "fixture-model", StandingInstructions: "fixture standing instructions"}
	t.Cleanup(func() { _ = d.Stop(s.InstanceID) })
	return d, s
}
func activateGrokFixture(t *testing.T, d *ACPDriver, s *session.RuntimeSession) *session.RuntimeEndpoint {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ep, err := d.Activate(ctx, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ep
}
func TestGrokACPPersistentTurnsAndNativeResume(t *testing.T) {
	d, s := grokFixture(t, "verify-mcp")
	s.Env = []string{`PAGNET_MCP_CONFIG={"mcpServers":{"pagnet":{"command":"/bin/true","args":[],"env":{"FIXTURE":"yes"}}}}`}
	ep := activateGrokFixture(t, d, s)
	if d.Capabilities().NativeTUI || d.Capabilities().SecondClientTerminalAttach {
		t.Fatal("ACP cannot advertise a native terminal")
	}
	for _, input := range []string{"first", "second"} {
		events := make(chan session.SessionEvent, 32)
		if err := d.Submit(context.Background(), s, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: input, Input: input}, events); err != nil {
			t.Fatal(err)
		}
		close(events)
		text := ""
		complete := 0
		for ev := range events {
			if ev.Type == session.EventTurnOutput {
				text += ev.Output
			}
			if ev.Type == session.EventTurnCompleted {
				complete++
			}
		}
		if text != "echo: "+input || complete != 1 {
			t.Fatalf("wrong native result text=%q complete=%d", text, complete)
		}
		if pid := d.PID(s.InstanceID); pid == nil || *pid != ep.PID {
			t.Fatal("prompt restarted persistent endpoint")
		}
	}
	s.Materialised = true
	native := s.NativeID
	if err := d.Hibernate(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	// Stop requests termination; the supervisor owns its bounded reap.
	deadline := time.Now().Add(3 * time.Second)
	for d.life.get().(interface{ EndpointPID(string) *int }).EndpointPID(s.InstanceID) != nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	events := make(chan session.SessionEvent, 8)
	if _, err := d.Activate(context.Background(), s, events); err != nil {
		t.Fatal(err)
	}
	if s.NativeID != native {
		t.Fatal("resume changed native identity")
	}
	if len(events) != 1 || (<-events).Type != session.EventSessionResumed {
		t.Fatal("session/load replay was treated as new output")
	}
}
func TestGrokACPPermissionsRequireExplicitNativeOption(t *testing.T) {
	d, s := grokFixture(t, "")
	activateGrokFixture(t, d, s)
	events := make(chan session.SessionEvent, 32)
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		done <- d.Submit(ctx, s, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: "permission-turn", Input: "permission"}, events)
	}()
	var id string
	for id == "" {
		select {
		case ev := <-events:
			if ev.Type == session.EventInteractionStarted {
				id = ev.Interaction.NativeInteractionID
				if len(ev.Interaction.Options) != 2 || ev.Interaction.Options[0].ID != "allow-once" || ev.Interaction.Options[1].Kind != "reject_once" {
					t.Fatalf("native choices lost: %+v", ev.Interaction.Options)
				}
			}
		case <-ctx.Done():
			t.Fatal("native permission was not exposed")
		}
	}
	if !d.ActiveWork(s.InstanceID) {
		t.Fatal("pending native permission must veto hibernation")
	}
	if err := d.Hibernate(ctx, s); !errors.Is(err, session.ErrBusy) {
		t.Fatalf("hibernate=%v", err)
	}
	if err := d.Submit(ctx, s, session.SubmitRequest{Kind: session.SubmitInteraction, InteractionID: id, Decision: "approve"}, nil); err == nil {
		t.Fatal("invented approval silently accepted")
	}
	if err := d.Submit(ctx, s, session.SubmitRequest{Kind: session.SubmitInteraction, InteractionID: id, Decision: "select", Answer: "allow-once"}, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("native selected permission did not settle prompt")
	}
	if err := d.Submit(ctx, s, session.SubmitRequest{Kind: session.SubmitInteraction, InteractionID: id, Decision: "cancel"}, nil); err == nil {
		t.Fatal("permission replay accepted")
	}
}
func TestGrokACPAmbiguousPromptNeverRetryable(t *testing.T) {
	for _, input := range []string{"disconnect", "block"} {
		t.Run(input, func(t *testing.T) {
			d, s := grokFixture(t, "")
			activateGrokFixture(t, d, s)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			err := d.Submit(ctx, s, session.SubmitRequest{Kind: session.SubmitPrompt, Input: input}, nil)
			if !errors.Is(err, session.ErrTurnInterrupted) || errors.Is(err, session.ErrEndpointGone) {
				t.Fatalf("accepted prompt could be retried: %v", err)
			}
		})
	}
}
func TestGrokACPHandshakeAndLoadCapabilities(t *testing.T) {
	for _, mode := range []string{"bad-version", "startup-block"} {
		t.Run(mode, func(t *testing.T) {
			d, s := grokFixture(t, mode)
			d.StartupTimeout = 100 * time.Millisecond
			if _, err := d.Activate(context.Background(), s, nil); err == nil {
				t.Fatal("invalid/blocked initialization accepted")
			}
			if d.Live(s.InstanceID) {
				t.Fatal("failed activation remained live")
			}
		})
	}
	d, s := grokFixture(t, "no-load")
	activateGrokFixture(t, d, s)
	s.Materialised = true
	if err := d.Hibernate(context.Background(), s); err == nil || !d.Live(s.InstanceID) {
		t.Fatalf("unresumable endpoint must remain live: %v", err)
	}
	if err := d.Stop(s.InstanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Activate(context.Background(), s, nil); !errors.Is(err, session.ErrSessionLost) {
		t.Fatalf("unsupported resume silently rebased: %v", err)
	}
}
func TestGrokACPRejectsUnsafeNativeStateAndMCP(t *testing.T) {
	d, s := grokFixture(t, "")
	d.Env = append(d.Env, "GROK_HOME="+t.TempDir())
	if _, err := d.Activate(context.Background(), s, nil); err == nil {
		t.Fatal("external global native state allowed")
	}
	d.Env = d.Env[:len(d.Env)-1]
	s.Env = []string{`PAGNET_MCP_CONFIG={"mcpServers":{"pagnet":{"url":"https://invalid.example"}}}}`}
	if _, err := d.Activate(context.Background(), s, nil); err == nil {
		t.Fatal("unsupported native MCP configuration silently ignored")
	}
}

func TestGrokACPReconnectReapsDeadEndpointBeforeHandshake(t *testing.T) {
	d, s := grokFixture(t, "")
	activateGrokFixture(t, d, s)
	if err := d.Submit(context.Background(), s, session.SubmitRequest{Kind: session.SubmitPrompt, Input: "disconnect"}, nil); !errors.Is(err, session.ErrTurnInterrupted) {
		t.Fatal(err)
	}
	// Reconnect immediately, without fixture sleeps or a fresh process identity.
	if _, err := d.Activate(context.Background(), s, nil); !errors.Is(err, session.ErrNotMaterialised) {
		t.Fatalf("unmaterialised resume accepted: %v", err)
	}
	s.NativeID = ""
	activateGrokFixture(t, d, s)
}
