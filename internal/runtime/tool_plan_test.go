package runtime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeNativeFullListOnlySuccessfulOwnedResults(t *testing.T) {
	fixture := `{"type":"system","subtype":"init","session_id":"claude-owned"}
{"type":"assistant","session_id":"claude-owned","message":{"content":[{"type":"tool_use","id":"create","name":"TaskCreate","input":{"subject":"proposed"}}]}}
{"type":"user","session_id":"claude-owned","message":{"content":[{"type":"tool_result","tool_use_id":"create"}]},"tool_use_result":{"task":{"id":"1","subject":"proposed"}}}
{"type":"assistant","session_id":"claude-owned","message":{"content":[{"type":"tool_use","id":"failed","name":"TaskList"}]}}
{"type":"user","session_id":"claude-owned","message":{"content":[{"type":"tool_result","tool_use_id":"failed","is_error":true}]},"tool_use_result":{"tasks":[{"id":"1","subject":"failed","status":"completed"}]}}
{"type":"assistant","session_id":"foreign","message":{"content":[{"type":"tool_use","id":"foreign","name":"TaskList"}]}}
{"type":"user","session_id":"claude-owned","message":{"content":[{"type":"tool_result","tool_use_id":"foreign"}]},"tool_use_result":{"tasks":[]}}
{"type":"assistant","session_id":"claude-owned","parent_tool_use_id":"subagent","message":{"content":[{"type":"tool_use","id":"child","name":"TaskList"}]}}
{"type":"user","session_id":"claude-owned","message":{"content":[{"type":"tool_result","tool_use_id":"child"}]},"tool_use_result":{"tasks":[]}}
{"type":"assistant","session_id":"claude-owned","message":{"content":[{"type":"tool_use","id":"list","name":"TaskList"}]}}
{"type":"user","session_id":"claude-owned","message":{"content":[{"type":"tool_result","tool_use_id":"list"}]},"tool_use_result":{"tasks":[{"id":"1","subject":"actual","status":"in_progress"}]}}
{"type":"assistant","session_id":"claude-owned","message":{"content":[{"type":"tool_use","id":"clear","name":"TodoWrite"}]}}
{"type":"user","session_id":"claude-owned","message":{"content":[{"type":"tool_result","tool_use_id":"clear"}]},"tool_use_result":{"oldTodos":[{"content":"actual","status":"in_progress"}],"newTodos":[]}}
{"type":"result","session_id":"claude-owned","subtype":"success"}
`
	spec := TurnSpec{InstanceID: "native-plan", Workspace: t.TempDir()}
	spec.SessionDir = filepath.Join(spec.Workspace, "state")
	events, _ := runClaudeStub(t, spec, fixture, nil)
	var plans []TurnEvent
	for _, event := range events {
		if event.Type == EventPlanUpdated {
			plans = append(plans, event)
		}
	}
	if len(plans) != 2 || plans[0].SessionID != "claude-owned" || plans[0].Plan.Source != "claude" || len(plans[0].Plan.Entries) != 1 || plans[0].Plan.Entries[0].Text != "actual" || len(plans[1].Plan.Entries) != 0 {
		t.Fatalf("unsafe/incomplete native results accepted %+v", plans)
	}
}

func TestOpenCodeNativeCompletedFullReplacement(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "opencode")
	if err := os.WriteFile(script, []byte(fakeOpenCodeScript), 0700); err != nil {
		t.Fatal(err)
	}
	var lines []string
	lines = append(lines, `{"type":"step_start","sessionID":"owned","part":{"type":"step-start"}}`)
	add := func(session, partSession, status, todos string) {
		lines = append(lines, `{"type":"tool_use","sessionID":"`+session+`","part":{"type":"tool","tool":"todowrite","sessionID":"`+partSession+`","state":{"status":"`+status+`","input":{"todos":[{"content":"input-only","status":"completed"}]},"metadata":{"todos":`+todos+`}}}}`)
	}
	add("owned", "owned", "running", `[{"content":"not completed","status":"pending"}]`)
	add("owned", "owned", "error", `[{"content":"failed","status":"completed"}]`)
	add("foreign", "foreign", "completed", `[]`)
	add("owned", "foreign", "completed", `[]`)
	add("owned", "owned", "completed", `[{"content":"persisted","status":"pending","priority":"high"}]`)
	add("owned", "owned", "completed", `[]`)
	out := filepath.Join(dir, "out.ndjson")
	if err := os.WriteFile(out, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	spec := opencodeSpec(dir)
	spec.Env = []string{"OPENCODE_FAKE_OUT=" + out, "OPENCODE_FAKE_ARGS=" + filepath.Join(spec.SessionDir, "argv")}
	events := make(chan TurnEvent, 64)
	if err := NewOpenCode(script).StartTurn(context.Background(), spec, events); err != nil {
		t.Fatal(err)
	}
	var plans []TurnEvent
	for event := range events {
		if event.Type == EventPlanUpdated {
			plans = append(plans, event)
		}
	}
	if len(plans) != 2 || plans[0].Plan.Source != "opencode" || len(plans[0].Plan.Entries) != 1 || plans[0].Plan.Entries[0].Text != "persisted" || plans[0].Plan.Entries[0].Priority != "high" || len(plans[1].Plan.Entries) != 0 {
		t.Fatalf("unsafe native result accepted %+v", plans)
	}
}

func TestNativeToolPlansMalformedBoundsAndPairing(t *testing.T) {
	for _, raw := range []string{`null`, `[{"content":"bad","status":"deleted"}]`, `[{"content":"","status":"pending"}]`, `[{"content":"x","status":"pending","priority":"urgent"}]`, strings.Repeat(" ", 32769)} {
		if todoPlan("opencode", json.RawMessage(raw)) != nil {
			t.Fatal("invalid plan accepted")
		}
	}
	var p claudePlanTracker
	var ev claudeEvent
	_ = json.Unmarshal([]byte(`{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"unpaired"}]},"tool_use_result":{"newTodos":[]}}`), &ev)
	if p.consume(ev) != nil {
		t.Fatal("unpaired native result trusted")
	}
}
