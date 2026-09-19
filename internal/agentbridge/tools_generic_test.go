package agentbridge

// Tests for the V2 GENERIC network surface (plan §52): 7 fixed tools
// (search / invoke / event publish+get+list / subscribe / unsubscribe),
// no per-capability tool generation, untrusted-data wording on the
// participant-content tools, and arg-shape fidelity over the bridge.

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var genericToolNames = []string{
	"network_search", "network_invoke", "network_event_publish",
	"network_event_get", "network_events", "network_subscribe",
	"network_unsubscribe",
}

// The worker surface registers the 12 collaboration tools PLUS the 7
// generic tools — and nothing else (no per-capability generation).
func TestGenericTools_Registered(t *testing.T) {
	socket, _ := fakeBridgeServer(t)
	br, err := Dial(socket, "inst-1", "net-1")
	if err != nil {
		t.Fatal(err)
	}
	defer br.Close()

	s := server.NewMCPServer("pagnet", "1.0.0")
	RegisterWorkerTools(s, br)
	tools := s.ListTools()

	for _, name := range genericToolNames {
		if _, ok := tools[name]; !ok {
			t.Errorf("generic tool %q is not registered", name)
		}
	}
	for _, name := range []string{
		"network_whoami", "network_discover", "network_ask", "network_delegate",
		"network_inbox", "network_reply", "network_task_get", "network_task_update",
		"network_claim", "network_release", "network_publish_artifact",
		"network_register_capabilities",
	} {
		if _, ok := tools[name]; !ok {
			t.Errorf("collaboration tool %q is not registered", name)
		}
	}
	if got, want := len(tools), 12+len(genericToolNames); got != want {
		t.Errorf("worker surface registers %d tools, want exactly %d (no per-capability generation)", got, want)
	}
}

// The fixed tool schemas carry the right required args and the
// untrusted-data wording on the participant-content tools.
func TestGenericTools_Schemas(t *testing.T) {
	socket, _ := fakeBridgeServer(t)
	br, err := Dial(socket, "inst-1", "net-1")
	if err != nil {
		t.Fatal(err)
	}
	defer br.Close()

	s := server.NewMCPServer("pagnet", "1.0.0")
	RegisterWorkerTools(s, br)
	tools := s.ListTools()

	cases := []struct {
		name     string
		required []string
	}{
		{"network_invoke", []string{"capability", "input"}},
		{"network_event_publish", []string{"type", "payload"}},
		{"network_event_get", []string{"eventId"}},
		{"network_subscribe", []string{"pattern"}},
		{"network_unsubscribe", []string{"subscriptionId"}},
		{"network_search", nil},
		{"network_events", nil},
	}
	for _, tc := range cases {
		tool, ok := tools[tc.name]
		if !ok {
			t.Errorf("%s not registered", tc.name)
			continue
		}
		if tc.required != nil {
			if !reflect.DeepEqual(tool.Tool.InputSchema.Required, tc.required) {
				t.Errorf("%s required args = %v, want %v", tc.name, tool.Tool.InputSchema.Required, tc.required)
			}
		}
	}

	// Free-form object args: additionalProperties must be open on the
	// capability input and the event payload.
	for _, name := range []string{"network_invoke", "network_event_publish"} {
		prop := "input"
		if name == "network_event_publish" {
			prop = "payload"
		}
		p, ok := tools[name].Tool.InputSchema.Properties[prop].(map[string]any)
		if !ok {
			t.Errorf("%s: property %q missing", name, prop)
			continue
		}
		if p["additionalProperties"] != true {
			t.Errorf("%s.%s must allow arbitrary keys (additionalProperties=true)", name, prop)
		}
	}

	// Untrusted-data wording on every tool returning participant content.
	for _, name := range []string{"network_event_get", "network_events"} {
		desc := tools[name].Tool.Description
		if !strings.Contains(desc, "UNTRUSTED DATA") {
			t.Errorf("%s description lacks the untrusted-data wording: %q", name, desc)
		}
	}
	// whoami reports the agent principal + instance provenance.
	if !strings.Contains(tools["network_whoami"].Tool.Description, "AGENT PRINCIPAL") {
		t.Errorf("network_whoami description must name the agent principal: %q",
			tools["network_whoami"].Tool.Description)
	}
}

// Each generic tool relays EXACTLY the declared args over the bridge
// (unknown keys are filtered by Handle; values pass through verbatim).
func TestGenericTools_RelayArgs(t *testing.T) {
	socket, _ := fakeBridgeServer(t)
	br, err := Dial(socket, "inst-1", "net-1")
	if err != nil {
		t.Fatal(err)
	}
	defer br.Close()

	s := server.NewMCPServer("pagnet", "1.0.0")
	RegisterWorkerTools(s, br)
	tools := s.ListTools()

	type call struct {
		name string
		args map[string]any
		want map[string]any
	}
	calls := []call{
		{
			"network_search",
			map[string]any{"query": "pdf", "kind": "service", "capability": "documents.extract", "limit": float64(5), "bogus": "filtered-out"},
			map[string]any{"query": "pdf", "kind": "service", "capability": "documents.extract", "limit": float64(5)},
		},
		{
			"network_invoke",
			map[string]any{"capability": "documents.extract", "input": map[string]any{"uri": "https://example.com/a.pdf", "pages": []any{float64(1), float64(2)}}, "idempotencyKey": "idem-1", "bogus": true},
			map[string]any{"capability": "documents.extract", "input": map[string]any{"uri": "https://example.com/a.pdf", "pages": []any{float64(1), float64(2)}}, "idempotencyKey": "idem-1"},
		},
		{
			"network_event_publish",
			map[string]any{"type": "build.completed", "payload": map[string]any{"status": "success"}, "target": "atlas"},
			map[string]any{"type": "build.completed", "payload": map[string]any{"status": "success"}, "target": "atlas"},
		},
		{
			"network_event_get",
			map[string]any{"eventId": "evt-1"},
			map[string]any{"eventId": "evt-1"},
		},
		{
			"network_events",
			map[string]any{"type": "build.*", "limit": float64(10)},
			map[string]any{"type": "build.*", "limit": float64(10)},
		},
		{
			"network_subscribe",
			map[string]any{"pattern": "build.*", "mode": "wake"},
			map[string]any{"pattern": "build.*", "mode": "wake"},
		},
		{
			"network_unsubscribe",
			map[string]any{"subscriptionId": "sub-1"},
			map[string]any{"subscriptionId": "sub-1"},
		},
	}

	for _, tc := range calls {
		tool, ok := tools[tc.name]
		if !ok {
			t.Fatalf("%s not registered", tc.name)
		}
		req := mcp.CallToolRequest{}
		req.Params.Name = tc.name
		req.Params.Arguments = tc.args
		res, err := tool.Handler(context.Background(), req)
		if err != nil {
			t.Fatalf("%s handler error: %v", tc.name, err)
		}
		if res.IsError {
			t.Fatalf("%s handler returned an error result", tc.name)
		}
		var text string
		for _, c := range res.Content {
			if tc2, ok := c.(mcp.TextContent); ok {
				text = tc2.Text
			}
		}
		// The fake bridge echoes the relayed args: {"args": {...}}.
		var out struct {
			Args json.RawMessage `json:"args"`
		}
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("%s: unparseable result %q: %v", tc.name, text, err)
		}
		var got, want any
		if err := json.Unmarshal(out.Args, &got); err != nil {
			t.Fatalf("%s: unparseable relayed args: %v", tc.name, err)
		}
		if err := json.Unmarshal(mustJSON(tc.want), &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s relayed args = %v, want %v (exact keys, no extras)", tc.name, got, want)
		}
	}
}
