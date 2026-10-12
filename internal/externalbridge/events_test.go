package externalbridge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/pagnet-code/pagnet/sdk"
)

type eventSourceFake struct {
	handlers map[string]func(*sdk.Event) error
	started  chan struct{}
}

func newEventSourceFake() *eventSourceFake {
	return &eventSourceFake{handlers: map[string]func(*sdk.Event) error{}, started: make(chan struct{})}
}

func (e *eventSourceFake) OnEvent(pattern string, deliver func(*sdk.Event) error) {
	e.handlers[pattern] = deliver
}
func (e *eventSourceFake) Run(ctx context.Context) {
	close(e.started)
	<-ctx.Done()
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func startEventBridge(t *testing.T, patterns []string) (*Bridge, *eventSourceFake) {
	t.Helper()
	b, err := New(&fakeClient{}, Config{Network: testNetwork, Events: patterns})
	if err != nil {
		t.Fatal(err)
	}
	src := newEventSourceFake()
	if err := b.StartEvents(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	return b, src
}

func TestEventToolsGatedOnGrantedPatterns(t *testing.T) {
	b, err := New(&fakeClient{}, Config{Network: testNetwork})
	if err != nil {
		t.Fatal(err)
	}
	tools := b.Server().ListTools()
	if _, exists := tools["pagnet_events"]; exists {
		t.Fatal("event tool exposed without a granted pattern")
	}
	b, src := startEventBridge(t, []string{"task.*"})
	tool, exists := b.Server().ListTools()["pagnet_events"]
	if !exists {
		t.Fatal("event tool missing with a granted pattern")
	}
	if !strings.Contains(tool.Tool.Description, "untrusted") {
		t.Fatal("event tool lacks the untrusted-data note")
	}
	if len(src.handlers) != 1 || src.handlers["task.*"] == nil {
		t.Fatal("granted pattern not registered on the event source")
	}
	select {
	case <-src.started:
	case <-time.After(2 * time.Second):
		t.Fatal("event loop not started")
	}
}

func TestInvalidEventPatterns(t *testing.T) {
	for _, p := range []string{"", "*", ".*", "a.*.b", "task..created", "task. created", strings.Repeat("a", 129) + ".b", "task.*x"} {
		if _, err := New(nil, Config{Network: testNetwork, Events: []string{p}}); err == nil {
			t.Fatal("accepted invalid event pattern", p)
		}
	}
	for _, p := range []string{"task.created", "task.*", "a-b.c_d.E1.*"} {
		if _, err := New(nil, Config{Network: testNetwork, Events: []string{p}}); err != nil {
			t.Fatal("rejected valid event pattern", p, err)
		}
	}
}

func TestEventPollDrainsInOrderOnce(t *testing.T) {
	b, src := startEventBridge(t, []string{"task.*"})
	deliver := src.handlers["task.*"]
	for i, tc := range []struct {
		id, typ string
		payload map[string]any
	}{
		{"ev-1", "task.created", map[string]any{"title": "first"}},
		{"ev-2", "task.status", map[string]any{"state": "blocked"}},
	} {
		if err := deliver(&sdk.Event{ID: tc.id, Type: tc.typ, ProducerPrincipalID: testTarget, OccurredAt: time.Now(), Payload: mustJSON(tc.payload)}); err != nil {
			t.Fatal(i, err)
		}
	}
	tools := b.Server().ListTools()
	out, _ := tools["pagnet_events"].Handler(context.Background(), request(nil))
	var got struct {
		Count  int `json:"count"`
		Events []struct {
			ID      string          `json:"eventId"`
			Type    string          `json:"type"`
			Payload json.RawMessage `json:"payload"`
		} `json:"events"`
	}
	if err := json.Unmarshal([]byte(out.Content[0].(mcp.TextContent).Text), &got); err != nil {
		t.Fatal(err)
	}
	if got.Count != 2 || got.Events[0].ID != "ev-1" || got.Events[1].ID != "ev-2" || got.Events[1].Type != "task.status" {
		t.Fatalf("drain: %+v", got)
	}
	if string(got.Events[0].Payload) != `{"title":"first"}` {
		t.Fatalf("payload not passed through opaquely: %s", got.Events[0].Payload)
	}
	out, _ = tools["pagnet_events"].Handler(context.Background(), request(nil))
	var again struct {
		Count  int   `json:"count"`
		Events []any `json:"events"`
	}
	if err := json.Unmarshal([]byte(out.Content[0].(mcp.TextContent).Text), &again); err != nil {
		t.Fatal(err)
	}
	if again.Count != 0 || len(again.Events) != 0 {
		t.Fatalf("redrained events: %+v", again)
	}
}

func TestFullEventBufferWithholdsAck(t *testing.T) {
	old := eventBufferCap
	eventBufferCap = 2
	defer func() { eventBufferCap = old }()
	_, src := startEventBridge(t, []string{"task.*"})
	deliver := src.handlers["task.*"]
	for i := 0; i < 2; i++ {
		if err := deliver(&sdk.Event{ID: "ev", Type: "task.created"}); err != nil {
			t.Fatal("queue accepted up to cap:", err)
		}
	}
	if err := deliver(&sdk.Event{ID: "ev-full", Type: "task.created"}); err == nil {
		t.Fatal("acked an event the buffer could not hold")
	}
}

func TestStartEventsLifecycle(t *testing.T) {
	b, err := New(&fakeClient{}, Config{Network: testNetwork})
	if err != nil {
		t.Fatal(err)
	}
	src := newEventSourceFake()
	if err := b.StartEvents(context.Background(), src); err != nil {
		t.Fatalf("no patterns: %v", err)
	}
	select {
	case <-src.started:
		t.Fatal("event loop started without patterns")
	default:
	}
	b, _ = New(&fakeClient{}, Config{Network: testNetwork, Events: []string{"task.*"}})
	if err := b.StartEvents(context.Background(), nil); err == nil {
		t.Fatal("started events without a source")
	}
	b, _ = startEventBridge(t, []string{"task.*"})
	if err := b.StartEvents(context.Background(), newEventSourceFake()); err == nil {
		t.Fatal("double start accepted")
	}
}

func TestIdentityListsEventPatterns(t *testing.T) {
	b, _ := startEventBridge(t, []string{"task.*", "agent.status"})
	out, _ := b.Server().ListTools()["pagnet_identity"].Handler(context.Background(), request(nil))
	var got map[string]any
	if err := json.Unmarshal([]byte(out.Content[0].(mcp.TextContent).Text), &got); err != nil {
		t.Fatal(err)
	}
	patterns, _ := got["eventPatterns"].([]any)
	if len(patterns) != 2 || patterns[0] != "agent.status" || patterns[1] != "task.*" {
		t.Fatalf("identity eventPatterns: %v", got["eventPatterns"])
	}
}

func TestHostedEventToolGatedOnPatterns(t *testing.T) {
	b, _ := New(&fakeClient{}, Config{Network: testNetwork})
	if _, err := b.HandleHosted(context.Background(), []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"pagnet_events"}}`)); err == nil {
		t.Fatal("hosted event call without a granted pattern")
	}
	b, _ = New(&fakeClient{}, Config{Network: testNetwork, Events: []string{"task.*"}})
	if _, err := b.HandleHosted(context.Background(), []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"pagnet_events"}}`)); err != nil {
		t.Fatal("hosted event call with a granted pattern: " + err.Error())
	}
}
