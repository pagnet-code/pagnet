package externalbridge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/sdk"
)

type fakeMessagingClient struct {
	fakeClient
	sent    map[string]string
	sentTo  map[string]string
	replies map[string]*sdk.BrowserAskResult
}

func (f *fakeMessagingClient) SendBrowserAsk(_ context.Context, _, target, message, text string) (*sdk.BrowserAskResult, error) {
	if f.sent == nil {
		f.sent = map[string]string{}
		f.sentTo = map[string]string{}
	}
	f.sent[message] = text
	f.sentTo[message] = target
	return &sdk.BrowserAskResult{MessageID: message, ThreadID: message, TargetPrincipalID: target, Messages: []domain.Message{}}, nil
}

func (f *fakeMessagingClient) GetBrowserAsk(_ context.Context, _, message string) (*sdk.BrowserAskResult, error) {
	return f.replies[message], nil
}

func TestCoreAskDeterministicKeysAndPolicy(t *testing.T) {
	f := &fakeMessagingClient{}
	b, err := New(f, Config{Network: testNetwork, MessagingTargets: []string{testTarget}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	out1, err := b.Ask(ctx, testTarget, "trip-1", "", "hello")
	if err != nil || out1 == nil {
		t.Fatalf("ask: %v", err)
	}
	if out1.RequestID != "trip-1" {
		t.Fatalf("RequestID=%q", out1.RequestID)
	}
	// The SAME key, agent and text retry under the SAME durable message id.
	out2, err := b.Ask(ctx, testTarget, "trip-1", "", "hello")
	if err != nil || out2.MessageID != out1.MessageID {
		t.Fatalf("same key must reuse the message id: %q vs %q (%v)", out2.MessageID, out1.MessageID, err)
	}
	if f.sent[out1.MessageID] != "hello" || f.sentTo[out1.MessageID] != testTarget {
		t.Fatalf("sent=%v sentTo=%v", f.sent, f.sentTo)
	}
	// A different key derives a different durable id.
	other, err := b.Ask(ctx, testTarget, "trip-2", "", "different")
	if err != nil || other.MessageID == out1.MessageID {
		t.Fatalf("different key must derive a different id: %v", err)
	}
	// The advanced UUID form is accepted as-is.
	u := uuid.NewString()
	if _, err := b.Ask(ctx, testTarget, "", u, "uuid form"); err != nil {
		t.Fatalf("uuid form: %v", err)
	}
	if _, err := b.Ask(ctx, testTarget, "trip-1", u, "both"); err == nil {
		t.Fatal("request key and message UUID are mutually exclusive")
	}
	if _, err := b.Ask(ctx, testTarget, "trip-1", "", ""); err == nil {
		t.Fatal("empty text must be refused")
	}
	if _, err := b.Ask(ctx, "01900000-0000-7000-8000-000000000009", "trip-1", "", "outside policy"); err == nil {
		t.Fatal("unapproved messaging target must be refused")
	}
}

func TestCoreAskGetPolicy(t *testing.T) {
	f := &fakeMessagingClient{replies: map[string]*sdk.BrowserAskResult{}}
	b, err := New(f, Config{Network: testNetwork, MessagingTargets: []string{testTarget}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	out1, err := b.Ask(ctx, testTarget, "trip-1", "", "hello")
	if err != nil {
		t.Fatal(err)
	}
	f.replies[out1.MessageID] = &sdk.BrowserAskResult{MessageID: out1.MessageID, ThreadID: out1.MessageID, TargetPrincipalID: testTarget, Messages: []domain.Message{{ID: domain.ID(out1.MessageID)}}}
	got, err := b.AskGet(ctx, testTarget, "trip-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.MessageID != out1.MessageID || got.RequestID != "trip-1" {
		t.Fatalf("ask-get: %#v", got)
	}
	if _, err := b.AskGet(ctx, "01900000-0000-7000-8000-000000000009", "trip-1", ""); err == nil {
		t.Fatal("unapproved target must be refused on ask-get")
	}
	if _, err := b.AskGet(ctx, testTarget, "never-sent", ""); err == nil {
		t.Fatal("a request with no submission must fail the poll")
	}
}

func TestCoreInvokeCapabilityPolicy(t *testing.T) {
	f := &fakeClient{}
	b, err := New(f, Config{Network: testNetwork, Grants: []string{testTarget + "/hello.say"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := b.InvokeCapability(ctx, testTarget, "danger", testInvocation, map[string]any{}); err == nil {
		t.Fatal("unauthorized pair must be refused")
	}
	if len(f.calls) != 0 {
		t.Fatal("refused invocation reached the client")
	}
	if _, err := b.InvokeCapability(ctx, testTarget, "hello.say", "not-a-uuid", map[string]any{}); err == nil {
		t.Fatal("non-UUID invocation id must be refused")
	}
	if _, err := b.InvokeCapability(ctx, testTarget, "hello.say", testInvocation, map[string]any{"blob": strings.Repeat("a", 1<<20)}); err == nil {
		t.Fatal("input over 1 MiB must be refused")
	}
	data, err := b.InvokeCapability(ctx, testTarget, "hello.say", testInvocation, map[string]any{"text": "world"})
	if err != nil {
		t.Fatal(err)
	}
	if data["invocationId"] != testInvocation || data["state"] != "pending" {
		t.Fatalf("data=%v", data)
	}
	if _, hasNotice := data["notice"]; !hasNotice {
		t.Fatal("a durable timeout must carry a notice")
	}
	if got := f.calls[0]; got.IdempotencyKey != "external:"+testInvocation || got.NetworkID != testNetwork || got.Timeout != 20*time.Second {
		t.Fatalf("dispatch=%#v", got)
	}
}

func TestCoreInvocationViewGrants(t *testing.T) {
	f := &fakeClient{read: &sdk.Invocation{ID: testInvocation, TargetPrincipalID: testTarget, CapabilityID: "hello.say", State: "completed"}}
	b, err := New(f, Config{Network: testNetwork, Grants: []string{testTarget + "/hello.say"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	data, err := b.InvocationView(ctx, testInvocation)
	if err != nil || data["state"] != "completed" {
		t.Fatalf("view=%v err=%v", data, err)
	}
	if _, err := b.InvocationView(ctx, "not-a-uuid"); err == nil {
		t.Fatal("non-UUID id must be refused")
	}
	f.read.CapabilityID = "other.cap"
	if _, err := b.InvocationView(ctx, testInvocation); err == nil {
		t.Fatal("an invocation outside the bridge's grants must be refused")
	}
}

func TestCoreIdentityAndSearchView(t *testing.T) {
	f := &fakeClient{}
	b, err := New(f, Config{Network: testNetwork, Grants: []string{testTarget + "/hello.say"}, MessagingTargets: []string{testTarget}, Events: []string{"task.*", "a.b"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	view, err := b.IdentityView(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view["principalId"] != testTarget || view["networkId"] != testNetwork {
		t.Fatalf("identity=%v", view)
	}
	if patterns := view["eventPatterns"].([]string); len(patterns) != 2 || patterns[0] != "a.b" || patterns[1] != "task.*" {
		t.Fatalf("eventPatterns=%v", patterns)
	}
	if _, err := b.Search(ctx, "kubernetes", "k8s.get", ""); err != nil {
		t.Fatal(err)
	}
	if f.queried != testNetwork {
		t.Fatalf("search escaped the fixed network: %q", f.queried)
	}
}

func TestCoreDrainEventsAndPatterns(t *testing.T) {
	b, err := New(&fakeClient{}, Config{Network: testNetwork, Events: []string{"task.*", "a.b"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := b.EventPatterns(); len(got) != 2 || got[0] != "a.b" || got[1] != "task.*" {
		t.Fatalf("patterns=%v", got)
	}
	first := sdk.Event{ID: "e1", Type: "task.created", Payload: json.RawMessage(`{"n":1}`)}
	second := sdk.Event{ID: "e2", Type: "a.b"}
	if err := b.pushEvent(&first); err != nil {
		t.Fatal(err)
	}
	if err := b.pushEvent(&second); err != nil {
		t.Fatal(err)
	}
	drained := b.DrainEvents()
	if len(drained) != 2 || drained[0].ID != "e1" || drained[1].ID != "e2" {
		t.Fatalf("drain order: %v", drained)
	}
	if len(b.DrainEvents()) != 0 {
		t.Fatal("second drain must be empty")
	}
	view := EventView(first)
	if view["eventId"] != "e1" || view["type"] != "task.created" {
		t.Fatalf("view=%v", view)
	}
}
