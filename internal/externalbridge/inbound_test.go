package externalbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/pagnet-code/pagnet/internal/externalbridge/inbox"
	"github.com/pagnet-code/pagnet/sdk"
)

func testAskInbox(t *testing.T) *AskInbox {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := inbox.Open(dir+"/inbox", inbox.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	a, err := NewAskInbox(store, testNetwork, testTarget, []string{testInvocation})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func inboundAsk(id string) *sdk.Message {
	return &sdk.Message{ID: id, NetworkID: testNetwork, ThreadID: testNetwork, Kind: "ASK", SenderPrincipalID: testInvocation, RecipientPrincipalID: testTarget}
}
func TestInboxReceivePolicyAndDurableWake(t *testing.T) {
	a := testAskInbox(t)
	ctx := context.Background()
	original := inboundAsk(testInvocation)
	for _, change := range []func(*sdk.Message){func(m *sdk.Message) { m.Kind = "REPLY" }, func(m *sdk.Message) { m.NetworkID = testTarget }, func(m *sdk.Message) { m.RecipientPrincipalID = "" }, func(m *sdk.Message) { m.SenderPrincipalID = testTarget }, func(m *sdk.Message) { m.ID = "replied:" + testInvocation }} {
		bad := *original
		change(&bad)
		if err := a.Receive(ctx, &bad); err != nil {
			t.Fatalf("terminal policy denial was not ACKed: %v", err)
		}
		keys, err := a.store.List()
		if err != nil || len(keys) != 0 {
			t.Fatalf("policy denial saved records: %v, err=%v", keys, err)
		}
		select {
		case <-a.Notifications():
			t.Fatal("policy denial caused wake")
		default:
		}
	}
	if err := a.Receive(ctx, original); err != nil {
		t.Fatal(err)
	}
	if err := a.Receive(ctx, original); err != nil {
		t.Fatal(err)
	}
	select {
	case <-a.Notifications():
	default:
		t.Fatal("missing durable wake")
	}
	select {
	case <-a.Notifications():
		t.Fatal("duplicate wake")
	default:
	}
	saved, err := a.GetSaved(original.ID)
	if err != nil || saved.SenderPrincipalID != original.SenderPrincipalID {
		t.Fatalf("saved=%v err=%v", saved, err)
	}
	if err := a.MarkReplied(original.ID, testNetwork); err != nil {
		t.Fatal(err)
	}
	_, markerErr := a.store.Put(a.key("native-started:"+original.ID), []byte("test"))
	if markerErr != nil {
		t.Fatal(markerErr)
	}
	ids, err := a.PendingIDs()
	if err != nil || len(ids) != 0 {
		t.Fatalf("pending=%v err=%v", ids, err)
	}
	if err := a.MarkReplied(original.ID, testTarget); !errors.Is(err, inbox.ErrConflict) {
		t.Fatalf("changed marker: %v", err)
	}
	a.store.Close()
	if err := a.Receive(ctx, original); err == nil {
		t.Fatal("ACK after store closed")
	}
}

func TestInboxDeniedBacklogLeavesCapacityForAllowedASK(t *testing.T) {
	a := testAskInbox(t)
	ctx := context.Background()
	// Exceed the local store's default record limit with terminal denials.
	// Every successful receive permits the transport to ACK and advance.
	for i := 0; i < 1025; i++ {
		denied := inboundAsk(fmt.Sprintf("01900000-0000-7000-8000-%012d", i+10))
		denied.SenderPrincipalID = testTarget
		if err := a.Receive(ctx, denied); err != nil {
			t.Fatalf("denied backlog stopped at %d: %v", i, err)
		}
	}
	select {
	case <-a.Notifications():
		t.Fatal("denied backlog caused wake")
	default:
	}
	allowed := inboundAsk(testInvocation)
	if err := a.Receive(ctx, allowed); err != nil {
		t.Fatalf("allowed ASK after denied backlog: %v", err)
	}
	keys, err := a.store.List()
	if err != nil || len(keys) != 1 || keys[0] != a.key(allowed.ID) {
		t.Fatalf("saved=%v err=%v", keys, err)
	}
	select {
	case <-a.Notifications():
	default:
		t.Fatal("missing allowed ASK wake after denied backlog")
	}
}
func toolJSON(t *testing.T, r *mcp.CallToolResult) map[string]any {
	t.Helper()
	if r.IsError {
		t.Fatalf("tool error: %v", r.Content)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(r.Content[0].(mcp.TextContent).Text), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func TestInboxMetadataPagination(t *testing.T) {
	a := testAskInbox(t)
	for i := 0; i < 21; i++ {
		if err := a.Receive(context.Background(), inboundAsk(fmt.Sprintf("01900000-0000-7000-8000-%012d", i+10))); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := New(&fakeClient{}, Config{Network: testNetwork, Inbox: a})
	tool := b.Server().ListTools()["pagnet_inbox"]
	r, _ := tool.Handler(context.Background(), request(nil))
	page := toolJSON(t, r)
	asks := page["asks"].([]any)
	if len(asks) != 20 || page["nextCursor"] == "" {
		t.Fatalf("page: %v", page)
	}
	if _, ok := asks[0].(map[string]any)["Parts"]; ok {
		t.Fatal("list exposed message body")
	}
	r, _ = tool.Handler(context.Background(), request(map[string]any{"cursor": page["nextCursor"]}))
	page = toolJSON(t, r)
	if len(page["asks"].([]any)) != 1 || page["nextCursor"] != "" {
		t.Fatalf("last page: %v", page)
	}
}

type inboundReplyFake struct {
	fakeClient
	original *sdk.Message
	text     string
	fail     bool
}

func (f *inboundReplyFake) SendDurableReply(_ context.Context, m *sdk.Message, text string) (string, error) {
	if f.text != "" && f.text != text {
		return "", errors.New("changed text")
	}
	f.text = text
	f.original = m
	if f.fail {
		return testNetwork, errors.New("timeout")
	}
	return testNetwork, nil
}
func TestInboxReplyUsesSavedRoutingAndUncertainID(t *testing.T) {
	a := testAskInbox(t)
	a.Receive(context.Background(), inboundAsk(testInvocation))
	f := &inboundReplyFake{fail: true}
	b, _ := New(f, Config{Network: testNetwork, Inbox: a})
	tool := b.Server().ListTools()["pagnet_reply"]
	args := map[string]any{"messageId": testInvocation, "text": "answer", "targetPrincipalId": testTarget, "threadId": testTarget}
	r, _ := tool.Handler(context.Background(), request(args))
	out := toolJSON(t, r)
	if out["replyId"] != testNetwork || !strings.Contains(out["notice"].(string), "uncertain") || f.original.ThreadID != testNetwork || f.original.SenderPrincipalID != testInvocation {
		t.Fatalf("reply: %v, original=%v", out, f.original)
	}
	f.fail = false
	r, _ = tool.Handler(context.Background(), request(args))
	toolJSON(t, r)
	ids, err := a.PendingIDs()
	if err != nil || len(ids) != 0 {
		t.Fatalf("pending=%v err=%v", ids, err)
	}
	args["text"] = "changed"
	r, _ = tool.Handler(context.Background(), request(args))
	if !r.IsError {
		t.Fatal("changed text accepted")
	}
}
