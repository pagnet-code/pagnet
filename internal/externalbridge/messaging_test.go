package externalbridge

import (
	"context"

	"github.com/pagnet-code/pagnet/sdk"
	"testing"
)

type messagingFake struct {
	fakeClient
	calls                     int
	network, target, id, text string
	read                      *sdk.BrowserAskResult
}

func (f *messagingFake) SendBrowserAsk(_ context.Context, network, target, id, text string) (*sdk.BrowserAskResult, error) {
	f.calls++
	f.network, f.target, f.id, f.text = network, target, id, text
	return &sdk.BrowserAskResult{MessageID: id, ThreadID: id, TargetPrincipalID: target}, nil
}
func (f *messagingFake) GetBrowserAsk(_ context.Context, network, id string) (*sdk.BrowserAskResult, error) {
	f.network, f.id = network, id
	return f.read, nil
}
func TestMessagingOnlyToolsAndTargetAuthority(t *testing.T) {
	f := &messagingFake{}
	b, err := New(f, Config{Network: testNetwork, MessagingTargets: []string{testTarget}})
	if err != nil {
		t.Fatal(err)
	}
	tools := b.Server().ListTools()
	if len(tools) != 4 || tools["pagnet_ask"].Tool.Name == "" {
		t.Fatal("messaging agent without capability lacks ASK tools")
	}
	if _, exists := tools["pagnet_invoke"]; exists {
		t.Fatal("messaging permission fabricated invocation authority")
	}
	for _, args := range []map[string]any{{"targetPrincipalId": testInvocation, "messageId": testInvocation, "text": "hello"}, {"targetPrincipalId": testTarget, "messageId": "bad", "text": "hello"}} {
		out, _ := tools["pagnet_ask"].Handler(context.Background(), request(args))
		if !out.IsError || f.calls != 0 {
			t.Fatal("unapproved or invalid ASK reached SDK")
		}
	}
	args := map[string]any{"targetPrincipalId": testTarget, "messageId": testInvocation, "text": "hello"}
	for i := 0; i < 2; i++ {
		out, _ := tools["pagnet_ask"].Handler(context.Background(), request(args))
		if out.IsError {
			t.Fatal("allowed ASK denied")
		}
	}
	if f.network != testNetwork || f.target != testTarget || f.id != testInvocation || f.calls != 2 {
		t.Fatal("retry changed network/target/message identity")
	}
	f.read = &sdk.BrowserAskResult{TargetPrincipalID: testInvocation}
	out, _ := tools["pagnet_ask_get"].Handler(context.Background(), request(map[string]any{"messageId": testInvocation, "targetPrincipalId": testTarget}))
	if !out.IsError {
		t.Fatal("foreign target result escaped device policy")
	}
}

func TestShortMessagingRequestKeysSurviveBridgeRestart(t *testing.T) {
	f := &messagingFake{}
	args := request(map[string]any{"targetPrincipalId": testTarget, "requestId": "travel-plan-1", "text": "hello"})
	var first string
	for i := 0; i < 2; i++ {
		b, err := New(f, Config{Network: testNetwork, MessagingTargets: []string{testTarget}})
		if err != nil {
			t.Fatal(err)
		}
		out, _ := b.Server().ListTools()["pagnet_ask"].Handler(context.Background(), args)
		if out.IsError {
			t.Fatal("short request key rejected")
		}
		if i == 0 {
			first = f.id
		} else if f.id != first {
			t.Fatal("bridge restart changed durable request identity")
		}
	}
	if first == "" || first == "travel-plan-1" {
		t.Fatal("short key not converted to internal identity")
	}
}
