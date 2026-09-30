package externalbridge

import (
	"context"
	"encoding/json"
	"testing"
)

func TestHostedDeviceBridgeRejectsUnexpectedRemoteSurface(t *testing.T) {
	b, err := New(&fakeClient{}, Config{Network: testNetwork})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`[{"jsonrpc":"2.0","method":"ping"}]`, `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"pagnet_invoke"}}`, `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec"}}`, `{"jsonrpc":"2.0","method":"resources/read"}`} {
		if _, err := b.HandleHosted(context.Background(), json.RawMessage(raw)); err == nil {
			t.Fatalf("remote surface accepted: %s", raw)
		}
	}
	raw, err := b.HandleHosted(context.Background(), json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil || !json.Valid(raw) {
		t.Fatalf("tools list: %s %v", raw, err)
	}
}
