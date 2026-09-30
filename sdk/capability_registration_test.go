package sdk

import (
	"context"
	"encoding/json"
	"testing"
)

func TestInvalidCapabilityPreservesLiveRegistration(t *testing.T) {
	fs := newFakeServer(t)
	network := fs.createNetwork("capability-validation", true)
	id, credential := fs.createPrincipal("service", "capability-target", network)
	target := mustConnect(t, fs, credential, t.TempDir())
	waitForCryptoReady(t, fs, id)
	svc := target.Service("target")
	if err := svc.Handle("valid", func(context.Context, *Invocation) (any, error) { return map[string]any{"ok": true}, nil }); err != nil {
		t.Fatal(err)
	}
	waitFor(t, DefaultInvokeTimeout, "promoted valid capability registration", func() bool {
		epID := target.EndpointID()
		fs.mu.Lock()
		defer fs.mu.Unlock()
		ep := fs.endpoints[epID]
		return target.connected.Load() && ep != nil && ep.online && fs.cryptoReady[epID] && hasCapability(ep.capabilities, "valid")
	})
	ep := target.EndpointID()
	target.handlerMu.RLock()
	revision := target.capsRevision
	target.handlerMu.RUnlock()
	for _, cap := range []Capability{{ID: "valid", InputSchema: json.RawMessage(`{"type":`)}, {ID: "valid", OutputSchema: json.RawMessage(`{"type":"unknown-type"}`)}, {ID: "valid", Metadata: map[string]any{"unsupported": make(chan int)}}} {
		if err := svc.Capability(cap); err == nil {
			t.Fatal("invalid descriptor accepted")
		}
	}
	if target.EndpointID() != ep || !target.connected.Load() {
		t.Fatal("invalid descriptor disconnected working endpoint")
	}
	target.handlerMu.RLock()
	defer target.handlerMu.RUnlock()
	if target.capsRevision != revision || len(target.caps["valid"].capability.InputSchema) != 0 {
		t.Fatal("invalid descriptor changed working registry")
	}
}
