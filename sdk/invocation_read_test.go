package sdk

import (
	"context"
	"strings"
	"testing"
)

func TestGetInvocationReadsDurableEncryptedResult(t *testing.T) {
	fs := newFakeServer(t)
	network := fs.createNetwork("net", true)
	callerID, callerCred := fs.createPrincipal("agent", "caller", network)
	targetID, targetCred := fs.createPrincipal("service", "target", network)
	target := mustConnect(t, fs, targetCred, t.TempDir())
	waitForCryptoReady(t, fs, targetID)
	if err := target.Service("svc").Handle("hello.say", func(_ context.Context, in *Invocation) (any, error) {
		return map[string]any{"text": "completed result"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	caller := mustConnect(t, fs, callerCred, t.TempDir())
	waitForCryptoReady(t, fs, callerID)
	original, err := caller.Invoke(testCtx(t), Invocation{NetworkID: network, TargetPrincipalID: targetID, CapabilityID: "hello.say", Input: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := caller.GetInvocation(testCtx(t), network, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "completed" || got.TargetPrincipalID != targetID || got.Output.(map[string]any)["text"] != "completed result" {
		t.Fatalf("unexpected result %#v", got)
	}
	if _, err := target.GetInvocation(testCtx(t), network, original.ID); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("target read caller outcome: %v", err)
	}
	fs.mu.Lock()
	fs.invocations[original.ID].output.AAD.ObjectID = "unrelated-object"
	fs.mu.Unlock()
	if _, err := caller.GetInvocation(testCtx(t), network, original.ID); err == nil || !strings.Contains(err.Error(), "AAD routing mismatch") {
		t.Fatalf("accepted substituted result: %v", err)
	}

}
