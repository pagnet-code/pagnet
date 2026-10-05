package mcpbridge

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
)

type replayDispatcher struct {
	closed atomic.Int32
	calls  int
}
type associatedFrames struct {
	*fixtureStream
	association fabric.ReplayAssociation
}

func (s *associatedFrames) ReplayAssociation() *fabric.ReplayAssociation {
	a := s.association.Clone()
	return &a
}
func (d *replayDispatcher) Invoke(ctx context.Context, c fabric.ExecutionContext, r fabric.InvokeRequest) (fabric.InvocationStream, error) {
	d.calls++
	_, o, f, ok := node.FinalizedRequestFromContext(ctx)
	if !ok {
		panic("missing trusted request")
	}
	h := sha256.Sum256([]byte("retained receipt"))
	a := fabric.ReplayAssociation{Version: 1, AuthorityNamespace: r.Target.Domain(), AuthorityStoreID: "actual-store", AuthorityKeyRevision: 1, Principal: c.PrincipalView(), RequestID: r.InvocationID, ExecutionID: "original-execution", Target: r.Target, ExpectedRevision: r.ExpectedRevision, OriginalRequestSHA: sha256.Sum256(o), FinalizedRequestSHA: sha256.Sum256(f), InputSHA: sha256.Sum256(r.Input), IdempotencySHA: sha256.Sum256([]byte(r.IdempotencyKey)), BindingFingerprint: h, OriginalReceiptSHA: h, Proof: []byte("retained signed alias")}
	return &associatedFrames{fixtureStream: &fixtureStream{id: a.ExecutionID, closed: &d.closed, done: make(chan struct{})}, association: a}, nil
}

type replayVerifier struct{}

func (replayVerifier) VerifyReplay(_ context.Context, _ fabric.ExecutionContext, _ fabric.ReplayRequest, _ fabric.ReplayAssociation) error {
	return nil
}

// The official transport fixture tests presentation/cursor invariants. Real
// same-root signed alias/authorization verification belongs to service ledger
// conformance; this trusted verifier is intentionally only a fixture port.
func TestOfficialMCPReplayPagesKeepOriginalFramesAndExposeAssociation(t *testing.T) {
	b, client, binder, _, _, target := newBridgeFixture(t, "2025-11-25")
	d := &replayDispatcher{}
	service, err := node.New(node.Config{Audience: "fixture-node", Authenticator: fixtureAuth{public: binder.factory.key.Public().(ed25519.PublicKey), principal: binder.factory.principal}, Dispatcher: d, ReplayVerifier: replayVerifier{}})
	if err != nil {
		t.Fatal(err)
	}
	b.config.Service = service
	start := pageResult(t, callBridge(t, client, "invoke", map[string]any{"target": target.String(), "revision": "remembered", "input": map[string]any{}, "idempotencyKey": "same-operation"}))
	if start.Replay == nil || start.Replay.RequestID != "server-owned-call" || start.Replay.ExecutionID != "original-execution" || start.Frames[0].InvocationID != "original-execution" {
		t.Fatal("association missing or source relabeled", start)
	}
	control := map[string]any{"stream": map[string]any{"handle": start.Handle, "afterSequence": "0"}}
	next := pageResult(t, callBridge(t, client, "invoke", control))
	retry := pageResult(t, callBridge(t, client, "invoke", control))
	a, _ := json.Marshal(next)
	z, _ := json.Marshal(retry)
	if string(a) != string(z) || next.Replay == nil || next.Frames[0].InvocationID != "original-execution" || d.calls != 1 {
		t.Fatal("retry changed source/association or resubmitted", next, retry, d.calls)
	}
	final := pageResult(t, callBridge(t, client, "invoke", map[string]any{"stream": map[string]any{"handle": start.Handle, "afterSequence": "1"}}))
	if final.Replay == nil || final.More || final.Frames[0].Kind != fabric.FrameComplete || final.Frames[0].InvocationID != "original-execution" {
		t.Fatal("lost actual source completion", final)
	}
}
