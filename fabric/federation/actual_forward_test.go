package federation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// This fixture uses the genuine SAME retained registry signer and current roots.
// The ingress ExecutionContexts and exchange certificate pins are explicitly
// trusted test ports, not a claim of product kernel/node/peer-store composition.
type actualForwardGate struct {
	a, b    Config
	current *testRootGate
}

func (g actualForwardGate) WithForward(ctx context.Context, f registry.ForwardFacts, step func(context.Context) error) error {
	if !checkPeer(g.a.Local) || !checkPeer(g.b.Local) || f.Frame.SourcePeerBindingDigest != g.a.Local.BindingDigest || f.Frame.DestinationPeerBindingDigest != g.b.Local.BindingDigest {
		return authError()
	}
	return g.current.WithCurrent(ctx, g.a.Local, g.b.Local, step)
}
func actualSignedForwardFixture(t *testing.T) (Config, Config, ForwardBundle) {
	t.Helper()
	a, b, g := cryptoFixture(t)
	now := time.Now().UTC()
	deadline := now.Add(time.Minute)
	p := fabric.Principal{Ref: "fixture-verified-actor", Kind: "actor.test", Issuer: a.Local.Authority.Namespace}
	original := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "actual-root-forward", Operation: fabric.OperationDiscover, Principal: p, Source: p.Ref, CreatedAt: now, Payload: json.RawMessage(`{"query":"private query","limit":4,"n":9007199254740993123456789}`), Context: fabric.EnvelopeContext{Origin: p.Ref, Deadline: &deadline, IdempotencyKey: "actual-root-forward"}}
	forwarded := original
	forwarded.Context.Hops = 1
	forwarded.Context.ExtensionChain = []string{"extension.source"}
	forwarded.Payload = json.RawMessage(`{"query":"finalized private query","limit":4,"n":9007199254740993123456789}`)
	raw, _ := json.Marshal(original)
	final, _ := json.Marshal(forwarded)
	caller, e := fabric.NewAuthenticatedContext(p, a.Local.Authority.Namespace, raw)
	if e != nil {
		t.Fatal(e)
	}
	owner, e := fabric.NewAuthenticatedContext(a.Local.Authority.Owner, a.Local.Authority.Namespace, []byte("explicit trusted operator fixture"))
	if e != nil {
		t.Fatal(e)
	}
	frame := fabric.ForwardFrame{SourceDomain: a.Local.Authority.Namespace, SourceStoreID: a.Local.Authority.StoreID, SourceKeyRevision: a.Local.Authority.KeyRevision, DestinationDomain: b.Local.Authority.Namespace, DestinationStoreID: b.Local.Authority.StoreID, SourcePeerBindingDigest: a.Local.BindingDigest, DestinationPeerBindingDigest: b.Local.BindingDigest, Principal: p, Operation: original.Operation, InvocationID: original.ID, ReplayID: original.Context.IdempotencyKey, OriginalEnvelopeDigest: sha256.Sum256(raw), ForwardedEnvelopeDigest: sha256.Sum256(final), OriginalProvenance: contextProvenance(original.Context), ForwardedProvenance: contextProvenance(forwarded.Context), IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano), Deadline: deadline.Format(time.RFC3339Nano), BindingProfile: Profile}
	proof, e := g.stores[0].SignForwardExact(context.Background(), owner, caller, raw, final, frame, actualForwardGate{a, b, g})
	if e != nil {
		t.Fatal("actual SAME-store forward signer", e)
	}
	return a, b, ForwardBundle{Original: raw, Forwarded: final, Proof: proof}
}
func TestActualRetainedRootSignerEncryptedRelayAndDestinationVerifier(t *testing.T) {
	a, b, bundle := actualSignedForwardFixture(t)
	left, relayLeft := net.Pipe()
	relayRight, right := net.Pipe()
	sourceDuplex, e := NewDuplex(context.Background(), a, boundedStream(t, left), 8<<20)
	if e != nil {
		t.Fatal(e)
	}
	destinationDuplex, e := NewDuplex(context.Background(), b, boundedStream(t, right), 8<<20)
	if e != nil {
		t.Fatal(e)
	}
	source, _ := NewForwardChannel(sourceDuplex)
	destination, _ := NewForwardChannel(destinationDuplex)
	t.Cleanup(func() { source.Close(); destination.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	relayDone := make(chan error, 1)
	spy := &relaySpy{PacketStream: boundedStream(t, relayRight)}
	go func() {
		relayDone <- RelayOpaque(ctx, boundedStream(t, relayLeft), spy, a.Channel, RelayLimits{MaxPackets: 16, MaxBytes: 1 << 20, Lifetime: 2 * time.Second})
	}()
	sent := make(chan error, 1)
	go func() { sent <- source.SendBundle(ctx, bundle) }()
	received, e := destination.ReceiveBundle(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-sent; e != nil {
		t.Fatal(e)
	}
	accepted := 0
	e = VerifyForwardBundle(ctx, b, received, VerifyLimits{MaxLifetime: time.Minute}, func(ctx context.Context, caller fabric.ExecutionContext) error {
		accepted++
		env, e := caller.DecodeVerifiedEnvelope(received.Forwarded, b.Local.Authority.Namespace)
		if e != nil || env.ID != bundle.Proof.Frame.InvocationID || caller.PrincipalView() != bundle.Proof.Frame.Principal || caller.ProvenanceView().Hops != 1 || !bytes.Contains(env.Payload, []byte("9007199254740993123456789")) {
			t.Fatal("actual root-forward context", e)
		}
		return nil
	})
	if e != nil || accepted != 1 {
		t.Fatal("actual root proof rejected", e)
	}
	spy.mu.Lock()
	for _, raw := range spy.records {
		if bytes.Contains(raw, []byte("private")) || bytes.Contains(raw, []byte(a.Local.Authority.Namespace)) || bytes.Contains(raw, []byte(bundle.Proof.Frame.Principal.Ref)) {
			t.Fatal("relay disclosed root/principal/query")
		}
	}
	spy.mu.Unlock()
	source.Close()
	select {
	case <-relayDone:
	case <-time.After(time.Second):
		t.Fatal("relay not joined")
	}
}
