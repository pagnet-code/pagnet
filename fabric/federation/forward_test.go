package federation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

// This is an explicit cryptographic unit fixture, NOT the actual Store signer
// or a root-issued peer-certificate integration claim. Production positive
// composition must exercise the actual same-store engine-authorized signer.
type forwardUnitGate struct {
	local, remote PeerBinding
	revoked       bool
	source        Config
}

func (g *forwardUnitGate) WithCurrent(ctx context.Context, local, remote PeerBinding, f func(context.Context) error) error {
	if g.revoked || !((reflect.DeepEqual(local, g.local) && reflect.DeepEqual(remote, g.remote)) || (reflect.DeepEqual(local, g.remote) && reflect.DeepEqual(remote, g.local))) {
		return authError()
	}
	return f(ctx)
}
func forwardUnitFixture(t *testing.T) (Config, ForwardBundle, ed25519.PrivateKey, *forwardUnitGate) {
	t.Helper()
	a, b, _ := cryptoFixture(t)
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	a.Local.Authority.PublicKey = public
	a.Local.Authority.Namespace, e = fabric.DomainNamespace(public)
	if e != nil {
		t.Fatal(e)
	}
	b.Remote = a.Local
	g := &forwardUnitGate{local: b.Local, remote: b.Remote}
	b.Trust = g
	a.Remote = b.Local
	a.Trust = g
	g.source = a
	now := time.Now().UTC()
	deadline := now.Add(time.Minute)
	p := fabric.Principal{Ref: "actor://exact-origin", Kind: "actor.test", Issuer: a.Local.Authority.Namespace}
	original := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "actual-unit-invocation", Operation: fabric.OperationDiscover, Principal: p, Source: p.Ref, CreatedAt: now.Add(-time.Second), Payload: json.RawMessage(`{"query":"private search","limit":5,"n":9007199254740993123456789}`), Context: fabric.EnvelopeContext{Origin: p.Ref, ParentID: "original-parent", Ancestry: []string{"accepted-ancestor"}, Hops: 2, ExtensionChain: []string{"extension.previous"}, TriggerLineage: []string{"trigger.previous"}, IdempotencyKey: "original-replay", Deadline: &deadline}}
	forwarded := original
	forwarded.Context.Hops++
	forwarded.Context.ExtensionChain = []string{"extension.previous", "extension.current"}
	forwarded.Payload = json.RawMessage(`{"query":"engine finalized query","limit":5,"n":9007199254740993123456789}`)
	ob, _ := json.Marshal(original)
	fb, _ := json.Marshal(forwarded)
	proof := fabric.ForwardFrame{SourceDomain: b.Remote.Authority.Namespace, SourceStoreID: b.Remote.Authority.StoreID, SourceKeyRevision: b.Remote.Authority.KeyRevision, DestinationDomain: b.Local.Authority.Namespace, DestinationStoreID: b.Local.Authority.StoreID, SourcePeerBindingDigest: b.Remote.BindingDigest, DestinationPeerBindingDigest: b.Local.BindingDigest, Principal: p, Operation: original.Operation, InvocationID: original.ID, ReplayID: original.Context.IdempotencyKey, OriginalEnvelopeDigest: sha256.Sum256(ob), ForwardedEnvelopeDigest: sha256.Sum256(fb), OriginalProvenance: contextProvenance(original.Context), ForwardedProvenance: contextProvenance(forwarded.Context), IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano), Deadline: deadline.Format(time.RFC3339Nano), BindingProfile: Profile}
	bundle := ForwardBundle{Original: ob, Forwarded: fb, Proof: fabric.SignedForwardProof{Frame: proof}}
	signUnitBundle(t, &bundle, private)
	return b, bundle, private, g
}
func signUnitBundle(t *testing.T, b *ForwardBundle, key ed25519.PrivateKey) {
	t.Helper()
	b.Proof.Frame.OriginalEnvelopeDigest = sha256.Sum256(b.Original)
	b.Proof.Frame.ForwardedEnvelopeDigest = sha256.Sum256(b.Forwarded)
	raw, e := b.Proof.Frame.SigningBytes()
	if e != nil {
		t.Fatal(e)
	}
	b.Proof.Signature = ed25519.Sign(key, raw)
}
func editUnitEnvelope(t *testing.T, b *ForwardBundle, original bool, edit func(*fabric.Envelope)) {
	t.Helper()
	raw := &b.Forwarded
	if original {
		raw = &b.Original
	}
	var env fabric.Envelope
	if e := fabric.DecodeJSON(*raw, &env); e != nil {
		t.Fatal(e)
	}
	edit(&env)
	var e error
	*raw, e = json.Marshal(env)
	if e != nil {
		t.Fatal(e)
	}
}
func TestForwardVerifierUnitExactSignedEngineContextAndImmutableSystemFields(t *testing.T) {
	c, b, _, _ := forwardUnitFixture(t)
	called := false
	e := VerifyForwardBundle(context.Background(), c, b, VerifyLimits{MaxLifetime: time.Minute, MaxClockSkew: time.Second}, func(ctx context.Context, caller fabric.ExecutionContext) error {
		called = true
		env, e := caller.DecodeVerifiedEnvelope(b.Forwarded, c.Local.Authority.Namespace)
		if e != nil || env.ID != b.Proof.Frame.InvocationID || caller.PrincipalView() != b.Proof.Frame.Principal || caller.ProvenanceView().Hops != 3 || !bytes.Contains(env.Payload, []byte("9007199254740993123456789")) {
			t.Fatal("forwarded identity/precision lost", e)
		}
		return nil
	})
	if e != nil || !called {
		t.Fatal("explicit signed unit proof rejected", e)
	}
}
func TestForwardVerifierUnitRejectsResignedSystemAndLineageMutation(t *testing.T) {
	changes := map[string]func(*testing.T, *ForwardBundle){
		"principal": func(t *testing.T, b *ForwardBundle) {
			editUnitEnvelope(t, b, false, func(e *fabric.Envelope) { e.Principal.Issuer = "other.issuer" })
		},
		"id": func(t *testing.T, b *ForwardBundle) {
			editUnitEnvelope(t, b, false, func(e *fabric.Envelope) { e.ID = "another-invocation" })
		},
		"source": func(t *testing.T, b *ForwardBundle) {
			editUnitEnvelope(t, b, false, func(e *fabric.Envelope) { e.Source = "another-source" })
		},
		"created": func(t *testing.T, b *ForwardBundle) {
			editUnitEnvelope(t, b, false, func(e *fabric.Envelope) { e.CreatedAt = e.CreatedAt.Add(time.Second) })
		},
		"trace": func(t *testing.T, b *ForwardBundle) {
			editUnitEnvelope(t, b, false, func(e *fabric.Envelope) { e.Trace.Baggage = "mutated" })
		},
		"replay": func(t *testing.T, b *ForwardBundle) {
			editUnitEnvelope(t, b, false, func(e *fabric.Envelope) { e.Context.IdempotencyKey = "new-replay" })
		},
		"deadline": func(t *testing.T, b *ForwardBundle) {
			editUnitEnvelope(t, b, false, func(e *fabric.Envelope) { d := e.Context.Deadline.Add(-time.Second); e.Context.Deadline = &d })
		},
		"wire-lineage": func(t *testing.T, b *ForwardBundle) {
			editUnitEnvelope(t, b, false, func(e *fabric.Envelope) { e.Context.Hops++ })
		},
		"hop-reset": func(t *testing.T, b *ForwardBundle) {
			editUnitEnvelope(t, b, false, func(e *fabric.Envelope) { e.Context.Hops = 0 })
			b.Proof.Frame.ForwardedProvenance.Hops = 0
		},
		"hop-skip": func(t *testing.T, b *ForwardBundle) {
			editUnitEnvelope(t, b, false, func(e *fabric.Envelope) { e.Context.Hops++ })
			b.Proof.Frame.ForwardedProvenance.Hops++
		},
		"ancestor-reset": func(t *testing.T, b *ForwardBundle) {
			editUnitEnvelope(t, b, false, func(e *fabric.Envelope) { e.Context.Ancestry = nil })
			b.Proof.Frame.ForwardedProvenance.Ancestry = nil
		},
		"trigger-reset": func(t *testing.T, b *ForwardBundle) {
			editUnitEnvelope(t, b, false, func(e *fabric.Envelope) { e.Context.TriggerLineage = nil })
			b.Proof.Frame.ForwardedProvenance.TriggerLineage = nil
		},
		"chain-reset": func(t *testing.T, b *ForwardBundle) {
			editUnitEnvelope(t, b, false, func(e *fabric.Envelope) { e.Context.ExtensionChain = []string{"extension.current"} })
			b.Proof.Frame.ForwardedProvenance.ExtensionChain = []string{"extension.current"}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c, b, key, _ := forwardUnitFixture(t)
			change(t, &b)
			signUnitBundle(t, &b, key)
			called := false
			e := VerifyForwardBundle(context.Background(), c, b, VerifyLimits{MaxLifetime: time.Minute}, func(context.Context, fabric.ExecutionContext) error { called = true; return nil })
			if e == nil || called {
				t.Fatal("resigned immutable mutation authenticated")
			}
		})
	}
}
func TestForwardVerifierUnitRefusesSignatureExpiryAndCurrentTrust(t *testing.T) {
	for _, change := range []string{"signature", "expired", "future", "binding", "store", "key-revision", "revoked"} {
		t.Run(change, func(t *testing.T) {
			c, b, key, g := forwardUnitFixture(t)
			switch change {
			case "signature":
				b.Proof.Signature[0] ^= 1
			case "expired":
				b.Proof.Frame.IssuedAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
				b.Proof.Frame.ExpiresAt = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
				signUnitBundle(t, &b, key)
			case "future":
				b.Proof.Frame.IssuedAt = time.Now().UTC().Add(10 * time.Second).Format(time.RFC3339Nano)
				b.Proof.Frame.ExpiresAt = time.Now().UTC().Add(20 * time.Second).Format(time.RFC3339Nano)
				signUnitBundle(t, &b, key)
			case "binding":
				b.Proof.Frame.SourcePeerBindingDigest[0] ^= 1
				signUnitBundle(t, &b, key)
			case "store":
				b.Proof.Frame.SourceStoreID = string(bytes.Repeat([]byte("a"), 64))
				signUnitBundle(t, &b, key)
			case "key-revision":
				b.Proof.Frame.SourceKeyRevision++
				signUnitBundle(t, &b, key)
			case "revoked":
				g.revoked = true
			}
			called := false
			e := VerifyForwardBundle(context.Background(), c, b, VerifyLimits{MaxLifetime: time.Minute}, func(context.Context, fabric.ExecutionContext) error { called = true; return nil })
			if e == nil || called {
				t.Fatal("untrusted forward entered admission")
			}
		})
	}
}
