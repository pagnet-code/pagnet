package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

type forwardGateFunc func(context.Context, ForwardFacts, func(context.Context) error) error

func (f forwardGateFunc) WithForward(c context.Context, facts ForwardFacts, next func(context.Context) error) error {
	return f(c, facts, next)
}

func actualForwardFixture(t *testing.T) (*Store, fabric.ExecutionContext, fabric.ExecutionContext, []byte, []byte, fabric.ForwardFrame) {
	t.Helper()
	s, owner, _ := fixture(t)
	destination, _, _ := fixture(t)
	ref := endpoint(t, destination).Ref
	now := time.Now().UTC()
	deadline := now.Add(time.Hour)
	before := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "original-federated-call", Operation: fabric.OperationInvoke, Principal: testOwner, Source: testOwner.Ref, Target: &ref, ExpectedRevision: "known-remote-revision", CreatedAt: now, Payload: json.RawMessage(`{"input":"original","n":900719925474099312345}`), Context: fabric.EnvelopeContext{Origin: testOwner.Ref, Deadline: &deadline}}
	original, _ := json.Marshal(before)
	caller, e := fabric.NewAuthenticatedContext(testOwner, s.Namespace(), original)
	if e != nil {
		t.Fatal(e)
	}
	after := before
	after.Payload = json.RawMessage(`{"input":"prepared","n":900719925474099312345}`)
	after.Context.Hops = 1
	after.Context.ExtensionChain = []string{"acme.security"}
	forwarded, _ := json.Marshal(after)
	root := s.AuthorityIdentity()
	remote := destination.AuthorityIdentity()
	binding := sha256.Sum256([]byte("explicit-fixture-peer-binding"))
	f := fabric.ForwardFrame{SourceDomain: root.Namespace, SourceStoreID: root.StoreID, SourceKeyRevision: root.KeyRevision, DestinationDomain: remote.Namespace, DestinationStoreID: remote.StoreID, SourcePeerBindingDigest: binding, DestinationPeerBindingDigest: binding, Principal: testOwner, Operation: before.Operation, InvocationID: before.ID, ReplayID: "stable-original-replay", OriginalEnvelopeDigest: sha256.Sum256(original), ForwardedEnvelopeDigest: sha256.Sum256(forwarded), OriginalProvenance: forwardProvenance(before), ForwardedProvenance: forwardProvenance(after), Target: &ref, ExpectedRevision: after.ExpectedRevision, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), Deadline: deadline.Format(time.RFC3339Nano), BindingProfile: fabric.ForwardBindingProfile}
	return s, owner, caller, original, forwarded, f
}

func TestSignForwardUsesActualRetainedRootAndExactCallerBytes(t *testing.T) {
	s, owner, caller, original, forwarded, frame := actualForwardFixture(t)
	gate := forwardGateFunc(func(c context.Context, _ ForwardFacts, next func(context.Context) error) error { return next(c) })
	proof, e := s.SignForwardExact(t.Context(), owner, caller, original, forwarded, frame, gate)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := proof.Frame.SigningBytes()
	if e != nil || !ed25519.Verify(s.AuthorityIdentity().PublicKey, raw, proof.Signature) {
		t.Fatal("retained root did not sign exact forwarding proof", e)
	}
	changed := append(append([]byte(nil), original...), ' ')
	if _, e = s.SignForwardExact(t.Context(), owner, caller, changed, forwarded, frame, gate); e == nil {
		t.Fatal("caller context authenticated different original bytes")
	}
	var final fabric.Envelope
	_ = json.Unmarshal(forwarded, &final)
	final.Context.ParentID = "invented-parent"
	bad, _ := json.Marshal(final)
	badFrame := frame
	badFrame.ForwardedEnvelopeDigest = sha256.Sum256(bad)
	badFrame.ForwardedProvenance = forwardProvenance(final)
	if _, e = s.SignForwardExact(t.Context(), owner, caller, original, bad, badFrame, gate); e == nil {
		t.Fatal("root signed erased or invented lineage")
	}
	foreign := testOwner
	foreign.Kind = "actor.other"
	other, _ := fabric.NewAuthenticatedContext(foreign, s.Namespace(), original)
	if _, e = s.SignForwardExact(t.Context(), owner, other, original, forwarded, frame, gate); e == nil {
		t.Fatal("changed full caller identity signed")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = s.SignForwardExact(t.Context(), owner, caller, original, forwarded, frame, gate); e == nil {
		t.Fatal("closed historical root signed")
	}
}

func TestSignForwardRejectsMissingRepeatedChangedAndEscapedTrustGate(t *testing.T) {
	s, owner, caller, original, forwarded, frame := actualForwardFixture(t)
	var escaped func(context.Context) error
	for name, gate := range map[string]ForwardGate{
		"missing":    nil,
		"noCallback": forwardGateFunc(func(context.Context, ForwardFacts, func(context.Context) error) error { return nil }),
		"late": forwardGateFunc(func(_ context.Context, _ ForwardFacts, next func(context.Context) error) error {
			escaped = next
			return nil
		}),
		"rejectAfterSigning": forwardGateFunc(func(c context.Context, _ ForwardFacts, next func(context.Context) error) error {
			if e := next(c); e != nil {
				return e
			}
			return errors.New("current peer revoked")
		}),
		"repeat": forwardGateFunc(func(c context.Context, _ ForwardFacts, next func(context.Context) error) error {
			if e := next(c); e != nil {
				return e
			}
			_ = next(c)
			return nil
		}),
		"modifyFacts": forwardGateFunc(func(c context.Context, f ForwardFacts, next func(context.Context) error) error {
			f.Original[0] ^= 1
			return next(c)
		}),
	} {
		t.Run(name, func(t *testing.T) {
			proof, e := s.SignForwardExact(t.Context(), owner, caller, original, forwarded, frame, gate)
			if e == nil || len(proof.Signature) != 0 {
				t.Fatal("bad trust gate released signed authority", e)
			}
		})
	}
	if escaped == nil || escaped(t.Context()) == nil {
		t.Fatal("late gate signed after closure")
	}
}
