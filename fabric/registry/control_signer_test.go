package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

type controlGateFunc func(context.Context, ControlFacts, func(context.Context) error) error

func (f controlGateFunc) WithControl(c context.Context, x ControlFacts, n func(context.Context) error) error {
	return f(c, x, n)
}
func TestActualRootControlSignerRequiresFreshExactControlAuthentication(t *testing.T) {
	s, owner, historical, _, _, f := actualForwardFixture(t)
	payload := []byte(`{"credit":1}`)
	now := time.Now().UTC()
	frame := fabric.ControlFrame{ProtocolVersion: "1", SourceDomain: f.SourceDomain, SourceStoreID: f.SourceStoreID, SourceKeyRevision: f.SourceKeyRevision, DestinationDomain: f.DestinationDomain, DestinationStoreID: f.DestinationStoreID, SourcePeerBindingDigest: f.SourcePeerBindingDigest, DestinationPeerBindingDigest: f.DestinationPeerBindingDigest, Principal: f.Principal, OriginalPrincipal: f.Principal, InvocationID: f.InvocationID, ReceiptDigest: f.OriginalEnvelopeDigest, AttemptID: "actual-attempt", Action: "pull", PayloadDigest: sha256.Sum256(payload), ReplayID: "fresh-control", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano), BindingProfile: fabric.ForwardBindingProfile}
	raw, err := frame.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	caller, err := fabric.NewAuthenticatedContext(testOwner, s.Namespace(), raw)
	if err != nil {
		t.Fatal(err)
	}
	gate := controlGateFunc(func(c context.Context, _ ControlFacts, next func(context.Context) error) error { return next(c) })
	proof, err := s.SignControlExact(t.Context(), owner, caller, payload, frame, gate)
	if err != nil || !ed25519.Verify(s.AuthorityIdentity().PublicKey, raw, proof.Signature) {
		t.Fatal("actual root control signing failed", err)
	}
	if _, err = s.SignControlExact(t.Context(), owner, historical, payload, frame, gate); err == nil {
		t.Fatal("original invocation authorized fresh control")
	}
	changed := frame
	changed.Action = "cancel"
	if _, err = s.SignControlExact(t.Context(), owner, caller, payload, changed, gate); err == nil {
		t.Fatal("changed control authenticated")
	}
	for name, g := range map[string]ControlGate{
		"missing":     nil,
		"no callback": controlGateFunc(func(context.Context, ControlFacts, func(context.Context) error) error { return nil }),
		"swallowed mutation": controlGateFunc(func(c context.Context, f ControlFacts, n func(context.Context) error) error {
			f.Payload[0] ^= 1
			_ = n(c)
			return nil
		}),
		"repeated": controlGateFunc(func(c context.Context, _ ControlFacts, n func(context.Context) error) error {
			_ = n(c)
			_ = n(c)
			return nil
		}),
	} {
		t.Run(name, func(t *testing.T) {
			p, e := s.SignControlExact(t.Context(), owner, caller, payload, frame, g)
			if e == nil || len(p.Signature) != 0 {
				t.Fatal("invalid gate released control proof", e)
			}
		})
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SignControlExact(t.Context(), owner, caller, payload, frame, gate); err == nil {
		t.Fatal("closed root signed control")
	}
}
