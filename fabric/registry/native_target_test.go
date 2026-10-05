package registry

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestNativeSelectedOfferExactSchemaAndCurrentBinding(t *testing.T) {
	s, owner, scope, _ := nativeFixture(t)
	ref, err := scope.Endpoint.WithOfferID([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	schema := json.RawMessage(`{"type":"object","properties":{"n":{"const":9007199254740993123456789}},"required":["n"],"additionalProperties":false}`)
	offer := fabric.OfferDescriptor{Ref: ref, Name: "Exact judgment", BindingID: scope.BindingID, InputSchema: schema}
	revision, err := s.PutOffer(context.Background(), owner, offer, "")
	if err != nil {
		t.Fatal(err)
	}
	good := json.RawMessage(`{"n":9007199254740993123456789}`)
	var escaped *AuthorityTx
	verify := func(target fabric.EndpointRef, rev fabric.Revision, input json.RawMessage) error {
		prepared, err := s.PrepareInvocationTarget(context.Background(), target, rev, input)
		if err != nil {
			return err
		}
		return s.WithNativeAuthority(context.Background(), owner, scope, func(tx *AuthorityTx) error {
			escaped = tx
			got, err := tx.VerifyInvocationTarget(target, rev, input, prepared)
			if err == nil && target.IsOffer() && got != sha256.Sum256(schema) {
				t.Fatal("wrong exact schema commitment")
			}
			return err
		})
	}
	if err = verify(ref, revision, good); err != nil {
		t.Fatal(err)
	}
	if _, err = escaped.VerifyInvocationTarget(ref, revision, good); err == nil {
		t.Fatal("escaped transaction admitted")
	}
	for _, bad := range []json.RawMessage{[]byte(`{"n":9007199254740993123456790}`), []byte(`{"n":9007199254740993123456789,"extra":true}`), []byte(`{"n":1,"n":9007199254740993123456789}`)} {
		if verify(ref, revision, bad) == nil {
			t.Fatal("malformed or precision-changed input admitted")
		}
	}
	if verify(ref, "stale", good) == nil {
		t.Fatal("stale offer admitted")
	}
	if _, err = s.RetireOffer(context.Background(), owner, ref, revision); err != nil {
		t.Fatal(err)
	}
	if verify(ref, revision, good) == nil {
		t.Fatal("retired offer admitted")
	}
}

func TestNativeSelectedOfferCannotLoadExternalSchema(t *testing.T) {
	s, owner, scope, _ := nativeFixture(t)
	for i, schema := range []string{`{"$ref":"file:///etc/passwd"}`, `{"$ref":"https://invalid.example/schema"}`} {
		ref, err := scope.Endpoint.WithOfferID([]byte(strings.Repeat(string(rune('a'+i)), 32)))
		if err != nil {
			t.Fatal(err)
		}
		revision, err := s.PutOffer(context.Background(), owner, fabric.OfferDescriptor{Ref: ref, Name: "Self-contained only", BindingID: scope.BindingID, InputSchema: json.RawMessage(schema)}, "")
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.PrepareInvocationTarget(context.Background(), ref, revision, []byte(`{}`))
		if err == nil {
			t.Fatal("external schema admitted")
		}
	}
}

func TestNativeSelectedOfferPreparedInputCannotSurviveMutationOrSubstitution(t *testing.T) {
	s, owner, scope, _ := nativeFixture(t)
	ref, _ := scope.Endpoint.WithOfferID([]byte(strings.Repeat("p", 32)))
	offer := fabric.OfferDescriptor{Ref: ref, Name: "Prepared", BindingID: scope.BindingID, InputSchema: json.RawMessage(`{"type":"integer"}`)}
	rev, err := s.PutOffer(context.Background(), owner, offer, "")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := s.PrepareInvocationTarget(context.Background(), ref, rev, []byte(`1`))
	if err != nil {
		t.Fatal(err)
	}
	check := func(revision fabric.Revision, payload json.RawMessage) error {
		return s.WithNativeAuthority(context.Background(), owner, scope, func(tx *AuthorityTx) error {
			_, err := tx.VerifyInvocationTarget(ref, revision, payload, prepared)
			return err
		})
	}
	if check(rev, []byte(`2`)) == nil {
		t.Fatal("validated input substituted under transaction")
	}
	offer.Name = "Changed"
	next, err := s.PutOffer(context.Background(), owner, offer, rev)
	if err != nil {
		t.Fatal(err)
	}
	if check(rev, []byte(`1`)) == nil || check(next, []byte(`1`)) == nil {
		t.Fatal("prepared old offer admitted after registry mutation")
	}
	// No partial authority evidence is committed when verification rejects.
	if nativeVersion(t, s) != 1 {
		t.Fatal("rejected preparation created authority evidence")
	}
}

func TestNativeSelectedOfferCannotBorrowOtherParentOrPublishedBinding(t *testing.T) {
	s, owner, scope, _ := nativeFixture(t)
	ctx := context.Background()
	descriptor, err := s.GetEndpoint(ctx, scope.Endpoint, scope.ExpectedRevision)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Revision = ""
	descriptor.Bindings = append(descriptor.Bindings, fabric.BindingSummary{ID: "other", Protocol: "local.native", Version: "1"})
	next, err := s.Update(ctx, owner, fabric.RegistryUpdate{Descriptor: descriptor, ExpectedRevision: scope.ExpectedRevision})
	if err != nil {
		t.Fatal(err)
	}
	scope.ExpectedRevision = next
	otherEndpoint := endpoint(t, s)
	if _, err = s.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: otherEndpoint}); err != nil {
		t.Fatal(err)
	}
	for i, parent := range []fabric.EndpointRef{scope.Endpoint, otherEndpoint.Ref} {
		ref, _ := parent.WithOfferID([]byte(strings.Repeat(string(rune('u'+i)), 32)))
		binding := "other"
		if i == 1 {
			binding = "local"
		}
		rev, err := s.PutOffer(ctx, owner, fabric.OfferDescriptor{Ref: ref, Name: "Different ownership", BindingID: binding, InputSchema: json.RawMessage(`{"type":"object"}`)}, "")
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := s.PrepareInvocationTarget(ctx, ref, rev, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		err = s.WithNativeAuthority(ctx, owner, scope, func(tx *AuthorityTx) error {
			_, err := tx.VerifyInvocationTarget(ref, rev, []byte(`{}`), prepared)
			return err
		})
		if err == nil {
			t.Fatal("other offer parent/binding borrowed current native authority")
		}
	}
}
