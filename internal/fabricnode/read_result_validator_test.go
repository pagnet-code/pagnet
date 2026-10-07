package fabricnode

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func validatorFixture(t *testing.T) (*registry.Store, fabric.ExecutionContext, fabric.EndpointRef, fabric.Revision, fabric.EndpointRef) {
	t.Helper()
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "domain")
	p := fabric.Principal{Ref: "local:owner", Kind: "actor.human", Issuer: "local:os"}
	store, err := registry.Bootstrap(ctx, dir, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	owner, err := fabric.NewAuthenticatedContext(p, store.Namespace(), []byte("trusted validation fixture"))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := fabric.NewEndpointRef(store.AuthorityIdentity().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "actor.agent", Name: "Probe", Description: "Read validation probe", Bindings: []fabric.BindingSummary{{ID: "local", Protocol: "local.native", Version: "1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	offerRef, err := ref.WithOfferID(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutOffer(ctx, owner, fabric.OfferDescriptor{Ref: offerRef, Name: "Probe offer", BindingID: "local", InputSchema: json.RawMessage(`{"type":"object"}`)}, ""); err != nil {
		t.Fatal(err)
	}
	return store, owner, ref, revision, offerRef
}

func wantProtocol(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("validator passed, want protocol denial")
	}
	var typed *fabric.Error
	if !errors.As(err, &typed) || typed.Code != fabric.CodeProtocolError {
		t.Fatalf("want CodeProtocolError, got %v", err)
	}
}

func TestCurrentStateReadValidatorDiscover(t *testing.T) {
	ctx := context.Background()
	store, owner, ref, revision, _ := validatorFixture(t)
	v := currentStateReadValidator(store)
	held := node.Result{Discover: &fabric.DiscoverResult{Candidates: []fabric.Candidate{{Document: fabric.SearchDocument{Ref: ref}, Score: 1}}}}
	if err := v(ctx, fabric.ExecutionContext{}, fabric.Envelope{}, held); err != nil {
		t.Fatalf("current registry reference must validate: %v", err)
	}
	// A foreign-domain reference cannot be disclosed by interception.
	foreign, err := fabric.NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	foreignResult := node.Result{Discover: &fabric.DiscoverResult{Candidates: []fabric.Candidate{{Document: fabric.SearchDocument{Ref: foreign}, Score: 1}}}}
	wantProtocol(t, v(ctx, fabric.ExecutionContext{}, fabric.Envelope{}, foreignResult))
	// A retired reference is no longer held by the current registry.
	if _, err := store.Retire(ctx, owner, ref, revision); err != nil {
		t.Fatal(err)
	}
	wantProtocol(t, v(ctx, fabric.ExecutionContext{}, fabric.Envelope{}, held))
}

func TestCurrentStateReadValidatorDescribe(t *testing.T) {
	ctx := context.Background()
	store, _, ref, revision, offerRef := validatorFixture(t)
	v := currentStateReadValidator(store)
	current := node.Result{Describe: &fabric.DescribeResult{Descriptions: []fabric.Description{
		{Ref: ref, Endpoint: &fabric.EndpointDescriptor{Ref: ref, Revision: revision}},
		{Ref: offerRef, Offer: &fabric.OfferDescriptor{Ref: offerRef, Revision: "offer-current"}},
	}}}
	// The offer revision must be the actual current one for validation to pass.
	if offer, err := store.GetOffer(ctx, offerRef, ""); err != nil {
		t.Fatal(err)
	} else {
		current.Describe.Descriptions[1].Offer.Revision = offer.Revision
	}
	if err := v(ctx, fabric.ExecutionContext{}, fabric.Envelope{}, current); err != nil {
		t.Fatalf("current registry state must validate: %v", err)
	}
	stale := node.Result{Describe: &fabric.DescribeResult{Descriptions: []fabric.Description{
		{Ref: ref, Endpoint: &fabric.EndpointDescriptor{Ref: ref, Revision: "stale-revision"}},
	}}}
	wantProtocol(t, v(ctx, fabric.ExecutionContext{}, fabric.Envelope{}, stale))
	// A missing target is part of the wire contract: per-selection errors pass.
	foreign, err := fabric.NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	absent := node.Result{Describe: &fabric.DescribeResult{Descriptions: []fabric.Description{
		{Ref: foreign, Error: fabric.NewError(fabric.CodeNotFound, "reference not found")},
	}}}
	if err := v(ctx, fabric.ExecutionContext{}, fabric.Envelope{}, absent); err != nil {
		t.Fatalf("per-selection describe errors are contract, not denial: %v", err)
	}
	// A disclosed entry carrying neither descriptor nor error is a denial.
	empty := node.Result{Describe: &fabric.DescribeResult{Descriptions: []fabric.Description{{Ref: ref}}}}
	wantProtocol(t, v(ctx, fabric.ExecutionContext{}, fabric.Envelope{}, empty))
	// A result carrying neither operation payload is a denial.
	wantProtocol(t, v(ctx, fabric.ExecutionContext{}, fabric.Envelope{}, node.Result{}))
}
