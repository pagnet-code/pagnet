package fabricnode

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type routerProvider struct {
	calls int
	err   error
}

func (p *routerProvider) ResolveBinding(context.Context, fabric.ExecutionContext, fabric.EndpointDescriptor, fabric.BindingSummary, *fabric.OfferDescriptor) (fabric.EndpointAdapter, [32]byte, error) {
	p.calls++
	return routerAdapter{}, sha256.Sum256([]byte("actual-private-binding")), p.err
}

type routerAdapter struct{}

func (routerAdapter) Invoke(context.Context, fabric.ExecutionContext, fabric.EndpointDescriptor, fabric.InvokeRequest) (fabric.InvocationStream, error) {
	panic("selection executed endpoint")
}
func TestRouterSelectsExactPublishedBindingWithoutFallbackOrExecution(t *testing.T) {
	owner := fabric.Principal{Ref: "local:owner", Kind: "actor.human", Issuer: "local:os"}
	store, err := registry.Bootstrap(t.Context(), filepath.Join(t.TempDir(), "node"), owner)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	caller, err := fabric.NewAuthenticatedContext(owner, store.Namespace(), []byte("actual registration fixture"))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := fabric.NewEndpointRef(store.AuthorityIdentity().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := fabric.EndpointDescriptor{Ref: ref, Kind: "acme.custom", Name: "Private endpoint", Description: "Caller-selected operation", Bindings: []fabric.BindingSummary{{ID: "first", Protocol: "acme.first", Version: "1"}, {ID: "second", Protocol: "acme.second", Version: "1"}}}
	revision, err := store.Register(t.Context(), caller, fabric.RegistryUpdate{Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err = store.GetEndpoint(t.Context(), ref, revision)
	if err != nil {
		t.Fatal(err)
	}
	first := &routerProvider{err: fabric.NewError(fabric.CodeTargetUnavailable, "selected unavailable")}
	second := &routerProvider{}
	router, err := NewRouter(map[BindingProtocol]BindingProvider{{"acme.first", "1"}: first, {"acme.second", "1"}: second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = router.Select(t.Context(), caller, descriptor, nil); err == nil || first.calls != 0 || second.calls != 0 {
		t.Fatal("ambiguous binding was automatically selected")
	}
	offerRef, err := ref.WithOfferID(store.AuthorityIdentity().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	offer := fabric.OfferDescriptor{Ref: offerRef, BindingID: "first"}
	if _, err = router.Select(t.Context(), caller, descriptor, &offer); err == nil || first.calls != 1 || second.calls != 0 {
		t.Fatal("failed binding silently fell back")
	}
	offer.BindingID = "second"
	selected, err := router.Select(t.Context(), caller, descriptor, &offer)
	if err != nil || selected.BindingID != "second" || selected.EndpointRevision != revision || second.calls != 1 {
		t.Fatal("explicit offer binding not selected", err)
	}
	if _, err = router.Select(t.Context(), fabric.ExecutionContext{}, descriptor, &offer); err == nil {
		t.Fatal("unauthenticated caller selected private config")
	}
}
