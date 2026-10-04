package fabricnode

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type testAuth struct{}

func (testAuth) Authenticate(context.Context, fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	return fabric.ExecutionContext{}, errors.New("fixture does not impersonate a transport peer")
}

type noBinding struct{}

func (noBinding) Select(context.Context, fabric.ExecutionContext, fabric.EndpointDescriptor, *fabric.OfferDescriptor) (dispatch.Selection, error) {
	panic("index synchronization executed a binding")
}

type noAdmission struct{}

func (noAdmission) WithDispatch(context.Context, fabric.ExecutionContext, []byte, []byte, fabric.EndpointDescriptor, *fabric.OfferDescriptor, dispatch.Selection, func(context.Context) (fabric.InvocationStream, error)) (fabric.InvocationStream, error) {
	panic("index synchronization admitted an invocation")
}
func config(dir string) Config {
	return Config{Directory: dir, Authenticator: testAuth{}, Bindings: noBinding{}, Admission: noAdmission{}}
}
func TestRetainedNodeIndexBoundedSyncAndRestart(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "domain")
	p := fabric.Principal{Ref: "local:owner", Kind: "actor.human", Issuer: "local:os"}
	store, err := registry.Bootstrap(ctx, dir, p)
	if err != nil {
		t.Fatal(err)
	}
	domain := store.Namespace()
	store.Close()
	n, err := Open(ctx, config(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	owner, err := fabric.NewAuthenticatedContext(p, domain, []byte("trusted registration fixture"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 65; i++ {
		ref, err := fabric.NewEndpointRef(n.Store.AuthorityIdentity().PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		_, err = n.Store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "actor.agent", Name: "Invoice", Description: "Historical invoice retrieval"}})
		if err != nil {
			t.Fatal(err)
		}
	}
	query := fabric.DiscoverRequest{Query: "invoice", Limit: 10}
	r, err := n.Search(ctx, query)
	if err != nil || len(r.Candidates) != 0 {
		t.Fatal("search secretly drained durable outbox", err)
	}
	more, err := n.Synchronize(ctx, 1)
	if err != nil || !more {
		t.Fatal("bounded page lost pending work", more, err)
	}
	more, err = n.Synchronize(ctx, 2)
	if err != nil || more {
		t.Fatal("retained delta did not finish", more, err)
	}
	before, err := n.Search(ctx, query)
	if err != nil || len(before.Candidates) != 10 {
		t.Fatal(err, len(before.Candidates))
	}
	if err = n.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, config(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after, err := reopened.Search(ctx, query)
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if err != nil || string(a) != string(b) {
		t.Fatal("genuine replay changed current index", err)
	}
	more, err = reopened.Synchronize(ctx, 1)
	if err != nil || more {
		t.Fatal("reopened node replayed committed delta", err)
	}
	foreign, err := fabric.DomainNamespace(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	query.Scope.Domains = []string{foreign}
	if _, err = reopened.Search(ctx, query); err == nil {
		t.Fatal("remote scope silently searched local or imported catalogs")
	}
}
func TestMissingNodeNeverBootstrapsIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	if n, err := Open(context.Background(), config(dir)); err == nil {
		n.Close()
		t.Fatal("node created missing retained identity")
	}
}
