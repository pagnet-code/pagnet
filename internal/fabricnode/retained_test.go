package fabricnode

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/fabric/search"
)

type retryJoin struct {
	fail  bool
	calls int
}

func (r *retryJoin) Close() error {
	r.calls++
	if r.fail {
		return errors.New("original resource still alive")
	}
	return nil
}
func retainedFixture(t *testing.T) (*registry.Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "authority")
	store, err := registry.Bootstrap(context.Background(), dir, fabric.Principal{Ref: "local:owner", Kind: "actor.human", Issuer: "local:os"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store, dir
}
func assertWriterHeld(t *testing.T, dir string) {
	t.Helper()
	duplicate, err := registry.Open(context.Background(), dir)
	if err == nil {
		duplicate.Close()
		t.Fatal("released original writer before its owner completed")
	}
}
func TestComposeRetainedDoesNotReleaseInstallationStore(t *testing.T) {
	store, dir := retainedFixture(t)
	root := store.AuthorityIdentity()
	c := config(dir)
	n, err := ComposeRetained(context.Background(), store, c.Compose)
	if err != nil {
		t.Fatal(err)
	}
	if n.Store != store || n.Directory() != dir {
		t.Fatal("substituted installation store")
	}
	if err = n.Close(); err != nil {
		t.Fatal(err)
	}
	assertWriterHeld(t, dir)
	actual, err := store.CurrentAuthorityIdentity(context.Background())
	if err != nil || actual.StoreID != root.StoreID {
		t.Fatal("node closed retained installation", err)
	}
	if _, err = n.Search(context.Background(), fabric.DiscoverRequest{Query: "x", Limit: 1}); err == nil {
		t.Fatal("closed node admitted work")
	}
}
func TestNodeCloseRetainsWriterUntilActualJoin(t *testing.T) {
	store, dir := retainedFixture(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	resource := &retryJoin{fail: true}
	c := config(dir)
	base := c.Compose
	c.Compose = func(ctx context.Context, s *registry.Store, i *search.Backend) (Ports, error) {
		p, e := base(ctx, s, i)
		p.Close = resource
		return p, e
	}
	n, err := Open(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if n.Close() == nil {
		t.Fatal("failed join reported completion")
	}
	assertWriterHeld(t, dir)
	if _, err = n.Store.CurrentAuthorityIdentity(context.Background()); err != nil {
		t.Fatal("failed join closed live root", err)
	}
	resource.fail = false
	if err = n.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := registry.Open(context.Background(), dir)
	if err != nil {
		t.Fatal("successful join kept writer lock", err)
	}
	reopened.Close()
	if resource.calls != 2 {
		t.Fatal("close did not retry genuine join", resource.calls)
	}
}
func TestFailedCompositionJoinKeepsRecoverableWriter(t *testing.T) {
	for _, own := range []bool{false, true} {
		t.Run(map[bool]string{false: "installation", true: "open"}[own], func(t *testing.T) {
			store, dir := retainedFixture(t)
			resource := &retryJoin{fail: true}
			compose := func(context.Context, *registry.Store, *search.Backend) (Ports, error) {
				return Ports{Close: resource}, errors.New("composition failed")
			}
			var err error
			if own {
				store.Close()
				_, err = Open(context.Background(), Config{Directory: dir, Compose: compose})
			} else {
				_, err = ComposeRetained(context.Background(), store, compose)
			}
			var retained *CompositionError
			if !errors.As(err, &retained) {
				t.Fatal("lost cleanup ownership", err)
			}
			assertWriterHeld(t, dir)
			resource.fail = false
			if err = retained.Close(); err != nil {
				t.Fatal(err)
			}
			if !own {
				assertWriterHeld(t, dir)
				store.Close()
			}
			reopened, err := registry.Open(context.Background(), dir)
			if err != nil {
				t.Fatal("cleanup did not release correct writer", err)
			}
			reopened.Close()
		})
	}
}
