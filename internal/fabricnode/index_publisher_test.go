package fabricnode

import (
	"context"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestCommitNoticesPublishActualRetainedIndexWithoutSearchPolling(t *testing.T) {
	store, dir := retainedFixture(t)
	n, err := ComposeRetained(t.Context(), store, config(dir).Compose)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	owner, err := fabric.NewAuthenticatedContext(store.AuthorityIdentity().Owner, store.Namespace(), []byte("explicit index fixture registration"))
	if err != nil {
		t.Fatal(err)
	}
	register := func(name string) {
		t.Helper()
		ref, e := fabric.NewEndpointRef(store.AuthorityIdentity().PublicKey)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = store.Register(t.Context(), owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "actor.agent", Name: name, Description: name}}); e != nil {
			t.Fatal(e)
		}
	}
	// More than one publication budget: startup commits must finish through
	// bounded delta passes, with no manually synchronized discovery call.
	for j := 0; j < 65; j++ {
		register("invoice")
	}
	notices := make(chan struct{}, 1)
	passes := make(chan struct {
		more bool
		err  error
	}, 8)
	p, err := NewIndexPublisher(t.Context(), n, notices, func(more bool, e error) {
		passes <- struct {
			more bool
			err  error
		}{more, e}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	wait := func() {
		t.Helper()
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case pass := <-passes:
				if pass.err != nil {
					t.Fatal(pass.err)
				}
				if !pass.more {
					return
				}
			case <-deadline.C:
				t.Fatal("no actual index publication")
			}
		}
	}
	wait()
	result, err := n.Search(t.Context(), fabric.DiscoverRequest{Query: "invoice", Limit: 100})
	if err != nil || len(result.Candidates) != 65 {
		t.Fatal("startup publication lost retained descriptors", err, len(result.Candidates))
	}
	register("meteor")
	before, err := n.Search(t.Context(), fabric.DiscoverRequest{Query: "meteor", Limit: 1})
	if err != nil || len(before.Candidates) != 0 {
		t.Fatal("search performed hidden registry synchronization", err)
	}
	notices <- struct{}{}
	wait()
	after, err := n.Search(t.Context(), fabric.DiscoverRequest{Query: "meteor", Limit: 1})
	if err != nil || len(after.Candidates) != 1 {
		t.Fatal("commit notice did not publish exact delta", err)
	}
	count, failure := p.Status()
	if count < 3 || failure != nil {
		t.Fatal(count, failure)
	}
	if err = p.CloseContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertWriterHeld(t, dir)
}

func TestActualPublisherFailureDoesNotAdvertiseStaleSearchAsCurrent(t *testing.T) {
	store, dir := retainedFixture(t)
	n, err := ComposeRetained(t.Context(), store, config(dir).Compose)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	// Actual durable writer loss, not a fabricated publisher failure callback.
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	failure := make(chan error, 1)
	p, err := NewIndexPublisher(t.Context(), n, make(chan struct{}, 1), func(_ bool, e error) { failure <- e })
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	select {
	case actual := <-failure:
		if actual == nil {
			t.Fatal("closed writer reported publication success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer loss was not reported")
	}
	if _, err = n.Search(t.Context(), fabric.DiscoverRequest{Query: "invoice", Limit: 1}); err == nil {
		t.Fatal("failed publisher silently served a stale index")
	}
	_, actual := p.Status()
	if actual == nil {
		t.Fatal("publisher failure vanished")
	}
}
