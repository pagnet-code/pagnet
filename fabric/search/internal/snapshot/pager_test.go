package snapshot

import (
	"context"
	"encoding/base32"
	"errors"
	"github.com/pagnet-code/pagnet/fabric"
	"testing"
	"time"
)

func state() State {
	pub := make([]byte, 32)
	pub[0] = 1
	domain, _ := fabric.DomainNamespace(pub)
	enc := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	cs := []fabric.Candidate{}
	for i := byte(1); i <= 3; i++ {
		id := make([]byte, 32)
		id[0] = i
		ref, _ := fabric.ParseEndpointRef("pagnet://" + domain + "/e/" + enc.EncodeToString(id))
		cs = append(cs, fabric.Candidate{Document: fabric.SearchDocument{Ref: ref, Revision: "r1", Kind: "actor.agent"}, Score: float64(4 - i)})
	}
	return State{Binding: "binding", Scope: "alice", Policy: "policy1", Revision: "index1", IndexRevisions: []fabric.Revision{"index1"}, Candidates: cs}
}
func TestAuthenticatedExpiryAndImmutableState(t *testing.T) {
	now := time.Now()
	p, e := New(Config{Now: func() time.Time { return now }, TTL: time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	r := fabric.DiscoverRequest{Query: "query", Limit: 1}
	s := state()
	first, e := p.Store(context.Background(), r, s)
	if e != nil {
		t.Fatal(e)
	}
	s.Candidates[1].Document.Revision = "changed"
	r.Cursor = first.NextCursor
	checks := 0
	second, e := p.Page(context.Background(), r, "binding", func(_ context.Context, _ fabric.DiscoverRequest, s State, cs []fabric.Candidate) error {
		checks++
		if cs[0].Document.Revision != "r1" {
			t.Fatal("caller mutated retained state")
		}
		s.Candidates[2].Document.Revision = "bad"
		return nil
	})
	if e != nil || checks != 1 || len(second.Candidates) != 1 {
		t.Fatal(e)
	}
	if _, e = p.Page(context.Background(), r, "wrong", func(context.Context, fabric.DiscoverRequest, State, []fabric.Candidate) error { return nil }); !errors.Is(e, ErrStale) {
		t.Fatal(e)
	}
	now = now.Add(2 * time.Minute)
	if _, e = p.Page(context.Background(), r, "binding", func(context.Context, fabric.DiscoverRequest, State, []fabric.Candidate) error { return nil }); !errors.Is(e, ErrStale) {
		t.Fatal("expired snapshot returned", e)
	}
}
