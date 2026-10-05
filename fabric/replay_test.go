package fabric

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
)

type replayVerifierFunc func(context.Context, ExecutionContext, ReplayRequest, ReplayAssociation) error

func (f replayVerifierFunc) VerifyReplay(c context.Context, a ExecutionContext, r ReplayRequest, p ReplayAssociation) error {
	return f(c, a, r, p)
}

func replayFixture(t *testing.T) (ExecutionContext, ReplayRequest, ReplayAssociation) {
	t.Helper()
	ref, err := NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	p := Principal{Ref: "local:alice", Kind: "actor.human", Issuer: "local:owner"}
	raw := []byte("exact authenticated bytes")
	caller, err := NewAuthenticatedContext(p, "local:domain", raw)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	r := ReplayRequest{Principal: p, RequestID: "new-request", Target: ref, ExpectedRevision: "r1", OriginalRequestSHA: h, FinalizedRequestSHA: h, InputSHA: h, IdempotencySHA: h}
	a := ReplayAssociation{Version: 1, AuthorityNamespace: ref.Domain(), AuthorityStoreID: "actual-retained-store", AuthorityKeyRevision: 1, Principal: p, RequestID: r.RequestID, ExecutionID: "original-execution", Target: ref, ExpectedRevision: r.ExpectedRevision, OriginalRequestSHA: h, FinalizedRequestSHA: h, InputSHA: h, IdempotencySHA: h, BindingFingerprint: h, OriginalReceiptSHA: h, Proof: []byte("signed retained alias")}
	return caller, r, a
}

type replayFrames struct {
	reads, closes int
	id            string
	next          uint64
}

func (s *replayFrames) Next(context.Context) (InvocationFrame, error) {
	s.reads++
	k := FrameStart
	if s.next == 1 {
		k = FrameComplete
	}
	if s.next > 1 {
		return InvocationFrame{}, io.EOF
	}
	f := InvocationFrame{InvocationID: s.id, Sequence: s.next, Kind: k}
	s.next++
	return f, nil
}
func (s *replayFrames) Close() error { s.closes++; return nil }

func TestReplayCorrelationRequiresFreshExactAuthority(t *testing.T) {
	caller, r, a := replayFixture(t)
	calls := 0
	verify := replayVerifierFunc(func(_ context.Context, _ ExecutionContext, _ ReplayRequest, v ReplayAssociation) error {
		calls++
		v.Proof[0] = 'X'
		return nil
	})
	for _, mutate := range []func(*ReplayAssociation){
		func(a *ReplayAssociation) { a.Principal.Ref = "local:bob" }, func(a *ReplayAssociation) { a.InputSHA[0] ^= 1 }, func(a *ReplayAssociation) { a.Target, _ = NewEndpointRef([]byte("another domain root public key!!")) }, func(a *ReplayAssociation) { a.RequestID = "another-request" }, func(a *ReplayAssociation) { a.ExpectedRevision = "r2" }, func(a *ReplayAssociation) { a.IdempotencySHA[0] ^= 1 }, func(a *ReplayAssociation) { a.OriginalRequestSHA[0] ^= 1 }, func(a *ReplayAssociation) { a.FinalizedRequestSHA[0] ^= 1 }, func(a *ReplayAssociation) { a.Proof = make([]byte, 8193) },
	} {
		b := a.Clone()
		mutate(&b)
		if _, err := VerifyReplayCorrelation(t.Context(), caller, r, b, verify); err == nil {
			t.Fatal("mismatched replay accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid association reached authority")
	}
	if _, err := VerifyReplayCorrelation(t.Context(), caller, r, a, nil); err == nil {
		t.Fatal("missing verifier accepted")
	}
	if _, err := VerifyReplayCorrelation(t.Context(), ExecutionContext{}, r, a, verify); err == nil {
		t.Fatal("asserted caller accepted")
	}
	denied := replayVerifierFunc(func(context.Context, ExecutionContext, ReplayRequest, ReplayAssociation) error {
		return errors.New("retired current binding")
	})
	if _, err := VerifyReplayCorrelation(t.Context(), caller, r, a, denied); err == nil {
		t.Fatal("revoked authority accepted")
	}
	proof, err := VerifyReplayCorrelation(t.Context(), caller, r, a, verify)
	if err != nil {
		t.Fatal(err)
	}
	if string(proof.Association().Proof) != string(a.Proof) {
		t.Fatal("authority callback mutated retained proof")
	}
	a.Proof[0] = 'Y'
	view := proof.Association()
	view.Proof[0] = 'Z'
	if string(proof.Association().Proof) == string(view.Proof) {
		t.Fatal("mutable proof view")
	}
	s := &replayFrames{id: "original-execution"}
	checked, err := NewCheckedReplayStream(t.Context(), r.RequestID, s, proof)
	if err != nil {
		t.Fatal(err)
	}
	f, err := checked.Next(t.Context())
	if err != nil || f.InvocationID != "original-execution" || f.Sequence != 0 {
		t.Fatal("source relabeled", f, err)
	}
	if _, err = checked.Next(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = checked.Next(t.Context()); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if _, err = NewCheckedReplayStream(t.Context(), "different-current-request", s, proof); err == nil {
		t.Fatal("proof reused for another current request")
	}
	if _, err = NewCheckedReplayStream(t.Context(), r.RequestID, s, &VerifiedReplayCorrelation{}); err == nil {
		t.Fatal("empty correlation accepted")
	}
	fresh, _ := NewCheckedStream(t.Context(), r.RequestID, &replayFrames{id: "original-execution"})
	if _, err = fresh.Next(t.Context()); err == nil {
		t.Fatal("unverified old identity accepted")
	}
}
