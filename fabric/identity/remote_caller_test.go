package identity

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func TestRemoteCallerWitnessExactPurposeLifetimeAndNoWireAuthority(t *testing.T) {
	p := fabric.Principal{Ref: "remote.operator", Kind: "local.owner", Issuer: "remote.root"}
	calls := 0
	makeWitness := func() Witness {
		return Witness{CurrentCallerKind: "remote-peer.request", CurrentCallerOpen: func() bool { return true }, RemoteCaller: &RemoteCallerWitness{Principal: p, RequestDigest: [32]byte{1}, AssertionDigest: [32]byte{2}, AssociationOpen: func() bool { return true }, VerifyCurrent: func(*registry.AuthorityTx) error { calls++; return nil }}}
	}
	a := &Authority{}
	w := makeWitness()
	if e := a.verifyCurrentCallerTx(nil, w, p); e != nil || calls != 1 {
		t.Fatal(e, calls)
	}
	raw, e := json.Marshal(w)
	if e != nil {
		t.Fatal(e)
	}
	var wire Witness
	if fabric.DecodeJSON(raw, &wire) != nil || wire.RemoteCaller != nil {
		t.Fatal("serialized remote authority")
	}
	mutations := []func(*Witness){
		func(w *Witness) { w.CurrentCallerKind = "local-peer.owner" },
		func(w *Witness) { w.RemoteCaller.Principal.Issuer = "foreign" },
		func(w *Witness) { w.RemoteCaller.RequestDigest = [32]byte{} },
		func(w *Witness) { w.RemoteCaller.AssertionDigest = [32]byte{} },
		func(w *Witness) { w.CurrentCallerOpen = func() bool { return false } },
		func(w *Witness) { w.RemoteCaller.AssociationOpen = func() bool { return false } },
		func(w *Witness) { w.RemoteCaller.VerifyCurrent = nil },
		func(w *Witness) { w.DeferredCaller = &DeferredCallerWitness{} },
	}
	for n, mutate := range mutations {
		w = makeWitness()
		mutate(&w)
		if a.verifyCurrentCallerTx(nil, w, p) == nil {
			t.Fatal("invalid remote evidence", n)
		}
	}
	w = makeWitness()
	expected := errors.New("current bilateral grant revoked")
	w.RemoteCaller.VerifyCurrent = func(*registry.AuthorityTx) error { return expected }
	if !errors.Is(a.verifyCurrentCallerTx(nil, w, p), expected) {
		t.Fatal("revocation swallowed")
	}
	w = makeWitness()
	alive := true
	w.RemoteCaller.AssociationOpen = func() bool { return alive }
	w.RemoteCaller.VerifyCurrent = func(*registry.AuthorityTx) error { alive = false; return nil }
	if a.verifyCurrentCallerTx(nil, w, p) == nil {
		t.Fatal("closed during current transaction")
	}
	w = makeWitness()
	owned := cloneWitness(w)
	w.RemoteCaller.Principal.Issuer = "mutated"
	if owned.RemoteCaller.Principal != p {
		t.Fatal("borrowed witness")
	}
}
