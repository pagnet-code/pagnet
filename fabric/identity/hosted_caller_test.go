package identity

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func TestHostedCallerWitnessExactPurposeCurrentTransactionAndNoWireAuthority(t *testing.T) {
	p := fabric.Principal{Ref: "original-agent", Kind: "actor.agent", Issuer: "explicit-root"}
	a := &Authority{}
	calls := 0
	fresh := func() Witness {
		return Witness{CurrentCallerKind: "local-peer.hosted", CurrentCallerOpen: func() bool { return true }, HostedCaller: &HostedCallerWitness{Principal: p, AssociationDigest: [32]byte{1}, VerifyCurrent: func(*registry.AuthorityTx) error { calls++; return nil }}}
	}
	w := fresh()
	if e := a.verifyCurrentCallerTx(nil, w, p); e != nil || calls != 1 {
		t.Fatal("explicit trusted current verifier", e, calls)
	}
	for i, mutate := range []func(*Witness){
		func(w *Witness) { w.CurrentCallerKind = "local-peer.owner" },
		func(w *Witness) { w.CurrentCallerKind = "local-peer.managed" },
		func(w *Witness) { w.HostedCaller.Principal.Issuer = "foreign" },
		func(w *Witness) { w.HostedCaller.AssociationDigest = [32]byte{} },
		func(w *Witness) { w.HostedCaller.VerifyCurrent = nil },
		func(w *Witness) { w.CurrentCallerOpen = func() bool { return false } },
		func(w *Witness) { w.CurrentCallerAuthority = &registry.NativeCallerAuthority{} },
		func(w *Witness) { w.RemoteCaller = &RemoteCallerWitness{} },
		func(w *Witness) { w.DeferredCaller = &DeferredCallerWitness{} },
	} {
		w = fresh()
		mutate(&w)
		if a.verifyCurrentCallerTx(nil, w, p) == nil {
			t.Fatal("invalid mixed original caller evidence", i)
		}
	}
	w = fresh()
	alive := true
	w.CurrentCallerOpen = func() bool { return alive }
	w.HostedCaller.VerifyCurrent = func(*registry.AuthorityTx) error { alive = false; return nil }
	if a.verifyCurrentCallerTx(nil, w, p) == nil {
		t.Fatal("closed during current transaction")
	}
	w = fresh()
	revoked := errors.New("original association retired")
	w.HostedCaller.VerifyCurrent = func(*registry.AuthorityTx) error { return revoked }
	if !errors.Is(a.verifyCurrentCallerTx(nil, w, p), revoked) {
		t.Fatal("retirement swallowed")
	}
	w = fresh()
	copy := cloneWitness(w)
	w.HostedCaller.Principal.Issuer = "mutated"
	if copy.HostedCaller.Principal != p {
		t.Fatal("borrowed mutable witness")
	}
	raw, e := json.Marshal(copy)
	var decoded Witness
	if e != nil || json.Unmarshal(raw, &decoded) != nil || decoded.HostedCaller != nil || decoded.CurrentCallerKind != "" {
		t.Fatal("current original authority persisted")
	}
	if _, e = json.Marshal(copy.HostedCaller); e == nil {
		t.Fatal("private original witness independently serialized")
	}
}
