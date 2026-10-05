package identity

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// This is the typed transaction conformance fixture, not a simulated live peer.
// The paired fabricnode fixture supplies real kernel/resumer/Store claim proofs.
func TestDeferredOriginalAndCurrentResumerRemainSeparateAtAdmissionTransaction(t *testing.T) {
	f := fixture(t)
	original := fabric.Principal{Ref: "spiffe://offline/original-agent", Kind: "local.agent", Issuer: "original.issuer"}
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "deferred-original", Operation: fabric.OperationInvoke, Principal: original, Source: original.Ref, Target: &f.scope.Endpoint, ExpectedRevision: f.scope.DescriptorRevision, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"input":"unchanged"}`), Context: fabric.EnvelopeContext{Origin: original.Ref}}
	raw, _ := json.Marshal(env)
	caller, err := fabric.NewAuthenticatedContext(original, f.store.Namespace(), raw)
	if err != nil {
		t.Fatal(err)
	}
	commitment := sha256.Sum256([]byte("exact durable allowed-owner snapshot"))
	value := registry.DeferredAdmission{Version: 1, DeferralID: fmt.Sprintf("%x", sha256.Sum256([]byte("deferral"))), OriginalCaller: original, Provenance: caller.ProvenanceView(), OriginalDigest: sha256.Sum256(raw), SnapshotCommitment: commitment, PlanRevision: "exact-configured-plan"}
	var proof registry.AuthorityRecord
	if err = f.store.WithNativeAuthority(t.Context(), f.owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
		var e error
		proof, e = tx.RecordDeferredAdmission(caller, raw, value)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	witness := Witness{CurrentCallerKind: "local-resume.owner", CurrentCallerOpen: func() bool { return true }, DeferredCaller: &DeferredCallerWitness{Admission: proof, Original: raw, SnapshotCommitment: commitment, Resumer: localOwner, ClaimOpen: func() bool { return true }, VerifyPlan: func(*registry.AuthorityTx) error { return nil }}}
	check := func(w Witness, principal fabric.Principal) error {
		return f.store.WithNativeAuthority(context.Background(), f.owner, registry.AuthorityScope{HistoryOnly: true}, func(tx *registry.AuthorityTx) error { return f.a.verifyCurrentCallerTx(tx, w, principal) })
	}
	if err = check(witness, original); err != nil {
		t.Fatal("genuine retained original/current-owner separation", err)
	}
	if check(Witness{CurrentCallerKind: "local-peer.owner", CurrentCallerOpen: func() bool { return true }}, original) == nil {
		t.Fatal("ordinary owner witness equality relaxed")
	}
	if check(witness, localOwner) == nil {
		t.Fatal("original principal replaced by resumer")
	}
	for _, mutate := range []func(*Witness){
		func(w *Witness) { w.DeferredCaller.Resumer.Issuer = "foreign" },
		func(w *Witness) { w.DeferredCaller.SnapshotCommitment[0] ^= 1 },
		func(w *Witness) { w.DeferredCaller.Original = append([]byte("changed"), w.DeferredCaller.Original...) },
		func(w *Witness) { w.DeferredCaller.ClaimOpen = func() bool { return false } },
		func(w *Witness) { w.CurrentCallerOpen = func() bool { return false } },
		func(w *Witness) { w.CurrentCallerKind = "local-peer.owner" },
		func(w *Witness) {
			w.DeferredCaller.VerifyPlan = func(*registry.AuthorityTx) error {
				return fabric.NewError(fabric.CodeStaleContinuation, "changed configured binding")
			}
		},
	} {
		changed := cloneWitness(witness)
		mutate(&changed)
		if check(changed, original) == nil {
			t.Fatal("forged/retired/stale resume authority accepted")
		}
	}
	encoded, err := json.Marshal(witness)
	if err != nil {
		t.Fatal(err)
	}
	var stored Witness
	if fabric.DecodeJSON(encoded, &stored) != nil || stored.DeferredCaller != nil || stored.CurrentCallerKind != "" || stored.CurrentCallerOpen != nil {
		t.Fatal("ephemeral resume evidence persisted")
	}
}
