package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestDeferredAdmissionImmutableActualRootHistoryAndClosedTransaction(t *testing.T) {
	s, owner, _, _ := nativeFixture(t)
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "deferred-original", Operation: fabric.OperationDiscover, Principal: owner.PrincipalView(), Source: owner.PrincipalView().Ref, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{}`), Context: fabric.EnvelopeContext{Origin: owner.PrincipalView().Ref}}
	raw, _ := json.Marshal(env)
	caller, err := fabric.NewAuthenticatedContext(owner.PrincipalView(), s.Namespace(), raw)
	if err != nil {
		t.Fatal(err)
	}
	id := sha256.Sum256([]byte("stable-engine-deferral"))
	facts := DeferredAdmission{Version: 1, DeferralID: hex.EncodeToString(id[:]), OriginalCaller: caller.PrincipalView(), Provenance: caller.ProvenanceView(), OriginalDigest: sha256.Sum256(raw), SnapshotCommitment: sha256.Sum256([]byte("immutable-snapshot")), PlanRevision: "configured-plan"}
	var proof AuthorityRecord
	var escaped *AuthorityTx
	write := func(v DeferredAdmission) error {
		return s.WithNativeAuthority(context.Background(), owner, AuthorityScope{}, func(tx *AuthorityTx) error {
			escaped = tx
			var e error
			proof, e = tx.RecordDeferredAdmission(caller, raw, v)
			return e
		})
	}
	if err = write(facts); err != nil {
		t.Fatal(err)
	}
	count := nativeCount(t, s)
	if err = write(facts); err != nil || nativeCount(t, s) != count {
		t.Fatal("exact retry appended", err)
	}
	changed := facts
	changed.SnapshotCommitment = sha256.Sum256([]byte("changed-snapshot"))
	if err = write(changed); err == nil {
		t.Fatal("changed deferral accepted")
	}
	if _, err = escaped.RecordDeferredAdmission(caller, raw, facts); err == nil {
		t.Fatal("escaped writer")
	}
	if err = write(facts); err != nil {
		t.Fatal(err)
	}
	verify := func(p AuthorityRecord, commitment [32]byte) error {
		return s.WithNativeAuthority(context.Background(), owner, AuthorityScope{HistoryOnly: true}, func(tx *AuthorityTx) error { _, e := tx.VerifyDeferredAdmission(p, raw, commitment); return e })
	}
	if err = verify(proof, facts.SnapshotCommitment); err != nil {
		t.Fatal(err)
	}
	forged := proof
	forged.Signature = append([]byte(nil), proof.Signature...)
	forged.Signature[0] ^= 1
	if err = verify(forged, facts.SnapshotCommitment); err == nil {
		t.Fatal("forged historical proof")
	}
	if err = verify(proof, changed.SnapshotCommitment); err == nil {
		t.Fatal("wrong snapshot")
	}
}
