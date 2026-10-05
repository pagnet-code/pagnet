package continuation

import (
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestClaimReceiptExactHistoricalReadHasNoCapabilityOrFreshClaim(t *testing.T) {
	s, dir, snapshot, caller, human, expiry := fixture(t)
	issued := issue(t, s, caller, snapshot, expiry)
	claimID := ident("same-private-claim")
	if _, found, e := s.ClaimReceipt(t.Context(), human, issued.ID, claimID); e != nil || found {
		t.Fatal("pending receipt fabricated", e)
	}
	claim, e := s.Claim(t.Context(), human, issued.Capability.Token(), claimID)
	if e != nil || !claim.Fresh {
		t.Fatal(e)
	}
	if _, _, e = s.ClaimReceipt(t.Context(), human, issued.ID, ident("different")); e == nil {
		t.Fatal("different claim read original receipt")
	}
	if _, _, e = s.ClaimReceipt(t.Context(), caller, issued.ID, claimID); e == nil {
		t.Fatal("original agent promoted to resumer")
	}
	foreign := human.PrincipalView()
	foreign.Issuer = "other:issuer"
	wrong := auth(t, foreign, "test:audience", []byte("genuine other issuer fixture"))
	if _, _, e = s.ClaimReceipt(t.Context(), wrong, issued.ID, claimID); e == nil {
		t.Fatal("wrong issuer read receipt")
	}
	out := Outcome{Effect: fabric.EffectUnknown, Data: []byte(`{"uncertain":true}`)}
	if _, e = s.Complete(t.Context(), human, claim.Receipt, out); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(t.Context(), dir, Scope{Audience: "test:audience"}, DefaultOptions(), testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	read, found, e := s.ClaimReceipt(t.Context(), human, issued.ID, claimID)
	if e != nil || !found || read.Fresh || read.Claim != nil || len(read.Snapshot.OriginalEnvelope) != 0 || read.Receipt != claim.Receipt || read.State != Complete || read.Outcome == nil || read.Outcome.Effect != fabric.EffectUnknown {
		t.Fatal("historical metadata revived work", e)
	}
}
