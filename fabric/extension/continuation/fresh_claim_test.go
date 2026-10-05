package continuation

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestFreshClaimExactOnceNoWireRetryOrForeignStore(t *testing.T) {
	s, _, v, caller, resumer, expiry := fixture(t)
	x := issue(t, s, caller, v, expiry)
	claim, err := s.Claim(ctx, resumer, x.Capability.Token(), ident("fresh-claim"))
	if err != nil || !claim.Fresh || claim.Claim == nil {
		t.Fatalf("fresh claim: %v", err)
	}
	if _, err = json.Marshal(claim.Claim); err == nil {
		t.Fatal("serialized capability")
	}
	var forged FreshClaim
	if json.Unmarshal([]byte(`{}`), &forged) == nil {
		t.Fatal("deserialized capability")
	}
	other, _, _, _, _, _ := fixture(t)
	if _, err = claim.Claim.Consume(ctx, other, resumer, claim.Receipt); err == nil {
		t.Fatal("other store")
	}
	wrong := fabric.Principal{Ref: human.Ref, Kind: human.Kind, Issuer: "different:issuer"}
	if _, err = claim.Claim.Consume(ctx, s, auth(t, wrong, "test:audience", []byte("claim")), claim.Receipt); err == nil {
		t.Fatal("wrong issuer")
	}
	changed := claim.Receipt
	changed.CapabilityRevision++
	if _, err = claim.Claim.Consume(ctx, s, resumer, changed); err == nil {
		t.Fatal("changed revision")
	}
	retry, err := s.Claim(ctx, resumer, x.Capability.Token(), claim.Receipt.ClaimID)
	if err != nil || retry.Fresh || retry.Claim != nil {
		t.Fatalf("retry manufactured proof: %v", err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snapshot, e := claim.Claim.Consume(ctx, s, resumer, claim.Receipt)
			if e == nil {
				successes.Add(1)
				if snapshot.DeferralID != v.DeferralID {
					t.Error("wrong snapshot")
				}
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("consumed %d times", successes.Load())
	}
	if _, err = forged.Consume(ctx, s, resumer, claim.Receipt); err == nil {
		t.Fatal("zero proof")
	}
}

func TestFreshClaimRejectsSettledOrClosedStore(t *testing.T) {
	s, _, v, caller, resumer, expiry := fixture(t)
	x := issue(t, s, caller, v, expiry)
	claim, err := s.Claim(ctx, resumer, x.Capability.Token(), ident("settled-claim"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Complete(ctx, resumer, claim.Receipt, Outcome{Effect: fabric.EffectNotStarted, Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err = claim.Claim.Consume(ctx, s, resumer, claim.Receipt); err == nil {
		t.Fatal("settled claim executable")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = claim.Claim.Consume(ctx, s, resumer, claim.Receipt); err == nil {
		t.Fatal("closed store executable")
	}
}
