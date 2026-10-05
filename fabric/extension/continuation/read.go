package continuation

import (
	"context"

	"github.com/pagnet-code/pagnet/fabric"
)

// ClaimReceipt reconciles an exact already claimed request without recovering
// or returning its capability. A pending record returns found=false. The
// composition must separately verify current live resumer authority; this
// historical metadata port never issues FreshClaim or executable permission.
func (s *Store) ClaimReceipt(ctx context.Context, c fabric.ExecutionContext, id, claimID string) (ClaimResult, bool, error) {
	var result ClaimResult
	if s.authenticated(c) != nil || !hexID(id) || !hexID(claimID) {
		return result, false, stale()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.transaction(ctx)
	if e != nil {
		return result, false, e
	}
	defer tx.Rollback()
	r, e := s.load(ctx, tx, id)
	if e != nil {
		return result, false, e
	}
	v, e := s.snapshot(r.snapshot)
	if e != nil || !allowed(v, c.PrincipalView()) {
		return result, false, stale()
	}
	if r.state == Pending {
		return result, false, nil
	}
	if e = decode(r.receipt, &result.Receipt, 16384); e != nil {
		return ClaimResult{}, false, internal()
	}
	if result.Receipt.ID != id || result.Receipt.ClaimID != claimID || result.Receipt.Principal != c.PrincipalView() || result.Receipt.Audience != s.scope.Audience {
		return ClaimResult{}, false, stale()
	}
	result.State = r.state
	if len(r.outcome) > 0 {
		var out Outcome
		if e = decode(r.outcome, &out, s.options.MaxOutcomeBytes); e != nil {
			return ClaimResult{}, false, internal()
		}
		result.Outcome = &out
	}
	return result, true, nil
}
