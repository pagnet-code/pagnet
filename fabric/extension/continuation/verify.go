package continuation

import (
	"context"
	"encoding/json"
	"time"
)

// Startup reads rows sequentially within configured bounds. No incomplete or
// corrupted claim is reset to pending; source snapshot and receipt remain pinned.
func (s *Store) verify(ctx context.Context) error {
	// Reject oversized stored blobs before asking the driver to allocate them.
	var malformed int
	if e := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM continuations
 WHERE length(snapshot)>? OR length(receipt)>16384+65536 OR length(outcome)>? OR length(cap_hash)!=32 OR cap_revision<1)`, s.options.MaxSnapshotBytes+maxSealOverhead, s.options.MaxOutcomeBytes+maxSealOverhead).Scan(&malformed); e != nil || malformed != 0 {
		return internal()
	}
	var count, total int64
	rows, e := s.db.QueryContext(ctx, "SELECT id,snapshot,snapshot_digest,expires,cap_hash,cap_revision,state,receipt,outcome FROM continuations ORDER BY id")
	if e != nil {
		return internal()
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var r row
		if e = rows.Scan(&id, &r.snapshot, &r.digest, &r.expires, &r.hash, &r.revision, &r.state, &r.receipt, &r.outcome); e != nil {
			return internal()
		}
		count++
		n := int64(len(r.snapshot) + len(r.receipt) + len(r.outcome))
		if n > s.options.MaxBytes-total || count > s.options.MaxRecords {
			return internal()
		}
		total += n
		if e = s.openRow(id, &r); e != nil {
			return e
		}
		if len(r.snapshot) > s.options.MaxSnapshotBytes || len(r.receipt) > 16384 || len(r.outcome) > s.options.MaxOutcomeBytes || len(r.hash) != 32 || r.revision < 1 || r.digest != digest(r.snapshot) {
			return internal()
		}
		v, e := s.snapshot(r.snapshot)
		if e != nil || v.DeferralID != id {
			return internal()
		}
		expiry, e := time.Parse(time.RFC3339Nano, r.expires)
		if e != nil || expiry.IsZero() || expiry.UTC().Format(time.RFC3339Nano) != r.expires {
			return internal()
		}
		if r.state == Pending {
			if len(r.receipt) != 0 || len(r.outcome) != 0 {
				return internal()
			}
			continue
		}
		if r.state != Claimed && r.state != Complete {
			return internal()
		}
		var receipt Receipt
		if e = decode(r.receipt, &receipt, 16384); e != nil || receipt.ID != id || !hexID(receipt.ClaimID) || !allowed(v, receipt.Principal) || receipt.Audience != s.scope.Audience || receipt.SnapshotDigest != r.digest || receipt.PlanDigest != v.PlanDigest || receipt.CapabilityRevision != uint64(r.revision) || receipt.ClaimedAt.IsZero() || !receipt.ClaimedAt.Before(expiry) {
			return internal()
		}
		b, _ := json.Marshal(receipt)
		if string(b) != string(r.receipt) {
			return internal()
		}
		if r.state == Claimed {
			if len(r.outcome) != 0 {
				return internal()
			}
			continue
		}
		var out Outcome
		if e = decode(r.outcome, &out, s.options.MaxOutcomeBytes); e != nil {
			return internal()
		}
		if !s.validOutcome(out) {
			return internal()
		}
	}
	if rows.Err() != nil {
		return internal()
	}
	if e = rows.Close(); e != nil {
		return internal()
	}
	var records, bytes int64
	if e = s.db.QueryRowContext(ctx, "SELECT records,bytes FROM budget WHERE singleton=1").Scan(&records, &bytes); e != nil || records != count || bytes != total {
		return internal()
	}
	return nil
}
func (s *Store) validOutcome(o Outcome) bool {
	if o.Effect != "unknown" && o.Effect != "not_started" && o.Effect != "completed" {
		return false
	}
	var v any
	return s.decodePrivate(o.Data, &v, s.options.MaxOutcomeBytes) == nil
}
