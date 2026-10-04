package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/fabric"
)

// Recovery reconstructs bounded local-private projection state from ORIGINAL
// signed records in private scratch SQLite. Public imports alone have no such
// root/store-bound history and never become a callable local MCP binding.
func (s *Store) verifyDescriptorProjections(ctx context.Context) error {
	tables, e := projectionTables(ctx, s.db)
	if e != nil || tables == 0 {
		return e
	}
	_, scratch, cleanup, e := s.newRecoveryProjection(ctx)
	if e != nil {
		return e
	}
	defer cleanup()
	_, e = scratch.ExecContext(ctx, `CREATE TABLE public_versions(sequence INTEGER PRIMARY KEY,ref TEXT,revision TEXT,expected TEXT,action TEXT,head BLOB,binding TEXT,bindings BLOB);
 CREATE INDEX public_exact_version ON public_versions(ref,revision);
 CREATE INDEX public_prior_endpoint ON public_versions(ref,sequence);
 CREATE TABLE projection_verified_heads(endpoint TEXT,binding TEXT,generation INTEGER,head BLOB,limits BLOB,rows INTEGER,bytes INTEGER,config BLOB,PRIMARY KEY(endpoint,binding));
 CREATE TABLE projection_verified_rows(endpoint TEXT,binding TEXT,ref TEXT,selector TEXT,retired INTEGER,row BLOB,cost INTEGER,PRIMARY KEY(endpoint,binding,ref));
 CREATE UNIQUE INDEX verified_active_selector ON projection_verified_rows(endpoint,binding,selector) WHERE retired=0;`)
	if e != nil {
		return e
	}
	// Signed public history was verified before this hook. Build indexed immutable
	// version associations once rather than repeatedly scanning the public ledger.
	ledger, e := s.db.QueryContext(ctx, "SELECT CASE WHEN length(record)<=? THEN record END,head FROM ledger WHERE domain=? ORDER BY sequence", s.options.Limits.MaxPayloadBytes*2+65536, s.identity.Namespace)
	if e != nil {
		return e
	}
	for ledger.Next() {
		var raw, head []byte
		if e = ledger.Scan(&raw, &head); e != nil {
			ledger.Close()
			return e
		}
		var r Record
		if e = s.decode(raw, &r); e != nil {
			ledger.Close()
			return e
		}
		binding := ""
		var bindings []byte
		if r.Frame.ActionKind == "offer.publish" {
			var d fabric.OfferDescriptor
			if e = s.decode(r.Payload, &d); e != nil {
				ledger.Close()
				return e
			}
			binding = d.BindingID
		}
		if r.Frame.ActionKind == "endpoint.publish" {
			var d fabric.EndpointDescriptor
			if e = s.decode(r.Payload, &d); e != nil {
				ledger.Close()
				return e
			}
			bindings, _ = json.Marshal(d.Bindings)
		}
		if _, e = scratch.ExecContext(ctx, "INSERT INTO public_versions VALUES(?,?,?,?,?,?,?,?)", r.Frame.Sequence, r.Frame.ExactTargetRef.String(), r.Frame.NewRevision, r.Frame.ExpectedPriorRevision, r.Frame.ActionKind, head, binding, bindings); e != nil {
			ledger.Close()
			return e
		}
	}
	e = ledger.Err()
	ledger.Close()
	if e != nil {
		return e
	}
	afterEndpoint, afterBinding := "", ""
	var afterGeneration uint64
	for {
		var endpoint, binding string
		var generation uint64
		var raw []byte
		e = s.db.QueryRowContext(ctx, "SELECT endpoint,binding,generation,CASE WHEN length(record)<=16777216 THEN record END FROM descriptor_projection_log WHERE (endpoint,binding,generation)>(?,?,?) ORDER BY endpoint,binding,generation LIMIT 1", afterEndpoint, afterBinding, afterGeneration).Scan(&endpoint, &binding, &generation, &raw)
		if errors.Is(e, sql.ErrNoRows) {
			break
		}
		if e != nil {
			return e
		}
		afterEndpoint, afterBinding, afterGeneration = endpoint, binding, generation
		r, b, x := decodeProjection(raw)
		if x != nil {
			return x
		}
		if b.Format != 1 || b.Namespace != s.identity.Namespace || b.StoreID != s.identity.StoreID || b.Owner != s.identity.Owner || b.KeyRevision != 1 || len(r.Signature) != ed25519.SignatureSize || !ed25519.Verify(s.identity.PublicKey, projectionSigning(r.Body), r.Signature) || b.Scope.Endpoint.String() != endpoint || b.Scope.BindingID != binding || b.Scope.Endpoint.IsOffer() || b.Scope.Endpoint.Domain() != s.identity.Namespace || b.Generation != generation || !hexHash(b.RequestID) || !hexHash(b.RequestDigest) || !validBatchLimits(b.Limits) || len(b.PrivateConfig) == 0 || len(b.PrivateConfig) > b.Limits.MaxValueBytes || len(b.Rows) > b.Limits.MaxChanges || b.RegistryAfterSequence-b.RegistryBeforeSequence != uint64(len(b.Rows)) {
			return invalid("Private descriptor signed scope/history mismatch")
		}
		var previousGeneration uint64
		var previousHead, previousLimits, previousConfig []byte
		var count, total int64
		e = scratch.QueryRowContext(ctx, "SELECT generation,head,limits,rows,bytes,config FROM projection_verified_heads WHERE endpoint=? AND binding=?", endpoint, binding).Scan(&previousGeneration, &previousHead, &previousLimits, &count, &total, &previousConfig)
		limitsRaw, _ := json.Marshal(b.Limits)
		if errors.Is(e, sql.ErrNoRows) {
			previousHead = make([]byte, 32)
		} else if e != nil {
			return e
		} else if !bytes.Equal(previousLimits, limitsRaw) || !bytes.Equal(previousConfig, b.PrivateConfig) {
			return invalid("Private descriptor limits history changed")
		}
		if len(b.Rows) == 0 && generation != 1 {
			return invalid("Invalid repeated empty projection initialization")
		}
		if generation != previousGeneration+1 || b.Scope.ExpectedProjectionRevision != previousGeneration || !bytes.Equal(previousHead, b.Previous[:]) {
			return invalid("Private descriptor generation/head mismatch")
		}
		var parentRev, parentAction string
		var parentBindings []byte
		if scratch.QueryRowContext(ctx, "SELECT revision,action,bindings FROM public_versions WHERE ref=? AND sequence<=? ORDER BY sequence DESC LIMIT 1", endpoint, b.RegistryBeforeSequence).Scan(&parentRev, &parentAction, &parentBindings) != nil || parentRev != string(b.Scope.ExpectedEndpointRevision) || parentAction != "endpoint.publish" {
			return invalid("Private descriptor historical endpoint mismatch")
		}
		var summaries []fabric.BindingSummary
		if fabric.DecodeJSON(parentBindings, &summaries) != nil {
			return invalid("Private descriptor historical bindings invalid")
		}
		found := false
		for _, summary := range summaries {
			found = found || summary.ID == binding
		}
		if !found {
			return invalid("Private descriptor historical binding absent")
		}
		for _, anchor := range []struct {
			sequence uint64
			head     [32]byte
		}{{b.RegistryBeforeSequence, b.RegistryBeforeHead}, {b.RegistryAfterSequence, b.RegistryAfterHead}} {
			var actual []byte
			if scratch.QueryRowContext(ctx, "SELECT head FROM public_versions WHERE sequence=?", anchor.sequence).Scan(&actual) != nil || !bytes.Equal(actual, anchor.head[:]) {
				return invalid("Private descriptor original public head association mismatch")
			}
		}
		// Retirement first frees only the active selector slot, preserving identity.
		for _, row := range b.Rows {
			if row.Retired {
				if _, e = scratch.ExecContext(ctx, "UPDATE projection_verified_rows SET retired=1 WHERE endpoint=? AND binding=? AND ref=?", endpoint, binding, row.Ref.String()); e != nil {
					return e
				}
			}
		}
		for i, row := range b.Rows {
			if row.Ref.Endpoint() != b.Scope.Endpoint || !row.Ref.IsOffer() || !hexHash(row.Selector) || row.OfferRevision == "" || len(row.Value) == 0 || len(row.Value) > b.Limits.MaxValueBytes || (i > 0 && b.Rows[i-1].Ref.String() >= row.Ref.String()) {
				return invalid("Private descriptor row scope/order mismatch")
			}
			var action, offerBinding, expected string
			var sequence uint64
			if scratch.QueryRowContext(ctx, "SELECT action,binding,expected,sequence FROM public_versions WHERE ref=? AND revision=?", row.Ref.String(), row.OfferRevision).Scan(&action, &offerBinding, &expected, &sequence) != nil || sequence <= b.RegistryBeforeSequence || sequence > b.RegistryAfterSequence || (row.Retired && action != "offer.retire") || (!row.Retired && (action != "offer.publish" || offerBinding != binding)) {
				return invalid("Private projection lacks exact genuine offer mutation")
			}
			var oldRaw []byte
			var oldCost int64
			e = scratch.QueryRowContext(ctx, "SELECT row,cost FROM projection_verified_rows WHERE endpoint=? AND binding=? AND ref=?", endpoint, binding, row.Ref.String()).Scan(&oldRaw, &oldCost)
			if e == nil {
				var old BindingProjectionRow
				if fabric.DecodeJSONWithLimits(oldRaw, &old, fabric.WireLimits{MaxBytes: 2 << 20, MaxDepth: 64, MaxMembers: 4096}) != nil || old.Retired || old.Selector != row.Selector || expected != string(old.OfferRevision) {
					return invalid("Private projection relabel/tombstone/CAS history violation")
				}
			} else if errors.Is(e, sql.ErrNoRows) {
				if row.Retired || expected != "" {
					return invalid("Private projection history begins with existing/retired identity")
				}
				count++
			} else {
				return e
			}
			cost := projectionCost(row)
			total += cost - oldCost
			if count > int64(b.Limits.MaxRows) || total < 0 || total > b.Limits.MaxBytes {
				return invalid("Private descriptor history exceeds retained bounds")
			}
			rowRaw, _ := json.Marshal(row)
			if _, e = scratch.ExecContext(ctx, "INSERT INTO projection_verified_rows VALUES(?,?,?,?,?,?,?) ON CONFLICT(endpoint,binding,ref) DO UPDATE SET retired=excluded.retired,row=excluded.row,cost=excluded.cost", endpoint, binding, row.Ref.String(), row.Selector, row.Retired, rowRaw, cost); e != nil {
				return invalid("Private descriptor active selector collision")
			}
		}
		digest := projectionHash(r)
		if _, e = scratch.ExecContext(ctx, "INSERT INTO projection_verified_heads VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(endpoint,binding) DO UPDATE SET generation=excluded.generation,head=excluded.head,rows=excluded.rows,bytes=excluded.bytes", endpoint, binding, generation, digest[:], limitsRaw, count, total, b.PrivateConfig); e != nil {
			return e
		}
	}
	for _, table := range []string{"heads", "rows"} {
		var actual, verified int64
		if s.db.QueryRowContext(ctx, "SELECT count(*) FROM descriptor_projection_"+table).Scan(&actual) != nil || scratch.QueryRowContext(ctx, "SELECT count(*) FROM projection_verified_"+table).Scan(&verified) != nil || actual != verified {
			return invalid("Private descriptor materialization count mismatch")
		}
	}
	heads, e := s.db.QueryContext(ctx, "SELECT endpoint,binding,generation,head,limits,rows,bytes,config FROM descriptor_projection_heads")
	if e != nil {
		return e
	}
	for heads.Next() {
		var endpoint, binding string
		var gen, count, total uint64
		var head, limits, config []byte
		if e = heads.Scan(&endpoint, &binding, &gen, &head, &limits, &count, &total, &config); e != nil {
			heads.Close()
			return e
		}
		var vg, vc, vt uint64
		var vh, vl, configVerified []byte
		if scratch.QueryRowContext(ctx, "SELECT generation,head,limits,rows,bytes,config FROM projection_verified_heads WHERE endpoint=? AND binding=?", endpoint, binding).Scan(&vg, &vh, &vl, &vc, &vt, &configVerified) != nil || gen != vg || count != vc || total != vt || !bytes.Equal(head, vh) || !bytes.Equal(limits, vl) || !bytes.Equal(config, configVerified) {
			heads.Close()
			return invalid("Private descriptor materialized head differs from signed history")
		}
	}
	e = heads.Err()
	heads.Close()
	if e != nil {
		return e
	}
	rows, e := s.db.QueryContext(ctx, "SELECT endpoint,binding,ref,selector,retired,CASE WHEN length(row)<=2097152 THEN row END,cost FROM descriptor_projection_rows")
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var endpoint, binding, ref, selector string
		var retired bool
		var raw []byte
		var cost int64
		if e = rows.Scan(&endpoint, &binding, &ref, &selector, &retired, &raw, &cost); e != nil {
			return e
		}
		var vs string
		var vr bool
		var vb []byte
		var vc int64
		if scratch.QueryRowContext(ctx, "SELECT selector,retired,row,cost FROM projection_verified_rows WHERE endpoint=? AND binding=? AND ref=?", endpoint, binding, ref).Scan(&vs, &vr, &vb, &vc) != nil || selector != vs || retired != vr || cost != vc || sha256.Sum256(raw) != sha256.Sum256(vb) {
			return invalid("Unsigned private descriptor projection mutation")
		}
	}
	return rows.Err()
}
