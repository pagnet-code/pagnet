package registry

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/fabric"
)

// PinForeign is explicit owner trust establishment. Imported roots remain read-only.
func (s *Store) PinForeign(ctx context.Context, c fabric.ExecutionContext, expectedNamespace string, g GenesisRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.authorize(c); e != nil {
		return e
	}
	body, e := decodeGenesis(g)
	if e != nil {
		return e
	}
	if body.Namespace != expectedNamespace || body.Namespace == s.identity.Namespace {
		return invalid("foreign root does not match explicitly selected namespace")
	}
	raw, e := json.Marshal(g)
	if e != nil {
		return e
	}
	var old []byte
	e = s.db.QueryRowContext(ctx, "SELECT genesis FROM pins WHERE domain=?", body.Namespace).Scan(&old)
	if e == nil {
		if !bytes.Equal(old, raw) {
			return conflict("trusted domain genesis cannot be replaced")
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	_, e = s.db.ExecContext(ctx, "INSERT INTO pins VALUES(?,?)", body.Namespace, raw)
	return e
}

// Import commits a bounded exact signed chain under a previously pinned root.
// Offline replicas cannot establish fresh remote invocation or revocation state.
func (s *Store) Import(ctx context.Context, c fabric.ExecutionContext, records []Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.authorize(c); e != nil {
		return e
	}
	if len(records) < 1 || len(records) > 32 {
		return invalid("invalid import packet bounds")
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, r := range records {
		domain := r.Frame.IssuerNamespace
		if domain == s.identity.Namespace {
			return invalid("cannot import writable local ownership")
		}
		var raw []byte
		if e = tx.QueryRowContext(ctx, "SELECT genesis FROM pins WHERE domain=?", domain).Scan(&raw); e != nil {
			return fabric.NewError(fabric.CodeUnauthenticated, "foreign domain is not explicitly pinned")
		}
		var g GenesisRecord
		if e = fabric.DecodeJSON(raw, &g); e != nil {
			return e
		}
		b, e := decodeGenesis(g)
		if e != nil {
			return e
		}
		o, e := objectFromRecord(r, b.PublicKey, s.options.Limits)
		if e != nil {
			return e
		}
		o.owner = b.Owner.Ref
		encoded, e := json.Marshal(r)
		if e != nil {
			return e
		}
		var existing []byte
		e = tx.QueryRowContext(ctx, "SELECT record FROM ledger WHERE domain=? AND sequence=?", domain, r.Frame.Sequence).Scan(&existing)
		if e == nil {
			if !bytes.Equal(existing, encoded) {
				return conflict("signed import forks pinned history")
			}
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		seq, previous, e := head(ctx, tx, domain)
		if e != nil {
			return e
		}
		if r.Frame.Sequence != seq+1 || r.Frame.PreviousHeadDigest != previous {
			return conflict("signed import sequence or previous head mismatch")
		}
		old, e := loadObject(ctx, tx, o.ref)
		exists := e == nil
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if exists && (old.retired || old.revision != r.Frame.ExpectedPriorRevision) || !exists && r.Frame.ExpectedPriorRevision != "" {
			return conflict("signed import conflicts with CAS or retained tombstone")
		}
		if e = s.validateImportedTransition(ctx, tx, o); e != nil {
			return e
		}
		if e = s.insertRecord(ctx, tx, r, o, true); e != nil {
			return e
		}
	}
	return tx.Commit()
}
