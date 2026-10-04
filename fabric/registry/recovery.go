package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/pagnet-code/pagnet/fabric"
)

// Recovery verification streams signed records into a private temporary SQLite
// projection. It never accumulates all descriptor bodies in process memory.
// Scratch transactions are not authority/admission receipts and are discarded.
func (s *Store) newRecoveryProjection(ctx context.Context) (*sql.DB, *sql.Tx, func(), error) {
	paths, e := filepath.Glob(filepath.Join(s.dir, ".verify-*.sqlite*"))
	if e != nil {
		return nil, nil, nil, e
	}
	for _, p := range paths {
		if e = os.Remove(p); e != nil && !os.IsNotExist(e) {
			return nil, nil, nil, e
		}
	}
	f, e := os.CreateTemp(s.dir, ".verify-*.sqlite")
	if e != nil {
		return nil, nil, nil, e
	}
	path := f.Name()
	if e = f.Close(); e != nil {
		os.Remove(path)
		return nil, nil, nil, e
	}
	db, e := openDB(path, s.options)
	if e != nil {
		os.Remove(path)
		return nil, nil, nil, e
	}
	cleanup := func() { db.Close(); os.Remove(path); os.Remove(path + "-journal") }
	if _, e = db.ExecContext(ctx, `PRAGMA cache_size=-2048; CREATE TABLE verified(ref TEXT PRIMARY KEY,domain TEXT,parent TEXT,kind TEXT,revision TEXT,retired INTEGER,digest BLOB,owner TEXT,mutation BLOB,bindings BLOB,offer_binding TEXT); CREATE INDEX verified_parent ON verified(parent,retired);`); e != nil {
		cleanup()
		return nil, nil, nil, e
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		cleanup()
		return nil, nil, nil, e
	}
	return db, tx, func() { tx.Rollback(); cleanup() }, nil
}
func (s *Store) verifyLedgerStream(ctx context.Context) error {
	var count, total, claimedCount, claimedTotal int64
	if e := s.db.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(length(record)),0) FROM ledger").Scan(&count, &total); e != nil {
		return e
	}
	if e := s.db.QueryRowContext(ctx, "SELECT records,bytes FROM ledger_budget WHERE singleton=1").Scan(&claimedCount, &claimedTotal); e != nil {
		return e
	}
	projectionCount, projectionBytes, e := s.descriptorProjectionUsage(ctx)
	if e != nil {
		return e
	}
	count += projectionCount
	total += projectionBytes
	if count != claimedCount || total != claimedTotal || uint64(count) > s.options.Limits.MaxRecords || total > s.options.Limits.MaxLedgerBytes {
		return invalid("signed ledger quota counters are inconsistent")
	}
	keys := map[string][]byte{s.identity.Namespace: s.identity.PublicKey}
	owners := map[string]string{s.identity.Namespace: s.identity.Owner.Ref}
	rows, e := s.db.QueryContext(ctx, "SELECT domain,CASE WHEN length(genesis)<=65536 THEN genesis END FROM pins")
	if e != nil {
		return e
	}
	for rows.Next() {
		var d string
		var raw []byte
		if e = rows.Scan(&d, &raw); e != nil {
			break
		}
		var g GenesisRecord
		if e = fabric.DecodeJSON(raw, &g); e != nil {
			break
		}
		b, x := decodeGenesis(g)
		if x != nil {
			e = x
			break
		}
		if b.Namespace != d || d == s.identity.Namespace {
			e = invalid("foreign authority pin mismatch")
			break
		}
		keys[d] = b.PublicKey
		owners[d] = b.Owner.Ref
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return e
	}
	_, scratch, cleanup, e := s.newRecoveryProjection(ctx)
	if e != nil {
		return e
	}
	defer cleanup()
	rows, e = s.db.QueryContext(ctx, "SELECT domain,sequence,CASE WHEN length(record)<=? THEN record END,head FROM ledger ORDER BY domain,sequence", s.options.Limits.MaxPayloadBytes+65536)
	if e != nil {
		return e
	}
	var currentDomain string
	var sequence uint64
	var previous [32]byte
	for rows.Next() {
		var domain string
		var seq uint64
		var raw, storedHead []byte
		if e = rows.Scan(&domain, &seq, &raw, &storedHead); e != nil {
			break
		}
		if domain != currentDomain {
			currentDomain = domain
			sequence = 0
			previous = [32]byte{}
		}
		var r Record
		if e = s.decode(raw, &r); e != nil {
			break
		}
		o, x := objectFromRecord(r, keys[domain], s.options.Limits)
		if x != nil {
			e = x
			break
		}
		if r.Frame.Sequence != seq || seq != sequence+1 || r.Frame.PreviousHeadDigest != previous {
			e = invalid("signed ledger sequence rollback or fork")
			break
		}
		var oldRevision fabric.Revision
		var oldRetired bool
		x = scratch.QueryRowContext(ctx, "SELECT revision,retired FROM verified WHERE ref=?", o.ref).Scan(&oldRevision, &oldRetired)
		exists := x == nil
		if x != nil && !errors.Is(x, sql.ErrNoRows) {
			e = x
			break
		}
		if exists && (oldRetired || oldRevision != r.Frame.ExpectedPriorRevision) || !exists && r.Frame.ExpectedPriorRevision != "" {
			e = invalid("signed ledger CAS or tombstone conflict")
			break
		}
		var bindings []byte
		var offerBinding string
		if o.kind == "endpoint" && !o.retired {
			var d fabric.EndpointDescriptor
			if e = s.decode(o.payload, &d); e != nil {
				break
			}
			ids := map[string]bool{}
			for _, b := range d.Bindings {
				ids[b.ID] = true
			}
			bindings, _ = json.Marshal(ids)
			children, x := scratch.QueryContext(ctx, "SELECT offer_binding FROM verified WHERE parent=? AND retired=0", o.ref)
			if x != nil {
				e = x
				break
			}
			for children.Next() {
				var id string
				if e = children.Scan(&id); e != nil {
					break
				}
				if !ids[id] {
					e = invalid("signed endpoint removes a live offer binding")
					break
				}
			}
			if e == nil {
				e = children.Err()
			}
			children.Close()
			if e != nil {
				break
			}
		}
		if o.kind == "offer" {
			var parentRetired bool
			var rawBindings []byte
			if e = scratch.QueryRowContext(ctx, "SELECT retired,bindings FROM verified WHERE ref=?", o.parent).Scan(&parentRetired, &rawBindings); e != nil || parentRetired {
				e = invalid("signed offer has no active endpoint")
				break
			}
			if !o.retired {
				var d fabric.OfferDescriptor
				if e = s.decode(o.payload, &d); e != nil {
					break
				}
				offerBinding = d.BindingID
				var ids map[string]bool
				if e = fabric.DecodeJSON(rawBindings, &ids); e != nil {
					break
				}
				if !ids[offerBinding] {
					e = invalid("signed offer binding is not published by endpoint")
					break
				}
			}
		}
		h, x := recordHash(r)
		if x != nil {
			e = x
			break
		}
		if !bytes.Equal(storedHead, h[:]) {
			e = invalid("stored signed head mismatch")
			break
		}
		digest := digestForObject(o.payload)
		if _, e = scratch.ExecContext(ctx, `INSERT INTO verified VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(ref) DO UPDATE SET revision=excluded.revision,retired=excluded.retired,digest=excluded.digest,mutation=excluded.mutation,bindings=excluded.bindings,offer_binding=excluded.offer_binding`, o.ref, o.domain, o.parent, o.kind, o.revision, o.retired, digest[:], owners[domain], o.mutation, bindings, offerBinding); e != nil {
			break
		}
		sequence = seq
		previous = h
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return e
	}
	rows, e = s.db.QueryContext(ctx, "SELECT ref,domain,parent,kind,revision,retired,CASE WHEN length(payload)<=? THEN payload END,owner,mutation FROM objects", s.options.Limits.MaxPayloadBytes)
	if e != nil {
		return e
	}
	defer rows.Close()
	actualCount := int64(0)
	for rows.Next() {
		var o storedObject
		if e = rows.Scan(&o.ref, &o.domain, &o.parent, &o.kind, &o.revision, &o.retired, &o.payload, &o.owner, &o.mutation); e != nil {
			return e
		}
		var domain, parent, kind, owner string
		var revision fabric.Revision
		var retired bool
		var digest, mutation []byte
		if e = scratch.QueryRowContext(ctx, "SELECT domain,parent,kind,revision,retired,digest,owner,mutation FROM verified WHERE ref=?", o.ref).Scan(&domain, &parent, &kind, &revision, &retired, &digest, &owner, &mutation); e != nil {
			return invalid("materialized reference has no signed source")
		}
		h := digestForObject(o.payload)
		if o.payload == nil || o.domain != domain || o.parent != parent || o.kind != kind || o.revision != revision || o.retired != retired || o.owner != owner || !bytes.Equal(h[:], digest) || !bytes.Equal(o.mutation, mutation) {
			return invalid("materialized registry differs from exact signed ledger")
		}
		actualCount++
	}
	if e = rows.Err(); e != nil {
		return e
	}
	var expectedCount int64
	if e = scratch.QueryRowContext(ctx, "SELECT COUNT(*) FROM verified").Scan(&expectedCount); e != nil {
		return e
	}
	if actualCount != expectedCount {
		return invalid("materialized registry is incomplete")
	}
	return nil
}

func digestForObject(raw []byte) [32]byte { return sha256.Sum256(raw) }
