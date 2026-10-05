package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/fabric"
)

// This native key codec never marshals an invalid zero EndpointRef to represent
// global controller scope. Endpoint-bearing kinds retain canonical exact refs.
func (k AuthorityKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Kind     NativeAuthorityKind `json:"kind"`
		Endpoint string              `json:"endpoint,omitempty"`
		ID       string              `json:"id"`
	}{k.Kind, k.Endpoint.String(), k.ID})
}
func (k *AuthorityKey) UnmarshalJSON(raw []byte) error {
	var v struct {
		Kind     NativeAuthorityKind `json:"kind"`
		Endpoint string              `json:"endpoint,omitempty"`
		ID       string              `json:"id"`
	}
	if e := fabric.DecodeJSON(raw, &v); e != nil {
		return e
	}
	next := AuthorityKey{Kind: v.Kind, ID: v.ID}
	if v.Endpoint != "" {
		ref, e := fabric.ParseEndpointRef(v.Endpoint)
		if e != nil {
			return e
		}
		next.Endpoint = ref
	}
	if !validAuthorityKind(next.Kind) || !text(next.ID, 256, false) || globalAuthorityKind(next.Kind) && v.Endpoint != "" || !globalAuthorityKind(next.Kind) && v.Endpoint == "" {
		return invalid("Malformed native authority key")
	}
	*k = next
	return nil
}

// Verification streams original signed records into private scratch SQLite,
// compares immutable CAS/head history and current materializations, then discards
// scratch state. Native history is never loaded as one in-memory map.
func (s *Store) verifyNativeAuthority(ctx context.Context) error {
	var count, total, sequence, claimedCount, claimedTotal int64
	var head []byte
	if e := s.db.QueryRowContext(ctx, "SELECT count(*),COALESCE(sum(length(record)),0) FROM native_authority_log").Scan(&count, &total); e != nil {
		return e
	}
	if e := s.db.QueryRowContext(ctx, "SELECT sequence,head,records,bytes FROM native_authority_head WHERE singleton=1").Scan(&sequence, &head, &claimedCount, &claimedTotal); e != nil {
		return e
	}
	if count != claimedCount || count != sequence || total != claimedTotal || count < 0 || uint64(count) > s.options.Limits.MaxRecords || total > s.options.Limits.MaxLedgerBytes || len(head) != 32 {
		return invalid("Native authority head/quota mismatch")
	}
	_, scratch, cleanup, e := s.newRecoveryProjection(ctx)
	if e != nil {
		return e
	}
	defer cleanup()
	if _, e = scratch.ExecContext(ctx, "CREATE TABLE native_verified(key TEXT PRIMARY KEY,revision INTEGER,retired INTEGER,digest BLOB)"); e != nil {
		return e
	}
	rows, e := s.db.QueryContext(ctx, "SELECT sequence,CASE WHEN length(record)<=? THEN record END FROM native_authority_log ORDER BY sequence", s.options.Limits.MaxPayloadBytes*2+65536)
	if e != nil {
		return e
	}
	defer rows.Close()
	identity := AuthorityIdentity{s.identity.Namespace, s.identity.StoreID, s.identity.Owner, bytes.Clone(s.identity.PublicKey), 1}
	var previous [32]byte
	var next uint64 = 1
	var extensionGeneration, pendingExtension uint64
	for rows.Next() {
		var seq uint64
		var raw []byte
		if e = rows.Scan(&seq, &raw); e != nil {
			return e
		}
		var record AuthorityRecord
		if e = s.decodeAuthority(raw, &record); e != nil {
			return e
		}
		if seq != next || record.Sequence != seq || record.PreviousHead != previous || len(record.Value) > s.options.Limits.MaxPayloadBytes || VerifyAuthorityRecord(identity, record) != nil {
			return invalid("Native authority signed history mismatch")
		}
		if pendingExtension != 0 && record.Key.Kind != AuthorityPurposeGeneration {
			return invalid("Extension mutation lacks intrinsic signed generation")
		}
		if record.Key.Kind == AuthorityExtensionConfiguration {
			pendingExtension = record.Sequence
		} else if record.Key.Kind == AuthorityPurposeGeneration {
			if validatePurposeGeneration(record) != nil || pendingExtension == 0 || record.Sequence != pendingExtension+1 || record.Revision != extensionGeneration+1 {
				return invalid("Intrinsic extension generation history mismatch")
			}
			extensionGeneration++
			pendingExtension = 0
		}
		var payload any
		if e = s.decode(record.Value, &payload); e != nil {
			return e
		}
		var revision uint64
		var retired bool
		e = scratch.QueryRowContext(ctx, "SELECT revision,retired FROM native_verified WHERE key=?", record.Key.string()).Scan(&revision, &retired)
		if errors.Is(e, sql.ErrNoRows) {
			if record.PreviousRevision != 0 || record.Retired {
				return invalid("Native authority history begins with invalid retirement/CAS")
			}
		} else if e != nil {
			return e
		} else if retired || revision != record.PreviousRevision {
			return invalid("Native authority tombstone or CAS history violated")
		}
		digest := sha256.Sum256(raw)
		if _, e = scratch.ExecContext(ctx, "INSERT INTO native_verified VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET revision=excluded.revision,retired=excluded.retired,digest=excluded.digest", record.Key.string(), record.Revision, record.Retired, digest[:]); e != nil {
			return e
		}
		previous = digest
		next++
	}
	if pendingExtension != 0 {
		return invalid("Extension mutation lacks intrinsic signed generation")
	}
	if rows.Err() != nil {
		return rows.Err()
	}
	if e = rows.Close(); e != nil {
		return e
	}
	if !bytes.Equal(previous[:], head) {
		return invalid("Native authority head differs from signed history")
	}
	var expected int64
	if e = scratch.QueryRowContext(ctx, "SELECT count(*) FROM native_verified").Scan(&expected); e != nil {
		return e
	}
	rows, e = s.db.QueryContext(ctx, "SELECT key,revision,retired,CASE WHEN length(record)<=? THEN record END FROM native_authority_state", s.options.Limits.MaxPayloadBytes*2+65536)
	if e != nil {
		return e
	}
	defer rows.Close()
	var actual int64
	for rows.Next() {
		actual++
		var key string
		var revision, verifiedRevision uint64
		var retired, verifiedRetired bool
		var raw, digest []byte
		if e = rows.Scan(&key, &revision, &retired, &raw); e != nil {
			return e
		}
		if e = scratch.QueryRowContext(ctx, "SELECT revision,retired,digest FROM native_verified WHERE key=?", key).Scan(&verifiedRevision, &verifiedRetired, &digest); e != nil {
			return e
		}
		h := sha256.Sum256(raw)
		if len(raw) == 0 || revision != verifiedRevision || retired != verifiedRetired || !bytes.Equal(h[:], digest) {
			return invalid("Native authority materialized state differs from signed history")
		}
	}
	if rows.Err() != nil {
		return rows.Err()
	}
	if actual != expected {
		return invalid("Native authority materialized row count differs")
	}
	return nil
}
