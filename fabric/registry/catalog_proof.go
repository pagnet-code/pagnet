package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/fabric"
)

const catalogProofIndex = `CREATE INDEX IF NOT EXISTS catalog_exact_record ON ledger(domain,json_extract(record,'$.frame.ExactTargetRef'),json_extract(record,'$.frame.NewRevision'))`
const catalogProofQuery = `SELECT record FROM ledger INDEXED BY catalog_exact_record WHERE domain=? AND json_extract(record,'$.frame.ExactTargetRef')=? AND json_extract(record,'$.frame.NewRevision')=? LIMIT 2`

// CatalogExporter exports one exact current signed object, never a domain's
// history. The caller must separately select which network may receive it.
// A signed object authenticates a descriptor; it does not grant invocation
// authority, establish trust in a foreign root, or prove remote freshness.
type CatalogExporter struct{ store *Store }

// NewCatalogExporter explicitly installs the indexed lookup while holding the
// authoritative writer lock. Read hot paths never construct indexes or scan
// ledger history. Existing registry writes maintain this index automatically.
func NewCatalogExporter(ctx context.Context, s *Store, owner fabric.ExecutionContext) (*CatalogExporter, error) {
	if s == nil {
		return nil, invalid("catalog export requires an authoritative registry")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.authorize(owner); err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx, catalogProofIndex); err != nil {
		return nil, err
	}
	return &CatalogExporter{store: s}, nil
}

// Exact returns the retained signed record only if this is still the current
// revision, including a tombstone. The explicit revision prevents accidental
// substitution of newer metadata during encrypted publication retries.
func (x *CatalogExporter) Exact(ctx context.Context, ref fabric.EndpointRef, revision fabric.Revision) (Record, error) {
	var out Record
	if x == nil || x.store == nil || revision == "" {
		return out, invalid("catalog export requires an exact revision")
	}
	s := x.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return out, errors.New("registry closed")
	}
	if _, err := fabric.ParseEndpointRef(ref.String()); err != nil {
		return out, err
	}
	if ref.Domain() != s.identity.Namespace {
		return out, invalid("catalog export requires the original local authority")
	}
	o, err := loadObject(ctx, s.db, ref.String())
	if errors.Is(err, sql.ErrNoRows) {
		return out, fabric.NewError(fabric.CodeNotFound, "catalog reference not found")
	}
	if err != nil {
		return out, err
	}
	if o.revision != revision {
		return out, conflict("catalog revision is stale")
	}
	rows, err := s.db.QueryContext(ctx, catalogProofQuery, s.identity.Namespace, ref.String(), string(revision))
	if err != nil {
		return out, err
	}
	defer rows.Close()
	var raw []byte
	if !rows.Next() {
		if err = rows.Err(); err != nil {
			return out, err
		}
		return out, invalid("current catalog object has no signed record")
	}
	if err = rows.Scan(&raw); err != nil {
		return out, err
	}
	if rows.Next() {
		return out, invalid("catalog revision has ambiguous signed history")
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	if err = json.Unmarshal(raw, &out); err != nil {
		return Record{}, err
	}
	signed, err := objectFromRecord(out, s.identity.PublicKey, s.options.Limits)
	if err != nil || signed.ref != o.ref || signed.revision != o.revision || signed.retired != o.retired || string(signed.payload) != string(o.payload) {
		return Record{}, invalid("catalog projection differs from signed original history")
	}
	return out, nil
}

// VerifyCatalogRecord authenticates a selectively shared descriptor against an
// explicitly trusted genesis. It deliberately does not import skipped domain
// history or establish a pin. Callers must maintain their own network-specific
// monotonic projection and verify freshness at invocation time.
func VerifyCatalogRecord(genesis GenesisRecord, record Record, ref fabric.EndpointRef, revision fabric.Revision) error {
	if revision == "" || record.Frame.ExactTargetRef != ref || record.Frame.NewRevision != revision {
		return invalid("catalog routing stub differs from signed descriptor")
	}
	root, err := decodeGenesis(genesis)
	if err != nil {
		return err
	}
	if ref.Domain() != root.Namespace {
		return invalid("catalog descriptor differs from explicitly trusted root")
	}
	_, err = objectFromRecord(record, root.PublicKey, DefaultOptions().Limits)
	return err
}
