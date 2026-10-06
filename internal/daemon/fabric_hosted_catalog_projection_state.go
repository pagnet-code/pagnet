package daemon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

// ErrHostedCatalogCapacity is a CAPACITY refusal of a whole page: the
// per-network projection limits are hard bounds enforced before retention,
// so an over-limit page is refused intact (never partially accepted).
var ErrHostedCatalogCapacity = errors.New("hosted catalog import capacity reached")

// ErrHostedCatalogConflict is a monotonicity violation: the page carries a
// record whose frame sequence does not advance over the retained one (a
// stale revision, a replay with different content, or a revived old profile
// after a tombstone). Nothing from the page is retained.
var ErrHostedCatalogConflict = errors.New("hosted catalog revision conflicts with the retained projection")

// HostedCatalogDefaultMaxRows / HostedCatalogDefaultMaxBytes are the
// product defaults for one network's projection (rows + sealed bytes). The
// trusted composition may lower them; a zero config value selects these
// defaults.
const (
	HostedCatalogDefaultMaxRows  = 4096
	HostedCatalogDefaultMaxBytes = 8 << 20
)

// HostedCatalogRetainedRecord is one verified page record offered for
// retention. It is already authenticated against an explicitly trusted root;
// the state layer only owns monotonicity, capacity and durable retention.
type HostedCatalogRetainedRecord struct {
	Ref           string
	Kind          string // "endpoint" | "offer" (fixed by the ref)
	Revision      fabric.Revision
	Sequence      uint64
	Retired       bool
	RootNamespace string
	// RecordJSON is the canonical re-marshaled signed record: the
	// verification material retained next to the sealed payload.
	RecordJSON []byte
	// Ciphertext/AAD is the descriptor payload SEALED at rest under the
	// network keyring (the pinned AAD carries the epoch); both are nil/""
	// for tombstones, which carry no protected content.
	Ciphertext []byte
	AAD        string
	// DataBytes is the retained byte weight of the row (record + ciphertext).
	DataBytes int
}

// HostedCatalogAcceptedChange is the retention outcome for one page record,
// in page order. A tombstone that replaced a live row carries that row's
// revision in ReplacedRevision — the exact ExpectedRevision a feed delete
// must use — and replays of the same page recompute the same value from the
// retained row (a failed feed is retried truthfully; the projection is the
// source of truth).
type HostedCatalogAcceptedChange struct {
	Ref              string
	Retired          bool
	Changed          bool // false = exact duplicate (idempotent no-op)
	ReplacedRevision fabric.Revision
}

// HostedCatalogProjectionRow is the retained state of one (network, ref)
// projection.
type HostedCatalogProjectionRow struct {
	NetworkID        string
	Ref              string
	RootNamespace    string
	Kind             string
	Revision         fabric.Revision
	Sequence         uint64
	Retired          bool
	ReplacedRevision fabric.Revision
	Record           []byte
	Ciphertext       []byte
	AAD              string
	DataBytes        int
	FirstSeen        time.Time
	LastSeen         time.Time
}

func (s *State) initHostedCatalogProjection() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS hosted_catalog_projection (
 network_id TEXT NOT NULL,ref TEXT NOT NULL,
 root_namespace TEXT NOT NULL,kind TEXT NOT NULL,
 revision TEXT NOT NULL,sequence INTEGER NOT NULL,
 retired INTEGER NOT NULL DEFAULT 0,replaced_revision TEXT NOT NULL DEFAULT '',
 record BLOB NOT NULL,ciphertext BLOB,aad TEXT NOT NULL DEFAULT '',
 data_bytes INTEGER NOT NULL DEFAULT 0,first_at INTEGER NOT NULL,last_at INTEGER NOT NULL,
 PRIMARY KEY (network_id,ref));
 CREATE INDEX IF NOT EXISTS hosted_catalog_projection_network ON hosted_catalog_projection(network_id,retired);
 CREATE TABLE IF NOT EXISTS hosted_catalog_import (
 network_id TEXT PRIMARY KEY,
 cursor TEXT NOT NULL DEFAULT '',
 rows_used INTEGER NOT NULL DEFAULT 0,bytes_used INTEGER NOT NULL DEFAULT 0,
 updated_at INTEGER NOT NULL);`)
	return err
}

const hostedCatalogProjectionSelect = `SELECT network_id,ref,root_namespace,kind,revision,sequence,
 COALESCE(retired,0),COALESCE(replaced_revision,''),COALESCE(record,''),COALESCE(ciphertext,''),
 COALESCE(aad,''),data_bytes,first_at,last_at FROM hosted_catalog_projection`

func scanHostedCatalogProjectionRow(row interface {
	Scan(dest ...any) error
}, r *HostedCatalogProjectionRow) error {
	var record, cipher []byte
	var retired int
	var first, last int64
	if err := row.Scan(&r.NetworkID, &r.Ref, &r.RootNamespace, &r.Kind, &r.Revision, &r.Sequence,
		&retired, &r.ReplacedRevision, &record, &cipher, &r.AAD, &r.DataBytes, &first, &last); err != nil {
		return err
	}
	r.Retired = retired == 1
	r.Record = record
	r.Ciphertext = cipher
	r.FirstSeen = time.UnixMilli(first).UTC()
	r.LastSeen = time.UnixMilli(last).UTC()
	return nil
}

// LoadHostedCatalogCursor returns the network's committed import watermark
// (ok=false when the daemon has never imported the network).
func (s *State) LoadHostedCatalogCursor(ctx context.Context, networkID string) (string, bool, error) {
	var cursor string
	err := s.db.QueryRowContext(ctx, `SELECT cursor FROM hosted_catalog_import WHERE network_id=?`, networkID).Scan(&cursor)
	if err == sql.ErrNoRows {
		return "", false, nil
	} else if err != nil {
		return "", false, err
	}
	return cursor, true, nil
}

// RetainHostedCatalogPage retains one verified page atomically under a
// BEGIN IMMEDIATE writer transaction. The per-ref monotonicity rule mirrors
// the registry ledger's local discipline: a record is accepted only when its
// frame sequence strictly advances over the retained one — a duplicate exact
// record is an idempotent no-op, and after a tombstone only a strictly newer
// sequence (a newer tombstone or an explicit re-publication) is accepted,
// never a revived older profile. The capacity limits are enforced against
// the POST-page totals BEFORE any write: an over-limit page rolls back
// intact (the import row and every projection row stay untouched).
//
// The import cursor is NOT advanced here: the caller advances it (see
// AdvanceHostedCatalogCursor) only after the configured feed has consumed
// the page, so a failed feed re-fetches and re-feeds the same page.
func (s *State) RetainHostedCatalogPage(ctx context.Context, networkID string, maxRows, maxBytes int, records []HostedCatalogRetainedRecord) ([]HostedCatalogAcceptedChange, error) {
	if maxRows < 1 || maxBytes < 1 || len(records) == 0 || len(records) > 64 {
		return nil, ErrHostedCatalogConflict
	}
	seen := map[string]bool{}
	for _, r := range records {
		if seen[r.Ref] {
			return nil, ErrHostedCatalogConflict // one page may not carry two records for one ref
		}
		seen[r.Ref] = true
	}
	type decision struct {
		record   HostedCatalogRetainedRecord
		exists   bool
		changed  bool
		replaced fabric.Revision
	}
	var out []HostedCatalogAcceptedChange
	err := s.hostedCatalogWrite(ctx, func(conn *sql.Conn) error {
		var rowsUsed, bytesUsed int
		e := conn.QueryRowContext(ctx, `SELECT rows_used,bytes_used FROM hosted_catalog_import WHERE network_id=?`, networkID).Scan(&rowsUsed, &bytesUsed)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		// Read every existing row for this page, then decide the whole page
		// (a page is atomic: one refused record refuses the page).
		decisions := make([]decision, 0, len(records))
		newRows := 0
		newBytes := 0
		for _, r := range records {
			var existing HostedCatalogProjectionRow
			e := scanHostedCatalogProjectionRow(
				conn.QueryRowContext(ctx, hostedCatalogProjectionSelect+` WHERE network_id=? AND ref=?`, networkID, r.Ref), &existing)
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			exists := e == nil
			d := decision{record: r, exists: exists, changed: true}
			if exists {
				if string(existing.Record) == string(r.RecordJSON) {
					// Exact duplicate record: idempotent no-op (the row, the
					// capacity counters and the timestamps stay untouched).
					d.changed = false
					decisions = append(decisions, d)
					continue
				}
				// A non-advancing sequence for the same ref is a stale
				// revision, a replay with different content, or a revived old
				// profile after a tombstone. The retained row is authoritative.
				if existing.Sequence >= r.Sequence || existing.Kind != r.Kind || existing.RootNamespace != r.RootNamespace {
					return ErrHostedCatalogConflict
				}
				newBytes += r.DataBytes - existing.DataBytes
				if r.Retired && !existing.Retired {
					d.replaced = existing.Revision
				} else if r.Retired {
					d.replaced = existing.ReplacedRevision
				}
			} else {
				newRows++
				newBytes += r.DataBytes
			}
			decisions = append(decisions, d)
		}
		// Hard capacity bounds against the post-page totals, BEFORE any
		// write (the worker stream's capacity discipline: refuse, never
		// partially accept).
		if rowsUsed+newRows > maxRows || bytesUsed+newBytes > maxBytes {
			return ErrHostedCatalogCapacity
		}
		now := time.Now().UTC().UnixMilli()
		for _, d := range decisions {
			if !d.changed {
				continue
			}
			r := d.record
			ciphertext := r.Ciphertext
			if _, err := conn.ExecContext(ctx, `
 INSERT INTO hosted_catalog_projection
  (network_id,ref,root_namespace,kind,revision,sequence,retired,replaced_revision,record,ciphertext,aad,data_bytes,first_at,last_at)
 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
 ON CONFLICT (network_id,ref) DO UPDATE SET
  revision=excluded.revision,sequence=excluded.sequence,retired=excluded.retired,
  replaced_revision=excluded.replaced_revision,record=excluded.record,
  ciphertext=excluded.ciphertext,aad=excluded.aad,data_bytes=excluded.data_bytes,
  last_at=excluded.last_at`,
				networkID, r.Ref, r.RootNamespace, r.Kind, r.Revision, r.Sequence, boolInt(r.Retired),
				string(d.replaced), r.RecordJSON, ciphertext, r.AAD, r.DataBytes, now, now); err != nil {
				return err
			}
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO hosted_catalog_import (network_id,cursor,rows_used,bytes_used,updated_at)
 VALUES(?,?,?, ?, ?)
 ON CONFLICT (network_id) DO UPDATE SET rows_used=excluded.rows_used,bytes_used=excluded.bytes_used,updated_at=excluded.updated_at`,
			networkID, "", rowsUsed+newRows, bytesUsed+newBytes, now); err != nil {
			return err
		}
		for _, d := range decisions {
			out = append(out, HostedCatalogAcceptedChange{Ref: d.record.Ref, Retired: d.record.Retired, Changed: d.changed, ReplacedRevision: d.replaced})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AdvanceHostedCatalogCursor commits the network's import watermark AFTER
// the page has been retained AND the configured feed has consumed it. The
// CAS on the expected old cursor makes a stale concurrent pass fail closed
// instead of rewinding (or skipping) the watermark.
func (s *State) AdvanceHostedCatalogCursor(ctx context.Context, networkID, expected, next string) error {
	return s.hostedCatalogWrite(ctx, func(conn *sql.Conn) error {
		res, err := conn.ExecContext(ctx, `UPDATE hosted_catalog_import SET cursor=?,updated_at=?
 WHERE network_id=? AND cursor=?`,
			next, time.Now().UTC().UnixMilli(), networkID, expected)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrHostedCatalogConflict
		}
		return nil
	})
}

// LookupHostedCatalogProjection returns the retained row for (network, ref)
// (ok=false when the projection has never seen it).
func (s *State) LookupHostedCatalogProjection(ctx context.Context, networkID, ref string) (HostedCatalogProjectionRow, bool, error) {
	var r HostedCatalogProjectionRow
	row := s.db.QueryRowContext(ctx, hostedCatalogProjectionSelect+` WHERE network_id=? AND ref=?`, networkID, ref)
	if err := scanHostedCatalogProjectionRow(row, &r); err == sql.ErrNoRows {
		return HostedCatalogProjectionRow{}, false, nil
	} else if err != nil {
		return HostedCatalogProjectionRow{}, false, err
	}
	return r, true, nil
}

// ListHostedCatalogProjections returns the network's retained rows in ref
// order, bounded (the rebuild seam: a configured index is reproducible from
// the projection alone).
func (s *State) ListHostedCatalogProjections(ctx context.Context, networkID string, limit int) ([]HostedCatalogProjectionRow, error) {
	if limit < 1 || limit > 1024 {
		limit = 1024
	}
	rows, err := s.db.QueryContext(ctx, hostedCatalogProjectionSelect+` WHERE network_id=? ORDER BY ref LIMIT ?`, networkID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostedCatalogProjectionRow
	for rows.Next() {
		var r HostedCatalogProjectionRow
		if err := scanHostedCatalogProjectionRow(rows, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// HostedCatalogImportUsage is the network's retained capacity ledger.
type HostedCatalogImportUsage struct {
	Cursor    string
	RowsUsed  int
	BytesUsed int
	UpdatedAt time.Time
}

// LoadHostedCatalogUsage returns the network's import row (ok=false when the
// daemon has never imported the network).
func (s *State) LoadHostedCatalogUsage(ctx context.Context, networkID string) (HostedCatalogImportUsage, bool, error) {
	var u HostedCatalogImportUsage
	var updated int64
	err := s.db.QueryRowContext(ctx, `SELECT cursor,rows_used,bytes_used,updated_at FROM hosted_catalog_import WHERE network_id=?`, networkID).
		Scan(&u.Cursor, &u.RowsUsed, &u.BytesUsed, &updated)
	if err == sql.ErrNoRows {
		return HostedCatalogImportUsage{}, false, nil
	} else if err != nil {
		return HostedCatalogImportUsage{}, false, err
	}
	u.UpdatedAt = time.UnixMilli(updated).UTC()
	return u, true, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *State) hostedCatalogWrite(ctx context.Context, fn func(*sql.Conn) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(cleanup, `ROLLBACK`)
	}()
	if err = fn(conn); err != nil {
		return err
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("commit hosted catalog projection: %w", err)
	}
	return nil
}
