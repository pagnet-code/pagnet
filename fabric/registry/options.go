package registry

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/pagnet-code/pagnet/fabric"
	"math"
)

// Limits are local finite storage admissions, not permanent protocol capacities.
// Reopening with smaller limits rejects retained state instead of purging identity.
type Limits struct {
	MaxRecords       uint64
	MaxLedgerBytes   int64
	MaxPayloadBytes  int
	MaxDatabaseBytes int64
}
type Options struct{ Limits Limits }

func DefaultOptions() Options {
	return Options{Limits: Limits{MaxRecords: maxRecords, MaxLedgerBytes: maxLedgerBytes, MaxPayloadBytes: maxPayload, MaxDatabaseBytes: 256 << 20}}
}
func (o Options) validate() error {
	l := o.Limits
	if l.MaxRecords == 0 || l.MaxRecords > math.MaxInt64 || l.MaxLedgerBytes < 1 || l.MaxPayloadBytes < 1 || l.MaxPayloadBytes > math.MaxInt-65536 || l.MaxDatabaseBytes < 65536 {
		return invalid("registry storage limits must be positive finite representable bounds")
	}
	return nil
}
func (s *Store) decode(raw []byte, out any) error {
	return fabric.DecodeJSONWithLimits(raw, out, fabric.WireLimits{MaxBytes: s.options.Limits.MaxPayloadBytes + 65536, MaxDepth: 64, MaxMembers: 4096})
}
func configureDatabase(db *sql.DB, options Options) error {
	var pageSize int64
	if e := db.QueryRow("PRAGMA page_size").Scan(&pageSize); e != nil {
		return e
	}
	if pageSize < 1 {
		return invalid("invalid database page size")
	}
	pages := options.Limits.MaxDatabaseBytes / pageSize
	var actual int64
	if e := db.QueryRow(fmt.Sprintf("PRAGMA max_page_count=%d", pages)).Scan(&actual); e != nil {
		return e
	}
	if actual != pages {
		return invalid("selected database capacity is unsupported or below retained pages")
	}
	return nil
}
func BootstrapWithOptions(ctx context.Context, dir string, owner fabric.Principal, options Options) (*Store, error) {
	return bootstrapWithOptions(ctx, dir, owner, nil, options)
}
func OpenWithOptions(ctx context.Context, dir string, options Options) (*Store, error) {
	return openWithOptions(ctx, dir, options)
}
