package registry

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/fabric"
)

type BindingProjectionPage struct {
	PrivateConfig []byte
	Generation    uint64
	Rows          []BindingProjectionRow
	NextCursor    string
}
type projectionCursor struct {
	Endpoint   string
	Binding    string
	Generation uint64
	After      string
}

func (s *Store) ReadBindingProjection(ctx context.Context, owner fabric.ExecutionContext, scope DescriptorBatchScope, cursor string, limit int) (BindingProjectionPage, error) {
	if ctx == nil || limit < 1 || limit > 100 || len(cursor) > 4096 {
		return BindingProjectionPage{}, invalid("Invalid projection page")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.authorize(owner); e != nil {
		return BindingProjectionPage{}, e
	}
	if e := s.validateProjectionScope(ctx, s.db, scope); e != nil {
		return BindingProjectionPage{}, e
	}
	tables, e := projectionTables(ctx, s.db)
	if e != nil {
		return BindingProjectionPage{}, e
	}
	if tables == 0 {
		return BindingProjectionPage{}, fabric.NewError(fabric.CodeNotFound, "Local descriptor projection not initialized")
	}
	var gen uint64
	var config []byte
	e = s.db.QueryRowContext(ctx, "SELECT generation,CASE WHEN length(config)<=1048576 THEN config END FROM descriptor_projection_heads WHERE endpoint=? AND binding=?", scope.Endpoint.String(), scope.BindingID).Scan(&gen, &config)
	if errors.Is(e, sql.ErrNoRows) {
		return BindingProjectionPage{}, fabric.NewError(fabric.CodeNotFound, "Local binding projection not initialized")
	}
	if e != nil {
		return BindingProjectionPage{}, e
	}
	after := ""
	if cursor != "" {
		raw, e := base64.RawURLEncoding.DecodeString(cursor)
		if e != nil {
			return BindingProjectionPage{}, invalid("Invalid projection cursor")
		}
		var c projectionCursor
		if fabric.DecodeJSON(raw, &c) != nil || c.Endpoint != scope.Endpoint.String() || c.Binding != scope.BindingID || c.Generation != gen {
			return BindingProjectionPage{}, conflict("Projection page snapshot changed")
		}
		ref, e := fabric.ParseEndpointRef(c.After)
		if e != nil || ref.Endpoint() != scope.Endpoint || !ref.IsOffer() {
			return BindingProjectionPage{}, invalid("Projection cursor scope differs")
		}
		after = c.After
	}
	rows, e := s.db.QueryContext(ctx, "SELECT CASE WHEN length(row)<=2097152 THEN row END FROM descriptor_projection_rows WHERE endpoint=? AND binding=? AND retired=0 AND ref>? ORDER BY ref LIMIT ?", scope.Endpoint.String(), scope.BindingID, after, limit+1)
	if e != nil {
		return BindingProjectionPage{}, e
	}
	defer rows.Close()
	page := BindingProjectionPage{Generation: gen, PrivateConfig: config}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			return page, e
		}
		if len(page.Rows) == limit {
			c := projectionCursor{scope.Endpoint.String(), scope.BindingID, gen, page.Rows[len(page.Rows)-1].Ref.String()}
			b, _ := json.Marshal(c)
			page.NextCursor = base64.RawURLEncoding.EncodeToString(b)
			break
		}
		var row BindingProjectionRow
		if e = fabric.DecodeJSONWithLimits(raw, &row, fabric.WireLimits{MaxBytes: 2 << 20, MaxDepth: 64, MaxMembers: 4096}); e != nil {
			return page, e
		}
		page.Rows = append(page.Rows, row)
	}
	return page, rows.Err()
}
func (s *Store) LookupBindingProjectionByRef(ctx context.Context, owner fabric.ExecutionContext, scope DescriptorBatchScope, ref fabric.EndpointRef) (BindingProjectionRow, uint64, error) {
	if ctx == nil || !ref.IsOffer() || ref.Endpoint() != scope.Endpoint {
		return BindingProjectionRow{}, 0, invalid("Invalid exact projection ref")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.authorize(owner); e != nil {
		return BindingProjectionRow{}, 0, e
	}
	if e := s.validateProjectionScope(ctx, s.db, scope); e != nil {
		return BindingProjectionRow{}, 0, e
	}
	tables, e := projectionTables(ctx, s.db)
	if e != nil {
		return BindingProjectionRow{}, 0, e
	}
	if tables == 0 {
		return BindingProjectionRow{}, 0, fabric.NewError(fabric.CodeNotFound, "Local descriptor projection not initialized")
	}
	var raw []byte
	var gen uint64
	e = s.db.QueryRowContext(ctx, "SELECT CASE WHEN length(r.row)<=2097152 THEN r.row END,h.generation FROM descriptor_projection_rows r JOIN descriptor_projection_heads h ON h.endpoint=r.endpoint AND h.binding=r.binding WHERE r.endpoint=? AND r.binding=? AND r.ref=?", scope.Endpoint.String(), scope.BindingID, ref.String()).Scan(&raw, &gen)
	if errors.Is(e, sql.ErrNoRows) {
		return BindingProjectionRow{}, 0, fabric.NewError(fabric.CodeStaleReference, "Local MCP offer absent")
	}
	if e != nil {
		return BindingProjectionRow{}, 0, e
	}
	var row BindingProjectionRow
	e = fabric.DecodeJSONWithLimits(raw, &row, fabric.WireLimits{MaxBytes: 2 << 20, MaxDepth: 64, MaxMembers: 4096})
	if e != nil {
		return row, 0, e
	}
	if row.Retired {
		return row, gen, fabric.NewError(fabric.CodeStaleReference, "Local MCP offer retired")
	}
	return row, gen, nil
}
func (s *Store) descriptorProjectionUsage(ctx context.Context) (int64, int64, error) {
	n, e := projectionTables(ctx, s.db)
	if e != nil || n == 0 {
		return 0, 0, e
	}
	var count, total int64
	e = s.db.QueryRowContext(ctx, "SELECT count(*),COALESCE(sum(length(record)),0) FROM descriptor_projection_log").Scan(&count, &total)
	return count, total, e
}
