package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/pagnet-code/pagnet/fabric"
)

// EndpointHeadPage is private bounded administrative enumeration, not discovery.
// Full descriptors and schemas are deliberately absent from this startup path.
type EndpointHead struct {
	Ref      fabric.EndpointRef
	Revision fabric.Revision
	Retired  bool
}
type EndpointHeadPage struct {
	Heads      []EndpointHead
	NextCursor string
}
type endpointHeadCursor struct {
	Generation uint64 `json:"generation,string"`
	After      string `json:"after"`
}

func (s *Store) ListEndpointHeads(ctx context.Context, owner fabric.ExecutionContext, cursor string, limit int) (EndpointHeadPage, error) {
	if ctx == nil || limit < 1 || limit > 100 || len(cursor) > 4096 {
		return EndpointHeadPage{}, invalid("Invalid endpoint page bounds")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.authorize(owner); err != nil {
		return EndpointHeadPage{}, err
	}
	var generation uint64
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(rowid),0) FROM ledger").Scan(&generation); err != nil {
		return EndpointHeadPage{}, err
	}
	c := endpointHeadCursor{Generation: generation}
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return EndpointHeadPage{}, invalid("Invalid endpoint page cursor")
		}
		if err = fabric.DecodeJSON(raw, &c); err != nil {
			return EndpointHeadPage{}, err
		}
		if c.Generation != generation {
			return EndpointHeadPage{}, conflict("Endpoint page snapshot changed")
		}
		ref, err := fabric.ParseEndpointRef(c.After)
		if err != nil || ref.IsOffer() {
			return EndpointHeadPage{}, invalid("Invalid endpoint page reference")
		}
	}
	// Existing offers_parent(parent,ref) provides ordered range access. Startup
	// may enumerate multiple pages; no full table scan occurs for an individual page.
	rows, err := s.db.QueryContext(ctx, "SELECT ref,revision,retired FROM objects WHERE parent='' AND ref>? ORDER BY ref LIMIT ?", c.After, limit+1)
	if err != nil {
		return EndpointHeadPage{}, err
	}
	defer rows.Close()
	page := EndpointHeadPage{Heads: make([]EndpointHead, 0, limit)}
	for rows.Next() {
		var ref, revision string
		var retired bool
		if err = rows.Scan(&ref, &revision, &retired); err != nil {
			return EndpointHeadPage{}, err
		}
		if len(page.Heads) == limit {
			c.After = page.Heads[len(page.Heads)-1].Ref.String()
			raw, _ := json.Marshal(c)
			page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
			break
		}
		parsed, err := fabric.ParseEndpointRef(ref)
		if err != nil || parsed.IsOffer() {
			return EndpointHeadPage{}, invalid("Invalid retained endpoint head")
		}
		page.Heads = append(page.Heads, EndpointHead{parsed, fabric.Revision(revision), retired})
	}
	if err = rows.Err(); err != nil {
		return EndpointHeadPage{}, err
	}
	return page, nil
}
