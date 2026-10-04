package registry

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/fabric"
)

func (s *Store) activeObject(ctx context.Context, ref fabric.EndpointRef, expected fabric.Revision) (storedObject, error) {
	if s.closed {
		return storedObject{}, errors.New("registry closed")
	}
	if _, e := fabric.ParseEndpointRef(ref.String()); e != nil {
		return storedObject{}, e
	}
	o, e := loadObject(ctx, s.db, ref.String())
	if errors.Is(e, sql.ErrNoRows) {
		return o, fabric.NewError(fabric.CodeNotFound, "reference not found")
	}
	if e != nil {
		return o, e
	}
	if o.retired || expected != "" && o.revision != expected {
		return o, conflict("reference is retired or revision is stale")
	}
	if ref.IsOffer() {
		parent, e := loadObject(ctx, s.db, ref.Endpoint().String())
		if e != nil || parent.retired {
			return o, conflict("offer endpoint is retired or unavailable")
		}
	}
	return o, nil
}
func (s *Store) GetEndpoint(ctx context.Context, ref fabric.EndpointRef, expected fabric.Revision) (fabric.EndpointDescriptor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getEndpoint(ctx, ref, expected)
}
func (s *Store) getEndpoint(ctx context.Context, ref fabric.EndpointRef, expected fabric.Revision) (fabric.EndpointDescriptor, error) {
	var d fabric.EndpointDescriptor
	if ref.IsOffer() {
		return d, invalid("endpoint read requires endpoint reference")
	}
	o, e := s.activeObject(ctx, ref, expected)
	if e != nil {
		return d, e
	}
	e = s.decode(o.payload, &d)
	return d, e
}
func (s *Store) Resolve(ctx context.Context, ref fabric.EndpointRef, expected fabric.Revision) (fabric.EndpointDescriptor, error) {
	return s.GetEndpoint(ctx, ref, expected)
}
func (s *Store) GetOffer(ctx context.Context, ref fabric.EndpointRef, expected fabric.Revision) (fabric.OfferDescriptor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var d fabric.OfferDescriptor
	if !ref.IsOffer() {
		return d, invalid("offer read requires offer reference")
	}
	o, e := s.activeObject(ctx, ref, expected)
	if e != nil {
		return d, e
	}
	e = s.decode(o.payload, &d)
	return d, e
}

type offerCursor struct {
	Parent     string          `json:"parent"`
	Revision   fabric.Revision `json:"revision"`
	Generation uint64          `json:"generation"`
	After      string          `json:"after"`
}

func (s *Store) ListOffers(ctx context.Context, parent fabric.EndpointRef, expected fabric.Revision, cursor string, limit int) ([]fabric.OfferSummary, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if parent.IsOffer() || limit < 1 || limit > 100 || len(cursor) > 4096 {
		return nil, "", invalid("invalid offer page bounds")
	}
	d, e := s.getEndpoint(ctx, parent, expected)
	if e != nil {
		return nil, "", e
	}
	var generation uint64
	if e = s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(rowid),0) FROM ledger").Scan(&generation); e != nil {
		return nil, "", e
	}
	c := offerCursor{Parent: parent.String(), Revision: d.Revision, Generation: generation}
	if cursor != "" {
		raw, e := base64.RawURLEncoding.DecodeString(cursor)
		if e != nil {
			return nil, "", invalid("invalid offer page cursor")
		}
		if e = fabric.DecodeJSON(raw, &c); e != nil {
			return nil, "", e
		}
		if c.Parent != parent.String() || c.Revision != d.Revision || c.Generation != generation {
			return nil, "", conflict("offer page snapshot has changed")
		}
		after, e := fabric.ParseEndpointRef(c.After)
		if e != nil || !after.IsOffer() || after.Endpoint() != parent {
			return nil, "", invalid("offer cursor belongs to another parent")
		}
	}
	rows, e := s.db.QueryContext(ctx, "SELECT payload FROM objects WHERE parent=? AND retired=0 AND ref>? ORDER BY ref LIMIT ?", parent.String(), c.After, limit+1)
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	out := make([]fabric.OfferSummary, 0, limit)
	next := ""
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			return nil, "", e
		}
		if len(out) == limit {
			c.After = out[len(out)-1].Ref.String()
			encoded, _ := json.Marshal(c)
			next = base64.RawURLEncoding.EncodeToString(encoded)
			break
		}
		var offer fabric.OfferDescriptor
		if e = s.decode(raw, &offer); e != nil {
			return nil, "", e
		}
		out = append(out, fabric.OfferSummary{Ref: offer.Ref, Revision: offer.Revision, Name: offer.Name, Description: offer.Description})
	}
	if e = rows.Err(); e != nil {
		return nil, "", e
	}
	return out, next, nil
}
func (s *Store) Records(ctx context.Context, domain string, after uint64, limit int) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("registry closed")
	}
	if limit < 1 || limit > 100 {
		return nil, invalid("invalid signed record page limit")
	}
	rows, e := s.db.QueryContext(ctx, "SELECT record FROM ledger WHERE domain=? AND sequence>? ORDER BY sequence LIMIT ?", domain, after, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := make([]Record, 0, limit)
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		var r Record
		if e = s.decode(raw, &r); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

var _ fabric.DescriptorStore = (*Store)(nil)
