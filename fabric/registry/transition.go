package registry

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
)

func (s *Store) validateImportedTransition(ctx context.Context, q indexQuery, o storedObject) error {
	if o.kind == "offer" {
		parent, e := loadObject(ctx, q, o.parent)
		if e != nil || parent.retired {
			return conflict("imported offer has no active parent")
		}
		if !o.retired {
			var endpoint fabric.EndpointDescriptor
			var offer fabric.OfferDescriptor
			if e = s.decode(parent.payload, &endpoint); e != nil {
				return e
			}
			if e = s.decode(o.payload, &offer); e != nil {
				return e
			}
			found := false
			for _, b := range endpoint.Bindings {
				found = found || b.ID == offer.BindingID
			}
			if !found {
				return invalid("imported offer binding is not published by endpoint")
			}
		}
	}
	if o.kind == "endpoint" && !o.retired {
		var d fabric.EndpointDescriptor
		if e := s.decode(o.payload, &d); e != nil {
			return e
		}
		ids := map[string]bool{}
		for _, b := range d.Bindings {
			ids[b.ID] = true
		}
		rows, e := q.QueryContext(ctx, "SELECT payload FROM objects WHERE parent=? AND retired=0", o.ref)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				return e
			}
			var offer fabric.OfferDescriptor
			if e = s.decode(raw, &offer); e != nil {
				return e
			}
			if !ids[offer.BindingID] {
				return conflict("imported update removes a live offer binding")
			}
		}
		return rows.Err()
	}
	return nil
}
