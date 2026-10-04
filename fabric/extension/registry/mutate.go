package registry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"

	"github.com/pagnet-code/pagnet/fabric"
	domain "github.com/pagnet-code/pagnet/fabric/registry"
)

func (s *Store) Install(ctx context.Context, owner fabric.ExecutionContext, generation uint64, input Installation) (Reference, error) {
	return s.mutate(ctx, owner, generation, 0, input.Manifest.ID, &input, false)
}
func (s *Store) Update(ctx context.Context, owner fabric.ExecutionContext, generation, revision uint64, input Installation) (Reference, error) {
	return s.mutate(ctx, owner, generation, revision, input.Manifest.ID, &input, false)
}
func (s *Store) Remove(ctx context.Context, owner fabric.ExecutionContext, generation, revision uint64, id string) error {
	_, e := s.mutate(ctx, owner, generation, revision, id, nil, true)
	return e
}
func (s *Store) mutate(ctx context.Context, owner fabric.ExecutionContext, generation, revision uint64, id string, input *Installation, remove bool) (Reference, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.quarantined {
		return Reference{}, failure()
	}
	if e := s.authorize(ctx, owner); e != nil {
		return Reference{}, e
	}
	if generation != s.generation || !fabric.ValidNamespacedName(id) {
		return Reference{}, conflict()
	}
	current, exists := s.refs[id]
	if revision == 0 && exists || revision != 0 && (!exists || revision != current.Revision) || remove && revision == 0 {
		return Reference{}, conflict()
	}
	if !exists && len(s.refs) >= s.config.MaxExtensions {
		return Reference{}, invalid()
	}
	refs := make(map[string]Reference, len(s.refs))
	entries := make(map[string]Installation, len(s.entries))
	for id, r := range s.refs {
		refs[id] = r
	}
	for id, e := range s.entries {
		entries[id] = e
	}
	var installed Installation
	var e error
	var entryValue []byte
	physical := current.PhysicalID
	if !exists {
		physical = physicalID(id, s.generation+1)
	}
	candidate := current
	if remove {
		delete(refs, id)
		delete(entries, id)
		entryValue, e = s.seal(physical, struct {
			Format    int
			RemovedID string
		}{1, id}, s.config.MaxEntryBytes)
	} else {
		installed, e = s.validateInstallation(*input)
		if e != nil {
			return Reference{}, e
		}
		raw, _ := json.Marshal(installed)
		candidate = Reference{id, physical, revision + 1, hash(raw)}
		refs[id] = candidate
		entries[id] = installed
		entryValue, e = s.seal(physical, installed, s.config.MaxEntryBytes)
	}
	if e != nil {
		return Reference{}, e
	}
	plan, e := s.compile(entries, refs, s.generation+1)
	if e != nil {
		return Reference{}, e
	}
	sorted := sortedReferences(refs)
	directoryValue, e := s.seal(directoryID, s.directory(sorted), s.config.MaxDirectoryBytes)
	if e != nil {
		return Reference{}, e
	}
	// Fence new runtime snapshots through commit/readback. Already-held immutable
	// snapshots may finish; no partial candidate or uncertain new plan is exposed.
	s.quarantined = true
	s.snapshot.Store(nil)
	e = s.transaction(ctx, owner, scope(s.config), func(tx *domain.AuthorityTx) error {
		previous, e := tx.Get(key(directoryID))
		if e != nil || previous.Retired || previous.Revision != generation {
			return conflict()
		}
		if exists {
			entry, e := tx.Get(key(physical))
			if e != nil || entry.Retired || entry.Revision != revision {
				return conflict()
			}
		} else {
			if _, e := tx.Get(key(physical)); e == nil {
				return conflict()
			} else {
				var f *fabric.Error
				if !errors.As(e, &f) || f.Code != fabric.CodeNotFound {
					return e
				}
			}
		}
		record, e := tx.CAS(key(physical), revision, entryValue, remove)
		if e != nil {
			return e
		}
		if record.Revision != revision+1 {
			return failure()
		}
		_, e = tx.CAS(key(directoryID), generation, directoryValue, false)
		return e
	})
	if e != nil {
		return Reference{}, e
	}
	// Exact signed readback after COMMIT pins the publication even when another
	// legitimate configuration handle raced immediately after our transaction.
	e = s.config.Root.WithNativeAuthority(ctx, owner, scope(s.config), func(tx *domain.AuthorityTx) error {
		d, e := tx.Get(key(directoryID))
		if e != nil || d.Retired || d.Revision != generation+1 || !bytes.Equal(d.Value, directoryValue) {
			return failure()
		}
		record, e := tx.Get(key(physical))
		if e != nil || record.Retired != remove || record.Revision != revision+1 || !bytes.Equal(record.Value, entryValue) {
			return failure()
		}
		return nil
	})
	if e != nil {
		return Reference{}, e
	}
	s.refs = refs
	s.ordered = sorted
	s.entries = entries
	s.generation = generation + 1
	s.plan = plan
	s.quarantined = false
	s.snapshot.Store(&Snapshot{s.generation, s.plan})
	if remove {
		return Reference{id, physical, revision + 1, ""}, nil
	}
	return candidate, nil
}
func sortedReferences(refs map[string]Reference) []Reference {
	out := make([]Reference, 0, len(refs))
	for _, r := range refs {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func (s *Store) checkCurrent(ctx context.Context, owner fabric.ExecutionContext) error {
	if s.closed || s.quarantined {
		return failure()
	}
	if e := s.authorize(ctx, owner); e != nil {
		return e
	}
	e := s.config.Root.WithNativeAuthority(ctx, owner, scope(s.config), func(tx *domain.AuthorityTx) error {
		r, e := tx.Get(key(directoryID))
		if e != nil || r.Retired || r.Revision != s.generation {
			return conflict()
		}
		return nil
	})
	if e != nil {
		s.quarantined = true
		s.snapshot.Store(nil)
	}
	return e
}

type cursor struct {
	Generation uint64
	After      string
}

func (s *Store) List(ctx context.Context, owner fabric.ExecutionContext, after string, limit int) (Page, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1 || limit > 100 || len(after) > 1024 {
		return Page{}, invalid()
	}
	if e := s.checkCurrent(ctx, owner); e != nil {
		return Page{}, e
	}
	c := cursor{Generation: s.generation}
	if after != "" {
		raw, e := base64.RawURLEncoding.DecodeString(after)
		if e != nil || fabric.DecodeJSON(raw, &c) != nil || c.Generation != s.generation || !text(c.After, 256, false) {
			return Page{}, conflict()
		}
	}
	entries := s.ordered
	position := sort.Search(len(entries), func(i int) bool { return entries[i].ID > c.After })
	end := position + limit
	if end > len(entries) {
		end = len(entries)
	}
	page := Page{Generation: s.generation, Entries: append([]Reference(nil), entries[position:end]...)}
	if end < len(entries) {
		raw, _ := json.Marshal(cursor{s.generation, entries[end-1].ID})
		page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return page, nil
}
func (s *Store) Inspect(ctx context.Context, owner fabric.ExecutionContext, id string) (Reference, Installation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.checkCurrent(ctx, owner); e != nil {
		return Reference{}, Installation{}, e
	}
	r, ok := s.refs[id]
	if !ok {
		return Reference{}, Installation{}, fabric.NewError(fabric.CodeNotFound, "Extension absent")
	}
	owned, e := s.validateInstallation(s.entries[id])
	return r, owned, e
}
