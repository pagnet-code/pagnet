package registry

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"strconv"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/search"
)

const checkpointPageRows = 32

func checkpointFrame(h hash.Hash, value any) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(raw)))
	h.Write(n[:])
	h.Write(raw)
	return nil
}
func checkpointPageHash(p search.CheckpointPage) (string, error) {
	p.SHA256 = ""
	raw, e := json.Marshal(p)
	if e != nil {
		return "", e
	}
	if len(raw) > 1<<20 {
		return "", invalid("checkpoint page exceeds private bound")
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}

// SaveCheckpoint is explicit O(N) maintenance, never hidden in registrations or
// search queries. SQLite atomically replaces the verified compact checkpoint and
// removes only prior search generation records. Signed identity/tombstone/source
// history and authoritative outbox commitments are retained independently.
func (s *Store) SaveCheckpoint(ctx context.Context, checkpoint *search.Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("registry closed")
	}
	if checkpoint == nil {
		return invalid("nil index checkpoint")
	}
	header := checkpoint.Header()
	var watermark, generation uint64
	var root string
	if e := s.db.QueryRowContext(ctx, "SELECT watermark,generation,commit_hash FROM search_state WHERE singleton=1").Scan(&watermark, &generation, &root); e != nil {
		return e
	}
	if header.Generation != generation || header.UpstreamCursor != indexCursor(generation, watermark) || header.RootCommitSHA256 != root || header.ReferenceRows > s.options.Limits.MaxRecords || header.RevisionRows > s.options.Limits.MaxRecords || !validSourceOrder(header.SourceOrder, header.SourceSequence, watermark, header.ReplayFloor) {
		return conflict("checkpoint differs from committed registry index head")
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "DELETE FROM checkpoint_pages"); e != nil {
		return e
	}
	unsigned := header
	unsigned.SHA256 = ""
	h := sha256.New()
	h.Write([]byte("pagnet.fabric.search-checkpoint.v1\x00"))
	if e = checkpointFrame(h, unsigned); e != nil {
		return e
	}
	var referenceRows, revisionRows uint64
	for _, section := range []string{search.CheckpointReferences, search.CheckpointRevisions} {
		after := ""
		for {
			page, e := checkpoint.Page(ctx, section, after, checkpointPageRows)
			if e != nil {
				return e
			}
			if page.Generation != generation || page.Section != section || page.After != after {
				return invalid("checkpoint mixed generation page")
			}
			checksum, e := checkpointPageHash(page)
			if e != nil || checksum != page.SHA256 {
				return invalid("checkpoint page checksum mismatch")
			}
			for _, r := range page.References {
				if e = checkpointFrame(h, r); e != nil {
					return e
				}
				referenceRows++
			}
			for _, r := range page.Revisions {
				if e = checkpointFrame(h, r); e != nil {
					return e
				}
				revisionRows++
			}
			if referenceRows > header.ReferenceRows || revisionRows > header.RevisionRows {
				return invalid("checkpoint row count exceeds header")
			}
			raw, e := json.Marshal(page)
			if e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO checkpoint_pages(section,after_key,page) VALUES(?,?,?)", section, after, raw); e != nil {
				return e
			}
			if page.Next == "" {
				break
			}
			if page.Next <= after {
				return invalid("checkpoint continuation does not advance")
			}
			after = page.Next
		}
	}
	if referenceRows != header.ReferenceRows || revisionRows != header.RevisionRows || hex.EncodeToString(h.Sum(nil)) != header.SHA256 {
		return invalid("checkpoint whole commitment mismatch")
	}
	raw, e := json.Marshal(header)
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO checkpoint_head VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET header=excluded.header", raw); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM index_commits WHERE generation<=?", generation); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) checkpointHeader(ctx context.Context) (search.CheckpointHeader, error) {
	var h search.CheckpointHeader
	var raw []byte
	e := s.db.QueryRowContext(ctx, "SELECT CASE WHEN length(header)<=65536 THEN header END FROM checkpoint_head WHERE singleton=1").Scan(&raw)
	if e != nil {
		return h, e
	}
	e = fabric.DecodeJSON(raw, &h)
	return h, e
}
func (s *Store) checkpointPage(ctx context.Context, header search.CheckpointHeader, section, after string, limit int) (search.CheckpointPage, error) {
	var p search.CheckpointPage
	if limit < checkpointPageRows || limit > search.MaxBatchDocuments || len(after) > 1024 || (section != search.CheckpointReferences && section != search.CheckpointRevisions) {
		return p, invalid("invalid persisted checkpoint page request")
	}
	var raw []byte
	if e := s.db.QueryRowContext(ctx, "SELECT CASE WHEN length(page)<=1048576 THEN page END FROM checkpoint_pages WHERE section=? AND after_key=?", section, after).Scan(&raw); e != nil {
		return p, e
	}
	if e := fabric.DecodeJSON(raw, &p); e != nil {
		return p, e
	}
	checksum, e := checkpointPageHash(p)
	if e != nil || checksum != p.SHA256 || p.Generation != header.Generation || p.Section != section || p.After != after || len(p.References) > checkpointPageRows || len(p.Revisions) > checkpointPageRows {
		return p, invalid("persisted checkpoint page commitment mismatch")
	}
	return p, nil
}

// LoadIndex restores one complete pinned compact checkpoint and a bounded
// page-at-a-time tail. Backend visibility is supplied only after its own complete
// checkpoint validation. SQL watermark is never returned as a ready index view.
func (s *Store) LoadIndex(ctx context.Context, config search.Config) (*search.Backend, error) {
	backend, e := search.New(config)
	if e != nil {
		return nil, e
	}
	if e = s.restoreIndex(ctx, backend); e != nil {
		return nil, e
	}
	return backend, nil
}
func (s *Store) restoreIndex(ctx context.Context, backend *search.Backend) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("registry closed")
	}
	if backend == nil {
		return invalid("nil search backend")
	}
	after := uint64(0)
	header, e := s.checkpointHeader(ctx)
	if e == nil {
		if e = backend.RestoreCheckpoint(ctx, header, func(ctx context.Context, section, after string, limit int) (search.CheckpointPage, error) {
			return s.checkpointPage(ctx, header, section, after, limit)
		}); e != nil {
			return e
		}
		after = header.Generation
	} else if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	for {
		records, e := s.indexRecords(ctx, after, 32)
		if e != nil {
			return e
		}
		if len(records) == 0 {
			break
		}
		for _, r := range records {
			if e = backend.Restore(ctx, r); e != nil {
				return e
			}
			after = r.Generation
		}
	}
	return nil
}

// verifyCheckpointInto streams only compact reference/revision rows into the
// temporary SQLite projection. It checks whole/order/count/ID commitments without
// loading a duplicate lexical index or old generation bodies into memory.
func (s *Store) verifyCheckpointInto(ctx context.Context, scratch *sql.Tx) (uint64, uint64, string, error) {
	header, e := s.checkpointHeader(ctx)
	if errors.Is(e, sql.ErrNoRows) {
		return 0, 0, "", nil
	}
	if e != nil {
		return 0, 0, "", e
	}
	if header.Format != search.FormatVersion || header.ReferenceRows > s.options.Limits.MaxRecords || header.RevisionRows > s.options.Limits.MaxRecords || header.ReferenceRows != header.NextID || header.LiveDocuments > header.ReferenceRows {
		return 0, 0, "", invalid("checkpoint header bounds mismatch")
	}
	watermark, e := strconv.ParseUint(header.UpstreamCursor, 10, 63)
	if header.Generation == 0 && header.UpstreamCursor == "" {
		watermark = 0
		e = nil
	}
	if e != nil || indexCursor(header.Generation, watermark) != header.UpstreamCursor {
		return 0, 0, "", invalid("checkpoint upstream watermark mismatch")
	}
	if !validSourceOrder(header.SourceOrder, header.SourceSequence, watermark, header.ReplayFloor) {
		return 0, 0, "", invalid("checkpoint source order differs from authoritative watermark")
	}
	unsigned := header
	unsigned.SHA256 = ""
	h := sha256.New()
	h.Write([]byte("pagnet.fabric.search-checkpoint.v1\x00"))
	if e = checkpointFrame(h, unsigned); e != nil {
		return 0, 0, "", e
	}
	if _, e = scratch.ExecContext(ctx, "CREATE TABLE checkpoint_ids(storage_id INTEGER PRIMARY KEY,ref TEXT UNIQUE)"); e != nil {
		return 0, 0, "", e
	}
	var references, revisions, live uint64
	for _, section := range []string{search.CheckpointReferences, search.CheckpointRevisions} {
		after := ""
		for {
			page, e := s.checkpointPage(ctx, header, section, after, search.MaxBatchDocuments)
			if e != nil {
				return 0, 0, "", e
			}
			last := after
			rows := 0
			if section == search.CheckpointReferences {
				if len(page.Revisions) != 0 {
					return 0, 0, "", invalid("checkpoint reference section contains revision rows")
				}
				for _, r := range page.References {
					if r.Ref.String() <= last || r.StorageID >= header.NextID || r.Revision == "" {
						return 0, 0, "", invalid("checkpoint reference ordering mismatch")
					}
					last = r.Ref.String()
					rows++
					references++
					if _, e = scratch.ExecContext(ctx, "INSERT INTO checkpoint_ids VALUES(?,?)", r.StorageID, r.Ref.String()); e != nil {
						return 0, 0, "", invalid("checkpoint duplicate storage identity")
					}
					if r.Document != nil {
						if r.Document.Ref != r.Ref || r.Document.Revision != r.Revision {
							return 0, 0, "", invalid("checkpoint live document binding mismatch")
						}
						if _, e = scratch.ExecContext(ctx, "INSERT INTO index_refs VALUES(?,?)", r.Ref.String(), r.Revision); e != nil {
							return 0, 0, "", e
						}
						live++
					}
					if e = checkpointFrame(h, r); e != nil {
						return 0, 0, "", e
					}
				}
			} else {
				if len(page.References) != 0 {
					return 0, 0, "", invalid("checkpoint revision section contains references")
				}
				for _, r := range page.Revisions {
					if r.Key <= last {
						return 0, 0, "", invalid("checkpoint revision ordering mismatch")
					}
					last = r.Key
					rows++
					revisions++
					if e = checkpointFrame(h, r); e != nil {
						return 0, 0, "", e
					}
				}
			}
			if references > header.ReferenceRows || revisions > header.RevisionRows {
				return 0, 0, "", invalid("checkpoint row count overflow")
			}
			if page.Next == "" {
				break
			}
			if rows == 0 || page.Next != last || page.Next <= after {
				return 0, 0, "", invalid("checkpoint continuation mismatch")
			}
			after = page.Next
		}
	}
	if references != header.ReferenceRows || revisions != header.RevisionRows || live != header.LiveDocuments || hex.EncodeToString(h.Sum(nil)) != header.SHA256 {
		return 0, 0, "", invalid("checkpoint whole commitment mismatch")
	}
	return header.Generation, watermark, header.RootCommitSHA256, nil
}

func indexCursor(generation, watermark uint64) string {
	if generation == 0 && watermark == 0 {
		return ""
	}
	return strconv.FormatUint(watermark, 10)
}
