package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/search"
)

// PendingIndex returns a deterministic compact delta from the last committed
// index generation. Preparing it exposes no new indexed watermark or view.
func (s *Store) PendingIndex(ctx context.Context, limit int) (search.Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return search.Batch{}, errors.New("registry closed")
	}
	if limit < 1 || limit > 32 {
		return search.Batch{}, invalid("invalid index outbox page limit")
	}
	var watermark uint64
	if e := s.db.QueryRowContext(ctx, "SELECT watermark FROM search_state WHERE singleton=1").Scan(&watermark); e != nil {
		return search.Batch{}, e
	}
	var end uint64
	if e := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(sequence),0) FROM (SELECT sequence FROM search_outbox WHERE sequence>? ORDER BY sequence LIMIT ?)", watermark, limit).Scan(&end); e != nil {
		return search.Batch{}, e
	}
	if end == 0 {
		return search.Batch{}, fabric.NewError(fabric.CodeNotFound, "no pending index delta")
	}
	return buildIndexBatch(ctx, s.db, watermark, end)
}

type indexQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func buildIndexBatch(ctx context.Context, q indexQuery, watermark, end uint64) (search.Batch, error) {
	return buildIndexBatchState(ctx, q, watermark, end, nil)
}
func buildIndexBatchState(ctx context.Context, q indexQuery, watermark, end uint64, known map[string]fabric.Revision) (search.Batch, error) {
	rows, e := q.QueryContext(ctx, "SELECT ref,revision,retired,document FROM search_outbox WHERE sequence>? AND sequence<=? ORDER BY sequence", watermark, end)
	if e != nil {
		return search.Batch{}, e
	}
	changes := map[string]struct {
		ref     fabric.EndpointRef
		rev     fabric.Revision
		retired bool
		doc     fabric.SearchDocument
	}{}
	for rows.Next() {
		var ref string
		var revision fabric.Revision
		var retired bool
		var raw []byte
		if e = rows.Scan(&ref, &revision, &retired, &raw); e != nil {
			break
		}
		parsed, x := fabric.ParseEndpointRef(ref)
		if x != nil {
			e = x
			break
		}
		var d fabric.SearchDocument
		if !retired {
			if e = fabric.DecodeJSON(raw, &d); e != nil {
				break
			}
			if d.Ref != parsed || d.Revision != revision {
				e = invalid("outbox descriptor commitment mismatch")
				break
			}
		}
		changes[ref] = struct {
			ref     fabric.EndpointRef
			rev     fabric.Revision
			retired bool
			doc     fabric.SearchDocument
		}{parsed, revision, retired, d}
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return search.Batch{}, e
	}
	refs := make([]string, 0, len(changes))
	for ref := range changes {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	batch := search.Batch{UpstreamCursor: strconv.FormatUint(end, 10)}
	for _, ref := range refs {
		change := changes[ref]
		if !change.retired {
			batch.Upserts = append(batch.Upserts, change.doc)
			continue
		}
		var old fabric.Revision
		if known != nil {
			var ok bool
			old, ok = known[ref]
			if !ok {
				continue
			}
		} else {
			e = q.QueryRowContext(ctx, "SELECT revision FROM index_refs WHERE ref=?", ref).Scan(&old)
			if errors.Is(e, sql.ErrNoRows) {
				continue
			}
			if e != nil {
				return search.Batch{}, e
			}
		}

		batch.Deletes = append(batch.Deletes, search.Deletion{Ref: change.ref, ExpectedRevision: old})
	}
	return batch, nil
}

// CommitIndex is passed ONLY to search.Backend.Publish by trusted composition.
// It persists the exact prepared delta and advances outbox/generation atomically
// before the backend publishes its immutable memory view. A crash in that gap
// is recovered with IndexRecords/Restore, never by advertising the SQL watermark.
func (s *Store) CommitIndex(ctx context.Context, record search.CommitRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("registry closed")
	}
	if record.Format != search.FormatVersion || record.Generation == 0 || record.Generation != record.BaseGeneration+1 {
		return invalid("invalid index commit generation")
	}
	hashInput := record
	hashInput.SHA256 = ""
	raw, e := json.Marshal(hashInput)
	if e != nil {
		return e
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != record.SHA256 {
		return invalid("index record digest mismatch")
	}
	encoded, e := json.Marshal(record)
	if e != nil {
		return e
	}
	if len(encoded) > 1<<20 {
		return invalid("index commit exceeds bound")
	}
	end, e := strconv.ParseUint(record.Batch.UpstreamCursor, 10, 63)
	if e != nil || strconv.FormatUint(end, 10) != record.Batch.UpstreamCursor {
		return invalid("invalid index upstream cursor")
	}
	if !validSourceOrder(record.SourceOrder, record.SourceSequence, end, 0) {
		return invalid("index commit source order differs from registry watermark")
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var watermark, generation uint64
	if e = tx.QueryRowContext(ctx, "SELECT watermark,generation FROM search_state WHERE singleton=1").Scan(&watermark, &generation); e != nil {
		return e
	}
	if generation == record.Generation {
		var old []byte
		if e = tx.QueryRowContext(ctx, "SELECT record FROM index_commits WHERE generation=?", generation).Scan(&old); e != nil {
			return e
		}
		if bytes.Equal(old, encoded) {
			return nil
		}
		return conflict("index generation retry conflicts")
	}
	if generation != record.BaseGeneration || end <= watermark {
		return conflict("index base generation or upstream watermark is stale")
	}
	var count int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM search_outbox WHERE sequence>? AND sequence<=?", watermark, end).Scan(&count); e != nil {
		return e
	}
	if count < 1 || count > 32 {
		return invalid("index commit outbox range exceeds bound")
	}
	var actualEnd uint64
	if e = tx.QueryRowContext(ctx, "SELECT MAX(sequence) FROM search_outbox WHERE sequence>? AND sequence<=?", watermark, end).Scan(&actualEnd); e != nil || actualEnd != end {
		return conflict("index outbox range is incomplete")
	}
	expected, e := buildIndexBatch(ctx, tx, watermark, end)
	if e != nil {
		return e
	}
	expectedBytes, _ := json.Marshal(expected)
	actualBytes, _ := json.Marshal(record.Batch)
	if !bytes.Equal(expectedBytes, actualBytes) {
		return conflict("prepared index delta differs from authoritative outbox")
	}
	for _, d := range record.Batch.Upserts {
		if _, e = tx.ExecContext(ctx, "INSERT INTO index_refs VALUES(?,?) ON CONFLICT(ref) DO UPDATE SET revision=excluded.revision", d.Ref.String(), d.Revision); e != nil {
			return e
		}
	}
	for _, d := range record.Batch.Deletes {
		result, e := tx.ExecContext(ctx, "DELETE FROM index_refs WHERE ref=? AND revision=?", d.Ref.String(), d.ExpectedRevision)
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil || n != 1 {
			return conflict("index deletion revision changed")
		}
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO index_commits VALUES(?,?)", record.Generation, encoded); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE search_state SET watermark=?,generation=?,commit_hash=? WHERE singleton=1", end, record.Generation, record.SHA256); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) IndexRecords(ctx context.Context, after uint64, limit int) ([]search.CommitRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.indexRecords(ctx, after, limit)
}
func (s *Store) indexRecords(ctx context.Context, after uint64, limit int) ([]search.CommitRecord, error) {
	if s.closed {
		return nil, errors.New("registry closed")
	}
	if limit < 1 || limit > 32 {
		return nil, invalid("invalid index history page limit")
	}
	rows, e := s.db.QueryContext(ctx, "SELECT record FROM index_commits WHERE generation>? ORDER BY generation LIMIT ?", after, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := make([]search.CommitRecord, 0, limit)
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		var r search.CommitRecord
		if e = fabric.DecodeJSON(raw, &r); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// verifyIndex checks crash-recovery commitments without publishing a view.
func (s *Store) verifyIndex(ctx context.Context) error {
	_, scratch, cleanup, e := s.newRecoveryProjection(ctx)
	if e != nil {
		return e
	}
	defer cleanup()
	if _, e = scratch.ExecContext(ctx, "CREATE TABLE index_refs(ref TEXT PRIMARY KEY,revision TEXT)"); e != nil {
		return e
	}
	generation, watermark, root, e := s.verifyCheckpointInto(ctx, scratch)
	if e != nil {
		return e
	}
	for {
		records, e := s.indexRecords(ctx, generation, 32)
		if e != nil {
			return e
		}
		if len(records) == 0 {
			break
		}
		for _, r := range records {
			unsigned := r
			unsigned.SHA256 = ""
			b, _ := json.Marshal(unsigned)
			h := sha256.Sum256(b)
			if r.Format != search.FormatVersion || r.SHA256 != hex.EncodeToString(h[:]) || r.BaseGeneration != generation || r.Generation != generation+1 {
				return invalid("index history generation or digest mismatch")
			}
			end, x := strconv.ParseUint(r.Batch.UpstreamCursor, 10, 63)
			if x != nil || end <= watermark || strconv.FormatUint(end, 10) != r.Batch.UpstreamCursor {
				return invalid("index history watermark mismatch")
			}
			var sourceCount int
			if e = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM search_outbox WHERE sequence>? AND sequence<=?", watermark, end).Scan(&sourceCount); e != nil {
				return e
			}
			if sourceCount < 1 || sourceCount > 32 {
				return invalid("index history source range is unbounded")
			}
			if !validSourceOrder(r.SourceOrder, r.SourceSequence, end, 0) {
				return invalid("index history source order mismatch")
			}
			known := map[string]fabric.Revision{}
			sources, e := s.db.QueryContext(ctx, "SELECT DISTINCT ref FROM search_outbox WHERE sequence>? AND sequence<=?", watermark, end)
			if e != nil {
				return e
			}
			for sources.Next() {
				var ref string
				if e = sources.Scan(&ref); e != nil {
					break
				}
				var rev fabric.Revision
				x := scratch.QueryRowContext(ctx, "SELECT revision FROM index_refs WHERE ref=?", ref).Scan(&rev)
				if x == nil {
					known[ref] = rev
				} else if !errors.Is(x, sql.ErrNoRows) {
					e = x
					break
				}
			}
			if e == nil {
				e = sources.Err()
			}
			sources.Close()
			if e != nil {
				return e
			}

			expected, x := buildIndexBatchState(ctx, s.db, watermark, end, known)
			if x != nil {
				return x
			}
			expectedBytes, _ := json.Marshal(expected)
			actualBytes, _ := json.Marshal(r.Batch)
			if !bytes.Equal(expectedBytes, actualBytes) {
				return invalid("index history differs from authentic source outbox")
			}
			for _, d := range r.Batch.Upserts {
				if _, e = scratch.ExecContext(ctx, "INSERT INTO index_refs VALUES(?,?) ON CONFLICT(ref) DO UPDATE SET revision=excluded.revision", d.Ref.String(), d.Revision); e != nil {
					return e
				}
			}
			for _, d := range r.Batch.Deletes {
				if _, e = scratch.ExecContext(ctx, "DELETE FROM index_refs WHERE ref=? AND revision=?", d.Ref.String(), d.ExpectedRevision); e != nil {
					return e
				}
			}
			generation = r.Generation
			watermark = end
			root = r.SHA256
		}
	}
	var claimedWatermark, claimedGeneration uint64
	var claimedRoot string
	if e = s.db.QueryRowContext(ctx, "SELECT watermark,generation,commit_hash FROM search_state WHERE singleton=1").Scan(&claimedWatermark, &claimedGeneration, &claimedRoot); e != nil {
		return e
	}
	if watermark != claimedWatermark || generation != claimedGeneration || root != claimedRoot {
		return invalid("index commitment watermark differs from history")
	}
	rows, e := s.db.QueryContext(ctx, "SELECT ref,revision FROM index_refs")
	if e != nil {
		return e
	}
	defer rows.Close()
	var count int64
	for rows.Next() {
		var ref string
		var revision fabric.Revision
		if e = rows.Scan(&ref, &revision); e != nil {
			return e
		}
		var expected fabric.Revision
		if e = scratch.QueryRowContext(ctx, "SELECT revision FROM index_refs WHERE ref=?", ref).Scan(&expected); e != nil || expected != revision {
			return invalid("index materialized revision differs from commitment")
		}
		count++
	}
	if e = rows.Err(); e != nil {
		return e
	}
	var expectedCount int64
	if e = scratch.QueryRowContext(ctx, "SELECT COUNT(*) FROM index_refs").Scan(&expectedCount); e != nil {
		return e
	}
	if count != expectedCount {
		return invalid("index materialized revisions are incomplete")
	}
	return nil
}

// Every compact outbox item must reproduce the authenticated signed source,
// including child-offer removals implied by a signed endpoint tombstone.
func (s *Store) verifyOutbox(ctx context.Context) error {
	keys := map[string][]byte{s.identity.Namespace: s.identity.PublicKey}
	rows, e := s.db.QueryContext(ctx, "SELECT domain,CASE WHEN length(genesis)<=65536 THEN genesis END FROM pins")
	if e != nil {
		return e
	}
	for rows.Next() {
		var d string
		var raw []byte
		if e = rows.Scan(&d, &raw); e != nil {
			break
		}
		var g GenesisRecord
		if e = fabric.DecodeJSON(raw, &g); e != nil {
			break
		}
		b, x := decodeGenesis(g)
		if x != nil {
			e = x
			break
		}
		keys[d] = b.PublicKey
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return e
	}

	_, scratch, cleanup, e := s.newRecoveryProjection(ctx)
	if e != nil {
		return e
	}
	defer cleanup()
	if _, e = scratch.ExecContext(ctx, "CREATE TABLE expected_outbox(sequence INTEGER PRIMARY KEY,ref TEXT,revision TEXT,retired INTEGER,document_digest BLOB)"); e != nil {
		return e
	}
	sequence := uint64(0)
	rows, e = s.db.QueryContext(ctx, "SELECT CASE WHEN length(record)<=? THEN record END FROM ledger ORDER BY rowid", s.options.Limits.MaxPayloadBytes+65536)
	if e != nil {
		return e
	}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			break
		}
		var r Record
		if e = s.decode(raw, &r); e != nil {
			break
		}
		o, x := objectFromRecord(r, keys[r.Frame.IssuerNamespace], s.options.Limits)
		if x != nil {
			e = x
			break
		}
		doc, x := searchDocument(o)
		if x != nil {
			e = x
			break
		}
		h := sha256.Sum256(doc)
		sequence++
		if _, e = scratch.ExecContext(ctx, "INSERT INTO expected_outbox VALUES(?,?,?,?,?)", sequence, o.ref, o.revision, o.retired, h[:]); e != nil {
			break
		}
		if o.kind == "offer" {
			if _, e = scratch.ExecContext(ctx, "INSERT INTO verified(ref,parent,revision,retired) VALUES(?,?,?,?) ON CONFLICT(ref) DO UPDATE SET revision=excluded.revision,retired=excluded.retired", o.ref, o.parent, o.revision, o.retired); e != nil {
				break
			}
		}
		if o.kind == "endpoint" && o.retired {
			result, x := scratch.ExecContext(ctx, "INSERT INTO expected_outbox SELECT ROW_NUMBER() OVER(ORDER BY ref)+?,ref,revision,1,NULL FROM verified WHERE parent=? AND retired=0", sequence, o.ref)
			if x != nil {
				e = x
				break
			}
			n, x := result.RowsAffected()
			if x != nil {
				e = x
				break
			}
			sequence += uint64(n)
		}
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return e
	}
	rows, e = s.db.QueryContext(ctx, "SELECT sequence,ref,revision,retired,CASE WHEN length(document)<=16384 THEN document END,length(document) FROM search_outbox ORDER BY sequence")
	if e != nil {
		return e
	}
	defer rows.Close()
	seen := uint64(0)
	for rows.Next() {
		var seq uint64
		var ref string
		var revision fabric.Revision
		var retired bool
		var doc []byte
		var docLength sql.NullInt64
		if e = rows.Scan(&seq, &ref, &revision, &retired, &doc, &docLength); e != nil {
			return e
		}
		seen++
		if seq != seen || seq > sequence || docLength.Valid && docLength.Int64 > 16384 {
			return invalid("outbox order or compact bounds mismatch")
		}
		var wantRef string
		var wantRevision fabric.Revision
		var wantRetired bool
		var digest []byte
		if e = scratch.QueryRowContext(ctx, "SELECT ref,revision,retired,document_digest FROM expected_outbox WHERE sequence=?", seq).Scan(&wantRef, &wantRevision, &wantRetired, &digest); e != nil {
			return e
		}
		if ref != wantRef || revision != wantRevision || retired != wantRetired {
			return invalid("outbox differs from signed source identity")
		}
		if digest == nil {
			if docLength.Valid {
				return invalid("child retirement outbox contains unsigned payload")
			}
		} else {
			h := sha256.Sum256(doc)
			if !bytes.Equal(h[:], digest) {
				return invalid("outbox differs from exact signed source data")
			}
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	if seen != sequence {
		return invalid("outbox is incomplete for signed history")
	}
	return nil
}
