// The bounded durable metadata-only trace store. The spans table mirrors
// the durable events store's retention pattern (the retain_until column +
// the retention index) and is keyed by invocation ID + span ID. It stores
// ONLY the bounded infrastructure metadata the fabric telemetry layer is
// allowed to export: names, stages, phases, dispositions, durations and
// the pagnet.* attribute set. No payloads, secrets, prompts, credentials
// or baggage are ever recorded — the span processor re-validates the
// metadata-only invariants at the persistence boundary.
package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

// ErrStoreMissing reports that no durable trace store exists yet (the
// reader-facing no-traces state, not a failure).
var ErrStoreMissing = errors.New("no durable trace store yet")

// ErrStoreClosed reports an operation on a closed store.
var ErrStoreClosed = errors.New("trace store closed")

// Metadata-only field bounds at the persistence boundary. They match the
// bounds fabric/telemetry enforces on the exported attributes; the store
// re-validates them so a store record can never outgrow the export
// contract.
const (
	MaxSpanNameBytes       = 128
	MaxSpanStageBytes      = 128
	MaxSpanStatusBytes     = 256
	MaxSpanInvocationBytes = 256
	MaxSpanAttributeBytes  = 4096
	// MaxSpanDuration caps a single recorded span's duration: longer
	// "spans" are not operation telemetry.
	MaxSpanDuration = 7 * 24 * time.Hour
	// maxRowBytes is the per-row slack bound behind the database size
	// check: attributes (4 KiB) + the fixed identity columns + index
	// overhead.
	maxRowBytes = 8192
)

// Retention bounds for the durable trace store.
const (
	DefaultTraceRetention = 30 * 24 * time.Hour
	MinTraceRetention     = time.Hour
	MaxTraceRetention     = 90 * 24 * time.Hour
	DefaultMaxTraces      = 100_000
	MinMaxTraces          = 1
	MaxMaxTraces          = 10_000_000
)

// MaxTraceQueryLimit bounds one invocation's listing.
const MaxTraceQueryLimit = 10_000

var (
	allowedPhases       = map[string]bool{"request": true, "response": true, "error": true, "chunk": true, "completion": true}
	allowedDispositions = map[string]bool{"completed": true, "deferred": true, "cancelled": true, "timeout": true, "rejected": true, "failed": true}
)

const traceSchema = `
CREATE TABLE spans(
  invocation_id TEXT NOT NULL,
  trace_id TEXT NOT NULL,
  span_id TEXT NOT NULL,
  parent_span_id TEXT NOT NULL,
  name TEXT NOT NULL,
  stage TEXT NOT NULL,
  phase TEXT NOT NULL,
  disposition TEXT NOT NULL,
  status_code INTEGER NOT NULL,
  status_description TEXT NOT NULL,
  attributes TEXT NOT NULL,
  start INTEGER NOT NULL,
  end INTEGER NOT NULL,
  retain_until INTEGER NOT NULL,
  PRIMARY KEY(invocation_id, span_id)
);
CREATE INDEX spans_retention ON spans(retain_until, invocation_id, span_id);
PRAGMA user_version=1;`

// SpanRecord is one durable metadata-only span. Every field is bounded and
// re-validated on write; the JSON tags are the `pagnet trace --json`
// contract.
type SpanRecord struct {
	InvocationID      string `json:"invocationId"`
	TraceID           string `json:"traceId"`
	SpanID            string `json:"spanId"`
	ParentSpanID      string `json:"parentSpanId,omitempty"`
	Name              string `json:"name"`
	Stage             string `json:"stage,omitempty"`
	Phase             string `json:"phase,omitempty"`
	Disposition       string `json:"disposition,omitempty"`
	StatusCode        int    `json:"statusCode"`
	StatusDescription string `json:"statusDescription,omitempty"`
	Attributes        string `json:"attributes,omitempty"`
	Start             int64  `json:"startNano"`
	End               int64  `json:"endNano"`
	RetainUntil       int64  `json:"retainUntilNano"`
}

// Duration is the recorded span duration (never negative).
func (r SpanRecord) Duration() time.Duration {
	if r.End < r.Start {
		return 0
	}
	return time.Duration(r.End - r.Start)
}

func invalidTraceRecord(msg string) error { return errors.New("invalid trace record: " + msg) }

func validSpanText(s string, max int) bool {
	return len(s) <= max && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

func validHexID(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < n; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// validate enforces the metadata-only invariants at the persistence
// boundary: W3C hex identifiers, bounded UTF-8 fields, the pagnet.*
// attribute key restriction, the phase/disposition allowlists, and a
// bounded duration. A record that fails is dropped, never stored.
func (r SpanRecord) validate() error {
	if !validHexID(r.TraceID, 32) {
		return invalidTraceRecord("trace id is not a 32-hex W3C identifier")
	}
	if !validHexID(r.SpanID, 16) {
		return invalidTraceRecord("span id is not a 16-hex W3C identifier")
	}
	if r.ParentSpanID != "" && !validHexID(r.ParentSpanID, 16) {
		return invalidTraceRecord("parent span id is not a 16-hex W3C identifier")
	}
	if len(r.InvocationID) == 0 || len(r.InvocationID) > MaxSpanInvocationBytes || !validSpanText(r.InvocationID, MaxSpanInvocationBytes) {
		return invalidTraceRecord("invocation id missing or beyond bound")
	}
	if len(r.Name) == 0 || !validSpanText(r.Name, MaxSpanNameBytes) {
		return invalidTraceRecord("span name missing or beyond bound")
	}
	if !validSpanText(r.Stage, MaxSpanStageBytes) {
		return invalidTraceRecord("stage beyond bound")
	}
	if r.Phase != "" && !allowedPhases[r.Phase] {
		return invalidTraceRecord("phase not in the allowlist")
	}
	if r.Disposition != "" && !allowedDispositions[r.Disposition] {
		return invalidTraceRecord("disposition not in the allowlist")
	}
	if r.StatusCode < 0 || r.StatusCode > 2 {
		return invalidTraceRecord("status code not unset/ok/error")
	}
	if !validSpanText(r.StatusDescription, MaxSpanStatusBytes) {
		return invalidTraceRecord("status description beyond bound")
	}
	if r.Start <= 0 || r.End < r.Start {
		return invalidTraceRecord("span times out of order")
	}
	if r.End-r.Start > int64(MaxSpanDuration) {
		return invalidTraceRecord("span duration beyond bound")
	}
	if len(r.Attributes) == 0 {
		r.Attributes = "{}"
	}
	if len(r.Attributes) > MaxSpanAttributeBytes {
		return invalidTraceRecord("attributes beyond bound")
	}
	var attrs map[string]string
	if err := json.Unmarshal([]byte(r.Attributes), &attrs); err != nil {
		return invalidTraceRecord("attributes are not a JSON string map")
	}
	for k, v := range attrs {
		// The key restriction is re-asserted here: only the pagnet.*
		// namespace, bounded, may be persisted.
		if !strings.HasPrefix(k, "pagnet.") || len(k) > MaxSpanNameBytes || !validSpanText(v, MaxSpanAttributeBytes) {
			return invalidTraceRecord("attribute outside the pagnet.* metadata-only key space")
		}
	}
	return nil
}

// StoreConfig bounds the durable trace store.
type StoreConfig struct {
	// Retention is how long a recorded span is kept (default 30d;
	// bounded 1h..90d). Zero selects the default.
	Retention time.Duration
	// MaxTraces is the row cap (default 100000; bounded 1..10000000).
	// Zero selects the default.
	MaxTraces int
}

func (c StoreConfig) normalize() (StoreConfig, error) {
	if c.Retention == 0 {
		c.Retention = DefaultTraceRetention
	}
	if c.Retention < MinTraceRetention || c.Retention > MaxTraceRetention {
		return StoreConfig{}, fmt.Errorf("trace retention must be within %s..%s (got %s)", MinTraceRetention, MaxTraceRetention, c.Retention)
	}
	if c.MaxTraces == 0 {
		c.MaxTraces = DefaultMaxTraces
	}
	if c.MaxTraces < MinMaxTraces || c.MaxTraces > MaxMaxTraces {
		return StoreConfig{}, fmt.Errorf("max traces must be within %d..%d (got %d)", MinMaxTraces, MaxMaxTraces, c.MaxTraces)
	}
	return c, nil
}

// TraceStore is the bounded durable metadata-only span store.
type TraceStore struct {
	mu     sync.Mutex
	db     *sql.DB
	cfg    StoreConfig
	closed bool
}

func traceStorePath(dir string) string { return filepath.Join(dir, "traces.sqlite") }

func openTraceStoreDB(dir string, cfg StoreConfig, readonly bool) (*TraceStore, error) {
	path := traceStorePath(dir)
	if readonly {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return nil, ErrStoreMissing
			}
			return nil, err
		}
	} else {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("trace store directory: %w", err)
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return nil, fmt.Errorf("trace store file: %w", err)
			}
			if err := f.Close(); err != nil {
				return nil, err
			}
		}
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > int64(cfg.MaxTraces)*maxRowBytes {
		return nil, fmt.Errorf("trace store database beyond its %d-row bound is unavailable", cfg.MaxTraces)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	slash := filepath.ToSlash(absolute)
	if !strings.HasPrefix(slash, "/") {
		slash = "/" + slash
	}
	u := url.URL{Scheme: "file", Path: slash}
	q := u.Query()
	q.Set("mode", "ro")
	if !readonly {
		q.Set("mode", "rw")
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if readonly {
		if _, err = db.Exec("PRAGMA busy_timeout=5000"); err != nil {
			db.Close()
			return nil, err
		}
	} else if _, err = db.Exec("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		return nil, err
	}
	var version int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		db.Close()
		return nil, err
	}
	switch version {
	case 0:
		if readonly {
			db.Close()
			return nil, fmt.Errorf("trace store schema uninitialized (version 0)")
		}
		if _, err = db.Exec(traceSchema); err != nil {
			db.Close()
			return nil, err
		}
	case 1:
		// current
	default:
		db.Close()
		return nil, fmt.Errorf("trace store schema version %d unsupported", version)
	}
	return &TraceStore{db: db, cfg: cfg}, nil
}

// OpenTraceStore opens (creating when absent) the durable trace store in
// dir. A failed open is a startup failure: an oversized or schema-unknown
// database is refused, never silently truncated.
func OpenTraceStore(dir string, cfg StoreConfig) (*TraceStore, error) {
	if dir == "" {
		return nil, errors.New("trace store requires an explicit directory")
	}
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	s, err := openTraceStoreDB(dir, cfg, false)
	if err != nil {
		return nil, err
	}
	// The first prune of the process lifetime: expired rows and any
	// over-cap backlog are removed before new records land.
	if _, err = s.Prune(context.Background()); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// OpenTraceStoreReadonly opens an existing store for listing only. A
// missing store returns ErrStoreMissing (the honest no-traces state).
func OpenTraceStoreReadonly(dir string) (*TraceStore, error) {
	if dir == "" {
		return nil, errors.New("trace store requires an explicit directory")
	}
	// A reader does not know (and must not assume) the writer's row cap;
	// the size check only needs a finite bound, so use the maximum.
	cfg, err := StoreConfig{MaxTraces: MaxMaxTraces}.normalize()
	if err != nil {
		return nil, err
	}
	return openTraceStoreDB(dir, cfg, true)
}

// Record durably stores one metadata-only span, then enforces the row cap
// (the oldest records beyond the cap are pruned). It is idempotent per
// (invocation, span).
func (s *TraceStore) Record(ctx context.Context, rec SpanRecord) error {
	if err := rec.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	rec.RetainUntil = rec.End + int64(s.cfg.Retention)
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO spans(invocation_id,trace_id,span_id,parent_span_id,name,stage,phase,disposition,status_code,status_description,attributes,start,end,retain_until)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		rec.InvocationID, rec.TraceID, rec.SpanID, rec.ParentSpanID, rec.Name, rec.Stage, rec.Phase, rec.Disposition,
		rec.StatusCode, rec.StatusDescription, rec.Attributes, rec.Start, rec.End, rec.RetainUntil,
	); err != nil {
		return err
	}
	return s.enforceCap(ctx)
}

// enforceCap prunes the oldest rows beyond the row cap. It must be called
// with s.mu held.
func (s *TraceStore) enforceCap(ctx context.Context) error {
	var count int64
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM spans").Scan(&count); err != nil {
		return err
	}
	excess := count - int64(s.cfg.MaxTraces)
	if excess <= 0 {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM spans WHERE rowid IN (SELECT rowid FROM spans ORDER BY start ASC, invocation_id ASC, span_id ASC LIMIT ?)`,
		excess)
	return err
}

// Prune removes expired rows (retain_until <= now) and re-enforces the row
// cap. It is bounded: one expiry sweep plus one cap sweep per call, both
// served by the retention index. It returns the expired rows removed.
func (s *TraceStore) Prune(ctx context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrStoreClosed
	}
	res, err := s.db.ExecContext(ctx, "DELETE FROM spans WHERE retain_until <= ?", time.Now().UTC().UnixNano())
	if err != nil {
		return 0, err
	}
	removed, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := s.enforceCap(ctx); err != nil {
		return 0, err
	}
	return removed, nil
}

// SpansForInvocation lists the recorded spans of one invocation, oldest
// first, bounded by limit (default 100, capped at MaxTraceQueryLimit).
func (s *TraceStore) SpansForInvocation(ctx context.Context, invocationID string, limit int) ([]SpanRecord, error) {
	if len(invocationID) == 0 || len(invocationID) > MaxSpanInvocationBytes {
		return nil, invalidTraceRecord("invocation id missing or beyond bound")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > MaxTraceQueryLimit {
		limit = MaxTraceQueryLimit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT invocation_id,trace_id,span_id,parent_span_id,name,stage,phase,disposition,status_code,status_description,attributes,start,end,retain_until
		 FROM spans WHERE invocation_id=? ORDER BY start ASC, span_id ASC LIMIT ?`,
		invocationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SpanRecord, 0, limit)
	for rows.Next() {
		var r SpanRecord
		if err := rows.Scan(&r.InvocationID, &r.TraceID, &r.SpanID, &r.ParentSpanID, &r.Name, &r.Stage, &r.Phase, &r.Disposition,
			&r.StatusCode, &r.StatusDescription, &r.Attributes, &r.Start, &r.End, &r.RetainUntil); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Close releases the store.
func (s *TraceStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}
