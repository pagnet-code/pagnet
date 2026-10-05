package continuation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/internal/privatefs"
	_ "modernc.org/sqlite"
)

type Store struct {
	mu        sync.Mutex
	db        *sql.DB
	lock      io.Closer
	scope     Scope
	options   Options
	closed    bool
	protector durable.DataProtector
	keyRef    durable.KeyReference
}

const schema = `CREATE TABLE identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),scope BLOB NOT NULL);
CREATE TABLE budget(singleton INTEGER PRIMARY KEY CHECK(singleton=1),records INTEGER NOT NULL,bytes INTEGER NOT NULL);
INSERT INTO budget VALUES(1,0,0);
CREATE TABLE continuations(id TEXT PRIMARY KEY,snapshot BLOB NOT NULL,snapshot_digest TEXT NOT NULL,expires TEXT NOT NULL,cap_hash BLOB NOT NULL,cap_revision INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','claimed','complete')),receipt BLOB,outcome BLOB);
CREATE TABLE private_notifications(id TEXT NOT NULL,recipient TEXT NOT NULL,revision INTEGER NOT NULL,payload BLOB NOT NULL,published INTEGER NOT NULL CHECK(published IN(0,1)),PRIMARY KEY(id,recipient));
PRAGMA user_version=3;`

func invalid(s string) error { return fabric.NewError(fabric.CodeInvalidInput, s) }
func stale() error {
	return fabric.NewError(fabric.CodeStaleContinuation, "Continuation unavailable or stale")
}
func internal() error {
	return fabric.NewError(fabric.CodeProtocolError, "Private continuation state unavailable")
}
func text(s string, n int) bool {
	return len(s) > 0 && len(s) <= n && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
func hexID(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func (o Options) validate() error {
	if o.MaxJSONDepth <= 0 || o.MaxJSONMembers <= 0 || o.MaxRecords <= 0 || o.MaxRecords > math.MaxInt64/2 || o.MaxBytes <= 0 || o.MaxDatabaseBytes < 4096 || o.MaxSnapshotBytes <= 0 || o.MaxOutcomeBytes <= 0 || o.MaxTTL <= 0 || int64(o.MaxSnapshotBytes) > o.MaxBytes || int64(o.MaxOutcomeBytes) > o.MaxBytes || o.MaxBytes > math.MaxInt64/2 || o.MaxDatabaseBytes/4096 > math.MaxUint32 {
		return invalid("Invalid continuation limits")
	}
	return nil
}

// Bootstrap creates a new private store explicitly. Open never regenerates a
// missing database. Both hold a lifetime native OS writer lock, not a PID file.
func Bootstrap(ctx context.Context, dir string, scope Scope, options Options, protector durable.DataProtector) (*Store, error) {
	return open(ctx, dir, scope, options, protector, true)
}
func Open(ctx context.Context, dir string, scope Scope, options Options, protector durable.DataProtector) (*Store, error) {
	return open(ctx, dir, scope, options, protector, false)
}
func open(ctx context.Context, dir string, scope Scope, o Options, protector durable.DataProtector, create bool) (s *Store, err error) {
	if ctx == nil || protector == nil || !text(protector.Reference().ID, 4096) || !text(protector.Reference().Version, 256) {
		return nil, invalid("Private continuation protector required")
	}
	if e := o.validate(); e != nil {
		return nil, e
	}
	if !text(scope.Audience, 4096) {
		return nil, invalid("Invalid continuation audience")
	}
	if create {
		if e := privatefs.CreateDirectory(dir); e != nil && !os.IsExist(e) {
			return nil, internal()
		}
	}
	lock, e := privatefs.Acquire(dir, "writer.lock")
	if e != nil {
		return nil, internal()
	}
	keep := false
	defer func() {
		if !keep {
			lock.Close()
		}
	}()
	path := filepath.Join(dir, "continuations.sqlite")
	if create {
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, internal()
		}
		if e = f.Close(); e != nil {
			return nil, internal()
		}
	}
	if e := privatefs.CheckFile(path, o.MaxDatabaseBytes); e != nil {
		return nil, internal()
	}
	absolute, e := filepath.Abs(path)
	if e != nil {
		return nil, internal()
	}
	if strings.HasPrefix(absolute, `\\`) {
		return nil, invalid("UNC state paths unsupported")
	}
	p := filepath.ToSlash(absolute)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	q := u.Query()
	q.Set("mode", "rw")
	u.RawQuery = q.Encode()
	db, e := sql.Open("sqlite", u.String())
	if e != nil {
		return nil, internal()
	}
	defer func() {
		if !keep {
			db.Close()
		}
	}()
	db.SetMaxOpenConns(1)
	if _, e = db.ExecContext(ctx, "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;"); e != nil {
		return nil, internal()
	}
	if _, e = db.ExecContext(ctx, "PRAGMA max_page_count="+formatInt(o.MaxDatabaseBytes/4096)); e != nil {
		return nil, internal()
	}
	s = &Store{db: db, lock: lock, scope: scope, options: o, protector: protector, keyRef: protector.Reference()}
	if create {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return nil, internal()
		}
		defer tx.Rollback()
		if _, e = tx.ExecContext(ctx, schema); e != nil {
			return nil, internal()
		}
		b, e := s.sealIdentity()
		if e != nil {
			return nil, e
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO identity VALUES(1,?)", b); e != nil {
			return nil, internal()
		}
		if e = tx.Commit(); e != nil {
			return nil, internal()
		}
		if e = privatefs.SyncDirectory(dir, "continuations.sqlite"); e != nil {
			return nil, internal()
		}
	}
	var v int
	var check string
	var saved []byte
	if e = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); e != nil || v != 3 {
		return nil, internal()
	}
	if e = db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); e != nil || check != "ok" {
		return nil, internal()
	}
	if e = db.QueryRowContext(ctx, "SELECT CASE WHEN length(scope)<=? THEN scope END FROM identity WHERE singleton=1", maxSealOverhead+1024).Scan(&saved); e != nil {
		return nil, internal()
	}
	if e = s.verifyIdentity(saved); e != nil {
		return nil, e
	}
	if e = s.verify(ctx); e != nil {
		return nil, e
	}
	keep = true
	return s, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	e := s.db.Close()
	e2 := s.lock.Close()
	return errors.Join(e, e2)
}
func formatInt(v int64) string { return strconv.FormatInt(v, 10) }
func (s *Store) authenticated(c fabric.ExecutionContext) error {
	return c.VerifyAuthenticated(s.scope.Audience)
}
func allowed(snapshot Snapshot, p fabric.Principal) bool {
	for _, a := range snapshot.AllowedResumePrincipals {
		if a == p {
			return true
		}
	}
	return false
}
func validPrincipal(p fabric.Principal) bool {
	return text(p.Ref, 4096) && text(p.Issuer, 4096) && fabric.ValidNamespacedName(p.Kind)
}
func decode(b []byte, v any, bound int) error {
	if e := fabric.DecodeJSONWithLimits(b, v, fabric.WireLimits{MaxBytes: bound, MaxDepth: 64, MaxMembers: 4096}); e != nil {
		return invalid("Invalid bounded continuation JSON")
	}
	return nil
}
func (s *Store) snapshot(b []byte) (Snapshot, error) {
	var v Snapshot
	if e := s.decodePrivate(b, &v, s.options.MaxSnapshotBytes); e != nil {
		return v, e
	}
	if e := s.validateSnapshot(v); e != nil {
		return v, e
	}
	return v, nil
}
func (s *Store) validateSnapshot(v Snapshot) error {
	if v.Format != 1 || !hexID(v.DeferralID) || !validPrincipal(v.OriginalPrincipal) || len(v.AllowedResumePrincipals) == 0 || len(v.AllowedResumePrincipals) > 64 || !text(string(v.PlanRevision), 4096) || !text(v.PlanVersion, 256) || !hexID(v.PlanDigest) || len(v.OriginalEnvelope) == 0 {
		return invalid("Invalid continuation snapshot")
	}
	seen := map[fabric.Principal]bool{}
	for _, p := range v.AllowedResumePrincipals {
		if !validPrincipal(p) || seen[p] {
			return invalid("Invalid continuation resumers")
		}
		seen[p] = true
	}
	h := sha256.Sum256(v.Pipeline)
	if hex.EncodeToString(h[:]) != v.PlanDigest {
		return invalid("Pipeline digest mismatch")
	}
	for _, b := range [][]byte{v.Pipeline, v.State} {
		var x any
		if e := s.decodePrivate(b, &x, s.options.MaxSnapshotBytes); e != nil {
			return e
		}
	}
	return nil
}
func digest(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func mint(id string) (Capability, []byte, error) {
	var b [32]byte
	if _, e := io.ReadFull(rand.Reader, b[:]); e != nil {
		return Capability{}, nil, internal()
	}
	h := sha256.Sum256(b[:])
	return Capability{token: id + "." + base64.RawURLEncoding.EncodeToString(b[:])}, h[:], nil
}
func parseToken(t string) (string, []byte, error) {
	if len(t) != 108 || t[64] != '.' || !hexID(t[:64]) {
		return "", nil, stale()
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(t[65:])
	if e != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != t[65:] {
		return "", nil, stale()
	}
	h := sha256.Sum256(b)
	return t[:64], h[:], nil
}
func (s *Store) charge(ctx context.Context, tx *sql.Tx, records, bytes int64) error {
	r, e := tx.ExecContext(ctx, "UPDATE budget SET records=records+?,bytes=bytes+? WHERE singleton=1 AND records+?<=? AND bytes+?<=?", records, bytes, records, s.options.MaxRecords, bytes, s.options.MaxBytes)
	if e != nil {
		return internal()
	}
	n, e := r.RowsAffected()
	if e != nil || n != 1 {
		return invalid("Continuation store capacity reached")
	}
	return nil
}

func (s *Store) decodePrivate(b []byte, v any, bound int) error {
	if e := fabric.DecodeJSONWithLimits(b, v, fabric.WireLimits{MaxBytes: bound, MaxDepth: s.options.MaxJSONDepth, MaxMembers: s.options.MaxJSONMembers}); e != nil {
		return invalid("Invalid bounded private continuation JSON")
	}
	return nil
}
