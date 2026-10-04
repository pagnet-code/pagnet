package a2a

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/internal/privatefs"
	_ "modernc.org/sqlite"
)

var ErrAttempted = errors.New("A2A invocation already attempted; never replay unknown effects")
var ErrAssociation = errors.New("A2A owned task association unavailable or changed")
var ErrConflict = errors.New("A2A invocation identity already binds different content")
var ErrCapacity = errors.New("A2A retained replay ledger capacity exhausted")

type DataProtector = durable.DataProtector
type KeyReference = durable.KeyReference
type StoreScope struct{ Domain, ID, Audience string }
type StoreConfig struct {
	MaxAdmissions, MaxEntries, MaxBytes, MaxDatabaseBytes int64
	MaxRecordBytes, MaxCipherBytes, ScanPage              int
}

func DefaultStoreConfig() StoreConfig {
	return StoreConfig{65536, 131072, 64 << 20, 128 << 20, 16384, 20480, 64}
}

type ledgerState struct {
	Format                     int
	Scope                      StoreScope
	Config                     StoreConfig
	Key                        KeyReference
	Admissions, Entries, Bytes int64
	Head                       string
}
type ledgerEntry struct {
	Sequence                   int64
	Previous, Identity, Action string
	Parent                     int64
	Association                Association
}
type SQLiteStore struct {
	mu          sync.Mutex
	db          *sql.DB
	lock        io.Closer
	scope       StoreScope
	config      StoreConfig
	protector   DataProtector
	reference   KeyReference
	state       ledgerState
	sealed      []byte
	dataVersion int64
	closed      bool
}

const ledgerSchema = `CREATE TABLE checkpoint(singleton INTEGER PRIMARY KEY CHECK(singleton=1),cipher BLOB NOT NULL);
CREATE TABLE journal(seq INTEGER PRIMARY KEY,identity TEXT NOT NULL,action TEXT NOT NULL CHECK(action IN ('admit','associate')),parent INTEGER NOT NULL,cipher BLOB NOT NULL,UNIQUE(identity,action));
CREATE TABLE latest(identity TEXT PRIMARY KEY,admit_seq INTEGER NOT NULL UNIQUE,last_seq INTEGER NOT NULL UNIQUE,FOREIGN KEY(admit_seq) REFERENCES journal(seq),FOREIGN KEY(last_seq) REFERENCES journal(seq));
PRAGMA user_version=1;`

func validStoreText(v string, n int) bool {
	return v != "" && len(v) <= n && utf8.ValidString(v) && !strings.ContainsAny(v, "\x00\r\n")
}
func validStoreConfig(c StoreConfig) bool {
	return c.MaxAdmissions > 0 && c.MaxAdmissions <= 10000000 && c.MaxEntries >= c.MaxAdmissions && c.MaxEntries <= 20000000 && c.MaxBytes > 0 && c.MaxBytes <= 1<<40 && c.MaxDatabaseBytes >= 32768 && c.MaxDatabaseBytes <= 1<<40 && c.MaxRecordBytes >= 1024 && c.MaxRecordBytes <= 65536 && c.MaxCipherBytes >= c.MaxRecordBytes && c.MaxCipherBytes <= 131072 && int64(c.MaxCipherBytes) <= c.MaxBytes && c.ScanPage > 0 && c.ScanPage <= 128
}
func Bootstrap(ctx context.Context, dir string, scope StoreScope, c StoreConfig, p DataProtector) (*SQLiteStore, error) {
	return openStore(ctx, dir, scope, c, p, true)
}
func Open(ctx context.Context, dir string, scope StoreScope, c StoreConfig, p DataProtector) (*SQLiteStore, error) {
	return openStore(ctx, dir, scope, c, p, false)
}
func openStore(ctx context.Context, dir string, scope StoreScope, c StoreConfig, p DataProtector, create bool) (*SQLiteStore, error) {
	if ctx == nil || p == nil || !validStoreText(scope.Domain, 256) || !validStoreText(scope.ID, 256) || !validStoreText(scope.Audience, 4096) || !validStoreConfig(c) {
		return nil, ErrAssociation
	}
	if _, e := fabric.ParseEndpointRef("pagnet://" + scope.Domain + "/e/" + strings.Repeat("a", 52)); e != nil {
		return nil, ErrAssociation
	}
	ref := p.Reference()
	if !validStoreText(ref.ID, 256) || !validStoreText(ref.Version, 128) {
		return nil, ErrAssociation
	}
	if create {
		if privatefs.CreateDirectory(dir) != nil {
			return nil, ErrAssociation
		}
	}
	lock, e := privatefs.Acquire(dir, "writer.lock")
	if e != nil {
		return nil, ErrAssociation
	}
	keep := false
	defer func() {
		if !keep {
			lock.Close()
		}
	}()
	path := filepath.Join(dir, "a2a.sqlite")
	if create {
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, ErrAssociation
		}
		if f.Close() != nil {
			return nil, ErrAssociation
		}
	}
	if privatefs.CheckFile(path, c.MaxDatabaseBytes) != nil {
		return nil, ErrAssociation
	}
	absolute, e := filepath.Abs(path)
	if e != nil || strings.HasPrefix(absolute, `\\`) {
		return nil, ErrAssociation
	}
	slash := filepath.ToSlash(absolute)
	if !strings.HasPrefix(slash, "/") {
		slash = "/" + slash
	}
	u := url.URL{Scheme: "file", Path: slash}
	q := u.Query()
	q.Set("mode", "rw")
	u.RawQuery = q.Encode()
	db, e := sql.Open("sqlite", u.String())
	if e != nil {
		return nil, ErrAssociation
	}
	defer func() {
		if !keep {
			db.Close()
		}
	}()
	db.SetMaxOpenConns(1)
	var pageSize int
	if db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize) != nil || pageSize != 4096 {
		return nil, ErrAssociation
	}
	if _, e = db.ExecContext(ctx, fmt.Sprintf("PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; PRAGMA max_page_count=%d", c.MaxDatabaseBytes/4096)); e != nil {
		return nil, ErrAssociation
	}
	s := &SQLiteStore{db: db, lock: lock, scope: scope, config: c, protector: p, reference: ref}
	if create {
		s.state = ledgerState{Format: 1, Scope: scope, Config: c, Key: ref}
		sealed, e := s.sealState(s.state)
		if e != nil {
			return nil, e
		}
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return nil, ErrAssociation
		}
		defer tx.Rollback()
		if _, e = tx.ExecContext(ctx, ledgerSchema); e != nil {
			return nil, ErrAssociation
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO checkpoint VALUES(1,?)", sealed); e != nil {
			return nil, ErrAssociation
		}
		if tx.Commit() != nil || privatefs.SyncDirectory(dir, "a2a.sqlite") != nil {
			return nil, ErrAssociation
		}
	}
	if s.verify(ctx) != nil {
		return nil, ErrAssociation
	}
	if db.QueryRowContext(ctx, "PRAGMA data_version").Scan(&s.dataVersion) != nil {
		return nil, ErrAssociation
	}
	keep = true
	return s, nil
}
func (s *SQLiteStore) Scope() StoreScope { return s.scope }
func (s *SQLiteStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return errors.Join(s.db.Close(), s.lock.Close())
}
func sum(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func identity(k AssociationKey) (string, error) {
	if !validStoreText(k.Principal.Ref, 4096) || !validStoreText(k.Principal.Issuer, 4096) || !validStoreText(string(k.Principal.Kind), 256) || !validStoreText(string(k.Revision), 256) || !validStoreText(k.Binding, 256) || !validStoreText(k.InvocationID, 256) || !validStoreText(k.Audience, 4096) {
		return "", ErrAssociation
	}
	if _, e := fabric.ParseEndpointRef(k.Ref.String()); e != nil {
		return "", ErrAssociation
	}
	raw, _ := json.Marshal(struct {
		Principal  fabric.Principal
		Invocation string
	}{k.Principal, k.InvocationID})
	return sum(raw), nil
}
func (s *SQLiteStore) aad(seq int64, id, action string, parent int64) []byte {
	raw, _ := json.Marshal(struct {
		Format           int
		Scope            StoreScope
		Config           StoreConfig
		Key              KeyReference
		Sequence         int64
		Identity, Action string
		Parent           int64
	}{1, s.scope, s.config, s.reference, seq, id, action, parent})
	return raw
}
func (s *SQLiteStore) sealState(st ledgerState) ([]byte, error) {
	raw, _ := json.Marshal(st)
	if len(raw) > s.config.MaxRecordBytes {
		return nil, ErrAssociation
	}
	sealed, e := s.protector.Seal(s.aad(0, "", "checkpoint", 0), raw)
	if e != nil || len(sealed) > s.config.MaxCipherBytes || len(sealed) == 0 {
		return nil, ErrAssociation
	}
	return sealed, nil
}
func (s *SQLiteStore) decode(cipher, aad []byte, out any) error {
	if len(cipher) == 0 || len(cipher) > s.config.MaxCipherBytes {
		return ErrAssociation
	}
	raw, e := s.protector.Open(aad, cipher)
	if e != nil || len(raw) > s.config.MaxRecordBytes {
		return ErrAssociation
	}
	if fabric.DecodeJSONWithLimits(raw, out, fabric.WireLimits{MaxBytes: s.config.MaxRecordBytes, MaxDepth: 32, MaxMembers: 256}) != nil {
		return ErrAssociation
	}
	return nil
}

type rowReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *SQLiteStore) readEntry(ctx context.Context, q rowReader, seq int64) (ledgerEntry, []byte, error) {
	var entry ledgerEntry
	var id, action string
	var parent int64
	var cipher []byte
	e := q.QueryRowContext(ctx, "SELECT CASE WHEN length(identity)=64 THEN identity ELSE NULL END,CASE WHEN length(action)<=16 THEN action ELSE NULL END,parent,CASE WHEN length(cipher)<=? THEN cipher ELSE NULL END FROM journal WHERE seq=?", s.config.MaxCipherBytes, seq).Scan(&id, &action, &parent, &cipher)
	if e != nil || s.decode(cipher, s.aad(seq, id, action, parent), &entry) != nil || entry.Sequence != seq || entry.Identity != id || entry.Action != action || entry.Parent != parent {
		return entry, nil, ErrAssociation
	}
	key, e := identity(entry.Association.Key)
	if e != nil || key != id || entry.Association.Key.Audience != s.scope.Audience || !validAssociation(entry.Association) {
		return entry, nil, ErrAssociation
	}
	return entry, cipher, nil
}
func validAssociation(a Association) bool {
	if len(a.InputSHA) != 64 || !((a.Operation == "send" && (a.Mode == "unary" || a.Mode == "stream")) || ((a.Operation == "get" || a.Operation == "subscribe" || a.Operation == "cancel") && a.Mode == "")) {
		return false
	}
	if _, e := hex.DecodeString(a.InputSHA); e != nil {
		return false
	}
	return (a.TaskID == "" && a.ContextID == "") || (validStoreText(a.TaskID, 4096) && validStoreText(a.ContextID, 4096))
}
func (s *SQLiteStore) verifySchema(ctx context.Context) error {
	expected := map[string]string{}
	for _, statement := range strings.Split(ledgerSchema, ";") {
		statement = strings.TrimSpace(statement)
		for _, name := range []string{"checkpoint", "journal", "latest"} {
			if strings.HasPrefix(statement, "CREATE TABLE "+name+"(") {
				expected[name] = statement
			}
		}
	}
	indices := map[string]string{"sqlite_autoindex_journal_1": "journal", "sqlite_autoindex_latest_1": "latest", "sqlite_autoindex_latest_2": "latest", "sqlite_autoindex_latest_3": "latest"}
	rows, e := s.db.QueryContext(ctx, "SELECT CASE WHEN length(type)<=16 THEN type ELSE NULL END,CASE WHEN length(name)<=128 THEN name ELSE NULL END,CASE WHEN length(tbl_name)<=128 THEN tbl_name ELSE NULL END,CASE WHEN length(sql)<=8192 THEN sql ELSE NULL END FROM sqlite_schema LIMIT 8")
	if e != nil {
		return ErrAssociation
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var kind, name, table string
		var statement sql.NullString
		if rows.Scan(&kind, &name, &table, &statement) != nil {
			return ErrAssociation
		}
		count++
		if kind == "table" {
			if name != table || !statement.Valid || expected[name] != statement.String {
				return ErrAssociation
			}
		} else if kind == "index" {
			if indices[name] != table || statement.Valid {
				return ErrAssociation
			}
		} else {
			return ErrAssociation
		}
	}
	if rows.Err() != nil || count != 7 {
		return ErrAssociation
	}
	return nil
}

func (s *SQLiteStore) verify(ctx context.Context) error {
	if s.verifySchema(ctx) != nil {
		return ErrAssociation
	}
	var version int
	var check string
	if s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version) != nil || version != 1 || s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check) != nil || check != "ok" {
		return ErrAssociation
	}
	var sealed []byte
	var count int
	if s.db.QueryRowContext(ctx, "SELECT count(*) FROM checkpoint").Scan(&count) != nil || count != 1 || s.db.QueryRowContext(ctx, "SELECT CASE WHEN length(cipher)<=? THEN cipher ELSE NULL END FROM checkpoint WHERE singleton=1", s.config.MaxCipherBytes).Scan(&sealed) != nil {
		return ErrAssociation
	}
	var st ledgerState
	if s.decode(sealed, s.aad(0, "", "checkpoint", 0), &st) != nil || st.Format != 1 || st.Scope != s.scope || st.Config != s.config || st.Key != s.reference || st.Admissions < 0 || st.Admissions > s.config.MaxAdmissions || st.Entries < st.Admissions || st.Entries > s.config.MaxEntries || st.Bytes < 0 || st.Bytes > s.config.MaxBytes {
		return ErrAssociation
	}
	var entries, admissions, bytes int64
	head := ""
	for entries < st.Entries {
		// Page keys only, bounded before decoding each record. No corpus-sized map.
		rows, e := s.db.QueryContext(ctx, "SELECT seq FROM journal WHERE seq>? ORDER BY seq LIMIT ?", entries, s.config.ScanPage)
		if e != nil {
			return ErrAssociation
		}
		seqs := make([]int64, 0, s.config.ScanPage)
		for rows.Next() {
			var seq int64
			if rows.Scan(&seq) != nil {
				rows.Close()
				return ErrAssociation
			}
			seqs = append(seqs, seq)
		}
		e = rows.Err()
		rows.Close()
		if e != nil || len(seqs) == 0 {
			return ErrAssociation
		}
		for _, seq := range seqs {
			if seq != entries+1 || seq > st.Entries {
				return ErrAssociation
			}
			entry, cipher, e := s.readEntry(ctx, s.db, seq)
			if e != nil || entry.Previous != head {
				return ErrAssociation
			}
			var first, last int64
			if s.db.QueryRowContext(ctx, "SELECT admit_seq,last_seq FROM latest WHERE identity=?", entry.Identity).Scan(&first, &last) != nil {
				return ErrAssociation
			}
			switch entry.Action {
			case "admit":
				if entry.Parent != 0 || first != seq || last < seq || entry.Association.TaskID != "" {
					return ErrAssociation
				}
				admissions++
				if last != seq {
					next, _, e := s.readEntry(ctx, s.db, last)
					if e != nil || next.Action != "associate" || next.Parent != seq || !sameAdmission(entry.Association, next.Association) {
						return ErrAssociation
					}
				}
			case "associate":
				if entry.Parent <= 0 || entry.Parent >= seq || first != entry.Parent || last != seq || entry.Association.TaskID == "" {
					return ErrAssociation
				}
				old, _, e := s.readEntry(ctx, s.db, entry.Parent)
				if e != nil || old.Action != "admit" || !sameAdmission(old.Association, entry.Association) {
					return ErrAssociation
				}
			default:
				return ErrAssociation
			}
			entries++
			bytes += int64(len(cipher))
			head = sum(cipher)
		}
	}
	var actualEntries, actualAdmissions int64
	if s.db.QueryRowContext(ctx, "SELECT count(*) FROM journal").Scan(&actualEntries) != nil || s.db.QueryRowContext(ctx, "SELECT count(*) FROM latest").Scan(&actualAdmissions) != nil || entries != actualEntries || admissions != actualAdmissions || admissions != st.Admissions || bytes != st.Bytes || head != st.Head {
		return ErrAssociation
	}
	s.state = st
	s.sealed = append([]byte(nil), sealed...)
	return nil
}
func sameAdmission(a, b Association) bool {
	a.TaskID = ""
	a.ContextID = ""
	b.TaskID = ""
	b.ContextID = ""
	return a == b
}
func (s *SQLiteStore) healthy(ctx context.Context) error {
	if s.closed || s.protector.Reference() != s.reference {
		return ErrAssociation
	}
	var v int64
	var sealed []byte
	if s.db.QueryRowContext(ctx, "PRAGMA data_version").Scan(&v) != nil || v != s.dataVersion || s.db.QueryRowContext(ctx, "SELECT CASE WHEN length(cipher)<=? THEN cipher ELSE NULL END FROM checkpoint WHERE singleton=1", s.config.MaxCipherBytes).Scan(&sealed) != nil || string(sealed) != string(s.sealed) {
		return ErrAssociation
	}
	return nil
}
func (s *SQLiteStore) lookup(ctx context.Context, q rowReader, k AssociationKey) (Association, int64, int64, error) {
	id, e := identity(k)
	if e != nil || k.Audience != s.scope.Audience {
		return Association{}, 0, 0, ErrAssociation
	}
	var first, last int64
	if q.QueryRowContext(ctx, "SELECT admit_seq,last_seq FROM latest WHERE identity=?", id).Scan(&first, &last) != nil {
		return Association{}, 0, 0, ErrAssociation
	}
	entry, _, e := s.readEntry(ctx, q, last)
	if e != nil || entry.Identity != id || entry.Association.Key != k {
		return Association{}, 0, 0, ErrAssociation
	}
	return entry.Association, first, last, nil
}
func (s *SQLiteStore) Lookup(ctx context.Context, k AssociationKey) (Association, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.healthy(ctx) != nil {
		return Association{}, ErrAssociation
	}
	a, _, _, e := s.lookup(ctx, s.db, k)
	return a, e
}
func (s *SQLiteStore) append(ctx context.Context, tx *sql.Tx, id, action string, parent int64, a Association) (ledgerState, []byte, error) {
	st := s.state
	st.Entries++
	if action == "admit" {
		st.Admissions++
	}
	if st.Entries > s.config.MaxEntries || st.Admissions > s.config.MaxAdmissions {
		return st, nil, ErrCapacity
	}
	entry := ledgerEntry{st.Entries, st.Head, id, action, parent, a}
	raw, e := json.Marshal(entry)
	if e != nil || len(raw) > s.config.MaxRecordBytes {
		return st, nil, ErrAssociation
	}
	cipher, e := s.protector.Seal(s.aad(st.Entries, id, action, parent), raw)
	if e != nil || len(cipher) == 0 || len(cipher) > s.config.MaxCipherBytes {
		return st, nil, ErrAssociation
	}
	st.Bytes += int64(len(cipher))
	if st.Bytes > s.config.MaxBytes {
		return st, nil, ErrCapacity
	}
	st.Head = sum(cipher)
	sealed, e := s.sealState(st)
	if e != nil {
		return st, nil, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO journal VALUES(?,?,?,?,?)", st.Entries, id, action, parent, cipher); e != nil {
		return st, nil, ErrAssociation
	}
	if action == "admit" {
		_, e = tx.ExecContext(ctx, "INSERT INTO latest VALUES(?,?,?)", id, st.Entries, st.Entries)
	} else {
		_, e = tx.ExecContext(ctx, "UPDATE latest SET last_seq=? WHERE identity=? AND admit_seq=? AND last_seq=?", st.Entries, id, parent, parent)
	}
	if e != nil {
		return st, nil, ErrAssociation
	}
	if _, e = tx.ExecContext(ctx, "UPDATE checkpoint SET cipher=? WHERE singleton=1", sealed); e != nil {
		return st, nil, ErrAssociation
	}
	return st, sealed, nil
}
func (s *SQLiteStore) Admit(ctx context.Context, a Association) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, e := identity(a.Key)
	if e != nil || a.Key.Audience != s.scope.Audience || !validAssociation(a) || a.TaskID != "" {
		return ErrAssociation
	}
	if s.healthy(ctx) != nil {
		return ErrAssociation
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return ErrAssociation
	}
	defer tx.Rollback()
	var seq int64
	e = tx.QueryRowContext(ctx, "SELECT admit_seq FROM latest WHERE identity=?", id).Scan(&seq)
	if e == nil {
		old, _, e := s.readEntry(ctx, tx, seq)
		if e != nil {
			return ErrAssociation
		}
		if sameAdmission(old.Association, a) {
			return ErrAttempted
		}
		return ErrConflict
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return ErrAssociation
	}
	st, sealed, e := s.append(ctx, tx, id, "admit", 0, a)
	if e != nil {
		return e
	}
	if tx.Commit() != nil {
		return ErrAssociation
	}
	s.state, s.sealed = st, sealed
	return nil
}
func (s *SQLiteStore) Associate(ctx context.Context, k AssociationKey, task, conversation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validStoreText(task, 4096) || !validStoreText(conversation, 4096) || s.healthy(ctx) != nil {
		return ErrAssociation
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return ErrAssociation
	}
	defer tx.Rollback()
	a, first, _, e := s.lookup(ctx, tx, k)
	if e != nil {
		return e
	}
	if a.TaskID != "" {
		if a.TaskID == task && a.ContextID == conversation {
			return nil
		}
		return ErrAssociation
	}
	a.TaskID, a.ContextID = task, conversation
	id, _ := identity(k)
	st, sealed, e := s.append(ctx, tx, id, "associate", first, a)
	if e != nil {
		return e
	}
	if tx.Commit() != nil {
		return ErrAssociation
	}
	s.state, s.sealed = st, sealed
	return nil
}
