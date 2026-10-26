// Package ledger stores the private, durable state of text bridge jobs. It does
// not perform provider requests or interpret SDK receipts.
package ledger

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

type Phase string

const (
	Queued          Phase = "queued"
	ProviderStarted Phase = "provider_started"
	OutputReady     Phase = "output_ready"
	ReplyPreparing  Phase = "reply_preparing"
	ReplyPrepared   Phase = "reply_prepared"
	Admitted        Phase = "admitted"
	Unknown         Phase = "unknown"
	Rejected        Phase = "rejected"
)

var (
	ErrConflict = errors.New("text bridge ASK conflicts with stored wire digest")
	ErrStale    = errors.New("text bridge ledger revision changed")
	ErrInvalid  = errors.New("invalid text bridge ledger state")
)

type Binding struct {
	ServiceOrigin string
	PrincipalID   string
}

// Data contains previously validated protocol data. Header and Receipt retain
// their original JSON; provider credentials must never be stored here.
type Data struct {
	Header                    json.RawMessage
	WireDigest                string
	Input                     []byte
	ProviderConfigFingerprint string
	Output                    []byte
	ReplyID                   string
	ReplyDigest               string
	Receipt                   json.RawMessage
}
type Job struct {
	ProjectID string
	AskID     string
	Revision  int64
	Phase     Phase
	Revoked   bool
	Data      Data
}
type Store struct {
	db      *sql.DB
	aead    cipher.AEAD
	binding Binding
}

type aad struct {
	Binding   Binding
	ProjectID string
	AskID     string
	Revision  int64
	Phase     Phase
	Revoked   bool
}

func normalizeBinding(b Binding) (Binding, error) {
	u, err := url.Parse(b.ServiceOrigin)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.TrimSpace(b.PrincipalID) == "" {
		return b, ErrInvalid
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return b, ErrInvalid
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return b, ErrInvalid
		}
	}
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	b.ServiceOrigin = u.Scheme + "://" + host
	return b, nil
}
func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

// makePrivateDir requires an absolute path. Sync every ancestor's directory
// entry, even if it already exists: an earlier attempt may have stopped after
// mkdir but before syncing its parent. Reject symlinks so the walked parents
// are the same directories that will contain the ledger.
func makePrivateDir(path string, syncDirectory func(string) error) error {
	info, err := os.Lstat(path)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return err
	}
	if !missing && !info.IsDir() {
		return fmt.Errorf("text bridge ledger path is not a directory: %s", path)
	}
	parent := filepath.Dir(path)
	if parent == path {
		return nil
	}
	if err = makePrivateDir(parent, syncDirectory); err != nil {
		return err
	}
	if missing {
		if err = os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err = os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("text bridge ledger path is not a directory: %s", path)
		}
		if err = os.Chmod(path, 0700); err != nil {
			return err
		}
	}
	return syncDirectory(parent)
}
func readKey(dir string, exists bool) ([]byte, error) {
	path := filepath.Join(dir, "key")
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && !exists {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		f, e := os.CreateTemp(dir, ".key-*")
		if e != nil {
			return nil, e
		}
		defer os.Remove(f.Name())
		if _, err = f.Write(key); err != nil {
			f.Close()
			return nil, err
		}
		if err = f.Sync(); err != nil {
			f.Close()
			return nil, err
		}
		if err = f.Close(); err != nil {
			return nil, err
		}
		if err = os.Link(f.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if err = syncDir(dir); err != nil {
			return nil, err
		}
		key, err = os.ReadFile(path)
	}
	if err != nil || len(key) != 32 {
		return nil, errors.New("text bridge ledger key unavailable")
	}
	if err = os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

// Open creates a private ledger or authenticates the complete existing ledger.
// An existing database is never reinitialized, including after key loss. Missing
// databases with initialization evidence also fail closed to retain deduplication.
func Open(dir string, b Binding) (*Store, error) {
	b, err := normalizeBinding(b)
	if err != nil {
		return nil, err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = makePrivateDir(dir, syncDir); err != nil {
		return nil, err
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "ledger.sqlite")
	_, err = os.Stat(path)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if !exists {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		if len(entries) != 0 {
			return nil, errors.New("text bridge ledger database missing with initialization evidence")
		}
	}
	key, err := readKey(dir, exists)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if !exists {
		f, err := os.CreateTemp(dir, ".ledger-*")
		if err != nil {
			return nil, err
		}
		temporary := f.Name()
		defer os.Remove(temporary)
		if err = f.Close(); err != nil {
			return nil, err
		}
		s, err := openDatabase(temporary, aead, b, true)
		if err != nil {
			return nil, err
		}
		if err = s.Close(); err != nil {
			return nil, err
		}
		if err = os.Link(temporary, path); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	if err = syncDir(dir); err != nil {
		return nil, err
	}
	return openDatabase(path, aead, b, false)
}
func openDatabase(path string, aead cipher.AEAD, b Binding, initialize bool) (_ *Store, err error) {
	if err = os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	q := url.Values{"mode": {"rw"}, "_pragma": {"journal_mode=DELETE", "synchronous=EXTRA", "busy_timeout=5000"}}
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}).String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, aead: aead, binding: b}
	defer func() {
		if err != nil {
			db.Close()
		}
	}()
	var sync int
	if err = db.QueryRow("PRAGMA synchronous").Scan(&sync); err != nil {
		return nil, err
	}
	if sync != 3 {
		return nil, errors.New("text bridge ledger durability unavailable")
	}
	if initialize {
		tx, e := db.Begin()
		if e != nil {
			return nil, e
		}
		defer tx.Rollback()
		for _, stmt := range []string{"CREATE TABLE binding(id INTEGER PRIMARY KEY CHECK(id=1),sealed BLOB NOT NULL)", "CREATE TABLE jobs(project_id TEXT NOT NULL,ask_id TEXT NOT NULL,revision INTEGER NOT NULL,phase TEXT NOT NULL,revoked INTEGER NOT NULL CHECK(revoked IN (0,1)),sealed BLOB NOT NULL,PRIMARY KEY(project_id,ask_id))"} {
			if _, err = tx.Exec(stmt); err != nil {
				return nil, err
			}
		}
		plain, _ := json.Marshal(b)
		var sealed []byte
		sealed, err = s.seal(plain, []byte("text-bridge-ledger-binding-v1"))
		if err != nil {
			return nil, err
		}
		if _, err = tx.Exec("INSERT INTO binding VALUES(1,?)", sealed); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
	}
	var check string
	if err = db.QueryRow("PRAGMA quick_check").Scan(&check); err != nil {
		return nil, err
	}
	if check != "ok" {
		return nil, ErrInvalid
	}
	var sealed []byte
	if err = db.QueryRow("SELECT sealed FROM binding WHERE id=1").Scan(&sealed); err != nil {
		return nil, err
	}
	plain, e := s.unseal(sealed, []byte("text-bridge-ledger-binding-v1"))
	if e != nil {
		return nil, e
	}
	expected, _ := json.Marshal(b)
	if !bytes.Equal(plain, expected) {
		return nil, errors.New("text bridge ledger binding mismatch")
	}
	if _, err = s.List(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) seal(plain, aad []byte) ([]byte, error) {
	n := make([]byte, s.aead.NonceSize())
	if _, e := rand.Read(n); e != nil {
		return nil, e
	}
	return s.aead.Seal(n, n, plain, aad), nil
}
func (s *Store) unseal(sealed, aad []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, ErrInvalid
	}
	p, e := s.aead.Open(nil, sealed[:n], sealed[n:], aad)
	if e != nil {
		return nil, fmt.Errorf("text bridge ledger authentication failed: %w", e)
	}
	return p, nil
}
func validPhase(p Phase) bool {
	switch p {
	case Queued, ProviderStarted, OutputReady, ReplyPreparing, ReplyPrepared, Admitted, Unknown, Rejected:
		return true
	}
	return false
}
func validDigest(s string) bool { b, e := hex.DecodeString(s); return e == nil && len(b) == 32 }
func validData(d Data) bool {
	return validDigest(d.WireDigest) && json.Valid(d.Header) && (len(d.Receipt) == 0 || json.Valid(d.Receipt)) && (d.ReplyDigest == "" || validDigest(d.ReplyDigest))
}
func (s *Store) jobAAD(j Job) []byte {
	b, _ := json.Marshal(aad{s.binding, j.ProjectID, j.AskID, j.Revision, j.Phase, j.Revoked})
	return b
}
func (s *Store) encode(j Job) ([]byte, error) {
	if j.ProjectID == "" || j.AskID == "" || j.Revision < 1 || !validPhase(j.Phase) || !validData(j.Data) {
		return nil, ErrInvalid
	}
	p, e := json.Marshal(j.Data)
	if e != nil {
		return nil, e
	}
	return s.seal(p, s.jobAAD(j))
}

type scanner interface{ Scan(...any) error }

func (s *Store) scan(row scanner) (Job, error) {
	var j Job
	var sealed []byte
	e := row.Scan(&j.ProjectID, &j.AskID, &j.Revision, &j.Phase, &j.Revoked, &sealed)
	if e != nil {
		return j, e
	}
	p, e := s.unseal(sealed, s.jobAAD(j))
	if e != nil {
		return Job{}, e
	}
	if e = json.Unmarshal(p, &j.Data); e != nil {
		return Job{}, e
	}
	if j.ProjectID == "" || j.AskID == "" || j.Revision < 1 || !validPhase(j.Phase) || !validData(j.Data) {
		return Job{}, ErrInvalid
	}
	return j, nil
}

const columns = "project_id,ask_id,revision,phase,revoked,sealed"

func (s *Store) Get(ctx context.Context, projectID, askID string) (Job, error) {
	return s.scan(s.db.QueryRowContext(ctx, "SELECT "+columns+" FROM jobs WHERE project_id=? AND ask_id=?", projectID, askID))
}

// List returns authenticated jobs, optionally restricted to recovery phases.
func (s *Store) List(ctx context.Context, phases ...Phase) ([]Job, error) {
	for _, p := range phases {
		if !validPhase(p) {
			return nil, ErrInvalid
		}
	}
	rows, e := s.db.QueryContext(ctx, "SELECT "+columns+" FROM jobs ORDER BY project_id,ask_id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	jobs := []Job{}
	for rows.Next() {
		j, e := s.scan(rows)
		if e != nil {
			return nil, e
		}
		include := len(phases) == 0
		for _, p := range phases {
			include = include || j.Phase == p
		}
		if include {
			jobs = append(jobs, j)
		}
	}
	return jobs, rows.Err()
}

// Insert records an ASK once. Repeated delivery returns the original state even
// after completion; a different wire digest for its identity fails closed.
func (s *Store) Insert(ctx context.Context, projectID, askID string, d Data) (Job, error) {
	j := Job{ProjectID: projectID, AskID: askID, Revision: 1, Phase: Queued, Data: d}
	sealed, e := s.encode(j)
	if e != nil {
		return Job{}, e
	}
	result, e := s.db.ExecContext(ctx, "INSERT INTO jobs("+columns+") VALUES(?,?,?,?,?,?) ON CONFLICT(project_id,ask_id) DO NOTHING", projectID, askID, j.Revision, j.Phase, j.Revoked, sealed)
	if e != nil {
		return Job{}, e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return Job{}, e
	}
	if n == 1 {
		return j, nil
	}
	old, e := s.Get(ctx, projectID, askID)
	if e != nil {
		return Job{}, e
	}
	if old.Data.WireDigest != d.WireDigest {
		return Job{}, ErrConflict
	}
	return old, nil
}
func allowed(from, to Phase) bool {
	if from == Admitted || from == Unknown || from == Rejected {
		return false
	}
	if to == Unknown {
		return true
	}
	switch from {
	case Queued:
		return to == ProviderStarted || to == Rejected
	case ProviderStarted:
		return to == OutputReady
	case OutputReady:
		return to == ReplyPreparing
	case ReplyPreparing:
		return to == ReplyPrepared
	case ReplyPrepared:
		return to == Admitted
	}
	return false
}

// CompareAndSwap advances exactly the caller's observed revision. A revoked
// job can only reconcile a previously prepared reply's validated receipt. The
// immutable incoming ASK digest cannot change.
func (s *Store) CompareAndSwap(ctx context.Context, expected Job, next Phase, d Data) (Job, error) {
	if expected.Revoked && (expected.Phase != ReplyPrepared || next != Admitted || len(d.Receipt) == 0 || bytes.Equal(bytes.TrimSpace(d.Receipt), []byte("null"))) {
		return Job{}, ErrInvalid
	}
	if !allowed(expected.Phase, next) || d.WireDigest != expected.Data.WireDigest {
		return Job{}, ErrInvalid
	}
	j := expected
	j.Revision++
	j.Phase = next
	j.Data = d
	return s.replace(ctx, expected, j)
}

// Revoke durably marks a job without deleting its deduplication record.
func (s *Store) Revoke(ctx context.Context, expected Job) (Job, error) {
	if expected.Revoked {
		return Job{}, ErrInvalid
	}
	j := expected
	j.Revision++
	j.Revoked = true
	return s.replace(ctx, expected, j)
}
func (s *Store) replace(ctx context.Context, expected, j Job) (Job, error) {
	stored, e := s.Get(ctx, expected.ProjectID, expected.AskID)
	if e != nil {
		return Job{}, e
	}
	if stored.Revision != expected.Revision || stored.Phase != expected.Phase || stored.Revoked != expected.Revoked {
		return Job{}, ErrStale
	}
	if j.Data.WireDigest != stored.Data.WireDigest || !bytes.Equal(j.Data.Header, stored.Data.Header) || !bytes.Equal(j.Data.Input, stored.Data.Input) || j.Data.ProviderConfigFingerprint != stored.Data.ProviderConfigFingerprint {
		return Job{}, ErrInvalid
	}
	if expected.Revoked && (stored.Data.ReplyID == "" || j.Data.ReplyID != stored.Data.ReplyID || j.Data.ReplyDigest != stored.Data.ReplyDigest) {
		return Job{}, ErrInvalid
	}
	if j.Revoked && !expected.Revoked {
		j.Data = stored.Data
	}
	sealed, e := s.encode(j)
	if e != nil {
		return Job{}, e
	}
	r, e := s.db.ExecContext(ctx, "UPDATE jobs SET revision=?,phase=?,revoked=?,sealed=? WHERE project_id=? AND ask_id=? AND revision=? AND phase=? AND revoked=?", j.Revision, j.Phase, j.Revoked, sealed, j.ProjectID, j.AskID, expected.Revision, expected.Phase, expected.Revoked)
	if e != nil {
		return Job{}, e
	}
	n, e := r.RowsAffected()
	if e != nil {
		return Job{}, e
	}
	if n != 1 {
		return Job{}, ErrStale
	}
	return j, nil
}
