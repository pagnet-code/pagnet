// Package registry implements a private, single-writer local domain ledger.
// Independent writable copies of one domain are unsupported forks, not failover.
// This package does not implement distributed consensus or invocation policy.
package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/internal/privatefs"
	_ "modernc.org/sqlite"
)

const maxPayload = 64 << 10
const maxRecords = 100000
const maxLedgerBytes = 64 << 20

type GenesisBody struct {
	Protocol  string           `json:"protocol"`
	Namespace string           `json:"namespace"`
	PublicKey []byte           `json:"publicKey"`
	StoreID   string           `json:"storeId"`
	Owner     fabric.Principal `json:"owner"`
}
type GenesisRecord struct {
	Body      json.RawMessage `json:"body"`
	Signature []byte          `json:"signature"`
}
type Record struct {
	Frame     fabric.RegistryFrame `json:"frame"`
	Payload   json.RawMessage      `json:"payload"`
	Signature []byte               `json:"signature"`
}

// Store owns the sole authoritative writer lock until Close. Private root keys
// never appear in descriptors, search documents, prompts or wire envelopes.
type Store struct {
	mu       sync.Mutex
	db       *sql.DB
	lock     io.Closer
	key      ed25519.PrivateKey
	genesis  GenesisRecord
	identity GenesisBody
	closed   bool
	dir      string
	options  Options
}

const schema = `
CREATE TABLE identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),genesis BLOB NOT NULL);
CREATE TABLE ledger(domain TEXT NOT NULL,sequence INTEGER NOT NULL,record BLOB NOT NULL,head BLOB NOT NULL,PRIMARY KEY(domain,sequence));
CREATE TABLE objects(ref TEXT PRIMARY KEY,domain TEXT NOT NULL,parent TEXT NOT NULL,kind TEXT NOT NULL,revision TEXT NOT NULL,retired INTEGER NOT NULL,payload BLOB NOT NULL,owner TEXT NOT NULL,mutation BLOB NOT NULL);
CREATE INDEX offers_parent ON objects(parent,ref);
CREATE TABLE pins(domain TEXT PRIMARY KEY,genesis BLOB NOT NULL);
CREATE TABLE search_outbox(sequence INTEGER PRIMARY KEY AUTOINCREMENT,ref TEXT NOT NULL,revision TEXT NOT NULL,retired INTEGER NOT NULL,document BLOB);
CREATE TABLE search_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),watermark INTEGER NOT NULL,generation INTEGER NOT NULL,commit_hash TEXT NOT NULL);
INSERT INTO search_state VALUES(1,0,0,'');
CREATE TABLE checkpoint_head(singleton INTEGER PRIMARY KEY CHECK(singleton=1),header BLOB NOT NULL);
CREATE TABLE checkpoint_pages(section TEXT NOT NULL,after_key TEXT NOT NULL,page BLOB NOT NULL,PRIMARY KEY(section,after_key));
CREATE TABLE index_refs(ref TEXT PRIMARY KEY,revision TEXT NOT NULL);
CREATE TABLE index_commits(generation INTEGER PRIMARY KEY,record BLOB NOT NULL);
CREATE TABLE ledger_budget(singleton INTEGER PRIMARY KEY CHECK(singleton=1),records INTEGER NOT NULL,bytes INTEGER NOT NULL);
INSERT INTO ledger_budget VALUES(1,0,0);
PRAGMA user_version=1;
`

// Bootstrap is an explicit trusted-composition action. A partially installed or
// existing identity always fails closed; it is never replaced automatically.
func Bootstrap(ctx context.Context, dir string, owner fabric.Principal) (*Store, error) {
	return bootstrap(ctx, dir, owner, nil)
}
func bootstrap(ctx context.Context, dir string, owner fabric.Principal, checkpoint func(string)) (*Store, error) {
	return bootstrapWithOptions(ctx, dir, owner, checkpoint, DefaultOptions())
}
func bootstrapWithOptions(ctx context.Context, dir string, owner fabric.Principal, checkpoint func(string), options Options) (*Store, error) {
	if e := options.validate(); e != nil {
		return nil, e
	}
	if !text(owner.Ref, 4096, false) || !text(owner.Issuer, 4096, false) || !fabric.ValidNamespacedName(owner.Kind) {
		return nil, invalid("invalid pinned local owner")
	}
	if e := createPrivateDirectory(dir); e != nil && !os.IsExist(e) {
		return nil, e
	}
	lock, e := lockDirectory(dir)
	if e != nil {
		return nil, e
	}
	keep := false
	defer func() {
		if !keep {
			lock.Close()
		}
	}()
	keyPath := filepath.Join(dir, "genesis.key")
	dbPath := filepath.Join(dir, "registry.sqlite")
	for _, p := range []string{keyPath, dbPath} {
		if _, e = os.Lstat(p); !os.IsNotExist(e) {
			return nil, invalid("local domain already exists or contains incomplete identity")
		}
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	var id [32]byte
	if _, e = io.ReadFull(rand.Reader, id[:]); e != nil {
		return nil, e
	}
	namespace, _ := fabric.DomainNamespace(pub)
	body := GenesisBody{Protocol: "pagnet.fabric.genesis.v1", Namespace: namespace, PublicKey: pub, StoreID: hex.EncodeToString(id[:]), Owner: owner}
	raw, e := json.Marshal(body)
	if e != nil {
		return nil, e
	}
	digest := sha256.Sum256(raw)
	var pk [32]byte
	copy(pk[:], pub)
	frame, e := (fabric.GenesisFrame{Namespace: namespace, GenesisPublicKey: pk, PayloadDigest: digest}).SigningBytes()
	if e != nil {
		return nil, e
	}
	g := GenesisRecord{Body: raw, Signature: ed25519.Sign(key, frame)}
	if e = installPrivate(dir, keyPath, key); e != nil {
		return nil, e
	}
	if checkpoint != nil {
		checkpoint("key-installed")
	}
	db, e := createDB(dbPath, options)
	if e != nil {
		return nil, e
	}
	good := false
	defer func() {
		if !good {
			db.Close()
		}
	}()
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, schema); e != nil {
		return nil, e
	}
	encoded, _ := json.Marshal(g)
	if _, e = tx.ExecContext(ctx, "INSERT INTO identity VALUES(1,?)", encoded); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	if checkpoint != nil {
		checkpoint("ledger-committed")
	}
	if e = syncDirectory(dir); e != nil {
		return nil, e
	}
	s := &Store{db: db, lock: lock, dir: dir, options: options}
	if e = s.readback(ctx); e != nil {
		return nil, e
	}
	good = true
	keep = true
	return s, nil
}

// Open validates the original key/genesis, complete signed ledger and current
// materialized heads. Missing/corrupt state never generates a replacement key.
func Open(ctx context.Context, dir string) (*Store, error) {
	return openWithOptions(ctx, dir, DefaultOptions())
}
func openWithOptions(ctx context.Context, dir string, options Options) (*Store, error) {
	if e := options.validate(); e != nil {
		return nil, e
	}
	lock, e := lockDirectory(dir)
	if e != nil {
		return nil, e
	}
	keep := false
	defer func() {
		if !keep {
			lock.Close()
		}
	}()
	if e = checkPrivateDatabase(filepath.Join(dir, "registry.sqlite"), options.Limits.MaxDatabaseBytes); e != nil {
		return nil, e
	}
	db, e := openDB(filepath.Join(dir, "registry.sqlite"), options)
	if e != nil {
		return nil, e
	}
	s := &Store{db: db, lock: lock, dir: dir, options: options}
	if e = s.readback(ctx); e != nil {
		db.Close()
		return nil, e
	}
	keep = true
	return s, nil
}
func createDB(path string, options Options) (*sql.DB, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = f.Close(); e != nil {
		return nil, e
	}
	return openDB(path, options)
}
func openDB(path string, options Options) (*sql.DB, error) {
	absolute, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	uriPath := filepath.ToSlash(absolute)
	volume := filepath.VolumeName(absolute)
	if strings.HasPrefix(volume, "\\") {
		return nil, invalid("registry database must be on a local filesystem")
	}
	if volume != "" && !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := u.Query()
	q.Set("mode", "rw")
	u.RawQuery = q.Encode()
	db, e := sql.Open("sqlite", u.String())
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	if _, e = db.Exec("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;"); e != nil {
		db.Close()
		return nil, e
	}
	if e = configureDatabase(db, options); e != nil {
		db.Close()
		return nil, e
	}
	return db, nil
}
func installPrivate(dir, path string, b []byte) error {
	f, e := os.CreateTemp(dir, ".key-install-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = publishPrivate(f.Name(), path); e != nil {
		return e
	}
	return privatefs.SyncDirectory(dir, "genesis.key")
}

func invalid(message string) error  { return fabric.NewError(fabric.CodeInvalidInput, message) }
func conflict(message string) error { return fabric.NewError(fabric.CodeStaleReference, message) }
func decodeGenesis(g GenesisRecord) (GenesisBody, error) {
	var body GenesisBody
	if len(g.Body) > 32768 || len(g.Signature) != ed25519.SignatureSize {
		return body, invalid("genesis record exceeds fixed identity bounds")
	}
	if e := fabric.DecodeJSON(g.Body, &body); e != nil {
		return body, e
	}
	if body.Protocol != "pagnet.fabric.genesis.v1" || len(body.PublicKey) != 32 || len(body.StoreID) != 64 || !text(body.Owner.Ref, 4096, false) || !text(body.Owner.Issuer, 4096, false) || !fabric.ValidNamespacedName(body.Owner.Kind) {
		return body, invalid("malformed domain genesis")
	}
	storeID, e := hex.DecodeString(body.StoreID)
	if e != nil || len(storeID) != 32 || hex.EncodeToString(storeID) != body.StoreID {
		return body, invalid("malformed genesis store identity")
	}
	var pk [32]byte
	copy(pk[:], body.PublicKey)
	frame, e := (fabric.GenesisFrame{Namespace: body.Namespace, GenesisPublicKey: pk, PayloadDigest: sha256.Sum256(g.Body)}).SigningBytes()
	if e != nil || !ed25519.Verify(body.PublicKey, frame, g.Signature) {
		return body, invalid("invalid self-certifying genesis signature")
	}
	return body, nil
}
func (s *Store) readback(ctx context.Context) error {
	var version int
	if e := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil || version != 1 {
		return invalid("unsupported or missing registry format")
	}
	var raw []byte
	if e := s.db.QueryRowContext(ctx, "SELECT CASE WHEN length(genesis)<=65536 THEN genesis END FROM identity WHERE singleton=1").Scan(&raw); e != nil {
		return e
	}
	if e := fabric.DecodeJSON(raw, &s.genesis); e != nil {
		return e
	}
	body, e := decodeGenesis(s.genesis)
	if e != nil {
		return e
	}
	key, e := readPrivate(filepath.Join(s.dir, "genesis.key"), 64)
	if e != nil {
		return e
	}
	if len(key) != 64 {
		return invalid("malformed original signing key")
	}
	expected := ed25519.NewKeyFromSeed(key[:32])
	if !bytes.Equal(key, expected) || !bytes.Equal(key[32:], body.PublicKey) {
		return invalid("original signing key does not match pinned genesis")
	}
	s.key = ed25519.PrivateKey(key)
	s.identity = body
	if e = s.verifyLedger(ctx); e != nil {
		return e
	}
	if e = s.verifyOutbox(ctx); e != nil {
		return e
	}
	return s.verifyIndex(ctx)
}

func (s *Store) authorize(c fabric.ExecutionContext) error {
	if s.closed {
		return errors.New("registry closed")
	}
	if e := c.VerifyAuthenticated(s.identity.Namespace); e != nil {
		return e
	}
	if c.PrincipalView() != s.identity.Owner {
		return fabric.NewError(fabric.CodeUnauthenticated, "registry owner does not match pinned local identity")
	}
	return nil
}
func (s *Store) Namespace() string { return s.identity.Namespace }
func (s *Store) Genesis() GenesisRecord {
	return GenesisRecord{Body: bytes.Clone(s.genesis.Body), Signature: bytes.Clone(s.genesis.Signature)}
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for i := range s.key {
		s.key[i] = 0
	}
	e := s.db.Close()
	lockErr := s.lock.Close()
	if e != nil {
		return e
	}
	return lockErr
}
