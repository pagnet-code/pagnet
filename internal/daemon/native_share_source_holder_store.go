//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
	"golang.org/x/sys/unix"
)

const nativeShareSourceHolderNamespace = "source-share-holders"

var errNativeShareSourceHolder = errors.New("native share source holder unavailable, unsafe or conflicting")

// NativeShareSourceHolderScope identifies logical local provenance, not current
// authorization or protection against cloning an entire registry installation.
// The installation ID is supplied by the registry, never by a remote request.
type NativeShareSourceHolderScope struct {
	ServerURL string    `json:"serverUrl"`
	TenantID  domain.ID `json:"tenantId"`
	AccountID domain.ID `json:"accountId"`
	HostID    domain.ID `json:"hostId"`
}

type NativeShareSourceHolderDescriptor struct {
	Version        int                          `json:"version"`
	Scope          NativeShareSourceHolderScope `json:"scope"`
	InstallationID domain.ID                    `json:"installationId"`
	HolderID       domain.ID                    `json:"holderId"`
	Generation     uint64                       `json:"generation"`
	X25519         string                       `json:"x25519"`
	Ed25519        string                       `json:"ed25519"`
	Fingerprint    string                       `json:"fingerprint"`
}

type nativeShareSourceHolderRecord struct {
	Descriptor     NativeShareSourceHolderDescriptor `json:"descriptor"`
	X25519Private  []byte                            `json:"x25519Private"`
	Ed25519Private []byte                            `json:"ed25519Private"`
}

// NativeShareSourceHolderStore is dormant. Its independent random keys carry no
// source, host, membership, registration or inventory authority. No HostIdentity
// or recipient key is accepted. The only root is an open local worker registry.
// Lock order is registry mutex, namespace flock, SQLite write reservation. A key
// callback must not reenter this store, the registry, or any other holder store.
type NativeShareSourceHolderStore struct {
	registry     *NativeWorkerRegistry
	installation domain.ID
	sync         func(*os.File) error
}

func (s NativeShareSourceHolderStore) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "NativeShareSourceHolderStore{closed}")
}

// initSourceHolderInstallation migrates only local metadata. FULL SQLite commits
// precede creation of the source-holder namespace. Existing filesystem or SQL
// enrollment evidence forbids creating a replacement installation identity.
func (r *NativeWorkerRegistry) initSourceHolderInstallation() error {
	root, err := nativeShareHolderDirectory(r.root)
	if err != nil {
		return err
	}
	defer root.Close()
	conn, err := r.db.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS native_registry_metadata(name TEXT PRIMARY KEY,value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS native_managed_endpoint_prepare_commands(command_id TEXT PRIMARY KEY,enrollment_id TEXT NOT NULL UNIQUE,installation_id TEXT NOT NULL,server_url TEXT NOT NULL,request BLOB NOT NULL CHECK(length(request)<=24576),request_digest BLOB NOT NULL CHECK(length(request_digest)=32),expires_at TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('reserved','succeeded','failed')),ack BLOB CHECK(length(ack)<=24576),CHECK((state='reserved' AND ack IS NULL) OR (state IN ('succeeded','failed') AND ack IS NOT NULL)))`,
		`CREATE TABLE IF NOT EXISTS native_managed_endpoint_pop_challenges(challenge_id TEXT PRIMARY KEY,enrollment_id TEXT NOT NULL UNIQUE,direct_intent_id TEXT NOT NULL UNIQUE,installation_id TEXT NOT NULL,request BLOB NOT NULL CHECK(length(request)<=65536),request_digest BLOB NOT NULL CHECK(length(request_digest)=32),proof BLOB CHECK(length(proof)<=1024))`,
		`CREATE TABLE IF NOT EXISTS native_managed_endpoint_key_slots(scope TEXT PRIMARY KEY,installation_id TEXT NOT NULL,identity BLOB NOT NULL,key_generation INTEGER NOT NULL CHECK(key_generation=1),file_format INTEGER NOT NULL CHECK(file_format IN(1,2)),legacy_enrollment_id TEXT NOT NULL,x25519 TEXT)`,
		`CREATE TABLE IF NOT EXISTS native_managed_endpoint_keys(enrollment_id TEXT PRIMARY KEY,scope TEXT NOT NULL UNIQUE,installation_id TEXT NOT NULL,request BLOB NOT NULL,reservation BLOB)`,
		`CREATE TABLE IF NOT EXISTS native_direct_managed_source_keys(binding_id TEXT PRIMARY KEY,scope TEXT NOT NULL UNIQUE,installation_id TEXT NOT NULL,request BLOB NOT NULL CHECK(length(request)<=24576),reservation BLOB CHECK(length(reservation)<=24576))`,
		`CREATE TABLE IF NOT EXISTS native_direct_managed_source_prepare_commands(command_id TEXT PRIMARY KEY,binding_id TEXT NOT NULL UNIQUE,installation_id TEXT NOT NULL,server_url TEXT NOT NULL,request BLOB NOT NULL CHECK(length(request)<=24576),request_digest BLOB NOT NULL CHECK(length(request_digest)=32),expires_at TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('reserved','succeeded','failed')),ack BLOB CHECK(length(ack)<=24576),key_started INTEGER NOT NULL DEFAULT 0 CHECK(key_started IN(0,1)),CHECK((state='reserved' AND ack IS NULL) OR (state IN ('succeeded','failed') AND ack IS NOT NULL)))`,
		`CREATE TABLE IF NOT EXISTS native_direct_managed_source_pop_challenges(challenge_id TEXT PRIMARY KEY,binding_id TEXT NOT NULL UNIQUE,direct_intent_id TEXT NOT NULL UNIQUE,installation_id TEXT NOT NULL,request BLOB NOT NULL CHECK(length(request)<=65536),request_digest BLOB NOT NULL CHECK(length(request_digest)=32),proof BLOB CHECK(length(proof)<=1024))`,
		`CREATE TABLE IF NOT EXISTS native_source_holder_enrollments(scope TEXT PRIMARY KEY,installation_id TEXT NOT NULL,descriptor BLOB)`,
		`CREATE TABLE IF NOT EXISTS native_source_prepare_journal(command_id TEXT PRIMARY KEY,enrollment_id TEXT NOT NULL UNIQUE,installation_id TEXT NOT NULL,scope TEXT NOT NULL,request_digest BLOB NOT NULL CHECK(length(request_digest)=32),prepared BLOB)`,
		`CREATE TABLE IF NOT EXISTS native_source_prove_journal(command_id TEXT PRIMARY KEY,enrollment_id TEXT NOT NULL UNIQUE,installation_id TEXT NOT NULL,scope TEXT NOT NULL,request_digest BLOB NOT NULL CHECK(length(request_digest)=32),request BLOB NOT NULL,receipt_digest TEXT)`,
	} {
		if _, err = conn.ExecContext(context.Background(), q); err != nil {
			return err
		}
	}
	// Old commands may already have attempted key creation. Never grant them a
	// fresh attempt when adding the durable start fence.
	rows, err := conn.QueryContext(context.Background(), `PRAGMA table_info(native_managed_endpoint_prepare_commands)`)
	if err != nil {
		return err
	}
	hasKeyStarted := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err = rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			break
		}
		hasKeyStarted = hasKeyStarted || name == "key_started"
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	if !hasKeyStarted {
		if _, err = conn.ExecContext(context.Background(), `ALTER TABLE native_managed_endpoint_prepare_commands ADD COLUMN key_started INTEGER NOT NULL DEFAULT 1 CHECK(key_started IN(0,1))`); err != nil {
			return err
		}
	}
	var id string
	err = conn.QueryRowContext(context.Background(), `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if err = conn.QueryRowContext(context.Background(), `SELECT (SELECT COUNT(*) FROM native_source_holder_enrollments)+(SELECT COUNT(*) FROM native_source_prepare_journal)+(SELECT COUNT(*) FROM native_source_prove_journal)+(SELECT COUNT(*) FROM native_managed_endpoint_key_slots)+(SELECT COUNT(*) FROM native_managed_endpoint_keys)+(SELECT COUNT(*) FROM native_managed_endpoint_prepare_commands)+(SELECT COUNT(*) FROM native_managed_endpoint_pop_challenges)+(SELECT COUNT(*) FROM native_direct_managed_source_keys)+(SELECT COUNT(*) FROM native_direct_managed_source_prepare_commands)+(SELECT COUNT(*) FROM native_direct_managed_source_pop_challenges)`).Scan(&count); err != nil || count != 0 {
			return errNativeShareSourceHolder
		}
		var stat unix.Stat_t
		if err = unix.Fstatat(int(root.Fd()), managedEndpointPrepareJournalNamespace, &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			return errNativeShareSourceHolder
		}
		if err = unix.Fstatat(int(root.Fd()), nativeManagedEndpointKeyNamespace, &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			return errNativeShareSourceHolder
		}
		for _, namespace := range []string{nativeDirectManagedSourceKeyNamespace, directManagedSourcePrepareJournalNamespace} {
			if err = unix.Fstatat(int(root.Fd()), namespace, &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
				return errNativeShareSourceHolder
			}
		}
		if err = unix.Fstatat(int(root.Fd()), nativeShareSourceHolderNamespace, &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			return errNativeShareSourceHolder
		}
		id = string(domain.NewID())
		if _, err = conn.ExecContext(context.Background(), `INSERT INTO native_registry_metadata(name,value) VALUES('installation_id',?)`, id); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if !nativeShareEpochStageID(domain.ID(id)) {
		return errNativeShareSourceHolder
	}
	var conflicts int
	if err = conn.QueryRowContext(context.Background(), `SELECT (SELECT COUNT(*) FROM native_source_holder_enrollments WHERE installation_id<>?)+(SELECT COUNT(*) FROM native_source_prepare_journal WHERE installation_id<>?)+(SELECT COUNT(*) FROM native_source_prove_journal WHERE installation_id<>?)+(SELECT COUNT(*) FROM native_managed_endpoint_key_slots WHERE installation_id<>?)+(SELECT COUNT(*) FROM native_managed_endpoint_keys WHERE installation_id<>?)+(SELECT COUNT(*) FROM native_managed_endpoint_prepare_commands WHERE installation_id<>?)+(SELECT COUNT(*) FROM native_managed_endpoint_pop_challenges WHERE installation_id<>?)+(SELECT COUNT(*) FROM native_direct_managed_source_keys WHERE installation_id<>?)+(SELECT COUNT(*) FROM native_direct_managed_source_prepare_commands WHERE installation_id<>?)+(SELECT COUNT(*) FROM native_direct_managed_source_pop_challenges WHERE installation_id<>?)`, id, id, id, id, id, id, id, id, id, id).Scan(&conflicts); err != nil || conflicts != 0 {
		return errNativeShareSourceHolder
	}
	if err = migrateManagedEndpointKeySlots(conn); err != nil {
		return err
	}
	if _, err = conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return err
	}
	return root.Sync()
}

func NewNativeShareSourceHolderStore(registry *NativeWorkerRegistry) (*NativeShareSourceHolderStore, error) {
	if registry == nil {
		return nil, errNativeShareSourceHolder
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	var id string
	if err := registry.db.QueryRow(`SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&id); err != nil || !nativeShareEpochStageID(domain.ID(id)) {
		return nil, errNativeShareSourceHolder
	}
	return &NativeShareSourceHolderStore{registry: registry, installation: domain.ID(id), sync: (*os.File).Sync}, nil
}

func nativeShareSourceHolderScope(scope NativeShareSourceHolderScope) (NativeShareSourceHolderScope, string, error) {
	server := textServiceServer(scope.ServerURL)
	if server == "" || legacyTextServiceServer(scope.ServerURL) != server {
		return scope, "", errNativeShareSourceHolder
	}
	scope.ServerURL = server
	if scope.ServerURL == "" || !nativeShareEpochStageID(scope.TenantID) || !nativeShareEpochStageID(scope.AccountID) || !nativeShareEpochStageID(scope.HostID) {
		return scope, "", errNativeShareSourceHolder
	}
	raw, err := json.Marshal(scope)
	if err != nil {
		return scope, "", err
	}
	sum := sha256.Sum256(raw)
	return scope, hex.EncodeToString(sum[:]), nil
}

func nativeShareSourceHolderFingerprint(d NativeShareSourceHolderDescriptor) string {
	d.Fingerprint = ""
	raw, _ := json.Marshal(d)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Ensure returns a descriptor only after the complete key record and enrollment
// have durably committed. Exact retries reuse the same keys, ID and generation.
// Uncertain creation cannot be retried into a new identity; it requires explicit
// future recovery. There is deliberately no implicit rotation or delete method.
func (s *NativeShareSourceHolderStore) Ensure(scope NativeShareSourceHolderScope) (NativeShareSourceHolderDescriptor, error) {
	return s.access(scope, nil, nil)
}

// NativeShareSourceHolderKeyUse exposes cryptographic operations, never private
// bytes. A retained capability fails after its callback returns. Returned shared
// secrets and challenges must be cleared by the caller when no longer needed.
type NativeShareSourceHolderKeyUse interface {
	Sign([]byte) ([]byte, error)
	SharedSecret([]byte) ([]byte, error)
	OpenEnrollmentChallenge(transport.NativeShareSourceProvePayload) ([]byte, error)
}

type nativeShareSourceHolderKeyUse struct {
	mu          sync.Mutex
	x, ed       []byte
	fingerprint string
}

func (k *nativeShareSourceHolderKeyUse) OpenEnrollmentChallenge(p transport.NativeShareSourceProvePayload) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.x) != 32 {
		return nil, errNativeShareSourceHolder
	}
	if _, err := p.CanonicalBytes(); err != nil || p.DescriptorFingerprint != k.fingerprint {
		return nil, errNativeShareSourceHolder
	}
	aad, err := p.ChallengeAAD()
	if err != nil {
		return nil, errNativeShareSourceHolder
	}
	plain, err := crypto.OpenKey(k.x, p.Challenge.Enc, []byte(transport.NativeShareSourceChallengeInfo), aad, p.Challenge.Ciphertext)
	if err != nil || len(plain) != 32 {
		clear(plain)
		return nil, errNativeShareSourceHolder
	}
	return plain, nil
}

func (k *nativeShareSourceHolderKeyUse) Sign(message []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.ed) != ed25519.PrivateKeySize {
		return nil, errNativeShareSourceHolder
	}
	return ed25519.Sign(ed25519.PrivateKey(k.ed), message), nil
}
func (k *nativeShareSourceHolderKeyUse) SharedSecret(peer []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.x) != 32 {
		return nil, errNativeShareSourceHolder
	}
	private, err := ecdh.X25519().NewPrivateKey(k.x)
	if err != nil {
		return nil, errNativeShareSourceHolder
	}
	public, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, errNativeShareSourceHolder
	}
	return private.ECDH(public)
}
func (k *nativeShareSourceHolderKeyUse) close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	clear(k.x)
	clear(k.ed)
	k.x = nil
	k.ed = nil
}
func (k *nativeShareSourceHolderKeyUse) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "NativeShareSourceHolderKeyUse{closed}")
}

// WithKeys reopens an already enrolled holder and requires the exact public
// descriptor. It cannot create a key. The callback runs under the store locks.
func (s *NativeShareSourceHolderStore) WithKeys(scope NativeShareSourceHolderScope, expected NativeShareSourceHolderDescriptor, use func(NativeShareSourceHolderKeyUse) error) error {
	if use == nil {
		return errNativeShareSourceHolder
	}
	_, err := s.access(scope, &expected, use)
	return err
}

func (s *NativeShareSourceHolderStore) access(scope NativeShareSourceHolderScope, expected *NativeShareSourceHolderDescriptor, use func(NativeShareSourceHolderKeyUse) error) (NativeShareSourceHolderDescriptor, error) {
	var empty NativeShareSourceHolderDescriptor
	if s == nil || s.registry == nil || s.sync == nil {
		return empty, errNativeShareSourceHolder
	}
	scope, name, err := nativeShareSourceHolderScope(scope)
	if err != nil {
		return empty, err
	}
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	root, err := nativeShareHolderDirectory(s.registry.root)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	dir, err := nativeShareHolderChild(root, nativeShareSourceHolderNamespace)
	if err != nil {
		return empty, err
	}
	defer dir.Close()
	lock, err := nativeShareHolderLock(dir)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	conn, err := s.registry.db.Conn(context.Background())
	if err != nil {
		return empty, err
	}
	defer conn.Close()
	begin := func() error { _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); return err }
	commit := func() error { _, err := conn.ExecContext(context.Background(), "COMMIT"); return err }
	if err = begin(); err != nil {
		return empty, err
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()
	var installation string
	if err = conn.QueryRowContext(context.Background(), `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&installation); err != nil || installation != string(s.installation) {
		return empty, errNativeShareSourceHolder
	}
	var enrolledInstallation string
	var enrolled []byte
	err = conn.QueryRowContext(context.Background(), `SELECT installation_id,descriptor FROM native_source_holder_enrollments WHERE scope=?`, name).Scan(&enrolledInstallation, &enrolled)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return empty, err
	}
	// Pending files are never recovered implicitly, even if their contents parse.
	var stat unix.Stat_t
	if err = unix.Fstatat(int(dir.Fd()), name+".pending", &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return empty, errNativeShareSourceHolder
	}
	file, err := nativeShareHolderOpen(dir, name+".json", false)
	if exists {
		if err != nil || enrolledInstallation != installation || len(enrolled) == 0 {
			if file != nil {
				file.Close()
			}
			return empty, errNativeShareSourceHolder
		}
		defer file.Close()
		record, err := nativeShareSourceHolderLoad(file)
		if err != nil {
			return empty, err
		}
		defer clear(record.X25519Private)
		defer clear(record.Ed25519Private)
		d := record.Descriptor
		raw, _ := json.Marshal(d)
		if !bytes.Equal(raw, enrolled) || d.Scope != scope || d.InstallationID != s.installation || expected != nil && d != *expected {
			return empty, errNativeShareSourceHolder
		}
		if err = dir.Sync(); err != nil {
			return empty, err
		}
		if err = commit(); err != nil {
			return empty, err
		}
		if use != nil {
			keys := &nativeShareSourceHolderKeyUse{x: bytes.Clone(record.X25519Private), ed: bytes.Clone(record.Ed25519Private), fingerprint: d.Fingerprint}
			defer keys.close()
			if err = use(keys); err != nil {
				return empty, err
			}
		}
		return d, nil
	}
	if file != nil {
		file.Close()
	}
	if !errors.Is(err, unix.ENOENT) || expected != nil {
		return empty, errNativeShareSourceHolder
	}
	// Commit the pending enrollment before generating keys. A crash at any later
	// point leaves evidence that forbids replacement, including loss of the file.
	if _, err = conn.ExecContext(context.Background(), `INSERT INTO native_source_holder_enrollments(scope,installation_id,descriptor) VALUES(?,?,NULL)`, name, installation); err != nil {
		return empty, err
	}
	if err = commit(); err != nil {
		return empty, err
	}
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return empty, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return empty, err
	}
	defer clear(private)
	xprivate := x.Bytes()
	defer clear(xprivate)
	d := NativeShareSourceHolderDescriptor{Version: 1, Scope: scope, InstallationID: s.installation, HolderID: domain.NewID(), Generation: 1, X25519: hex.EncodeToString(x.PublicKey().Bytes()), Ed25519: hex.EncodeToString(public)}
	d.Fingerprint = nativeShareSourceHolderFingerprint(d)
	raw, err := json.Marshal(nativeShareSourceHolderRecord{Descriptor: d, X25519Private: xprivate, Ed25519Private: private})
	if err != nil {
		return empty, err
	}
	defer clear(raw)
	pending, err := nativeShareHolderOpen(dir, name+".pending", true)
	if err != nil {
		return empty, err
	}
	if _, err = pending.Write(raw); err == nil {
		err = s.sync(pending)
	}
	closeErr := pending.Close()
	if err != nil {
		return empty, err
	}
	if closeErr != nil {
		return empty, closeErr
	}
	if err = unix.Linkat(int(dir.Fd()), name+".pending", int(dir.Fd()), name+".json", 0); err != nil {
		return empty, err
	}
	if err = unix.Unlinkat(int(dir.Fd()), name+".pending", 0); err != nil {
		return empty, err
	}
	if err = s.sync(dir); err != nil {
		return empty, err
	}
	if err = begin(); err != nil {
		return empty, err
	}
	descriptor, _ := json.Marshal(d)
	result, err := conn.ExecContext(context.Background(), `UPDATE native_source_holder_enrollments SET descriptor=? WHERE scope=? AND installation_id=? AND descriptor IS NULL AND EXISTS(SELECT 1 FROM native_registry_metadata WHERE name='installation_id' AND value=?)`, descriptor, name, installation, installation)
	if err != nil {
		return empty, err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return empty, errNativeShareSourceHolder
	}
	if err = commit(); err != nil {
		return empty, err
	}
	return d, nil
}

func nativeShareSourceHolderLoad(file *os.File) (nativeShareSourceHolderRecord, error) {
	var record nativeShareSourceHolderRecord
	valid := false
	defer func() {
		if !valid {
			clear(record.X25519Private)
			clear(record.Ed25519Private)
		}
	}()
	raw, err := io.ReadAll(io.LimitReader(file, nativeShareHolderMaxBytes+1))
	if err != nil {
		return record, err
	}
	defer clear(raw)
	if len(raw) > nativeShareHolderMaxBytes {
		return record, errNativeShareSourceHolder
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF {
		return record, errNativeShareSourceHolder
	}
	d := record.Descriptor
	if d.Version != 1 || d.Generation != 1 || !nativeShareEpochStageID(d.InstallationID) || !nativeShareEpochStageID(d.HolderID) || d.Fingerprint != nativeShareSourceHolderFingerprint(d) || len(record.Ed25519Private) != ed25519.PrivateKeySize {
		return record, errNativeShareSourceHolder
	}
	derived := ed25519.NewKeyFromSeed(record.Ed25519Private[:ed25519.SeedSize])
	defer clear(derived)
	x, err := ecdh.X25519().NewPrivateKey(record.X25519Private)
	if err != nil || d.X25519 != hex.EncodeToString(x.PublicKey().Bytes()) || !bytes.Equal(derived, record.Ed25519Private) || d.Ed25519 != hex.EncodeToString(ed25519.PrivateKey(record.Ed25519Private).Public().(ed25519.PublicKey)) {
		return record, errNativeShareSourceHolder
	}
	valid = true
	return record, nil
}
