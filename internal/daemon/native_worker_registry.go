//go:build linux || darwin

package daemon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
	_ "modernc.org/sqlite"
)

const maxNativeWorkerRecords = 4096

// NativeWorkerRecord is immutable local authority, never an assertion of live
// native ownership. Only authenticated snapshots and backend receipts prove it.
type NativeWorkerRecord struct {
	Scope                                            sessionworker.Scope
	Dir                                              string
	Spec                                             sessionworker.NativeSpec
	Profile, ProfileFingerprint, OriginalOwnershipID string
	Ownership                                        *transport.NativeWorkerOwnership `json:",omitempty"`
	LaunchState                                      string
}
type NativeWorkerRegistry struct {
	db   *sql.DB
	root string
	mu   sync.Mutex
}

func privateNativeRegistryDir(path string) error { return privateNativeRegistryPath(path, true) }
func privateNativeRegistryPath(path string, exact bool) error {
	if !filepath.IsAbs(path) {
		return errors.New("native registry path must be absolute")
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("native registry path is unavailable or symlinked")
		}
		if p == filepath.Clean(path) {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != uint32(os.Getuid()) || (exact && info.Mode().Perm() != 0700) || (!exact && info.Mode().Perm()&0022 != 0) {
				return errors.New("native registry directory is not private")
			}
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
func OpenNativeWorkerRegistry(stateDir string) (*NativeWorkerRegistry, error) {
	root := filepath.Join(stateDir, "native-workers")
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("native state path must be absolute")
	}
	// Reject symlinked ancestors before creating descendants.
	if err := privateNativeRegistryPath(stateDir, false); err != nil {
		return nil, err
	}
	if err := os.Mkdir(root, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	parent, syncErr := os.Open(stateDir)
	if syncErr != nil {
		return nil, syncErr
	}
	syncErr = parent.Sync()
	_ = parent.Close()
	if syncErr != nil {
		return nil, syncErr
	}
	if err := privateNativeRegistryDir(root); err != nil {
		return nil, err
	}
	path := filepath.Join(root, "registry.sqlite")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		_ = f.Close()
	} else if !os.IsExist(err) {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("native registry file is not private")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{`PRAGMA busy_timeout=5000`, `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=FULL`, `CREATE TABLE IF NOT EXISTS native_workers(instance_id TEXT PRIMARY KEY,payload BLOB NOT NULL,launch_state TEXT NOT NULL)`} {
		if _, err = db.Exec(q); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return &NativeWorkerRegistry{db: db, root: root}, nil
}
func (r *NativeWorkerRegistry) Close() error { return r.db.Close() }
func (r *NativeWorkerRegistry) Dir(scope sessionworker.Scope) string {
	raw, _ := json.Marshal(scope)
	sum := sha256.Sum256(raw)
	return filepath.Join(r.root, hex.EncodeToString(sum[:16]))
}
func (r *NativeWorkerRegistry) Lookup(instanceID string) (NativeWorkerRecord, error) {
	var raw []byte
	var state string
	if err := r.db.QueryRow(`SELECT payload,launch_state FROM native_workers WHERE instance_id=?`, instanceID).Scan(&raw, &state); err != nil {
		return NativeWorkerRecord{}, err
	}
	var record NativeWorkerRecord
	if len(raw) > 256<<10 || json.Unmarshal(raw, &record) != nil || record.Scope.InstanceID != instanceID || record.Dir != r.Dir(record.Scope) || record.ProfileFingerprint != sessionworker.NativeProfileFingerprint(record.Spec) {
		return NativeWorkerRecord{}, errors.New("native worker registry identity corrupt")
	}
	if state != "reserved" && state != "launching" && state != "launched" {
		return NativeWorkerRecord{}, errors.New("native worker registry launch state corrupt")
	}
	record.LaunchState = state
	return record, nil
}
func (r *NativeWorkerRegistry) Owns(instanceID string) bool {
	var n int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM native_workers WHERE instance_id=?`, instanceID).Scan(&n)
	return err != nil || n > 0
} // fail closed on registry errors
func (r *NativeWorkerRegistry) List() ([]NativeWorkerRecord, error) {
	rows, err := r.db.Query(`SELECT instance_id FROM native_workers ORDER BY instance_id LIMIT ?`, maxNativeWorkerRecords+1)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(ids) > maxNativeWorkerRecords {
		return nil, errors.New("native registry exceeds bound")
	}
	records := make([]NativeWorkerRecord, 0, len(ids))
	for _, id := range ids {
		record, err := r.Lookup(id)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}
func (r *NativeWorkerRegistry) Reserve(scope sessionworker.Scope, spec sessionworker.NativeSpec, profile, originalOwnershipID string) (NativeWorkerRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record := NativeWorkerRecord{Scope: scope, Dir: r.Dir(scope), Spec: spec, Profile: profile, OriginalOwnershipID: originalOwnershipID, ProfileFingerprint: sessionworker.NativeProfileFingerprint(spec), LaunchState: "reserved"}
	record.Spec.Env = nil
	if len(filepath.Join(record.Dir, "controller.sock")) > 103 {
		return NativeWorkerRecord{}, errors.New("native worker state path exceeds Unix socket limit")
	}
	if scope.ServerURL == "" || scope.TenantID == "" || scope.AccountID == "" || scope.HostID == "" || scope.InstanceID == "" || scope.Generation == "" || spec.TenantID != scope.TenantID || !filepath.IsAbs(spec.Workspace) || !filepath.IsAbs(spec.Binary) || !filepath.IsAbs(spec.MCPExecutable) {
		return NativeWorkerRecord{}, errors.New("incomplete original native worker authority")
	}
	existing, err := r.Lookup(scope.InstanceID)
	if err == nil {
		if existing.Scope != scope || existing.Profile != profile || existing.ProfileFingerprint != record.ProfileFingerprint || (originalOwnershipID != "" && existing.OriginalOwnershipID != originalOwnershipID) {
			return NativeWorkerRecord{}, errors.New("native worker original identity conflict")
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return NativeWorkerRecord{}, err
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > 256<<10 {
		return NativeWorkerRecord{}, errors.New("native worker registry record exceeds bound")
	}
	// Publish registry authority before bootstrap creation. A crash leaves owned
	// state excluded from legacy reconciliation, never a silently replaced PID.
	tx, err := r.db.BeginTx(context.Background(), nil)
	if err != nil {
		return NativeWorkerRecord{}, err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM native_workers`).Scan(&count); err != nil {
		return NativeWorkerRecord{}, err
	}
	if count >= maxNativeWorkerRecords {
		return NativeWorkerRecord{}, errors.New("native worker registry full")
	}
	if _, err = tx.Exec(`INSERT INTO native_workers VALUES(?,?,?)`, scope.InstanceID, raw, "reserved"); err != nil {
		return NativeWorkerRecord{}, err
	}
	if err = tx.Commit(); err != nil {
		return NativeWorkerRecord{}, err
	}
	return record, nil
}
func (r *NativeWorkerRegistry) BindOwnership(record NativeWorkerRecord, ownership transport.NativeWorkerOwnership) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tx, err := r.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var stored []byte
	var state string
	if err = tx.QueryRow(`SELECT payload,launch_state FROM native_workers WHERE instance_id=?`, record.Scope.InstanceID).Scan(&stored, &state); err != nil {
		return err
	}
	var current NativeWorkerRecord
	if len(stored) > 256<<10 || json.Unmarshal(stored, &current) != nil || current.Dir != r.Dir(current.Scope) || current.ProfileFingerprint != sessionworker.NativeProfileFingerprint(current.Spec) {
		return errors.New("native registry identity corrupt")
	}
	current.LaunchState = state
	if validateOwnership(current.Scope, current.Spec, current.Profile, &ownership) != nil || current.Scope != record.Scope || current.ProfileFingerprint != record.ProfileFingerprint || ownership.ID == "" || ownership.InstanceID != current.Scope.InstanceID || ownership.OwnershipGeneration != current.Scope.Generation || ownership.ProfileFingerprint != current.ProfileFingerprint || ownership.Runtime != string(current.Spec.Runtime) || ownership.Profile != current.Profile || ownership.State != "active" {
		return errors.New("native ownership receipt conflicts with original registry")
	}
	if current.OriginalOwnershipID != "" && current.OriginalOwnershipID != ownership.ID {
		return errors.New("original native ownership cannot be replaced")
	}
	if current.Ownership != nil {
		if ownership.LastDispatchSequence < current.Ownership.LastDispatchSequence || ownership.RetiredFloor < current.Ownership.RetiredFloor {
			return errors.New("original ownership receipt counters regressed")
		}
		previous, next := *current.Ownership, ownership
		previous.LastDispatchSequence = 0
		previous.RetiredFloor = 0
		next.LastDispatchSequence = 0
		next.RetiredFloor = 0
		a, _ := json.Marshal(previous)
		b, _ := json.Marshal(next)
		if string(a) != string(b) {
			return errors.New("original native ownership receipt cannot be mutated")
		}
	}
	current.OriginalOwnershipID = ownership.ID
	current.Ownership = &ownership
	raw, err := json.Marshal(current)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE native_workers SET payload=? WHERE instance_id=?`, raw, current.Scope.InstanceID); err != nil {
		return err
	}
	return tx.Commit()
}
func (r *NativeWorkerRegistry) prepare(record NativeWorkerRecord) error {
	if err := os.Mkdir(record.Dir, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	parent, syncErr := os.Open(r.root)
	if syncErr != nil {
		return syncErr
	}
	syncErr = parent.Sync()
	_ = parent.Close()
	if syncErr != nil {
		return syncErr
	}
	if err := privateNativeRegistryDir(record.Dir); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(record.Dir, "bootstrap.json")); err == nil {
		b, key, err := sessionworker.LoadControllerBootstrap(record.Dir, record.Scope)
		clear(key)
		if err != nil {
			return err
		}
		if sessionworker.NativeProfileFingerprint(b.Native) != record.ProfileFingerprint {
			return errors.New("original bootstrap profile conflict")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	defer clear(key)
	return sessionworker.PrepareBootstrap(record.Dir, sessionworker.Bootstrap{Protocol: sessionworker.Protocol, Scope: record.Scope, Native: record.Spec}, key)
}
