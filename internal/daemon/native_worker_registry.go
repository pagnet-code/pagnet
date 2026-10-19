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
	"strings"
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
	for _, q := range []string{`PRAGMA busy_timeout=5000`, `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=FULL`, `CREATE TABLE IF NOT EXISTS native_workers(instance_id TEXT PRIMARY KEY,payload BLOB NOT NULL,launch_state TEXT NOT NULL)`, `CREATE TABLE IF NOT EXISTS native_worker_gc(instance_id TEXT PRIMARY KEY,payload BLOB NOT NULL)`, `CREATE TABLE IF NOT EXISTS native_worker_recoveries(recovery_id TEXT PRIMARY KEY,instance_id TEXT NOT NULL,original_generation TEXT NOT NULL,prepare_boot_identity TEXT NOT NULL,phase TEXT NOT NULL CHECK(phase IN ('prepared','committed','collected')),UNIQUE(instance_id,original_generation))`} {
		if _, err = db.Exec(q); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	// Older tombstones remain launch fences, but lack the immutable evidence
	// needed to authorize phase advancement. Never infer or backfill that evidence.
	rows, err := db.Query(`PRAGMA table_info(native_worker_recoveries)`)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	hasPayload, hasCleaned := false, false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err = rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			break
		}
		hasPayload = hasPayload || name == "payload"
		hasCleaned = hasCleaned || name == "server_cleaned"
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err == nil && !hasPayload {
		_, err = db.Exec(`ALTER TABLE native_worker_recoveries ADD COLUMN payload BLOB NOT NULL DEFAULT ''`)
	}
	if err == nil && !hasCleaned {
		_, err = db.Exec(`ALTER TABLE native_worker_recoveries ADD COLUMN server_cleaned INTEGER NOT NULL DEFAULT 0 CHECK(server_cleaned IN(0,1))`)
	}
	if err != nil {
		_ = db.Close()
		return nil, err
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
	err := r.db.QueryRow(`SELECT (SELECT COUNT(*) FROM native_workers WHERE instance_id=?)+(SELECT COUNT(*) FROM native_worker_recoveries WHERE instance_id=?)`, instanceID, instanceID).Scan(&n)
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
	if scope.ServerURL == "" || scope.TenantID == "" || scope.AccountID == "" || scope.HostID == "" || scope.InstanceID == "" || scope.Generation == "" || spec.TenantID != scope.TenantID || !filepath.IsAbs(spec.Workspace) || !filepath.IsAbs(spec.Binary) || !filepath.IsAbs(spec.MCPExecutable) {
		return NativeWorkerRecord{}, errors.New("incomplete original native worker authority")
	}
	if err := r.checkRecoveryFence(scope.InstanceID, scope.Generation); err != nil {
		return NativeWorkerRecord{}, err
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

func validNativeRecovery(record NativeWorkerRecovery) bool {
	for _, value := range []string{record.RecoveryID, record.InstanceID} {
		if !validNativeRecoveryToken(value, false) {
			return false
		}
	}
	if !validNativeRecoveryToken(record.OriginalGeneration, true) || !validNativeRecoveryToken(record.LocalGeneration, true) {
		return false
	}
	if record.OriginalGeneration != "" && record.LocalGeneration != "" && record.OriginalGeneration != record.LocalGeneration {
		return false
	}
	if record.Action != "replace" && record.Action != "delete" {
		return false
	}
	if !record.PrepareBoot.Valid() || !record.FenceBoot.Valid() {
		return false
	}
	if record.OriginalBoot != (transport.KernelBootEvidence{}) && !record.OriginalBoot.Valid() {
		return false
	}
	return record.Phase == "prepared" || record.Phase == "committed" || record.Phase == "collected"
}

func validNativeRecoveryToken(value string, optional bool) bool {
	return (optional || value != "") && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func (r *NativeWorkerRegistry) LookupRecovery(recoveryID string) (NativeWorkerRecovery, error) {
	var record NativeWorkerRecovery
	var raw []byte
	var instanceID, generation, bootIdentity, phase string
	var cleaned bool
	err := r.db.QueryRow(`SELECT instance_id,original_generation,prepare_boot_identity,phase,payload,server_cleaned FROM native_worker_recoveries WHERE recovery_id=?`, recoveryID).Scan(&instanceID, &generation, &bootIdentity, &phase, &raw, &cleaned)
	if err != nil {
		return NativeWorkerRecovery{}, err
	}
	if len(raw) > 8192 || json.Unmarshal(raw, &record) != nil || !validNativeRecovery(record) || record.RecoveryID != recoveryID || record.InstanceID != instanceID || record.OriginalGeneration != generation || record.PrepareBoot.Identity != bootIdentity || record.Phase != "prepared" {
		return NativeWorkerRecovery{}, errors.New("native worker recovery identity corrupt or missing boot evidence")
	}
	// The immutable payload always retains the preparation; the adjacent CAS
	// transition is represented only by the phase column.
	record.Phase = phase
	record.ServerCleaned = cleaned
	if !validNativeRecovery(record) {
		return NativeWorkerRecovery{}, errors.New("native worker recovery phase corrupt")
	}
	return record, nil
}

// RecoveryTombstoned fails closed on registry errors. Every recorded phase is
// a fence; collected records remain fences after server cleanup confirmation.
func (r *NativeWorkerRegistry) RecoveryTombstoned(instanceID, generation string) (bool, error) {
	var count int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM native_worker_recoveries WHERE instance_id=? AND (original_generation=? OR original_generation='')`, instanceID, generation).Scan(&count)
	return err != nil || count > 0, err
}
func (r *NativeWorkerRegistry) checkRecoveryFence(instanceID, generation string) error {
	fenced, err := r.RecoveryTombstoned(instanceID, generation)
	if err != nil {
		return err
	}
	if fenced {
		return errors.New("native worker generation is fenced by recovery")
	}
	return nil
}

// PrepareRecovery durably commits the fence before the caller may perform any
// recovery action. SQLite synchronous=FULL fsyncs the commit. Only exact identity
// replay is accepted, returning the already persisted phase without regression.
func (r *NativeWorkerRegistry) PrepareRecovery(record NativeWorkerRecovery) (NativeWorkerRecovery, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !validNativeRecovery(record) || record.Phase != "prepared" || record.ServerCleaned {
		return NativeWorkerRecovery{}, errors.New("invalid native worker recovery preparation")
	}
	existing, err := r.LookupRecovery(record.RecoveryID)
	if err == nil {
		identity := existing
		identity.Phase = "prepared"
		identity.ServerCleaned = false
		if identity != record {
			return NativeWorkerRecovery{}, errors.New("native worker recovery identity conflict")
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return NativeWorkerRecovery{}, err
	}
	worker, err := r.Lookup(record.InstanceID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return NativeWorkerRecovery{}, err
	}
	if err == nil && record.OriginalGeneration != "" && worker.Scope.Generation != record.OriginalGeneration {
		return NativeWorkerRecovery{}, errors.New("native worker recovery original generation conflict")
	}
	localGeneration := ""
	if err == nil {
		localGeneration = worker.Scope.Generation
	}
	if record.LocalGeneration != localGeneration {
		return NativeWorkerRecovery{}, errors.New("native worker recovery local generation conflict")
	}
	tx, err := r.db.BeginTx(context.Background(), nil)
	if err != nil {
		return NativeWorkerRecovery{}, err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM native_worker_recoveries`).Scan(&count); err != nil {
		return NativeWorkerRecovery{}, err
	}
	if count >= maxNativeWorkerRecords {
		return NativeWorkerRecovery{}, errors.New("native worker recovery registry full")
	}
	var overlap int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM native_worker_recoveries WHERE instance_id=? AND (original_generation=? OR original_generation='' OR ?='')`, record.InstanceID, record.OriginalGeneration, record.OriginalGeneration).Scan(&overlap); err != nil {
		return NativeWorkerRecovery{}, err
	}
	if overlap != 0 {
		return NativeWorkerRecovery{}, errors.New("native worker recovery fence conflict")
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return NativeWorkerRecovery{}, err
	}
	if _, err = tx.Exec(`INSERT INTO native_worker_recoveries(recovery_id,instance_id,original_generation,prepare_boot_identity,phase,payload) VALUES(?,?,?,?,?,?)`, record.RecoveryID, record.InstanceID, record.OriginalGeneration, record.PrepareBoot.Identity, record.Phase, raw); err != nil {
		return NativeWorkerRecovery{}, err
	}
	if err = tx.Commit(); err != nil {
		return NativeWorkerRecovery{}, err
	}
	return record, nil
}

// AdvanceRecoveryPhase applies only the two adjacent state transitions. Exact
// replay of a completed transition is idempotent; older phases never overwrite it.
func (r *NativeWorkerRegistry) AdvanceRecoveryPhase(recoveryID, from, to string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !((from == "prepared" && to == "committed") || (from == "committed" && to == "collected")) {
		return errors.New("invalid native worker recovery phase transition")
	}
	record, err := r.LookupRecovery(recoveryID)
	if err != nil {
		return err
	}
	if record.Phase == to {
		return nil
	}
	result, err := r.db.Exec(`UPDATE native_worker_recoveries SET phase=? WHERE recovery_id=? AND phase=?`, to, recoveryID, from)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("native worker recovery phase conflict")
	}
	return nil
}
