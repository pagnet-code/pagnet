//go:build linux || darwin

package daemon

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/domain"
	"os"
	"path/filepath"
)

func (r *NativeWorkerRegistry) pendingCollectedRecoveries() ([]NativeWorkerRecovery, error) {
	rows, err := r.db.Query(`SELECT recovery_id FROM native_worker_recoveries WHERE phase='collected' AND server_cleaned=0 ORDER BY recovery_id LIMIT ?`, maxNativeWorkerRecords+1)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(ids) > maxNativeWorkerRecords {
		return nil, errors.New("native recovery registry exceeds bound")
	}
	records := make([]NativeWorkerRecovery, 0, len(ids))
	for _, id := range ids {
		record, err := r.LookupRecovery(id)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (r *NativeWorkerRegistry) confirmRecoveryCleaned(id string) error {
	result, err := r.db.Exec(`UPDATE native_worker_recoveries SET server_cleaned=1 WHERE recovery_id=? AND phase='collected'`, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNativeObservationConflict
	}
	return nil
}

// collectRecovery preserves the original directory and all command journals in
// a durable archive. It never opens a worker journal, advances dispatch floors,
// produces a stopped receipt, or deletes evidence of unknown original outcomes.
func (r *NativeWorkerRegistry) collectRecovery(record NativeWorkerRecovery) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := domain.ParseID(record.RecoveryID); err != nil {
		return ErrNativeObservationConflict
	}
	current, err := r.LookupRecovery(record.RecoveryID)
	if err != nil {
		return err
	}
	if current != record || record.Phase != "committed" {
		return ErrNativeObservationConflict
	}
	local, err := r.Lookup(record.InstanceID)
	if errors.Is(err, sql.ErrNoRows) {
		if record.LocalGeneration != "" {
			return ErrNativeObservationConflict
		}
	} else if err != nil {
		return err
	} else {
		if record.LocalGeneration == "" || local.Scope.Generation != record.LocalGeneration {
			return ErrNativeObservationConflict
		}
		archive := filepath.Join(r.root, "recovery-"+record.RecoveryID)
		info, sourceErr := os.Lstat(local.Dir)
		archived, archiveErr := os.Lstat(archive)
		if sourceErr == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.IsNotExist(archiveErr) {
				return ErrNativeObservationConflict
			}
			if err = privateNativeRegistryDir(local.Dir); err != nil {
				return err
			}
			if err = os.Rename(local.Dir, archive); err != nil {
				return err
			}
		} else if !os.IsNotExist(sourceErr) {
			return sourceErr
		} else if archiveErr == nil {
			if !archived.IsDir() || archived.Mode()&os.ModeSymlink != 0 {
				return ErrNativeObservationConflict
			}
			if err = privateNativeRegistryDir(archive); err != nil {
				return err
			}
		} else if !os.IsNotExist(archiveErr) {
			return archiveErr
		} else if local.LaunchState != "reserved" {
			return ErrNativeObservationConflict
		}
		// A never-launched reservation has no directory. It still needs the durable
		// fence and matching generation before its registry row can be collected.
		dir, err := os.Open(r.root)
		if err != nil {
			return err
		}
		err = dir.Sync()
		_ = dir.Close()
		if err != nil {
			return err
		}
	}
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Revalidate inside the transaction as well as under this registry's lock:
	// another process may have its own connection to the same durable registry.
	var raw []byte
	lookupErr := tx.QueryRow(`SELECT payload FROM native_workers WHERE instance_id=?`, record.InstanceID).Scan(&raw)
	if record.LocalGeneration == "" {
		if !errors.Is(lookupErr, sql.ErrNoRows) {
			if lookupErr != nil {
				return lookupErr
			}
			return ErrNativeObservationConflict
		}
	} else {
		if lookupErr != nil {
			return lookupErr
		}
		var exact NativeWorkerRecord
		if len(raw) > 256<<10 || json.Unmarshal(raw, &exact) != nil || exact.Scope != local.Scope || exact.Scope.Generation != record.LocalGeneration || exact.Dir != local.Dir {
			return ErrNativeObservationConflict
		}
		deleted, deleteErr := tx.Exec(`DELETE FROM native_workers WHERE instance_id=? AND payload=?`, record.InstanceID, raw)
		if deleteErr != nil {
			return deleteErr
		}
		count, deleteErr := deleted.RowsAffected()
		if deleteErr != nil {
			return deleteErr
		}
		if count != 1 {
			return ErrNativeObservationConflict
		}
	}
	result, err := tx.Exec(`UPDATE native_worker_recoveries SET phase='collected' WHERE recovery_id=? AND phase='committed'`, record.RecoveryID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNativeObservationConflict
	}
	return tx.Commit()
}
