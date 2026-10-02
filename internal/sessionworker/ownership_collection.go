package sessionworker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

// CollectRetiredWorker requires the exclusive lifetime owner lock and the
// worker's durable retirement receipt. A cloud request or missing PID is never
// sufficient authority to erase a journal. The caller separately retains the
// backend confirmation outbox until the remote deletion transaction commits.
func CollectRetiredWorker(ctx context.Context, dir string, scope Scope, proof transport.NativeWorkerOwnership, authorizeCollection func() error) error {
	if proof.State != "retired" || proof.InstanceID != scope.InstanceID || proof.OwnershipGeneration != scope.Generation || proof.LastDispatchSequence != proof.RetiredFloor {
		return ErrConflict
	}
	if _, err := os.Lstat(filepath.Join(dir, "intents.sqlite")); err != nil {
		return err
	}
	// Retirement acknowledges its durable receipt before graceful worker exit.
	// Wait only for that exact lifetime lock; no PID inference or force kill.
	j, err := OpenJournal(dir, scope)
	for errors.Is(err, ErrWorkerOwned) {
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		j, err = OpenJournal(dir, scope)
	}
	if err != nil {
		return err
	}
	defer j.Close()
	var raw []byte
	if err = j.db.QueryRowContext(ctx, `SELECT payload FROM worker_ownership_retirement WHERE singleton=1`).Scan(&raw); err != nil {
		return err
	}
	var committed transport.NativeWorkerOwnership
	if json.Unmarshal(raw, &committed) != nil || !reflect.DeepEqual(committed, proof) {
		return ErrConflict
	}
	if authorizeCollection == nil {
		return ErrConflict
	}
	if err = authorizeCollection(); err != nil {
		return err
	}
	// A live owner cannot hold the same lock. Do not traverse external symlinks.
	if err = privateDirectory(dir); err != nil {
		return err
	}
	if err = removeRetiredSockets(dir); err != nil {
		return err
	}
	if err = os.RemoveAll(dir); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(dir))
	if err != nil {
		return err
	}
	defer parent.Close()
	if err = parent.Sync(); err != nil {
		return errors.Join(ErrConflict, err)
	}
	return nil
}

// CompleteRetiredWorkerCollection resumes only after the caller's durable
// collecting marker recorded exclusive receipt validation before unlink.
func CompleteRetiredWorkerCollection(dir string) error {
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return syncCollectionParent(dir)
	} else if err != nil {
		return err
	}
	if err := privateDirectory(dir); err != nil {
		return err
	}
	lock, err := acquireOwnership(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = removeRetiredSockets(dir); err != nil {
		return err
	}
	if err = os.RemoveAll(dir); err != nil {
		return err
	}
	return syncCollectionParent(dir)
}
func syncCollectionParent(dir string) error {
	parent, err := os.Open(filepath.Dir(dir))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
func removeRetiredSockets(dir string) error {
	for _, socket := range []func(string) (string, error){SocketPath, NativeSocketPath} {
		path, err := socket(dir)
		if err != nil {
			return err
		}
		if err = removeStaleSocket(path); err != nil {
			return err
		}
	}
	return nil
}
