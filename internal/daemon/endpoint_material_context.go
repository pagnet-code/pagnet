//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// This path only reads existing custody. Namespace and registry acquisition
// precede the publication fence, which remains held through SQL cleanup.
func withEndpointMaterialLockedContext(ctx context.Context, registry *NativeWorkerRegistry, namespace string, fn func(*sql.Conn, *os.File, *func()) error) error {
	unlock, err := directEndpointTryLock(ctx, &registry.mu)
	if err != nil {
		return err
	}
	defer unlock()
	root, err := nativeShareHolderDirectory(registry.root)
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := nativeShareHolderExistingChild(root, namespace)
	if err != nil {
		return err
	}
	defer dir.Close()
	lock, err := directEndpointTryNativeShareHolderLockMode(ctx, dir, false)
	if err != nil {
		return err
	}
	defer lock.Close()
	return withDirectEndpointSQLContext(ctx, registry.db, true, func(conn *sql.Conn, release *func()) error {
		return fn(conn, dir, release)
	})
}

// The borrowed connection never returns to the pool with a changed timeout or
// uncertain transaction. Cleanup has its own bounded context, even on panic.
func withDirectEndpointSQLContext(ctx context.Context, db *sql.DB, reserve bool, fn func(*sql.Conn, *func()) error) (resultErr error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var busy int
	if err = conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busy); err != nil {
		return err
	}
	var release func()
	beginAttempted, committed := false, false
	defer func() {
		if release != nil {
			defer release()
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		discard := func() { _ = conn.Raw(func(any) error { return driver.ErrBadConn }) }
		if beginAttempted && !committed {
			if _, err := conn.ExecContext(cleanup, "ROLLBACK"); err != nil {
				discard()
				if resultErr == nil {
					resultErr = err
				}
				return
			}
		}
		if _, err := conn.ExecContext(cleanup, fmt.Sprintf("PRAGMA busy_timeout=%d", busy)); err != nil {
			discard()
			if resultErr == nil {
				resultErr = err
			}
		}
	}()
	if _, err = conn.ExecContext(ctx, "PRAGMA busy_timeout=0"); err != nil {
		return err
	}
	if reserve {
		beginAttempted = true
		if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			var sqliteErr *sqlite.Error
			if errors.As(err, &sqliteErr) && (sqliteErr.Code()&0xff == sqlite3.SQLITE_BUSY || sqliteErr.Code()&0xff == sqlite3.SQLITE_LOCKED) {
				beginAttempted = false
				return errDirectEndpointLocalBusy
			}
			return err
		}
	}
	if err = fn(conn, &release); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if reserve {
		_, err = conn.ExecContext(ctx, "COMMIT")
		committed = err == nil
	}
	return err
}

// Endpoint operations need only installation identity, not Prepare/PoP journal
// construction or namespace creation. The existing constructors stay unchanged.
func directEndpointInstallationContext(ctx context.Context, registry *NativeWorkerRegistry) (domain.ID, error) {
	if registry == nil {
		return "", errDirectEndpointLocalBusy
	}
	unlock, err := directEndpointTryLock(ctx, &registry.mu)
	if err != nil {
		return "", err
	}
	defer unlock()
	var id string
	err = withDirectEndpointSQLContext(ctx, registry.db, false, func(conn *sql.Conn, _ *func()) error {
		if err := conn.QueryRowContext(ctx, `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&id); err != nil {
			return err
		}
		if !nativeShareEpochStageID(domain.ID(id)) {
			return errDirectEndpointLocalBusy
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return domain.ID(id), nil
}

func newManagedEndpointKeyStoreContext(ctx context.Context, registry *NativeWorkerRegistry) (*ManagedEndpointKeyStore, error) {
	id, err := directEndpointInstallationContext(ctx, registry)
	if err != nil {
		return nil, err
	}
	return &ManagedEndpointKeyStore{registry: registry, installation: id, now: time.Now, sync: (*os.File).Sync}, nil
}

func newDirectManagedSourceKeyStoreV2Context(ctx context.Context, registry *NativeWorkerRegistry) (*DirectManagedSourceKeyStoreV2, error) {
	id, err := directEndpointInstallationContext(ctx, registry)
	if err != nil {
		return nil, err
	}
	return &DirectManagedSourceKeyStoreV2{registry: registry, installation: id, now: time.Now, sync: (*os.File).Sync}, nil
}
