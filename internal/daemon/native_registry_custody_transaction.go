//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// nativeRegistryCustodyTransaction performs bounded local persistence only.
// completion runs after connection cleanup and before releasing registry.mu.
func nativeRegistryCustodyTransaction(ctx context.Context, r *NativeWorkerRegistry, poisoned *bool, schema func(context.Context, *sql.Conn) error, fn func(*sql.Conn) error, completion func(error)) (resultErr error) {
	if r == nil || poisoned == nil || schema == nil {
		return errDirectChannelConsent
	}
	unlock, e := directEndpointTryLock(ctx, &r.mu)
	if e != nil {
		return e
	}
	defer unlock()
	if completion != nil {
		defer func() {
			if recovered := recover(); recovered != nil {
				completion(errDirectChannelConsent)
				panic(recovered)
			}
			completion(resultErr)
		}()
	}
	if *poisoned || r.closed {
		return errDirectChannelConsent
	}
	root, e := nativeRegistryProtectedDirectory(r.root)
	if e != nil {
		return e
	}
	defer root.Close()
	if e = nativeShareHolderPrivate(root, true); e != nil {
		return e
	}
	custody, e := directEndpointTryNativeRegistryCustodyLock(ctx, root)
	if e != nil {
		return e
	}
	defer custody.Close()
	if _, e = nativeRegistryInspectFiles(root, r.custodyIdentity, false); e != nil {
		return e
	}
	c, e := r.db.Conn(ctx)
	if e != nil {
		return e
	}
	defer c.Close()
	var timeout int
	if e = c.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&timeout); e != nil {
		return e
	}
	committed, beginAttempted := false, false
	// Cleanup outlives request cancellation. Never return a transaction-bearing
	// or reconfigured connection to the registry pool if cleanup is uncertain.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		discard := func() { _ = c.Raw(func(any) error { return driver.ErrBadConn }) }
		if beginAttempted && !committed {
			if _, err := c.ExecContext(cleanup, "ROLLBACK"); err != nil {
				discard()
				r.directConsentLeases.revokeAll()
				if resultErr == nil {
					resultErr = err
				}
				return
			}
		}
		if _, err := c.ExecContext(cleanup, fmt.Sprintf("PRAGMA busy_timeout=%d", timeout)); err != nil {
			discard()
			r.directConsentLeases.revokeAll()
			if resultErr == nil {
				resultErr = err
			}
		}
	}()
	if _, e = c.ExecContext(ctx, "PRAGMA busy_timeout=0"); e != nil {
		return e
	}
	beginAttempted = true
	if _, e = c.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
		var sqliteErr *sqlite.Error
		if errors.As(e, &sqliteErr) && (sqliteErr.Code()&0xff == sqlite3.SQLITE_BUSY || sqliteErr.Code()&0xff == sqlite3.SQLITE_LOCKED) {
			beginAttempted = false
			return errDirectEndpointLocalBusy
		}
		return e
	}
	if _, e = nativeRegistryInspectFiles(root, r.custodyIdentity, false); e != nil {
		return e
	}
	if e = schema(ctx, c); e != nil {
		return e
	}
	if e = fn(c); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	_, e = c.ExecContext(ctx, "COMMIT")
	committed = e == nil
	if e != nil {
		*poisoned = true
		r.directConsentLeases.revokeAll()
	}
	return e
}
