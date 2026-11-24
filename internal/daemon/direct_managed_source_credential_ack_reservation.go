//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// withCredentialACKReserved follows writeMu -> registry -> State -> memory.
// Unlike installation custody, ACK custody never waits for another registry or
// namespace owner while the caller holds the global socket writer.
func (s *DirectManagedSourceKeyStore) withCredentialACKReserved(ctx context.Context, fn func(*sql.Conn, *os.File, *func()) error) error {
	if ctx.Err() != nil || !s.registry.mu.TryLock() {
		return ErrManagedEndpointPrepareRetryable
	}
	defer s.registry.mu.Unlock()
	root, err := nativeShareHolderDirectory(s.registry.root)
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := nativeShareHolderExistingChild(root, nativeDirectManagedSourceKeyNamespace)
	if err != nil {
		return err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), "holder.lock", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	lock := os.NewFile(uintptr(fd), "holder.lock")
	defer lock.Close()
	if err := nativeShareHolderPrivate(lock, false); err != nil {
		return err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return ErrManagedEndpointPrepareRetryable
	}
	acquireCtx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	conn, err := s.registry.db.Conn(acquireCtx)
	cancel()
	if err != nil {
		return ErrManagedEndpointPrepareRetryable
	}
	defer conn.Close()
	var busy int
	if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busy); err != nil {
		return ErrManagedEndpointPrepareRetryable
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout=0"); err != nil {
		return ErrManagedEndpointPrepareRetryable
	}
	var release func()
	reserved := false
	defer func() {
		// Cleanup must finish even after cancellation; never return an unfinished
		// transaction or changed busy policy to the single-connection pool.
		if reserved {
			if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
				_ = conn.Raw(func(any) error { return driver.ErrBadConn })
				_ = conn.Close()
			}
		}
		if _, err := conn.ExecContext(context.Background(), "PRAGMA busy_timeout="+strconv.Itoa(busy)); err != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
		if release != nil {
			release()
		}
	}()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return ErrManagedEndpointPrepareRetryable
	}
	reserved = true
	if ctx.Err() != nil {
		return ErrManagedEndpointPrepareRetryable
	}
	if err := fn(conn, dir, &release); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	reserved = false
	return nil
}
