//go:build linux || darwin

package crypto

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Context epochs are shared by independently owned session workers. A local
// mutex cannot fence rotation against a native approval in another process.
func lockContextKeyring(ctx context.Context, path string, exclusive bool) (func(), error) {
	dir := filepath.Dir(path)
	return lockAuthorityKeyring(ctx, path, exclusive, []string{filepath.Dir(filepath.Dir(dir)), filepath.Dir(dir), dir})
}
func lockNetworkKeyring(ctx context.Context, path string, exclusive bool) (func(), error) {
	dir := filepath.Dir(path)
	return lockAuthorityKeyring(ctx, path, exclusive, []string{filepath.Dir(dir), dir})
}
func lockAuthorityKeyring(ctx context.Context, path string, exclusive bool, directories []string) (func(), error) {
	dir := filepath.Dir(path)
	// Validate each authority directory before creating the lock file. An
	// ancestor symlink must not cause side effects in another key store.
	for _, candidate := range directories {
		info, err := os.Lstat(candidate)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode().Perm()&0077 != 0 || validateContextFileOwner(info) != nil {
			return nil, errors.New("protected context lock directory is not private")
		}
	}
	fd, err := unix.Open(filepath.Join(dir, "authority.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "authority.lock")
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || validateContextFileOwner(info) != nil {
		_ = f.Close()
		return nil, errors.New("protected context lock is not an owner-private regular file")
	}
	mode := unix.LOCK_SH
	if exclusive {
		mode = unix.LOCK_EX
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = f.Close()
			return nil, err
		}
		err = unix.Flock(fd, mode|unix.LOCK_NB)
		if err == nil {
			return func() { _ = f.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = f.Close()
			return nil, err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = f.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
