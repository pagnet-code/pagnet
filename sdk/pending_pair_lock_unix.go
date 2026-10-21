//go:build linux || darwin

package sdk

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func (k *keyring) lockPendingPairs() (func(), error) {
	if err := syncPairDir(filepath.Dir(k.root)); err != nil {
		return nil, err
	}
	dir := filepath.Join(k.root, "pending-pairs")
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("sdk: pending pair directory is not private")
	}
	if err := syncPairDir(k.root); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(dir, "store.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "store.lock")
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		f.Close()
		return nil, errors.New("sdk: pending pair lock is not private regular file")
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}
