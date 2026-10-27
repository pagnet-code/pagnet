//go:build linux || darwin

package sdk

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func (k *keyring) lockOwnerTextProjectMessages(principal string) (func(), error) {
	fd, err := unix.Open(filepath.Join(k.root, "owner-text-project-messages.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "owner-text-project-messages.lock")
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		file.Close()
		return nil, errors.New("sdk: owner text project message lock is not private regular file")
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	if err = k.initOwnerTextProjectMessages(principal); err != nil {
		file.Close()
		return nil, err
	}
	return func() { _ = file.Close() }, nil
}
