//go:build linux || darwin

package privatefs

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func verifyOwnedParent(path string) error {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return e
	}
	if st.Uid != uint32(os.Getuid()) || st.Mode&0022 != 0 {
		return errors.New("installation parent is foreign-owned or permits another writer")
	}
	return nil
}

// CheckPrivateDirectory verifies an existing owner-only private directory and
// never creates a lock file or changes its permissions.
func CheckPrivateDirectory(path string) error {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return e
	}
	if st.Uid != uint32(os.Getuid()) || st.Mode&0777 != 0700 {
		return errors.New("private directory is not exclusive to this owner")
	}
	return nil
}
