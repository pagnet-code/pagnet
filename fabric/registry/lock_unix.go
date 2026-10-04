//go:build linux || darwin

package registry

import (
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
)

func lockDirectory(dir string) (io.Closer, error) {
	fd, e := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return nil, e
	}
	if st.Uid != uint32(os.Getuid()) || st.Mode&0777 != 0700 {
		return nil, errors.New("registry directory is not private to this owner")
	}
	fd, e = unix.Open(filepath.Join(dir, "writer.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "registry writer lock")
	if e = unix.Fstat(fd, &st); e != nil {
		f.Close()
		return nil, e
	}
	if st.Uid != uint32(os.Getuid()) || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 {
		f.Close()
		return nil, errors.New("registry writer lock is not private")
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("registry already has a writer or locking is unavailable")
	}
	return f, nil
}
func readPrivate(path string, bound int) ([]byte, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "private registry state")
	defer f.Close()
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return nil, e
	}
	if st.Uid != uint32(os.Getuid()) || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Size < 0 || st.Size > int64(bound) {
		return nil, errors.New("registry state is not a bounded private file")
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(bound)+1))
	if e != nil || len(b) > bound {
		return nil, errors.New("registry state exceeds bound")
	}
	return b, nil
}

func checkPrivateDatabase(path string, bound int64) error {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return e
	}
	if st.Uid != uint32(os.Getuid()) || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Size < 0 || st.Size > bound {
		return errors.New("registry database is not a bounded private owner file")
	}
	return nil
}

func createPrivateDirectory(dir string) error { return os.Mkdir(dir, 0700) }
func publishPrivate(from, to string) error    { return os.Link(from, to) }
func syncDirectory(dir string) error {
	f, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
