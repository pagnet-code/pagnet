//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package inbox

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Resolve every component through held directory descriptors, rejecting symlinks
// and ancestors where another user could replace a child directory.
func openDirectory(path string) (*os.File, error) {
	if path == "" {
		return nil, ErrPrivate
	}
	if !filepath.IsAbs(path) {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		path = cwd + "/" + path
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	sticky := false
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			unix.Close(fd)
			return nil, ErrPrivate
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e == unix.ENOENT {
			if e = unix.Mkdirat(fd, part, 0700); e == nil {
				e = unix.Fsync(fd)
			}
			if e != nil && e != unix.EEXIST {
				unix.Close(fd)
				return nil, e
			}
			next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		unix.Close(fd)
		if e != nil {
			return nil, ErrPrivate
		}
		var st unix.Stat_t
		if unix.Fstat(next, &st) != nil || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (sticky && st.Uid != uint32(os.Geteuid())) {
			unix.Close(next)
			return nil, ErrPrivate
		}
		sticky = st.Uid == 0 && st.Mode&unix.S_ISVTX != 0
		if st.Mode&0022 != 0 && !sticky {
			unix.Close(next)
			return nil, ErrPrivate
		}
		fd = next
	}
	dir := os.NewFile(uintptr(fd), "inbox directory")
	if !privateInfo(dir, true) {
		dir.Close()
		return nil, ErrPrivate
	}
	return dir, nil
}
func privateInfo(f *os.File, directory bool) bool {
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != uint32(os.Geteuid()) {
		return false
	}
	if directory {
		return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&0777 == 0700
	}
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0777 == 0600 && st.Nlink == 1
}
func openPrivate(dir *os.File, name string, flags int) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	if !privateInfo(f, false) {
		f.Close()
		return nil, ErrPrivate
	}
	return f, nil
}
func acquireLock(dir *os.File) (*os.File, error) {
	f, err := openPrivate(dir, "lock", unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, ErrLocked
	}
	return f, nil
}
func readPrivate(dir *os.File, name string, max int64) ([]byte, error) {
	f, err := openPrivate(dir, name, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, ErrCorrupt
	}
	return data, nil
}
func writeAtomic(dir *os.File, name string, data []byte) (err error) {
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	temp := ".tmp-" + hex.EncodeToString(nonce)
	f, err := openPrivate(dir, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return err
	}
	defer func() { f.Close(); unix.Unlinkat(int(dir.Fd()), temp, 0) }()
	n, err := f.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	// Ownership lock guarantees no legitimate concurrent writer. Never replace an
	// existing committed record or key, including one inserted outside this Store.
	var st unix.Stat_t
	if err = unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err = unix.Renameat(int(dir.Fd()), temp, int(dir.Fd()), name); err != nil {
		return err
	}
	return dir.Sync()
}
func removeTemporary(dir *os.File, name string) error {
	f, err := openPrivate(dir, name, unix.O_RDONLY)
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}
	if err = unix.Unlinkat(int(dir.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}
