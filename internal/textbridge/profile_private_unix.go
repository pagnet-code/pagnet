//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package textbridge

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var errTextBridgePrivate = errors.New("text bridge requires a private, user-owned file or directory")

// Walk with directory descriptors so a replaced path component cannot redirect
// an operation through a symlink. Ancestors must also prevent other users from
// replacing children; root-owned sticky directories such as /tmp are allowed.
func textBridgeOpenDir(path string, create bool) (*os.File, error) {
	if path == "" {
		return nil, errTextBridgePrivate
	}
	if !filepath.IsAbs(path) {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, errTextBridgePrivate
		}
		path = cwd + string(os.PathSeparator) + path
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errTextBridgePrivate
	}
	sticky, safe := textBridgeSafeAncestor(fd)
	if !safe {
		unix.Close(fd)
		return nil, errTextBridgePrivate
	}
	for _, component := range strings.Split(path, string(os.PathSeparator)) {
		if component == "" || component == "." {
			continue
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr == unix.ENOENT && create {
			if mkdirErr := unix.Mkdirat(fd, component, 0700); mkdirErr == nil || mkdirErr == unix.EEXIST {
				next, openErr = unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		unix.Close(fd)
		if openErr != nil {
			return nil, errTextBridgePrivate
		}
		var stat unix.Stat_t
		if sticky && (unix.Fstat(next, &stat) != nil || stat.Uid != uint32(os.Getuid())) {
			unix.Close(next)
			return nil, errTextBridgePrivate
		}
		sticky, safe = textBridgeSafeAncestor(next)
		if !safe {
			unix.Close(next)
			return nil, errTextBridgePrivate
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), "text bridge directory"), nil
}

// A sticky root-owned directory protects a user-owned next component from
// replacement. Every other ancestor must be owned by root or this user and
// must not permit writes by group or other users.
func textBridgeSafeAncestor(fd int) (sticky, safe bool) {
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || (stat.Uid != 0 && stat.Uid != uint32(os.Getuid())) {
		return false, false
	}
	if stat.Mode&0022 == 0 {
		return false, true
	}
	sticky = stat.Uid == 0 && stat.Mode&unix.S_ISVTX != 0
	return sticky, sticky
}

func textBridgePrivateInfo(file *os.File, directory bool) bool {
	info, err := file.Stat()
	if err != nil || info.Mode().Perm()&0077 != 0 || info.IsDir() != directory {
		return false
	}
	if !directory && !info.Mode().IsRegular() {
		return false
	}
	var stat unix.Stat_t
	return unix.Fstat(int(file.Fd()), &stat) == nil && stat.Uid == uint32(os.Getuid())
}

// PrivateDir creates or checks a private directory owned by the current OS user.
func PrivateDir(path string) error {
	dir, err := textBridgeOpenDir(path, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	if !textBridgePrivateInfo(dir, true) {
		return errTextBridgePrivate
	}
	return nil
}

// ReadPrivate reads a bounded private regular file without following symlinks.
func ReadPrivate(path string, max int64) ([]byte, error) {
	if max < 0 || path == "" {
		return nil, errTextBridgePrivate
	}
	// Split preserves uncleaned parent components for the no-follow walk.
	slash := strings.LastIndex(path, string(os.PathSeparator))
	parent, name := ".", path
	if slash >= 0 {
		parent, name = path[:slash], path[slash+1:]
		if parent == "" {
			parent = "/"
		}
	}
	if name == "" || name == "." || name == ".." {
		return nil, errTextBridgePrivate
	}
	dir, err := textBridgeOpenDir(parent, false)
	if err != nil {
		return nil, errTextBridgePrivate
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errTextBridgePrivate
	}
	file := os.NewFile(uintptr(fd), "text bridge private file")
	defer file.Close()
	if !textBridgePrivateInfo(file, false) {
		return nil, errTextBridgePrivate
	}
	info, err := file.Stat()
	if err != nil || info.Size() > max {
		return nil, errTextBridgePrivate
	}
	data, err := io.ReadAll(io.LimitReader(file, max))
	if err != nil {
		return nil, errTextBridgePrivate
	}
	var extra [1]byte
	if n, err := file.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, errTextBridgePrivate
	}
	return data, nil
}

// LockProfile takes the nonblocking exclusive local responder lock.
func LockProfile(path string) (func(), error) {
	dir, err := textBridgeOpenDir(path, false)
	if err != nil {
		return nil, errTextBridgePrivate
	}
	defer dir.Close()
	if !textBridgePrivateInfo(dir, true) {
		return nil, errTextBridgePrivate
	}
	fd, err := unix.Openat(int(dir.Fd()), "run.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errTextBridgePrivate
	}
	file := os.NewFile(uintptr(fd), "text bridge lock")
	if !textBridgePrivateInfo(file, false) {
		file.Close()
		return nil, errTextBridgePrivate
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("text bridge responder is already running or cannot acquire its lock")
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			unix.Flock(fd, unix.LOCK_UN)
			file.Close()
		})
	}, nil
}
