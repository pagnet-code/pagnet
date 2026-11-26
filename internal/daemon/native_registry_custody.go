//go:build linux || darwin

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type nativeRegistryFileIdentity struct{ device, inode uint64 }

var errNativeRegistryCustody = errors.New("native registry custody files are unsafe or unavailable")

// The threat model excludes malicious same-UID writers and complete directory or
// database rollback. Every pathname ancestor is protected against other UIDs.
func nativeRegistryProtectedDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errNativeRegistryCustody
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	current := os.NewFile(uintptr(fd), "/")
	var rootStat unix.Stat_t
	if e = unix.Fstat(fd, &rootStat); e != nil || rootStat.Uid != 0 || uint32(rootStat.Mode)&0022 != 0 {
		current.Close()
		return nil, errNativeRegistryCustody
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	stickyParent := false
	for i, part := range parts {
		if part == "" {
			continue
		}
		next, e := nativeShareHolderOpenDir(current, part)
		current.Close()
		if e != nil {
			return nil, e
		}
		current = next
		var stat unix.Stat_t
		if e = unix.Fstat(int(current.Fd()), &stat); e != nil {
			current.Close()
			return nil, e
		}
		trusted := stat.Uid == 0 || stat.Uid == uint32(os.Geteuid())
		writable := uint32(stat.Mode)&0022 != 0
		stickyTmp := i == 0 && part == "tmp" && stat.Uid == 0 && uint32(stat.Mode)&unix.S_ISVTX != 0
		if !trusted || (writable && !stickyTmp) || (stickyParent && (!trusted || writable)) {
			current.Close()
			return nil, errNativeRegistryCustody
		}
		stickyParent = stickyTmp
	}
	if stickyParent {
		current.Close()
		return nil, errNativeRegistryCustody
	}
	return current, nil
}
func nativeRegistryCustodyLock(root *os.File) (*os.File, error) {
	fd, e := unix.Openat(int(root.Fd()), "registry.custody.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "registry.custody.lock")
	if e = nativeShareHolderPrivate(f, false); e == nil {
		for {
			e = unix.Flock(fd, unix.LOCK_EX)
			if e != unix.EINTR {
				break
			}
		}
	}
	if e == nil {
		e = f.Sync()
	}
	if e == nil {
		e = root.Sync()
	}
	if e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func nativeRegistryInspectFiles(root *os.File, expected nativeRegistryFileIdentity, create bool) (nativeRegistryFileIdentity, error) {
	var identity nativeRegistryFileIdentity
	db, e := nativeShareHolderOpen(root, "registry.sqlite", false)
	missing := errors.Is(e, os.ErrNotExist)
	if e != nil && !missing {
		return identity, e
	}
	for _, name := range []string{"registry.sqlite-wal", "registry.sqlite-shm", "registry.sqlite-journal"} {
		f, err := nativeShareHolderOpen(root, name, false)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			if db != nil {
				db.Close()
			}
			return identity, err
		}
		f.Close()
		if missing {
			return identity, errNativeRegistryCustody
		}
	}
	if missing {
		if !create {
			return identity, errNativeRegistryCustody
		}
		db, e = nativeShareHolderOpen(root, "registry.sqlite", true)
		if e != nil {
			return identity, e
		}
		if e = db.Sync(); e == nil {
			e = root.Sync()
		}
		if e != nil {
			db.Close()
			return identity, e
		}
	}
	defer db.Close()
	var stat unix.Stat_t
	if e = unix.Fstat(int(db.Fd()), &stat); e != nil {
		return identity, e
	}
	identity = nativeRegistryFileIdentity{uint64(stat.Dev), uint64(stat.Ino)}
	if expected != (nativeRegistryFileIdentity{}) && identity != expected {
		return identity, errNativeRegistryCustody
	}
	return identity, nil
}
func nativeRegistryOpenCustody(stateDir string) (*os.File, *os.File, nativeRegistryFileIdentity, error) {
	var empty nativeRegistryFileIdentity
	parent, e := nativeRegistryProtectedDirectory(stateDir)
	if e != nil {
		return nil, nil, empty, e
	}
	defer parent.Close()
	root, e := nativeShareHolderChild(parent, "native-workers")
	if e != nil {
		return nil, nil, empty, e
	}
	lock, e := nativeRegistryCustodyLock(root)
	if e != nil {
		root.Close()
		return nil, nil, empty, e
	}
	identity, e := nativeRegistryInspectFiles(root, empty, true)
	if e != nil {
		lock.Close()
		root.Close()
		return nil, nil, empty, e
	}
	return root, lock, identity, nil
}
