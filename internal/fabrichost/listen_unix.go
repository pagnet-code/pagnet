//go:build linux || darwin

package fabrichost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func listenPrivate(path string) (*net.UnixListener, func(), error) {
	parent := filepath.Dir(path)
	directory, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, failure()
	}
	directoryKept := false
	defer func() {
		if !directoryKept {
			unix.Close(directory)
		}
	}()
	var st unix.Stat_t
	if unix.Fstat(directory, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700 {
		return nil, nil, failure()
	}
	directoryIdentity := st
	digest := sha256.Sum256([]byte(path))
	name := "fabric-mcp-" + hex.EncodeToString(digest[:]) + ".lock"
	fd, err := unix.Openat(directory, name, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, nil, failure()
	}
	keep := false
	defer func() {
		if !keep {
			unix.Close(fd)
		}
	}()
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, nil, failure()
	}
	if info, err := os.Lstat(path); err == nil {
		var socket unix.Stat_t
		if unix.Lstat(path, &socket) != nil || socket.Uid != uint32(os.Geteuid()) || socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Mode&0777 != 0600 {
			return nil, nil, failure()
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		probe, probeErr := (&net.Dialer{}).DialContext(ctx, "unix", path)
		cancel()
		if probeErr == nil {
			probe.Close()
			return nil, nil, failure()
		}
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(info, current) || os.Remove(path) != nil {
			return nil, nil, failure()
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, failure()
	}
	var currentDirectory unix.Stat_t
	if unix.Lstat(parent, &currentDirectory) != nil || currentDirectory.Dev != directoryIdentity.Dev || currentDirectory.Ino != directoryIdentity.Ino {
		return nil, nil, failure()
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, nil, failure()
	}
	listener.SetUnlinkOnClose(false)
	if err = os.Chmod(path, 0600); err != nil {
		listener.Close()
		os.Remove(path)
		return nil, nil, failure()
	}
	var created unix.Stat_t
	if unix.Fstatat(directory, filepath.Base(path), &created, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Lstat(parent, &currentDirectory) != nil || currentDirectory.Dev != directoryIdentity.Dev || currentDirectory.Ino != directoryIdentity.Ino {
		listener.Close()
		return nil, nil, failure()
	}
	release := func() {
		listener.Close()
		var current unix.Stat_t
		if unix.Fstatat(directory, filepath.Base(path), &current, unix.AT_SYMLINK_NOFOLLOW) == nil && current.Dev == created.Dev && current.Ino == created.Ino {
			unix.Unlinkat(directory, filepath.Base(path), 0)
		}
		unix.Flock(fd, unix.LOCK_UN)
		unix.Close(fd)
		unix.Close(directory)
	}
	directoryKept = true
	keep = true
	return listener, release, nil
}

func sameOwner(uid uint32) bool { return uid == uint32(os.Geteuid()) }
func checkSocket(path string) error {
	fd, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return failure()
	}
	defer unix.Close(fd)
	var parent, socket unix.Stat_t
	if unix.Fstat(fd, &parent) != nil || parent.Uid != uint32(os.Geteuid()) || parent.Mode&0777 != 0700 || unix.Fstatat(fd, filepath.Base(path), &socket, unix.AT_SYMLINK_NOFOLLOW) != nil || socket.Uid != uint32(os.Geteuid()) || socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Mode&0777 != 0600 {
		return failure()
	}
	return nil
}
