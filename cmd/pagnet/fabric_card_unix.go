//go:build linux || darwin

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// Opening a selected document must not block on a FIFO or follow a swapped
// final-component symlink. The caller validates the actual opened file too.
func openLocalA2ACard(path string) (*os.File, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), path), nil
}
