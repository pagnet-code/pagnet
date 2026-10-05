//go:build linux || darwin

package fabricauth

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
)

// checkSocketLiveness never consumes protocol bytes. A signal interruption is
// not evidence of peer death. Recheck the whole poll/peek pair on EINTR, within
// both the caller's existing check deadline and a fixed syscall-attempt budget.
// The injected syscall seam is private; it does not replace kernel identity,
// socket ownership, birth or root authorization checks.
func checkSocketLiveness(ctx context.Context, fd int, poll func([]unix.PollFd, int) (int, error), peek func(int, []byte, int) (int, error)) error {
	const maxAttempts = 8
	if ctx == nil || poll == nil || peek == nil {
		return denied()
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return denied()
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err := poll(fds, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return denied()
		}
		var b [1]byte
		n, err := peek(fd, b[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if ctx.Err() != nil || (err == nil && n == 0) || (err != nil && err != unix.EAGAIN && err != unix.EWOULDBLOCK) {
			return denied()
		}
		return nil
	}
	return denied()
}
