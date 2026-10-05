//go:build linux || darwin

package fabricauth

import (
	"context"
	"fmt"
	"github.com/pagnet-code/pagnet/fabric"
	"golang.org/x/sys/unix"
	"runtime"
	"sync"
	"testing"
)

func TestSocketLivenessInterruptedSyscallsRecheckWithoutConsuming(t *testing.T) {
	var polls, peeks int
	err := checkSocketLiveness(t.Context(), 99, func(fds []unix.PollFd, timeout int) (int, error) {
		polls++
		if timeout != 0 || len(fds) != 1 || fds[0].Fd != 99 || fds[0].Events != unix.POLLIN {
			t.Fatal("altered nonblocking check")
		}
		if polls == 1 {
			return 0, fmt.Errorf("signal: %w", unix.EINTR)
		}
		return 0, nil
	}, func(fd int, b []byte, flags int) (int, error) {
		peeks++
		if fd != 99 || len(b) != 1 || flags != unix.MSG_PEEK|unix.MSG_DONTWAIT {
			t.Fatal("consuming or blocking probe")
		}
		if peeks == 1 {
			return 0, unix.EINTR
		}
		return 0, unix.EAGAIN
	})
	if err != nil || polls != 3 || peeks != 2 {
		t.Fatal("transient interruption rejected live idle socket", err, polls, peeks)
	}
}
func TestSocketLivenessEINTRDoesNotHideClosureErrorsOrCancellation(t *testing.T) {
	for _, event := range []int16{unix.POLLHUP, unix.POLLERR, unix.POLLNVAL} {
		var polls, peeks int
		err := checkSocketLiveness(t.Context(), 99, func(f []unix.PollFd, _ int) (int, error) {
			polls++
			if polls == 1 {
				return 0, unix.EINTR
			}
			f[0].Revents = event
			return 1, nil
		}, func(int, []byte, int) (int, error) { peeks++; return 1, nil })
		if err == nil || polls != 2 || peeks != 0 {
			t.Fatal("closed/invalid socket accepted", event)
		}
	}
	for _, last := range []struct {
		n   int
		err error
	}{{0, nil}, {0, unix.EBADF}, {0, unix.ECONNRESET}} {
		peeks := 0
		if checkSocketLiveness(t.Context(), 99, func([]unix.PollFd, int) (int, error) { return 0, nil }, func(int, []byte, int) (int, error) {
			peeks++
			if peeks == 1 {
				return 0, unix.EINTR
			}
			return last.n, last.err
		}) == nil {
			t.Fatal("EOF/failure accepted after signal", last)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	if checkSocketLiveness(ctx, 99, func([]unix.PollFd, int) (int, error) { calls++; cancel(); return 0, unix.EINTR }, func(int, []byte, int) (int, error) { t.Fatal("peek after cancellation"); return 0, nil }) == nil || calls != 1 {
		t.Fatal("canceled syscall check retried")
	}
	calls = 0
	if checkSocketLiveness(t.Context(), 99, func([]unix.PollFd, int) (int, error) { calls++; return 0, unix.EINTR }, func(int, []byte, int) (int, error) { t.Fatal("peek before successful poll"); return 0, nil }) == nil || calls != 8 {
		t.Fatal("unbounded signal retry", calls)
	}
}

func TestActualKernelOwnerAuthenticationDuringSchedulerPreemption(t *testing.T) {
	a, _, path := ownerFixture(t)
	conn, _ := ownerSocket(t, path)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var load sync.WaitGroup
	for range 2 {
		load.Add(1)
		go func() {
			defer load.Done()
			for ctx.Err() == nil {
				for range 1000 {
				}
				runtime.Gosched()
			}
		}()
	}
	defer func() { cancel(); load.Wait() }()
	s, err := a.BindOwner(t.Context(), conn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for range 50 {
		raw, proof, err := s.Build(t.Context(), discoverCall())
		if err != nil {
			t.Fatal(err)
		}
		caller, err := a.Authenticate(t.Context(), fabric.AuthenticationRequest{ExactEnvelope: raw, PeerEvidence: proof, Audience: a.config.Audience})
		if err != nil {
			t.Fatal(err)
		}
		if !a.AssociationOpen(caller) {
			t.Fatal("real current peer lost association")
		}
	}
}
