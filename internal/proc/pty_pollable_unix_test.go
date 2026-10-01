//go:build unix

package proc

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func TestPTYMasterDeadlinesSurviveResize(t *testing.T) {
	original, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close()
	// Reproduce the vendor's Fd-based resize before normalization. On Linux
	// this switches OpenFile's initially-pollable descriptor to blocking.
	if err := pty.Setsize(original, &pty.Winsize{Rows: 24, Cols: 80}); err != nil {
		original.Close()
		t.Fatal(err)
	}
	master, err := pollablePTYMaster(original)
	if err != nil {
		original.Close()
		t.Fatal(err)
	}
	defer master.Close()
	if _, err := term.MakeRaw(int(slave.Fd())); err != nil {
		t.Fatal(err)
	}
	for _, size := range []*pty.Winsize{{Rows: 45, Cols: 132}, {Rows: 24, Cols: 80}} {
		if err := pty.Setsize(master, size); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := master.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	var flagErr error
	if err := raw.Control(func(fd uintptr) { flags, flagErr = unix.FcntlInt(fd, unix.F_GETFL, 0) }); err != nil {
		t.Fatal(err)
	}
	if flagErr != nil {
		t.Fatal(flagErr)
	}
	if flags&unix.O_NONBLOCK == 0 {
		t.Fatal("resizing disabled nonblocking mode; deadlines would not cancel syscall writes")
	}
	if err := master.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := master.Read(make([]byte, 1)); n != 0 || !os.IsTimeout(err) {
		t.Fatalf("read deadline ineffective: n=%d err=%v", n, err)
	}
	if err := master.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 256*1024)
	if n, err := master.Write(payload); n == len(payload) || !os.IsTimeout(err) {
		t.Fatalf("stalled PTY write deadline ineffective: n=%d err=%v", n, err)
	}
	// The original handle was transferred/closed and must not remain an
	// accidental second owner of the descriptor.
	if _, err := original.Stat(); err == nil {
		t.Fatal("original master retained ownership")
	}
}
