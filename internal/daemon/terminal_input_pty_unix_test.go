//go:build unix

package daemon

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

func TestTerminalInputFIFOIncludesResizes(t *testing.T) {
	tm := inputTestManager(t)
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	if _, err := term.MakeRaw(int(slave.Fd())); err != nil {
		t.Fatal(err)
	}
	s := inputTestSession(tm, "agent", "viewer", master)
	// Reading from the slave observes the actual PTY input, not a mock.
	if !tm.submit(terminalLiveMsg{instance: "agent", session: "viewer", data: bytes.Repeat([]byte("a"), 32768)}) {
		t.Fatal("first input rejected")
	}
	if !tm.submit(terminalLiveMsg{instance: "agent", session: "viewer", isResize: true, cols: 132, rows: 45}) {
		t.Fatal("resize rejected")
	}
	if !tm.submit(terminalLiveMsg{instance: "agent", session: "viewer", data: []byte("tail")}) {
		t.Fatal("last input rejected")
	}
	got := make([]byte, 32772)
	complete := make(chan error, 1)
	go func() { _, err := io.ReadFull(slave, got); complete <- err }()
	select {
	case err := <-complete:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("input/resize FIFO stalled")
	}
	if !bytes.Equal(got[:32768], bytes.Repeat([]byte("a"), 32768)) || string(got[32768:]) != "tail" {
		t.Fatal("PTY input was reordered")
	}
	waitInput(t, tm, s, func(q *terminalInputQueue) bool { return q.bytes == 0 && len(q.messages) == 0 })
	rows, cols, err := pty.Getsize(master)
	if err != nil || rows != 45 || cols != 132 {
		t.Fatalf("resize missing: rows=%d cols=%d err=%v", rows, cols, err)
	}
	tm.stop("agent")
	select {
	case <-s.input.done:
	case <-time.After(time.Second):
		t.Fatal("PTY input worker did not stop")
	}
}
