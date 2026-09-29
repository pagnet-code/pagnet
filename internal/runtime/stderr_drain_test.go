package runtime

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestCapturedStderr_ProcessWaitReap — regression for the 2026-09-29
// -race CI finding. The drivers once passed a *bytes.Buffer directly as
// cmd.Stderr; the pipe→buffer copier exec.Cmd spawns internally is
// joined ONLY by cmd.Wait, but the supervisor reaps the direct child
// with a raw Process.Wait (the bounded-termination design never calls
// cmd.Wait — it would close the I/O pipes while the driver is still
// draining stdout). h.Wait() could return while the copier was still
// writing, and the driver's post-reap stderrBuf.String() data-raced.
//
// This mirrors the supervisor's reap exactly — a real child, a raw
// Process.Wait, never cmd.Wait — and then reads the captured text. Run
// under -race: the old io.Writer form fails here, and the driver-owned
// drain must return the COMPLETE stream (the child's write end closes
// at exit, so the drain finishes and the bound never elapses).
func TestCapturedStderr_ProcessWaitReap(t *testing.T) {
	const lines = 5000 // ~150KB of stderr: at exit the tail is still in the pipe
	script := fmt.Sprintf(
		"for i in $(seq %d); do printf 'fake-stderr-line-%%05d\\n' \"$i\"; done >&2; exit 3",
		lines)
	cmd := exec.Command("sh", "-c", script)
	c, err := attachStderrDrain(cmd)
	if err != nil {
		t.Fatalf("attachStderrDrain: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	// The supervisor's reap: a raw waitpid, never cmd.Wait (cmd.Wait
	// would join exec's copier and mask the regression). Raw
	// Process.Wait reports a non-zero exit through the state (nil
	// error) — the supervisor converts it to an ExitError the same way.
	state, werr := cmd.Process.Wait()
	if werr != nil {
		t.Fatalf("Process.Wait: %v", werr)
	}
	if state.Success() {
		t.Fatal("child exited clean, want non-zero exit 3")
	}
	text := c.Text()
	if got := strings.Count(text, "fake-stderr-line-"); got != lines {
		t.Fatalf("captured %d lines, want %d (the normal-case drain must complete before Text returns)", got, lines)
	}
}

// TestCapturedStderr_BoundWhileWriteEndHeld — the pipe-hold hazard: a
// descendant keeps the write end open past the "reap". Text must return
// a best-effort prefix within the bound (never wedge), and once the
// holder releases the end the drain completes with the full stream (in
// production the reaper's group reclaim is what kills the holder).
func TestCapturedStderr_BoundWhileWriteEndHeld(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	c := newCapturedStderr(r, 100*time.Millisecond)
	go func() {
		if _, err := w.WriteString("prefix-"); err != nil {
			t.Errorf("write prefix: %v", err)
		}
		time.Sleep(300 * time.Millisecond) // hold the write end past the bound
		if _, err := w.WriteString("suffix"); err != nil {
			t.Errorf("write suffix: %v", err)
		}
		w.Close()
	}()
	done := make(chan string, 1)
	go func() { done <- c.Text() }()
	select {
	case text := <-done:
		if !strings.HasPrefix(text, "prefix-") {
			t.Fatalf("Text = %q, want the prefix captured before the bound", text)
		}
		if strings.Contains(text, "suffix") {
			t.Fatalf("Text = %q, the holder had not released the write end yet", text)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Text wedged: the drain bound must return a best-effort prefix")
	}
	<-c.drained // the holder released: the drain must complete
	c.mu.Lock()
	full := c.buf.String()
	c.mu.Unlock()
	if !strings.Contains(full, "suffix") {
		t.Fatalf("drained text = %q, want the full stream after the holder released", full)
	}
}
