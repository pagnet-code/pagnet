//go:build linux || darwin

package runtime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

func tailFixture(t *testing.T, data []byte) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "events")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	if _, err = f.Write(data); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestQwenNativeTailBoundedBacklog(t *testing.T) {
	data := bytes.Repeat([]byte("event\n"), maxQwenNativeBatchLines*9+7)
	data = append(data, []byte("partial")...)
	f := tailFixture(t, data)
	var offset int64
	total := 0
	for {
		lines, next, err := readNewLines(f, offset)
		if err != nil {
			t.Fatal(err)
		}
		if len(lines) > maxQwenNativeBatchLines {
			t.Fatal("unbounded line batch")
		}
		for _, line := range lines {
			if string(line) != "event" {
				t.Fatalf("corrupt line %q", line)
			}
		}
		total += len(lines)
		if next == offset {
			break
		}
		offset = next
	}
	if total != maxQwenNativeBatchLines*9+7 || offset != int64(len(data)-7) {
		t.Fatalf("lost backlog: lines=%d offset=%d", total, offset)
	}
	if _, err := f.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	lines, next, err := readNewLines(f, offset)
	if err != nil || len(lines) != 1 || string(lines[0]) != "partial" || next != int64(len(data)+1) {
		t.Fatalf("partial tail: %q %d %v", lines, next, err)
	}
}

func TestQwenNativeTailExactFrameBound(t *testing.T) {
	for _, size := range []int{maxQwenNativeLineBytes - 1, maxQwenNativeLineBytes, maxQwenNativeLineBytes + 1} {
		t.Run(string(rune(size-maxQwenNativeLineBytes+'b')), func(t *testing.T) {
			data := append(bytes.Repeat([]byte("x"), size), '\n')
			lines, next, err := readNewLines(tailFixture(t, data), 0)
			if size > maxQwenNativeLineBytes {
				if !errors.Is(err, errQwenNativeLineTooLarge) || next != 0 {
					t.Fatalf("oversize accepted: %d %v", next, err)
				}
			} else if err != nil || len(lines) != 1 || len(lines[0]) != size || next != int64(size+1) {
				t.Fatalf("valid exact frame refused: %d %v", next, err)
			}
		})
	}
	f := tailFixture(t, bytes.Repeat([]byte("x"), maxQwenNativeLineBytes+1))
	if _, _, err := readNewLines(f, 0); !errors.Is(err, errQwenNativeLineTooLarge) {
		t.Fatalf("unterminated oversize: %v", err)
	}
}

func TestQwenNativeTailSparseBacklogAllocation(t *testing.T) {
	f := tailFixture(t, []byte("small\n"))
	if err := f.Truncate(1 << 30); err != nil {
		t.Fatal(err)
	}
	lines, next, err := readNewLines(f, 0)
	if err != nil || len(lines) != 1 || string(lines[0]) != "small" || next != 6 {
		t.Fatalf("sparse backlog: %q %d %v", lines, next, err)
	}
	if cap(lines[0]) > qwenNativeReadBatchBytes {
		t.Fatalf("allocated whole unread backlog: capacity %d", cap(lines[0]))
	}
}

func TestQwenOversizedNativeEventStopsOwnedProcess(t *testing.T) {
	q, workspace, _, argsPath, env := newQwenPersistentFixture(t, false)
	sess := &session.RuntimeSession{InstanceID: "oversized-events", Runtime: domain.RuntimeQwenCode, Workspace: workspace, Env: env}
	if _, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 16)); err != nil {
		t.Fatal(err)
	}
	q.mu.Lock()
	endpoint := q.endpoints[sess.InstanceID]
	q.mu.Unlock()
	if endpoint == nil {
		t.Fatal("missing native endpoint")
	}
	t.Cleanup(func() { q.requestEndpointStop(endpoint) })
	f, err := os.OpenFile(qwenArgAfter(readArgv(t, argsPath), "--json-file"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write(bytes.Repeat([]byte("x"), maxQwenNativeLineBytes+1))
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if !q.Live(sess.InstanceID) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("malformed native stream left a live process/reader waiting forever")
}

func TestQwenOldReaderCannotStopReplacement(t *testing.T) {
	q, workspace, _, _, env := newQwenPersistentFixture(t, false)
	sess := &session.RuntimeSession{InstanceID: "same-instance", Runtime: domain.RuntimeQwenCode, Workspace: workspace, Env: env}
	if _, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 16)); err != nil {
		t.Fatal(err)
	}
	q.mu.Lock()
	old := q.endpoints[sess.InstanceID]
	q.mu.Unlock()
	if err := q.Hibernate(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(6 * time.Second)
	for !old.processGone() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !old.processGone() {
		t.Fatal("old endpoint did not terminate")
	}
	select {
	case <-old.readerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("old reader did not finish reaping")
	}
	// No exchange was submitted; replacement is an explicit fresh native activation.
	sess.NativeID = ""
	if _, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 16)); err != nil {
		t.Fatal(err)
	}
	q.mu.Lock()
	replacement := q.endpoints[sess.InstanceID]
	q.mu.Unlock()
	t.Cleanup(func() { q.requestEndpointStop(replacement) })
	q.requestEndpointStop(old)
	time.Sleep(250 * time.Millisecond)
	if replacement == old || replacement.processGone() || !q.Live(sess.InstanceID) {
		t.Fatal("late old reader terminated replacement generation")
	}
}

func TestQwenNativeExitDrainsEveryBoundedBatch(t *testing.T) {
	q, workspace, _, argsPath, env := newQwenPersistentFixture(t, false)
	sess := &session.RuntimeSession{InstanceID: "final-backlog", Runtime: domain.RuntimeQwenCode, Workspace: workspace, Env: env}
	if _, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 16)); err != nil {
		t.Fatal(err)
	}
	q.mu.Lock()
	e := q.endpoints[sess.InstanceID]
	q.mu.Unlock()
	t.Cleanup(func() { q.requestEndpointStop(e) })
	events := make(chan session.SessionEvent, 4)
	e.mu.Lock()
	e.currentTurnEvents = events
	e.currentTurnID = "final-turn"
	e.mu.Unlock()
	e.state.mu.Lock()
	e.state.turnActive = true
	e.state.turnIsMachine = true
	e.state.machineTurnID = "final-turn"
	data := bytes.Repeat([]byte("{\"type\":\"future_event\"}\n"), maxQwenNativeBatchLines*9)
	data = append(data, []byte("{\"type\":\"system\",\"subtype\":\"continue_turn_failed\"}\n")...)
	f, err := os.OpenFile(qwenArgAfter(readArgv(t, argsPath), "--json-file"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		e.state.mu.Unlock()
		t.Fatal(err)
	}
	_, err = f.Write(data)
	f.Close()
	if err != nil {
		e.state.mu.Unlock()
		t.Fatal(err)
	}
	if err = syscall.Kill(*e.pid(), syscall.SIGKILL); err != nil {
		e.state.mu.Unlock()
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !e.processGone() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	e.state.mu.Unlock()
	select {
	case ev := <-events:
		if ev.Type != session.EventTurnFailed || ev.TurnID != "final-turn" {
			t.Fatalf("lost final native terminal event: %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bounded exit drain dropped final native terminal event")
	}
}

func TestQwenNativeTailRejectsTruncatedOrInvalidCursor(t *testing.T) {
	f := tailFixture(t, []byte("first\n"))
	_, offset, err := readNewLines(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(0); err != nil {
		t.Fatal(err)
	}
	lines, next, err := readNewLines(f, offset)
	if err == nil || len(lines) != 0 || next != offset {
		t.Fatalf("truncated native generation silently replayed: %q %d %v", lines, next, err)
	}
	if _, _, err = readNewLines(f, -1); err == nil {
		t.Fatal("negative cursor accepted")
	}
}
