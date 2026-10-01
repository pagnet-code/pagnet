package daemon

import (
	"bytes"
	"encoding/json"
	"github.com/pagnet-code/pagnet/transport"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"
)

func inputTestManager(t *testing.T) *terminalManager {
	t.Helper()
	d := &Daemon{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), attaches: map[string]map[string]time.Time{}}
	tm := newTerminalManager(d)
	t.Cleanup(tm.stopAll)
	return tm
}

func inputTestSession(tm *terminalManager, instance, viewer string, f *os.File) *ptySession {
	s := &ptySession{instanceID: instance, f: f, live: make(chan struct{}), endpointView: true}
	close(s.live)
	tm.mu.Lock()
	tm.sessions[instance] = s
	tm.mu.Unlock()
	tm.d.addAttach(instance, viewer)
	return s
}

func inputTestPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return r, w
}

func waitInput(t *testing.T, tm *terminalManager, s *ptySession, condition func(*terminalInputQueue) bool) *terminalInputQueue {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		tm.mu.Lock()
		q := s.input
		ok := q != nil && condition(q)
		tm.mu.Unlock()
		if ok {
			return q
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("terminal input worker did not reach expected state")
	return nil
}

func TestTerminalInputStalledPTYDoesNotDelayOtherAgent(t *testing.T) {
	tm := inputTestManager(t)
	_, stalled := inputTestPipe(t)
	slow := inputTestSession(tm, "slow", "slow-view", stalled)
	if !tm.submit(terminalLiveMsg{instance: "slow", session: "slow-view", data: bytes.Repeat([]byte("s"), 128*1024)}) {
		t.Fatal("slow input rejected")
	}
	waitInput(t, tm, slow, func(q *terminalInputQueue) bool { return len(q.messages) == 0 && q.bytes > 0 })
	r, w := inputTestPipe(t)
	fast := inputTestSession(tm, "fast", "fast-view", w)
	for _, data := range []string{"first", "-second", "-third"} {
		if !tm.submit(terminalLiveMsg{instance: "fast", session: "fast-view", data: []byte(data)}) {
			t.Fatal("fast input rejected")
		}
	}
	if err := r.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("first-second-third"))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("unrelated blocked terminal delayed input: %v", err)
	}
	if string(got) != "first-second-third" {
		t.Fatalf("FIFO changed: %q", got)
	}
	q := waitInput(t, tm, fast, func(q *terminalInputQueue) bool { return q.bytes == 0 })
	tm.stop("slow")
	slowQ := slow.input
	select {
	case <-slowQ.done:
	case <-time.After(time.Second):
		t.Fatal("stalled borrowed PTY input worker leaked after stop")
	}
	tm.stop("fast")
	select {
	case <-q.done:
	case <-time.After(time.Second):
		t.Fatal("idle input worker leaked")
	}
	// Stopping a terminal view must leave the runtime-owned descriptor open
	// and remove the cancellation deadline before returning it to its owner.
	if _, err := w.Write([]byte("owner")); err != nil {
		t.Fatalf("borrowed master closed or deadline poisoned: %v", err)
	}
}

func TestTerminalInputNeverReplaysIntoReplacementOrDetachedViewer(t *testing.T) {
	tm := inputTestManager(t)
	_, w := inputTestPipe(t)
	old := inputTestSession(tm, "agent", "old-view", w)
	if !tm.submit(terminalLiveMsg{instance: "agent", session: "old-view", data: bytes.Repeat([]byte("x"), 128*1024)}) {
		t.Fatal("initial input rejected")
	}
	waitInput(t, tm, old, func(q *terminalInputQueue) bool { return len(q.messages) == 0 && q.bytes > 0 })
	if !tm.submit(terminalLiveMsg{instance: "agent", session: "old-view", data: []byte("NEVER-REPLAY")}) {
		t.Fatal("queued input rejected")
	}
	tm.stop("agent")
	select {
	case <-old.input.done:
	case <-time.After(time.Second):
		t.Fatal("old worker did not stop")
	}
	r, fresh := inputTestPipe(t)
	replacement := inputTestSession(tm, "agent", "fresh-view", fresh)
	tm.d.removeAttach("agent", "old-view")
	if tm.submit(terminalLiveMsg{instance: "agent", session: "old-view", data: []byte("DETACHED")}) {
		t.Fatal("detached viewer input accepted")
	}
	if !tm.submit(terminalLiveMsg{instance: "agent", session: "fresh-view", data: []byte("fresh")}) {
		t.Fatal("fresh input rejected")
	}
	if err := r.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "fresh" {
		t.Fatalf("old input crossed PTY generations: %q", got)
	}
	waitInput(t, tm, replacement, func(q *terminalInputQueue) bool { return q.bytes == 0 })
	if err := r.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := r.Read(make([]byte, 32)); n != 0 || !os.IsTimeout(err) {
		t.Fatalf("unexpected replay n=%d err=%v", n, err)
	}
}

func TestTerminalInputBoundsBytesAndRejectsRemainderOfViewer(t *testing.T) {
	tm := inputTestManager(t)
	_, w := inputTestPipe(t)
	s := inputTestSession(tm, "agent", "paste-view", w)
	if !tm.submit(terminalLiveMsg{instance: "agent", session: "paste-view", data: bytes.Repeat([]byte("x"), terminalInputBytes)}) {
		t.Fatal("bounded maximum paste rejected")
	}
	q := waitInput(t, tm, s, func(q *terminalInputQueue) bool { return q.bytes == terminalInputBytes })
	if tm.submit(terminalLiveMsg{instance: "agent", session: "paste-view", data: []byte("overflow")}) {
		t.Fatal("overflow accepted")
	}
	if tm.submit(terminalLiveMsg{instance: "agent", session: "paste-view", data: []byte("remainder")}) {
		t.Fatal("rejected paste remainder accepted")
	}
	tm.mu.Lock()
	if q.bytes > terminalInputBytes {
		t.Errorf("byte budget exceeded: %d", q.bytes)
	}
	tm.mu.Unlock()
	tm.stop("agent")
	select {
	case <-q.done:
	case <-time.After(time.Second):
		t.Fatal("overflow worker leaked")
	}
}

func TestTerminalInputRetriesRejectionWhenNotificationCapacityReturns(t *testing.T) {
	tm := inputTestManager(t)
	client, server := newMemWS(t)
	tm.d.curConn = client
	tm.d.writeTimeout = time.Second
	_, w := inputTestPipe(t)
	inputTestSession(tm, "agent", "viewer", w)
	for i := 0; i < cap(tm.reports); i++ {
		tm.reports <- struct{}{}
	}
	if tm.submit(terminalLiveMsg{instance: "agent", session: "viewer", data: make([]byte, terminalInputBytes+1)}) {
		t.Fatal("oversize input accepted")
	}
	// Rejection was retained while the bounded notification path was full.
	// The next key must retry the error, never silently leave a dead keyboard.
	<-tm.reports
	if tm.submit(terminalLiveMsg{instance: "agent", session: "viewer", data: []byte("next-key")}) {
		t.Fatal("rejected viewer remainder accepted")
	}
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, raw, err := server.ReadMessage()
	if err != nil {
		t.Fatalf("rejection was lost after notification capacity returned: %v", err)
	}
	var env transport.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	var p transport.TerminalOutputPayload
	if err := env.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p.InstanceID != "agent" || p.SessionID != "viewer" || p.ClosedReason != "input_backpressure" {
		t.Fatalf("incorrect targeted rejection: %+v", p)
	}
}
