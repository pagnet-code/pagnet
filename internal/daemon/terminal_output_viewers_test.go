package daemon

import (
	"bytes"
	"encoding/base64"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func outputTestSession(t *testing.T, d *Daemon, instance string) (*ptySession, *os.File, <-chan struct{}) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	live := make(chan struct{})
	close(live)
	s := &ptySession{instanceID: instance, f: r, live: live}
	d.terminal.mu.Lock()
	d.terminal.sessions[instance] = s
	d.terminal.mu.Unlock()
	t.Cleanup(func() {
		d.terminal.mu.Lock()
		if d.terminal.sessions[instance] == s {
			delete(d.terminal.sessions, instance)
		}
		d.terminal.mu.Unlock()
	})
	done := make(chan struct{})
	go func() { defer close(done); d.terminal.readLoop(s) }()
	return s, w, done
}

func registerOutputViewer(t *testing.T, d *Daemon, s *ptySession, id string) {
	t.Helper()
	if ok, err := d.registerTerminalAttach(s, transport.TerminalAttachPayload{InstanceID: s.instanceID, SessionID: id}); err != nil || !ok {
		t.Fatalf("register viewer %s: ok=%v err=%v", id, ok, err)
	}
}

func waitOutputSeq(t *testing.T, s *ptySession, seq uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.bufMu.Lock()
		got := s.seq
		s.bufMu.Unlock()
		if got == seq {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("output seq=%d, want %d", got, seq)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTerminalOutputUnattachedBuffersWithoutSending(t *testing.T) {
	d := newTestDaemon(t)
	client, peer := newMemWS(t)
	d.curConn = client
	s, w, done := outputTestSession(t, d, "agent")
	input := bytes.Repeat([]byte("x"), terminalRingCap+terminalChunk)
	if _, err := w.Write(input); err != nil {
		t.Fatal(err)
	}
	w.Close()
	<-done
	registerOutputViewer(t, d, s, "first")
	data, seq := d.terminal.snapshot(s)
	if err := d.send(nil, transport.MsgTerminalOutput, transport.TerminalOutputPayload{InstanceID: "agent", SessionID: "first", Snapshot: true, Data: data, LastSeq: seq}); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	var env transport.Envelope
	if err := peer.ReadJSON(&env); err != nil {
		t.Fatal(err)
	}
	var output transport.TerminalOutputPayload
	if err := env.DecodePayload(&output); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(output.Data)
	if err != nil || !output.Snapshot || output.SessionID != "first" || output.LastSeq != uint64(len(input)) || !bytes.Equal(raw, input[len(input)-terminalRingCap:]) {
		t.Fatalf("first output must be bounded replay with full byte seq: snapshot=%v viewer=%q seq=%d bytes=%d err=%v", output.Snapshot, output.SessionID, output.LastSeq, len(raw), err)
	}
}

func TestTerminalOutputDetachAndGenerationIsolation(t *testing.T) {
	d := newTestDaemon(t)
	client, peer := newMemWS(t)
	d.curConn = client
	old, oldWriter, oldDone := outputTestSession(t, d, "agent")
	registerOutputViewer(t, d, old, "first")
	registerOutputViewer(t, d, old, "second")
	// Detaching one viewer retains the other viewer's live stream.
	if d.removeAttach("agent", "first") {
		t.Fatal("first detach removed last viewer")
	}
	if _, err := oldWriter.Write([]byte("remaining")); err != nil {
		t.Fatal(err)
	}
	waitOutputSeq(t, old, 9)
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	var env transport.Envelope
	if err := peer.ReadJSON(&env); err != nil {
		t.Fatal(err)
	}
	var output transport.TerminalOutputPayload
	if err := env.DecodePayload(&output); err != nil || output.SessionID != "second" || output.Seq != 9 {
		t.Fatalf("remaining viewer output: %+v err=%v", output, err)
	}
	if !d.removeAttach("agent", "second") {
		t.Fatal("second detach must remove the last viewer")
	}
	if _, err := oldWriter.Write([]byte("detached")); err != nil {
		t.Fatal(err)
	}
	waitOutputSeq(t, old, 17)
	// Leave one old-generation viewer registered when replacing the PTY.
	registerOutputViewer(t, d, old, "old")
	// A replacement never inherits the old instance-wide attach bookkeeping.
	replacement, writer, done := outputTestSession(t, d, "agent")
	if _, err := writer.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	waitOutputSeq(t, replacement, 6)
	if err := d.doTerminalSnapshot(nil, transport.TerminalSnapshotPayload{InstanceID: "agent", SessionID: "old"}); err != nil {
		t.Fatal(err)
	}
	registerOutputViewer(t, d, replacement, "new")
	if _, err := oldWriter.Write([]byte("retired")); err != nil {
		t.Fatal(err)
	}
	oldWriter.Close()
	<-oldDone
	if _, err := writer.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	<-done
	if err := peer.ReadJSON(&env); err != nil {
		t.Fatal(err)
	}
	if err := env.DecodePayload(&output); err != nil || output.SessionID != "new" || output.Seq != 11 {
		t.Fatalf("replacement output: %+v err=%v", output, err)
	}
	raw, _ := base64.StdEncoding.DecodeString(output.Data)
	if string(raw) != "after" {
		t.Fatalf("replacement leaked output %q", raw)
	}
	// A wire marker proves there were no additional old/broadcast frames.
	if err := d.send(nil, "test.output_done", struct{}{}); err != nil {
		t.Fatal(err)
	}
	if err := peer.ReadJSON(&env); err != nil || env.Type != "test.output_done" {
		t.Fatalf("unexpected extra output: %+v err=%v", env, err)
	}
}

func TestTerminalOutputConcurrentAttachHasNoGap(t *testing.T) {
	d := newTestDaemon(t)
	client, peer := newMemWS(t)
	d.curConn = client
	peer.SetReadDeadline(time.Now().Add(10 * time.Second))
	s, writer, done := outputTestSession(t, d, "agent")
	// Capture the wire concurrently so a long stream cannot fill the socket.
	var frames []transport.TerminalOutputPayload
	var readErr error
	var read sync.WaitGroup
	read.Add(1)
	go func() {
		defer read.Done()
		for {
			var env transport.Envelope
			if err := peer.ReadJSON(&env); err != nil {
				readErr = err
				return
			}
			if env.Type == "test.output_done" {
				return
			}
			var output transport.TerminalOutputPayload
			if err := env.DecodePayload(&output); err != nil {
				readErr = err
				return
			}
			frames = append(frames, output)
		}
	}()
	input := bytes.Repeat([]byte("concurrent-output"), 8192)
	written := make(chan error, 1)
	go func() { _, err := writer.Write(input); writer.Close(); written <- err }()
	registerOutputViewer(t, d, s, "viewer")
	data, seq := d.terminal.snapshot(s)
	if err := d.send(nil, transport.MsgTerminalOutput, transport.TerminalOutputPayload{InstanceID: "agent", SessionID: "viewer", Snapshot: true, Data: data, LastSeq: seq}); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	<-done
	if err := d.send(nil, "test.output_done", struct{}{}); err != nil {
		t.Fatal(err)
	}
	read.Wait()
	if readErr != nil {
		t.Fatal(readErr)
	}
	// Live frames can precede the snapshot on the wire. LastSeq discards
	// their replayed prefix; the remaining frames must cover every byte.
	var replay []byte
	for _, frame := range frames {
		if frame.SessionID != "viewer" {
			t.Fatalf("unscoped output: %+v", frame)
		}
		if frame.Snapshot {
			replay, _ = base64.StdEncoding.DecodeString(frame.Data)
		}
	}
	last := seq
	for _, frame := range frames {
		if frame.Snapshot || frame.Seq <= last {
			continue
		}
		chunk, err := base64.StdEncoding.DecodeString(frame.Data)
		if err != nil {
			t.Fatal(err)
		}
		start := frame.Seq - uint64(len(chunk))
		if start > last {
			t.Fatalf("gap between snapshot/live frames: last=%d start=%d", last, start)
		}
		replay = append(replay, chunk[last-start:]...)
		last = frame.Seq
	}
	if !bytes.Equal(replay, input) {
		t.Fatalf("replay/live coverage=%d bytes, want %d", len(replay), len(input))
	}
}
