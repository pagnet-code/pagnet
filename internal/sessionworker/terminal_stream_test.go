package sessionworker

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTerminalKeysDoNotWaitForAckAndResizeCoalesces(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	stream := newTerminalStream(client, "native-generation")
	defer stream.Close()
	started := time.Now()
	for _, key := range []byte("hello") {
		if err := stream.SendInput([]byte{key}); err != nil {
			t.Fatal(err)
		}
	}
	// The peer sends no acknowledgment, including while local resize changes.
	for i := uint16(1); i <= 1000; i++ {
		if err := stream.Resize(i, i); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(started) > 100*time.Millisecond {
		t.Fatal("input waited for peer delivery/ack")
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	var received []byte
	var dimensions uint16
	for len(received) < 5 || dimensions != 1000 {
		var frame terminalFrame
		if err := readFrame(server, &frame); err != nil {
			t.Fatal(err)
		}
		received = append(received, frame.Data...)
		if frame.Rows > 0 {
			dimensions = frame.Rows
			if frame.Rows != frame.Cols {
				t.Fatal("inconsistent coalesced resize")
			}
		}
	}
	if string(received) != "hello" {
		t.Fatal("key input changed or reordered")
	}
}

func TestTerminalSlowConsumerIsBoundedAndEOFNeverReplaysPaste(t *testing.T) {
	client, server := net.Pipe()
	stream := newTerminalStream(client, "native-generation")
	defer stream.Close()
	payload := bytes.Repeat([]byte{'x'}, maxTerminalInputBytes)
	full := false
	started := time.Now()
	for i := 0; i < 100; i++ {
		err := stream.SendInput(payload)
		if errors.Is(err, ErrFull) {
			full = true
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !full || time.Since(started) > 100*time.Millisecond {
		t.Fatal("slow consumer did not apply immediate bounded backpressure")
	}
	stream.mu.Lock()
	queued := stream.queued
	stream.mu.Unlock()
	if queued > maxTerminalQueueBytes {
		t.Fatal("unbounded pending terminal paste")
	}
	_ = server.Close()
	select {
	case <-stream.done:
	case <-time.After(time.Second):
		t.Fatal("stream EOF not exposed")
	}
	if stream.SendInput([]byte("new key")) == nil {
		t.Fatal("disconnected stream accepted fresh input")
	}
	stream.mu.Lock()
	retained := stream.queued + len(stream.queue)
	stream.mu.Unlock()
	if retained != 0 {
		t.Fatal("uncertain paste retained for replay")
	}
	// Replacement starts without copying uncertain input into a new queue.
	freshClient, freshServer := net.Pipe()
	defer freshServer.Close()
	fresh := newTerminalStream(freshClient, "native-generation")
	defer fresh.Close()
	_ = freshServer.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	var frame terminalFrame
	if readFrame(freshServer, &frame) == nil {
		t.Fatal("replacement replayed unknown old input")
	}
}

func TestPTYLessNativeSessionRejectsTerminalWithoutReplacingController(t *testing.T) {
	dir, err := os.MkdirTemp("", "pgn-tstream-")
	if err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close(); _ = os.RemoveAll(dir) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	spec := NativeSpec{Kind: "worker", TenantID: j.scope.TenantID, NetworkID: "network"}
	owner := &SessionOwner{journal: j, ctx: ctx, relay: newRelayBroker(j.scope, spec)}
	key := bytes.Repeat([]byte{1}, 32)
	done := make(chan error, 1)
	go func() { done <- ServeOwner(ctx, owner, key, "fixture") }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("terminal rejection interrupted controller cleanup")
		}
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(filepath.Join(dir, "controller.sock")); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	controller, err := DialOwnerController(ctx, dir, j.scope, key, "controller")
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	before := controller.Lease
	stream, err := controller.OpenTerminalStream(ctx, dir, j.scope, key, "native-generation")
	if stream != nil || err == nil || !strings.Contains(err.Error(), "does not expose a live interactive terminal") {
		t.Fatalf("PTY-less runtime advertised a terminal: %v", err)
	}
	if err = j.CurrentLease(ctx, before); err != nil {
		t.Fatal("unsupported terminal advanced ownership", err)
	}
	reply, err := controller.Call(ctx, Request{Type: "bridge_poll"})
	if err != nil || reply.Error != "fresh control-plane admission is required" {
		t.Fatal("terminal setup interrupted the machine controller", err, reply.Error)
	}
}
