package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func attachTestSocket(t *testing.T, serve func(*websocket.Conn)) *websocket.Conn {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		serve(conn)
	}))
	t.Cleanup(server.Close)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestAttachWriterConcurrentInputAndResize(t *testing.T) {
	const count = 200
	received := make(chan error, 1)
	conn := attachTestSocket(t, func(conn *websocket.Conn) {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		seen := map[string]bool{}
		for i := 0; i < count; i++ {
			var frame map[string]any
			if err := conn.ReadJSON(&frame); err != nil {
				received <- err
				return
			}
			seen[frame["id"].(string)] = true
		}
		if len(seen) != count {
			received <- fmt.Errorf("received %d unique frames", len(seen))
			return
		}
		received <- nil
	})
	send := newAttachWriter(conn)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); send(map[string]any{"type": "input", "id": fmt.Sprint(i)}) }(i)
	}
	wg.Wait()
	if err := <-received; err != nil {
		t.Fatal(err)
	}
}

func TestAttachSnapshotPreservesSequenceAndReasonReadIsSafe(t *testing.T) {
	conn := attachTestSocket(t, func(conn *websocket.Conn) {
		for _, frame := range []ptyFrame{
			{Type: "terminal", Snapshot: true, LastSeq: 10, Data: base64.StdEncoding.EncodeToString([]byte("snapshot"))},
			{Type: "terminal", Seq: 9, Data: base64.StdEncoding.EncodeToString([]byte("duplicate"))},
			{Type: "terminal", Seq: 14, Data: base64.StdEncoding.EncodeToString([]byte("live"))},
			{Type: "closed", Reason: "stopped"},
		} {
			_ = conn.WriteJSON(frame)
		}
	})
	var output bytes.Buffer
	done, reason := outputPumpTo(conn, &output)
	for {
		select {
		case <-done:
			goto finished
		default:
			_ = reason()
		}
	}
finished:
	if output.String() != "snapshotlive" {
		t.Fatalf("output = %q", output.String())
	}
	if reason() != "stopped" {
		t.Fatalf("reason = %q", reason())
	}
}

func TestAttachOutputByteContinuity(t *testing.T) {
	encode := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for _, tc := range []struct {
		name   string
		frames []ptyFrame
		want   string
		failed bool
	}{
		{"replay overlap", []ptyFrame{{Type: "terminal", Snapshot: true, LastSeq: 100, Data: encode("abc")}, {Type: "terminal", Seq: 100, Data: encode("abc")}, {Type: "terminal", Seq: 102, Data: encode("cde")}, {Type: "terminal", Seq: 103, Data: encode("f")}}, "abcdef", false},
		{"gap", []ptyFrame{{Type: "terminal", Snapshot: true, LastSeq: 1, Data: encode("a")}, {Type: "terminal", Seq: 3, Data: encode("c")}}, "a", true},
		{"malformed snapshot", []ptyFrame{{Type: "terminal", Snapshot: true, LastSeq: 10, Data: "%%%"}}, "", true},
		{"snapshot underflow", []ptyFrame{{Type: "terminal", Snapshot: true, LastSeq: 1, Data: encode("abc")}}, "", true},
		{"live underflow", []ptyFrame{{Type: "terminal", Snapshot: true, LastSeq: 1, Data: encode("a")}, {Type: "terminal", Seq: 2, Data: encode("abc")}}, "a", true},
		{"malformed duplicate", []ptyFrame{{Type: "terminal", Snapshot: true, LastSeq: 1, Data: encode("a")}, {Type: "terminal", Seq: 1, Data: "%%%"}}, "a", true},
		{"missing snapshot", []ptyFrame{{Type: "terminal", Seq: 1, Data: encode("a")}}, "", true},
		{"oversized snapshot", []ptyFrame{{Type: "terminal", Snapshot: true, LastSeq: 300000, Data: encode(strings.Repeat("x", 256*1024+1))}}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peerClosed := make(chan struct{})
			conn := attachTestSocket(t, func(peer *websocket.Conn) {
				for _, frame := range tc.frames {
					if err := peer.WriteJSON(frame); err != nil {
						return
					}
				}
				if tc.failed {
					_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
					_, _, _ = peer.ReadMessage()
					close(peerClosed)
				} else {
					_ = peer.WriteJSON(ptyFrame{Type: "closed", Reason: "stopped"})
				}
			})
			var output bytes.Buffer
			done, reason := outputPumpTo(conn, &output)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("output pump did not finish")
			}
			if output.String() != tc.want {
				t.Fatalf("output length=%d want length=%d", output.Len(), len(tc.want))
			}
			if tc.failed {
				if reason() == "" || reason() == "stopped" {
					t.Fatalf("missing corruption reason: %q", reason())
				}
				select {
				case <-peerClosed:
				case <-time.After(5 * time.Second):
					t.Fatal("corrupt stream socket stayed open")
				}
			}
		})
	}
}

func TestAttachWriterFailureClosesSocket(t *testing.T) {
	closed := make(chan struct{})
	conn := attachTestSocket(t, func(peer *websocket.Conn) {
		_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _, _ = peer.ReadMessage()
		close(closed)
	})
	done, _ := outputPumpTo(conn, &bytes.Buffer{})
	// Unsupported JSON values fail locally without a peer/network failure.
	newAttachWriter(conn)(map[string]any{"type": "input", "invalid": make(chan int)})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("failed write did not unblock output pump")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("failed write did not close socket")
	}
}

func TestAttachReadyWaitsForValidatedSnapshot(t *testing.T) {
	release := make(chan struct{})
	conn := attachTestSocket(t, func(peer *websocket.Conn) {
		<-release
		_ = peer.WriteJSON(ptyFrame{Type: "terminal", Snapshot: true, LastSeq: 0})
		_, _, _ = peer.ReadMessage()
	})
	done, ready, reason := outputPumpToReady(conn, &bytes.Buffer{})
	waiting := make(chan error, 1)
	go func() { waiting <- waitAttachReady(conn, done, ready, reason) }()
	select {
	case err := <-waiting:
		t.Fatalf("ready before snapshot: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-waiting:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("valid empty snapshot did not mark ready")
	}
	_ = conn.Close()
	<-done
}

func TestAttachReadyRejectsInvalidSnapshot(t *testing.T) {
	conn := attachTestSocket(t, func(peer *websocket.Conn) {
		_ = peer.WriteJSON(ptyFrame{Type: "terminal", Snapshot: true, Data: "%%%"})
	})
	done, ready, reason := outputPumpToReady(conn, &bytes.Buffer{})
	if err := waitAttachReady(conn, done, ready, reason); err == nil {
		t.Fatal("invalid snapshot accepted as ready")
	}
	select {
	case <-ready:
		t.Fatal("invalid snapshot published readiness")
	default:
	}
}
