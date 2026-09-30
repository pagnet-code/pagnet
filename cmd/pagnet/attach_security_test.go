package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
			{Type: "terminal", Seq: 11, Data: base64.StdEncoding.EncodeToString([]byte("live"))},
			{Type: "closed", Reason: "stopped"},
		} {
			_ = conn.WriteJSON(frame)
		}
	})
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = write
	defer func() { os.Stdout = previous; read.Close(); write.Close() }()
	done, reason := outputPump(conn)
	for {
		select {
		case <-done:
			goto finished
		default:
			_ = reason()
		}
	}
finished:
	write.Close()
	data, err := io.ReadAll(read)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "snapshotlive" {
		t.Fatalf("output = %q", data)
	}
	if reason() != "stopped" {
		t.Fatalf("reason = %q", reason())
	}
}
