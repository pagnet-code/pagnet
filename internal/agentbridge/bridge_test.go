package agentbridge

// Regression tests for the id-correlated bridge client (the daemon's
// agent-bridge socket is the only network path a managed agent has).

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeBridgeServer plays the daemon side: one serial request loop that
// echoes each request's args in the result, with per-tool behavior hooks.
func fakeBridgeServer(t *testing.T) (socket string, closeFn func()) {
	t.Helper()
	dir := t.TempDir()
	socket = filepath.Join(dir, "agentnetd.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		var auth struct {
			Type       string `json:"type"`
			InstanceID string `json:"instanceId"`
			NetworkID  string `json:"networkId"`
		}
		if err := json.Unmarshal([]byte(line), &auth); err != nil || auth.Type != "auth" {
			return
		}
		c.Write([]byte(`{"type":"auth_ok","instanceId":"` + auth.InstanceID + `"}` + "\n"))
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			var req struct {
				ID   string          `json:"id"`
				Tool string          `json:"tool"`
				Args json.RawMessage `json:"args"`
			}
			if err := json.Unmarshal([]byte(line), &req); err != nil {
				return
			}
			if req.Tool == "slow" {
				time.Sleep(300 * time.Millisecond)
			}
			c.Write(append(mustJSON(map[string]any{"id": req.ID, "ok": true, "result": map[string]any{"args": json.RawMessage(req.Args)}}), '\n'))
		}
	}()

	closeFn = func() {
		_ = l.Close()
		wg.Wait()
	}
	t.Cleanup(func() {
		closeFn()
		_ = os.Remove(socket)
	})
	return socket, closeFn
}

// Concurrent tool calls (runtimes batch parallel calls) must each receive
// THEIR OWN result — the old per-Call reader raced on the shared conn.
func TestBridgeConcurrentCalls_EchoOwnMarker(t *testing.T) {
	socket, _ := fakeBridgeServer(t)
	b, err := Dial(socket, "inst-1", "net-1")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := b.Call(context.Background(), "echo", map[string]any{"marker": i})
			if err != nil {
				errs[i] = err
				return
			}
			var out struct {
				Args struct {
					Marker int `json:"marker"`
				} `json:"args"`
			}
			if err := json.Unmarshal(res, &out); err != nil {
				errs[i] = err
				return
			}
			if out.Args.Marker != i {
				errs[i] = fmt.Errorf("call %d got marker %d (crossed results)", i, out.Args.Marker)
			}
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("call %d: %v", i, e)
		}
	}
}

// Canceling one in-flight call (MCP notifications/cancelled) must not
// corrupt the bridge: the late response is dropped by id, and the next
// call on the same bridge works.
func TestBridgeCanceledCall_DoesNotCorruptNext(t *testing.T) {
	socket, _ := fakeBridgeServer(t)
	b, err := Dial(socket, "inst-1", "net-1")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	_, err = b.Call(ctx, "slow", map[string]any{"marker": 0})
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled call: err = %v, want context.DeadlineExceeded", err)
	}

	// The slow response is still in flight (300 ms server hold); the next
	// call is queued behind it on the serial daemon and must still resolve
	// with its OWN marker — not the dropped one.
	res, err := b.Call(context.Background(), "echo", map[string]any{"marker": 42})
	if err != nil {
		t.Fatalf("call after cancel: %v", err)
	}
	var out struct {
		Args struct {
			Marker int `json:"marker"`
		} `json:"args"`
	}
	if err := json.Unmarshal(res, &out); err != nil || out.Args.Marker != 42 {
		t.Fatalf("call after cancel = %s (marker %d), want marker 42", res, out.Args.Marker)
	}
}

// Closing the bridge must fail a pending in-flight call (no goroutine
// blocks on a dead connection).
func TestBridgeClose_FailsPending(t *testing.T) {
	socket, _ := fakeBridgeServer(t)
	b, err := Dial(socket, "inst-1", "net-1")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := b.Call(context.Background(), "slow", map[string]any{})
		done <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the call go in flight
	b.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("pending call must fail when the bridge is closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending call did not unblock on Close")
	}
}
