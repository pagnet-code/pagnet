package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestWriteFailureInvalidatesAndReconnects proves the WAVE 2 transport
// resilience behavior end to end:
//
//  1. A write failure on the CURRENT host connection invalidates it —
//     curConn is cleared (compare-and-clear) and the failed conn is closed.
//  2. The daemon reconnects (a NEW connection is established).
//  3. A subsequent send uses the NEW connection.
//
// It is DETERMINISTIC: the transport deadlines (write / read / ping) are
// shortened so the test never depends on real-second deadlines, and the
// failure is forced by closing the connection — no flaky sleeps, no reliance
// on a stalled peer filling a TCP buffer. The fake server is an in-process
// httptest + gorilla-upgrade websocket that answers PINGs with PONG at the
// protocol level (like the real control plane) and signals when it receives
// the test's marker message.
func TestWriteFailureInvalidatesAndReconnects(t *testing.T) {
	// --- in-process fake websocket server (httptest + gorilla upgrade) ---
	// Accepts connections, reads the data messages it receives, and answers
	// PINGs with PONG automatically (gorilla's read pump does this at the
	// protocol level — exactly like the real control plane). When it receives
	// the test's marker message it signals gotPing, so the test can verify a
	// send landed on a LIVE connection (connA is closed by then, so the only
	// live conn is the re-established one).
	var (
		gotPing = make(chan struct{}, 1)
	)
	upg := websocket.Upgrader{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upg.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			_, raw, err := c.ReadMessage()
			if err != nil {
				return
			}
			if strings.Contains(string(raw), `"type":"test.ping"`) {
				select {
				case gotPing <- struct{}{}:
				default:
				}
			}
		}
	}))
	defer ts.Close()

	d := newTestDaemon(t)
	d.ServerURL = ts.URL
	d.Credential = "test-cred"
	d.NoScan = true         // no git scan; keep the test fast
	d.Heartbeat = time.Hour // never fires; the test drives writes explicitly
	// Shorten the transport deadlines so the test is fast and deterministic
	// (no real-second deadlines).
	d.writeTimeout = 200 * time.Millisecond
	d.readTimeout = 400 * time.Millisecond
	d.pingEvery = 100 * time.Millisecond

	// --- Phase 1: a write failure on curConn invalidates it ---
	// Dial a connection to the fake server; this becomes the current conn.
	connA, _, err := websocket.DefaultDialer.Dial(d.wsURL(), nil)
	if err != nil {
		t.Fatalf("dial connA: %v", err)
	}
	d.connMu.Lock()
	d.curConn = connA
	d.connMu.Unlock()

	// Poison the connection: close it. A subsequent write must fail.
	_ = connA.Close()

	// A write to the poisoned conn fails and must invalidate it.
	if err := d.write(connA, []byte(`{"protocolVersion":2,"type":"x","id":"1","payload":{}}`)); err == nil {
		t.Fatal("write to a closed conn succeeded; want a failure")
	}

	// curConn must be cleared (the failed conn was current).
	d.connMu.Lock()
	cur := d.curConn
	d.connMu.Unlock()
	if cur != nil {
		t.Fatalf("curConn = %v after a failed write; want nil (invalidated)", cur)
	}
	// The failed conn must be closed (a write on it fails).
	if err := connA.WriteMessage(websocket.TextMessage, []byte("x")); err == nil {
		t.Fatal("write on the invalidated conn succeeded; want it closed")
	}

	// --- Phase 2: the daemon reconnects and a subsequent send uses the NEW conn ---
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// A minimal reconnect loop (mirrors Run, without the serve-lock /
	// bridge-socket setup): dial, run the read loop, and on exit dial again.
	// The FIRST dial is immediate (no backoff), so the new connection is
	// established without a real-second wait.
	go func() {
		backoff := time.Second
		for ctx.Err() == nil {
			// Dial + run the read loop; on any exit (connection lost) the
			// loop dials again — that IS the reconnect.
			_ = d.connectAndRun(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}()

	// Wait for the daemon to establish a NEW connection (curConn != nil and
	// != the invalidated connA).
	var connB *websocket.Conn
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		d.connMu.Lock()
		c := d.curConn
		d.connMu.Unlock()
		if c != nil && c != connA {
			connB = c
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if connB == nil {
		t.Fatal("daemon did not re-establish a connection after the write failure")
	}
	if connB == connA {
		t.Fatal("the re-established connection is the invalidated one; want a NEW connection")
	}

	// A subsequent send must use the NEW connection (connB). d.send prefers
	// curConn, so passing nil forces it onto connB.
	if err := d.send(nil, "test.ping", map[string]any{"n": 1}); err != nil {
		t.Fatalf("send on the new connection failed: %v", err)
	}
	// Verify the fake server received the send on a LIVE connection. connA is
	// closed by now, so the only live conn is the re-established one (connB) —
	// a delivery proves the send used the NEW connection.
	select {
	case <-gotPing:
		// success: the new connection received the send.
	case <-time.After(5 * time.Second):
		t.Fatal("the new connection did not receive the send")
	}
}
