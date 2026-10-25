package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestReconnectBackoff(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name        string
		backoff     time.Duration
		connectedAt time.Time
		want        time.Duration
	}{
		{"failed dial at cap", 30 * time.Second, time.Time{}, 30 * time.Second},
		{"failed dial while increasing", 4 * time.Second, time.Time{}, 4 * time.Second},
		{"brief flap", 8 * time.Second, now.Add(-time.Second), 8 * time.Second},
		{"just below stable", 30 * time.Second, now.Add(-time.Minute + time.Nanosecond), 30 * time.Second},
		{"stable at threshold", 30 * time.Second, now.Add(-time.Minute), time.Second},
		{"healthy for hours", 30 * time.Second, now.Add(-3 * time.Hour), time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := reconnectBackoff(tc.backoff, tc.connectedAt, now); got != tc.want {
				t.Fatalf("retry delay = %v, want %v", got, tc.want)
			}
		})
	}

	// A stable connection clears old failures, but a subsequent short-lived
	// connection retains the new exponential retry history.
	backoff := reconnectBackoff(30*time.Second, now.Add(-time.Minute), now)
	backoff *= 2 // Run increases the delay after waiting for the retry.
	if got := reconnectBackoff(backoff, now.Add(-time.Second), now); got != 2*time.Second {
		t.Fatalf("retry delay after stable recovery then flap = %v, want 2s", got)
	}
}

func TestConnectAndRunFailedUpgradeDoesNotRecordConnectedAt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	d := newTestDaemon(t)
	d.ServerURL = server.URL
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connectedAt, err := d.connectAndRun(ctx)
	if err == nil {
		t.Fatal("rejected WebSocket upgrade succeeded")
	}
	if !connectedAt.IsZero() {
		t.Fatalf("failed upgrade recorded connectedAt = %v", connectedAt)
	}
}

func TestConnectAndRunRecordsUpgradeTime(t *testing.T) {
	upgradeStarted := make(chan time.Time, 1)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The dial has already started when the request reaches the server.
		// A timestamp taken at dial start would precede this boundary.
		upgradeStarted <- time.Now()
		conn, err := upgrader.Upgrade(w, r, nil)
		if err == nil {
			_ = conn.Close()
		}
	}))
	t.Cleanup(server.Close)
	d := newTestDaemon(t)
	d.ServerURL = server.URL
	d.NoScan = true
	d.Heartbeat = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connectedAt, err := d.connectAndRun(ctx)
	if err == nil {
		t.Fatal("closed WebSocket did not end connection")
	}
	select {
	case started := <-upgradeStarted:
		if connectedAt.IsZero() || connectedAt.Before(started) {
			t.Fatalf("connectedAt = %v, want timestamp after upgrade began at %v", connectedAt, started)
		}
	default:
		t.Fatal("WebSocket upgrade was not attempted")
	}
}
