package daemon

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// TestOwnerMailboxLiveHost is an opt-in subprocess entry point for the server's
// cross-repository browser smoke. It uses production startup and reconciliation.
func TestOwnerMailboxLiveHost(t *testing.T) {
	path := os.Getenv("PAGNET_OWNER_MAILBOX_LIVE_HOST_CONFIG")
	if path == "" {
		t.Skip("server-driven live host helper")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read live host configuration:", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal("decode live host configuration:", err)
	}
	clear(raw)
	if cfg.ServerURL == "" || cfg.HostID == "" || cfg.Credential == "" || cfg.StateDir == "" {
		t.Fatal("incomplete live host configuration")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Cover server readiness, both browser phases, SDK enrollment and teardown.
	ctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	d, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Run(ctx); err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}
}
