package daemon

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
)

// TestOwnerTextConsoleLiveHost is an opt-in subprocess entry point for the
// server's owner text console browser test. Both inputs contain private local
// credentials: a Config and an array of complete textbridge.Profile values.
// Responder profiles may point at the server test's loopback HTTP provider.
func TestOwnerTextConsoleLiveHost(t *testing.T) {
	path := os.Getenv("PAGNET_OWNER_TEXT_LIVE_HOST_CONFIG")
	if path == "" {
		t.Skip("server-driven live text host helper")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read live text host configuration:", err)
	}
	var cfg Config
	err = json.Unmarshal(raw, &cfg)
	clear(raw)
	if err != nil {
		t.Fatal("decode live text host configuration:", err)
	}
	if cfg.ServerURL == "" || cfg.HostID == "" || cfg.Credential == "" || cfg.StateDir == "" {
		t.Fatal("incomplete live text host configuration")
	}
	raw, err = os.ReadFile(os.Getenv("PAGNET_OWNER_TEXT_LIVE_PROFILES"))
	if err != nil {
		t.Fatal("read live text profiles:", err)
	}
	var profiles []textbridge.Profile
	err = json.Unmarshal(raw, &profiles)
	clear(raw)
	if err != nil {
		t.Fatal("decode live text profiles:", err)
	}
	if len(profiles) == 0 {
		t.Fatal("live text profiles are required")
	}
	for _, p := range profiles {
		persistOwnerTextLiveProfile(t, cfg, p)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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

func persistOwnerTextLiveProfile(t *testing.T, cfg Config, p textbridge.Profile) {
	t.Helper()
	r := p.Registration
	if p.ProjectContract != textbridge.OwnerTextProjectContract || p.Server != cfg.ServerURL || p.Disabled || r == nil || r.HostID != cfg.HostID || r.Pending || r.DesiredState != "enabled" {
		t.Fatal("live text profile requires a matching confirmed enabled owner installation")
	}
	dir, err := textbridge.ProfileDirectoryForRole(cfg.StateDir, p.Service, p.ServiceRole())
	if err != nil {
		t.Fatal("create live text profile directory:", err)
	}
	unlock, err := textbridge.LockProfile(dir)
	if err != nil {
		t.Fatal("lock live text profile:", err)
	}
	defer unlock()
	// A restart must retain reconciliation's updated registration and all durable
	// sender or responder work instead of replacing it with the initial fixture.
	if _, err := os.Lstat(filepath.Join(dir, "profile.json")); err == nil {
		if _, err := textbridge.LoadProfile(dir, p.Service); err != nil {
			t.Fatal("validate existing live text profile:", err)
		}
		return
	} else if !os.IsNotExist(err) {
		t.Fatal("inspect existing live text profile:", err)
	}
	if p.ServiceRole() == "responder" && p.Fingerprint == "" {
		key, err := textbridge.ReadProviderKey(p.KeyFile)
		if err != nil {
			t.Fatal("read live responder fixture key:", err)
		}
		p.Fingerprint = textbridge.ProviderFingerprint(provider.Config{BaseURL: p.ProviderOrigin, Model: p.Model, APIKey: key})
	}
	if err := textbridge.SaveProfile(dir, p); err != nil {
		t.Fatal("save live text profile:", err)
	}
	if _, err := textbridge.LoadProfile(dir, p.Service); err != nil {
		t.Fatal("validate live text profile:", err)
	}
	if p.ServiceRole() == "sender" {
		store, err := sender.Open(filepath.Join(dir, "operations"), p.SenderBinding())
		if err != nil {
			t.Fatal("initialize live sender state:", err)
		}
		if err := store.Close(); err != nil {
			t.Fatal("close live sender state:", err)
		}
	} else {
		store, err := ledger.Open(filepath.Join(dir, "ledger"), p.LedgerBinding(), p.Limits)
		if err != nil {
			t.Fatal("initialize live responder ledger:", err)
		}
		if err := store.Close(); err != nil {
			t.Fatal("close live responder ledger:", err)
		}
	}
}
