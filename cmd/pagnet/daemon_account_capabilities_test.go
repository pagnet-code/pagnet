//go:build linux || darwin

package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/config"
	"github.com/pagnet-code/pagnet/internal/daemon"
	"github.com/pagnet-code/pagnet/transport"
)

func TestServeAccountCapabilitiesReachHostHandshake(t *testing.T) {
	queries := make(chan url.Values, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/hosts/ws" {
			select {
			case queries <- r.URL.Query():
			default:
			}
		}
		// No host admission: offering support must not require authorization
		// to be relaxed or a managed runtime to be launched.
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := serveDaemonConfig(server.URL, config.Daemon{
		Credential: "test-host-credential", HostID: "test-host", StateDir: stateDir, NoScan: true,
	})
	if !cfg.AccountMessageSealEnabled || !cfg.AccountMessageExecutionEnabled ||
		!cfg.AccountReplyDeliveryEnabled || !cfg.AccountReplyReadEnabled {
		t.Fatal("serve omitted an account messaging capability")
	}
	d, err := daemon.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("daemon did not stop after handshake test")
		}
	}()
	select {
	case q := <-queries:
		for key, want := range map[string]string{
			"native_account_reply":       transport.NativeAccountReplyProtocol,
			"browser_account_reply_read": transport.BrowserAccountReplyReadProtocol,
		} {
			if got := q.Get(key); got != want {
				t.Errorf("host handshake %s = %q, want %q", key, got, want)
			}
		}
	case <-ctx.Done():
		t.Fatal("serve did not attempt a host handshake")
	}
}
